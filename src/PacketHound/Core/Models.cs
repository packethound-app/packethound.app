using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Windows.Media;

namespace PacketHound.Core;

public enum PromptDecision { Later, Allow, Block, Dismiss }

/// <summary>
/// One entry in the prompt's "Applies to" list. Destination is null for "Any connection". Address and
/// HostName are the connection the entry was built from, used to seed a host or domain rule.
/// </summary>
public sealed record ScopeOption(string Label, RuleDestination? Destination, string Address, string? HostName)
{
    public override string ToString() => Label;
}

/// <summary>An app waiting for the user's Allow/Block decision. Updated as more attempts arrive.</summary>
public sealed class PendingRequest : INotifyPropertyChanged
{
    static readonly Dictionary<int, string> WellKnownPorts = new()
    {
        [20] = "FTP data", [21] = "FTP", [22] = "SSH", [23] = "Telnet", [25] = "SMTP", [53] = "DNS",
        [67] = "DHCP", [80] = "HTTP", [110] = "POP3", [123] = "NTP", [137] = "NetBIOS", [143] = "IMAP",
        [161] = "SNMP", [389] = "LDAP", [443] = "HTTPS", [445] = "SMB", [465] = "SMTPS", [587] = "SMTP",
        [853] = "DNS over TLS", [993] = "IMAPS", [995] = "POP3S", [1194] = "OpenVPN", [1900] = "SSDP",
        [3389] = "Remote Desktop", [3478] = "STUN", [5353] = "mDNS", [5355] = "LLMNR", [8080] = "HTTP alt",
        [8443] = "HTTPS alt",
    };

    public PendingRequest(AppDetails app, BlockedConnection first)
    {
        App = app;
        FirstSeen = first.Time;
        ProcessName = TryGetProcessName(first.ProcessId);
        InTempFolder = TempFolders.Contains(app.Path);
        Update(first);
    }

    /// <summary>Runs from a temporary folder: probably an installer or updater that unpacks to a new folder each time.</summary>
    public bool InTempFolder { get; }

    public string FileName => System.IO.Path.GetFileName(AppPath);

    /// <summary>Verified Authenticode signer, filled in shortly after the request is created (null: unsigned or not checked yet).</summary>
    public string? Signer { get; private set; }

    public void SetSigner(string? signer)
    {
        Signer = signer;
        Changed();
    }

    public AppDetails App { get; }
    public string AppPath => App.Path;
    public string DisplayName => App.DisplayName;
    public ImageSource? Icon => App.Icon;
    public string Publisher => string.IsNullOrEmpty(App.Publisher) ? "Unknown publisher" : App.Publisher;
    public DateTime FirstSeen { get; }

    public int ProcessId { get; private set; }
    public string? ProcessName { get; }
    public string RemoteAddress { get; private set; } = "";
    public int RemotePort { get; private set; }
    public string ProtocolName { get; private set; } = "";
    public string? HostName { get; private set; }
    public int Attempts { get; private set; }

    public string DestinationTitle => HostName ?? RemoteAddress;

    public string DestinationDetail
    {
        get
        {
            var service = WellKnownPorts.TryGetValue(RemotePort, out var s) ? $" ({s})" : "";
            var port = RemotePort > 0 ? $"{ProtocolName} port {RemotePort}{service}" : ProtocolName;
            return HostName != null ? $"{RemoteAddress}  ·  {port}" : port;
        }
    }

    public string ProcessText => ProcessName != null ? $"{ProcessName}.exe (PID {ProcessId})" : $"PID {ProcessId}";
    public string AttemptsText => Attempts == 1 ? "1 attempt blocked so far" : $"{Attempts} attempts blocked so far";

    DateTime? _snoozedUntil;

    /// <summary>After "Decide later": when to ask again. Null once that time has passed (or while in the prompt queue).</summary>
    public DateTime? SnoozedUntil
    {
        get => _snoozedUntil;
        set { _snoozedUntil = value; Changed(); }
    }

    public bool IsSnoozed => SnoozedUntil > DateTime.Now;

    public string DeferredText => SnoozedUntil is { } until
        ? $"Asks again at {until:t} if it's running"
        : "Asks again when it next connects";

    public void Update(BlockedConnection c)
    {
        Attempts++;
        ProcessId = c.ProcessId;
        if (c.RemoteAddress != RemoteAddress) HostName = null;
        RemoteAddress = c.RemoteAddress;
        RemotePort = c.RemotePort;
        ProtocolName = c.ProtocolName;
        Changed();
    }

    public void SetHostName(string address, string? name)
    {
        if (address != RemoteAddress || string.IsNullOrEmpty(name)) return;
        HostName = name;
        Changed();
    }

    static string? TryGetProcessName(int pid)
    {
        try { using var p = Process.GetProcessById(pid); return p.ProcessName; }
        catch { return null; }
    }

    void Changed() => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(string.Empty));

    public event PropertyChangedEventHandler? PropertyChanged;
}

public sealed class ActivityEntry : INotifyPropertyChanged
{
    public DateTime Time { get; init; }
    public string AppName { get; init; } = "";
    public string AppPath { get; init; } = "";
    public string RemoteAddress { get; init; } = "";
    public int RemotePort { get; init; }
    public string Protocol { get; init; } = "";
    public string Result { get; init; } = "";

    string? _host;
    public string? HostName
    {
        get => _host;
        set { _host = value; PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Destination))); }
    }

    public string Destination =>
        (HostName != null ? $"{HostName} ({RemoteAddress})" : RemoteAddress) + (RemotePort > 0 ? $" : {RemotePort}" : "");

    public event PropertyChangedEventHandler? PropertyChanged;
}

/// <summary>A row in the Rules list: a Windows Firewall rule, or a signed-copy rule kept in PacketHound's settings.</summary>
public sealed class RuleRow
{
    public FirewallRuleInfo? Rule { get; init; }
    public SignedCopyRule? SignedCopy { get; init; }
    public ProgramState Program { get; init; }
    public bool IsMissing => Program == ProgramState.Missing;
    public bool IsWindowsAuto => Rule?.IsWindowsAuto == true;
    public string Name => Rule?.Name ?? "signed:" + SignedCopy!.Key;
    public string AppName => Rule?.DisplayName ?? SignedCopy!.DisplayName;
    public string Path => Rule?.ApplicationName ?? $"Any copy of {SignedCopy!.FileName} ({SignedCopy.Signer})";
    public bool IsAllow => Rule?.Allow ?? SignedCopy!.Allow;
    public string Action => IsAllow ? "Allow" : "Block";
    public string Kind => SignedCopy != null ? "Installer / updater" :Rule!.IsWindowsAuto ? "Windows (automatic)" : "Your decision";
    public string AppliesTo => Rule == null ? "Any connection"
        : Rule.Destination?.Label ?? (Rule.IsScoped ? "Some connections" : "Any connection");
    public DateTime? CreatedDate => Rule?.Created ?? SignedCopy!.Created;
    public string Created => CreatedDate?.ToString("g") ?? "";
    public string State =>
        Rule == null ? ""
        : IsMissing ? "Program not found"
        : Program == ProgramState.DriveUnavailable ? "Drive not connected"
        : !Rule.Enabled ? "Disabled"
        : Rule.IsTemporary ? "Until app quits" : "";

    public string? StateTip => Program switch
    {
        ProgramState.Missing => "This program is no longer on this PC, so the rule does nothing. Use “Remove missing” to delete it.",
        ProgramState.DriveUnavailable => "The drive this program is on isn't connected right now.",
        _ when SignedCopy != null => "This installer or updater runs from a new temporary folder each time. Your answer applies to every copy in a temporary folder with the same file name and a valid signature from the same publisher.",
        _ => null,
    };
}

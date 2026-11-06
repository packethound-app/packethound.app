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
        Update(first);
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

public sealed class RuleRow
{
    public required FirewallRuleInfo Rule { get; init; }
    public string Name => Rule.Name;
    public string AppName => Rule.DisplayName;
    public string Path => Rule.ApplicationName;
    public string Action => Rule.Allow ? "Allow" : "Block";
    public bool IsAllow => Rule.Allow;
    public string Kind => Rule.IsWindowsAuto ? "Windows (automatic)" : "Your decision";
    public string AppliesTo => Rule.Destination?.Label ?? (Rule.IsScoped ? "Some connections" : "Any connection");
    public string Created => Rule.Created?.ToString("g") ?? "";
    public DateTime? CreatedDate => Rule.Created;
    public string State => !Rule.Enabled ? "Disabled" : Rule.IsTemporary ? "Until app quits" : "";
}

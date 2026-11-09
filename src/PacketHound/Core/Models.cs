using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Windows.Media;

namespace PacketHound.Core;

/// <summary>SameAsBefore: copy the rules of the app's earlier version (see <see cref="PendingRequest.PreviousVersion"/>).</summary>
public enum PromptDecision { Later, Allow, Block, Dismiss, SameAsBefore }

/// <summary>
/// A rule as changed in the Edit dialog. Destination is null for "Any connection". Temporary: until the app
/// quits; Expires: a timed rule's end.
/// </summary>
public sealed record RuleEdit(bool Allow, RuleDestination? Destination, bool Temporary, DateTime? Expires);

public static class TimeText
{
    /// <summary>"18:30" today, "tomorrow 09:00", or the date and time.</summary>
    public static string When(DateTime t) =>
        t.Date == DateTime.Today ? t.ToString("t")
        : t.Date == DateTime.Today.AddDays(1) ? "tomorrow " + t.ToString("t")
        : t.ToString("g");
}

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

    /// <summary>The signature has been checked (so a null <see cref="Signer"/> means unsigned).</summary>
    public bool SignerChecked { get; private set; }

    public void SetSigner(string? signer)
    {
        Signer = signer;
        SignerChecked = true;
        Changed();
    }

    /// <summary>An earlier version of this program (in another versioned folder) that has rules; found when the request is made.</summary>
    public PreviousVersion? PreviousVersion { get; init; }

    /// <summary>For script hosts and interpreters: the prompt shows the command line of the process that connected.</summary>
    public bool ShowsCommandLine => WindowsAppClassifier.ShowsCommandLine(AppPath);

    public string? CommandLine { get; private set; }
    bool _commandLineChecked;

    public string CommandLineText => CommandLine ?? (_commandLineChecked ? "Unknown: the process has already exited" : "Looking it up…");

    /// <summary>The command line of process <paramref name="pid"/>; ignored if a newer attempt came from another process meanwhile.</summary>
    public void SetCommandLine(int pid, string? commandLine)
    {
        if (pid != ProcessId) return;
        // A newer process that has already exited keeps the last command line seen.
        if (commandLine != null || CommandLine == null) CommandLine = commandLine;
        _commandLineChecked = true;
        Changed();
    }

    /// <summary>Waiting because of quiet mode (rather than the user's "Decide later"); asked about when it ends.</summary>
    public bool QuietDeferred { get; set; }

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

    public string AttemptsText
    {
        get
        {
            var text = Attempts == 1 ? "1 attempt blocked so far" : $"{Attempts} attempts blocked so far";
            var count = _addressesSeen.Count;
            return count > 1 ? $"{text}, to {count}{(count >= MaxAddressesCounted ? "+" : "")} different addresses" : text;
        }
    }

    // ---------------------------------------------------------------- every destination it tried

    /// <summary>A destination the app tried while waiting, offered under "Applies to".</summary>
    public sealed class SeenDestination
    {
        public SeenDestination(string address) => Address = address;
        public string Address { get; }
        public int Port { get; set; }
        public string? HostName { get; set; }
    }

    // Offered in the prompt, in the order first tried. Later ones are only counted: nobody picks one of 50 addresses.
    const int MaxDestinations = 50;
    const int MaxAddressesCounted = 1000;
    readonly List<SeenDestination> _destinations = new();
    readonly HashSet<string> _addressesSeen = new();

    public IReadOnlyList<SeenDestination> Destinations => _destinations;

    /// <summary>
    /// The addresses a rule for <paramref name="destination"/> starts with: the one chosen, plus, for a host or
    /// domain, every other address the app tried whose name it covers.
    /// </summary>
    public List<string> AddressesFor(RuleDestination destination, string chosen)
    {
        var list = new List<string> { chosen };
        if (destination.Scope != RuleScope.Address)
            list.AddRange(_destinations.Where(d => d.HostName != null && destination.Matches(d.HostName)).Select(d => d.Address));
        return list.Distinct().ToList();
    }

    public int PortFor(string address) => _destinations.FirstOrDefault(d => d.Address == address)?.Port ?? RemotePort;

    DateTime? _snoozedUntil;

    /// <summary>After "Decide later": when to ask again. Null once that time has passed (or while in the prompt queue).</summary>
    public DateTime? SnoozedUntil
    {
        get => _snoozedUntil;
        set { _snoozedUntil = value; Changed(); }
    }

    public bool IsSnoozed => SnoozedUntil > DateTime.Now;

    public string DeferredText => QuietDeferred ? "Quiet mode · asks when it ends, if it's running"
        : SnoozedUntil is { } until ? $"Asks again at {until:t} if it's running"
        : "Asks again when it next connects";

    public void Update(BlockedConnection c)
    {
        Attempts++;
        ProcessId = c.ProcessId;
        if (_addressesSeen.Count < MaxAddressesCounted) _addressesSeen.Add(c.RemoteAddress);
        var seen = _destinations.FirstOrDefault(d => d.Address == c.RemoteAddress);
        if (seen == null && _destinations.Count < MaxDestinations) _destinations.Add(seen = new SeenDestination(c.RemoteAddress));
        if (seen != null) seen.Port = c.RemotePort;
        if (c.RemoteAddress != RemoteAddress) HostName = seen?.HostName;
        RemoteAddress = c.RemoteAddress;
        RemotePort = c.RemotePort;
        ProtocolName = c.ProtocolName;
        Changed();
    }

    /// <summary>The name found for an address the app tried (looked up in the background).</summary>
    public void SetHostName(string address, string? name)
    {
        if (string.IsNullOrEmpty(name)) return;
        if (_destinations.FirstOrDefault(d => d.Address == address) is { } seen) seen.HostName = name;
        if (address == RemoteAddress) HostName = name;
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
    /// <summary>Why the Edit button is off for this row; null when it can be edited.</summary>
    public string? CannotEditReason =>
        SignedCopy != null ? "Installer and updater rules can only be switched between Allow and Block."
        : IsMissing ? "This program is no longer on this PC, so the rule does nothing."
        : Rule!.Destination == null && Rule.IsScoped ? "This rule only covers some connections (certain ports or protocols), which PacketHound can't edit."
        : null;

    public bool CanEdit => CannotEditReason == null;

    public string AppliesTo => Rule == null ? "Any connection"
        : Rule.Destination?.Label ?? (Rule.IsScoped ? "Some connections" : "Any connection");
    public DateTime? CreatedDate => Rule?.Created ?? SignedCopy!.Created;
    public string Created => CreatedDate?.ToString("g") ?? "";
    public string State =>
        Rule == null ? ""
        : IsMissing ? "Program not found"
        : Program == ProgramState.DriveUnavailable ? "Drive not connected"
        : !Rule.Enabled ? "Disabled"
        : Rule.IsTemporary ? "Until app quits"
        : Rule.Expires is { } expires ? $"Until {TimeText.When(expires)}" : "";

    public string? StateTip => Program switch
    {
        ProgramState.Missing => "This program is no longer on this PC, so the rule does nothing. Use “Remove missing” to delete it.",
        ProgramState.DriveUnavailable => "The drive this program is on isn't connected right now.",
        _ when SignedCopy != null => "This installer or updater runs from a new temporary folder each time. Your answer applies to every copy in a temporary folder with the same file name and a valid signature from the same publisher.",
        _ => null,
    };
}

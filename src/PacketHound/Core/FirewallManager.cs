using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace PacketHound.Core;

public sealed class FirewallRuleInfo
{
    public string Name { get; init; } = "";
    public string ApplicationName { get; init; } = "";
    public bool Allow { get; init; }
    public bool Enabled { get; init; }
    public string Grouping { get; init; } = "";
    public string Description { get; init; } = "";

    /// <summary>The rule only applies to some protocols/ports/addresses rather than the whole app.</summary>
    public bool IsScoped { get; init; }

    /// <summary>For PacketHound rules limited to an IP, host or domain: what they cover. Null for whole-app rules.</summary>
    public RuleDestination? Destination { get; init; }

    /// <summary>Remote IPs of a destination rule, normalized (see <see cref="FirewallManager.NormalizeAddress"/>).</summary>
    public IReadOnlySet<string> Addresses { get; init; } = new HashSet<string>();

    /// <summary>Removed automatically when the app quits.</summary>
    public bool IsTemporary => IsPacketHound && Description.Contains(FirewallManager.TemporaryMarker, StringComparison.Ordinal);

    public bool IsPacketHound => Grouping == FirewallManager.UserGroup || Grouping == FirewallManager.WindowsGroup;
    public bool IsWindowsAuto => Grouping == FirewallManager.WindowsGroup;

    public DateTime? Created
    {
        get
        {
            var m = Regex.Match(Description, @"on (\d{4}-\d{2}-\d{2} \d{2}:\d{2})");
            return m.Success && DateTime.TryParseExact(m.Groups[1].Value, "yyyy-MM-dd HH:mm",
                CultureInfo.InvariantCulture, DateTimeStyles.None, out var d) ? d : null;
        }
    }

    public string DisplayName
    {
        get
        {
            var n = Name.StartsWith(FirewallManager.RulePrefix, StringComparison.Ordinal)
                ? Name[FirewallManager.RulePrefix.Length..] : Name;
            n = Regex.Replace(n, @"\s*\[[0-9a-f]{6}\]$", "");
            var arrow = n.LastIndexOf(" → ", StringComparison.Ordinal);
            return Destination != null && arrow > 0 ? n[..arrow] : n;
        }
    }
}

/// <summary>
/// Thin wrapper over the Windows Firewall COM API (HNetCfg.FwPolicy2 / INetFwPolicy2).
/// Every rule PacketHound creates is a normal Windows Firewall rule, visible in wf.msc under
/// the "PacketHound" groups, so it keeps working even if PacketHound is uninstalled.
/// </summary>
public static class FirewallManager
{
    public const string UserGroup = "PacketHound";
    public const string WindowsGroup = "PacketHound (Windows components)";
    public const string RulePrefix = "PacketHound: ";
    public const string TemporaryMarker = "Removed when the app quits.";
    const int MaxRemoteAddresses = 1000;

    public const int ActionBlock = 0;
    public const int ActionAllow = 1;
    const int DirectionOut = 2;
    const int ProtocolAny = 256;
    const int ProfilesAll = 0x7FFFFFFF;

    /// <summary>Domain, Private, Public.</summary>
    public static readonly int[] Profiles = { 1, 2, 4 };

    public static string ProfileName(int p) => p switch { 1 => "Domain", 2 => "Private", 4 => "Public", _ => p.ToString() };

    static dynamic CreatePolicy() =>
        Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: true)!)!;

    // INetFwPolicy2 exposes several *indexed* properties (by profile); late-bound IDispatch handles them.
    static object? GetIndexed(object o, string property, int index) =>
        o.GetType().InvokeMember(property, BindingFlags.GetProperty, null, o, new object[] { index });

    static void SetIndexed(object o, string property, int index, object value) =>
        o.GetType().InvokeMember(property, BindingFlags.SetProperty, null, o, new[] { index, value });

    public static int GetDefaultOutboundAction(int profile) =>
        Convert.ToInt32(GetIndexed(CreatePolicy(), "DefaultOutboundAction", profile));

    public static void SetDefaultOutboundAction(int profile, int action) =>
        SetIndexed(CreatePolicy(), "DefaultOutboundAction", profile, action);

    public static bool IsFirewallEnabled(int profile) =>
        Convert.ToBoolean(GetIndexed(CreatePolicy(), "FirewallEnabled", profile));

    public static int CurrentProfileTypes => Convert.ToInt32(CreatePolicy().CurrentProfileTypes);

    /// <summary>All outbound rules that target a specific program.</summary>
    public static List<FirewallRuleInfo> GetOutboundProgramRules()
    {
        var result = new List<FirewallRuleInfo>();
        dynamic policy = CreatePolicy();
        foreach (dynamic r in policy.Rules)
        {
            try
            {
                if ((int)r.Direction != DirectionOut) continue;
                string? app = r.ApplicationName;
                if (string.IsNullOrWhiteSpace(app)) continue;

                int protocol = r.Protocol;
                string remoteAddresses = (string?)r.RemoteAddresses ?? "*";
                string remotePorts = "*";
                if (protocol == 6 || protocol == 17) remotePorts = (string?)r.RemotePorts ?? "*";
                string? service = r.ServiceName;

                string grouping = (string?)r.Grouping ?? "";
                string description = (string?)r.Description ?? "";
                var destination = grouping == UserGroup ? RuleDestination.FromDescription(description) : null;

                result.Add(new FirewallRuleInfo
                {
                    Name = (string?)r.Name ?? "",
                    ApplicationName = NormalizePath(app),
                    Allow = (int)r.Action == ActionAllow,
                    Enabled = (bool)r.Enabled,
                    Grouping = grouping,
                    Description = description,
                    Destination = destination,
                    Addresses = destination != null ? ParseAddresses(remoteAddresses) : new HashSet<string>(),
                    IsScoped = protocol != ProtocolAny || remoteAddresses != "*" || remotePorts != "*"
                               || !string.IsNullOrEmpty(service) && service != "*",
                });
            }
            catch
            {
                // Skip rules with properties we can't read.
            }
        }
        return result;
    }

    public static List<FirewallRuleInfo> GetPacketHoundRules() =>
        GetOutboundProgramRules().Where(r => r.IsPacketHound).ToList();

    /// <summary>
    /// Creates (or replaces) the whole-app PacketHound rule for an application. Any destination rules
    /// the app had are removed too, since this decision covers every connection.
    /// </summary>
    public static void SetAppRule(string appPath, string displayName, bool allow, bool windowsComponent, bool temporary = false)
    {
        RemovePacketHoundRulesFor(appPath);
        var note = windowsComponent ? " (Windows component, allowed automatically)" : "";
        AddRule(BuildRuleName(displayName, appPath), appPath, allow, windowsComponent ? WindowsGroup : UserGroup,
            Describe(note, null, temporary), remoteAddresses: null);
        Log.Info($"{(allow ? "Allow" : "Block")} rule created for {appPath}{(windowsComponent ? " (Windows)" : "")}{(temporary ? " until it quits" : "")}");
    }

    /// <summary>
    /// Creates (or replaces) a rule limited to one destination. Other rules for the app are left alone.
    /// Returns the rule's name.
    /// </summary>
    public static string SetDestinationRule(string appPath, string displayName, bool allow, RuleDestination destination,
        IEnumerable<string> addresses, bool temporary)
    {
        var list = addresses.Select(NormalizeAddress).OfType<string>().Distinct().Take(MaxRemoteAddresses).ToList();
        if (list.Count == 0) throw new ArgumentException("No valid IP address for the rule.", nameof(addresses));

        var name = BuildRuleName(displayName, appPath, destination);
        if (GetPacketHoundRules().Any(r => r.Name == name)) RemoveRule(name);
        AddRule(name, appPath, allow, UserGroup, Describe("", destination, temporary), string.Join(",", list));
        Log.Info($"{(allow ? "Allow" : "Block")} rule for {appPath} → {destination.Label} ({list.Count} addresses){(temporary ? " until it quits" : "")}");
        return name;
    }

    /// <summary>Adds addresses to a destination rule. Returns true if the rule changed.</summary>
    public static bool AddRemoteAddresses(string ruleName, IEnumerable<string> addresses)
    {
        dynamic policy = CreatePolicy();
        dynamic rule = policy.Rules.Item(ruleName);
        string current = (string?)rule.RemoteAddresses ?? "*";
        if (current == "*") return false; // a whole-app rule; never narrow it

        var existing = ParseAddresses(current);
        var added = addresses.Select(NormalizeAddress).OfType<string>().Where(a => !existing.Contains(a)).Distinct().ToList();
        if (added.Count == 0) return false;

        var all = current.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Concat(added).ToList();
        if (all.Count > MaxRemoteAddresses) all = all.Skip(all.Count - MaxRemoteAddresses).ToList(); // drop the oldest
        rule.RemoteAddresses = string.Join(",", all);
        Log.Info($"Rule '{ruleName}': added {string.Join(", ", added)}");
        return true;
    }

    static string Describe(string note, RuleDestination? destination, bool temporary)
    {
        var text = string.Create(CultureInfo.InvariantCulture, $"Created by PacketHound on {DateTime.Now:yyyy-MM-dd HH:mm}{note}.");
        if (destination != null) text += " " + destination.DescriptionText;
        if (temporary) text += " " + TemporaryMarker;
        return text;
    }

    static void AddRule(string name, string appPath, bool allow, string grouping, string description, string? remoteAddresses)
    {
        dynamic rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule", throwOnError: true)!)!;
        rule.Name = name;
        rule.Description = description;
        rule.ApplicationName = appPath;
        rule.Protocol = ProtocolAny;
        if (remoteAddresses != null) rule.RemoteAddresses = remoteAddresses;
        rule.Direction = DirectionOut;
        rule.Action = allow ? ActionAllow : ActionBlock;
        rule.Profiles = ProfilesAll;
        rule.InterfaceTypes = "All";
        rule.Grouping = grouping;
        rule.Enabled = true;

        dynamic policy = CreatePolicy();
        policy.Rules.Add(rule);
    }

    /// <summary>
    /// Lets PacketHound itself make HTTPS connections (TCP port 443 only), for update checks. Without it,
    /// protection would block PacketHound like any other app. Shown in the Rules list, so it can be
    /// switched to Block, which simply stops update checks. Created once; an existing rule is left as is.
    /// </summary>
    public static void EnsureSelfRule(string exePath)
    {
        var name = BuildRuleName("PacketHound (update checks, HTTPS only)", exePath);
        if (GetPacketHoundRules().Any(r => r.Name == name)) return;

        dynamic rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule", throwOnError: true)!)!;
        rule.Name = name;
        rule.Description = string.Create(CultureInfo.InvariantCulture,
            $"Created by PacketHound on {DateTime.Now:yyyy-MM-dd HH:mm} so it can check for updates.");
        rule.ApplicationName = exePath;
        rule.Protocol = 6; // TCP; must be set before ports
        rule.RemotePorts = "443";
        rule.Direction = DirectionOut;
        rule.Action = ActionAllow;
        rule.Profiles = ProfilesAll;
        rule.InterfaceTypes = "All";
        rule.Grouping = UserGroup;
        rule.Enabled = true;

        dynamic policy = CreatePolicy();
        policy.Rules.Add(rule);
        Log.Info($"Update-check rule created for {exePath}");
    }

    /// <summary>Flips an existing PacketHound rule between Allow and Block. It becomes a user decision.</summary>
    public static void ChangeRuleAction(string ruleName, bool allow)
    {
        dynamic policy = CreatePolicy();
        dynamic rule = policy.Rules.Item(ruleName);
        rule.Action = allow ? ActionAllow : ActionBlock;
        rule.Grouping = UserGroup;
        rule.Enabled = true;
        Log.Info($"Rule '{ruleName}' changed to {(allow ? "Allow" : "Block")}");
    }

    public static void RemoveRule(string ruleName)
    {
        dynamic policy = CreatePolicy();
        policy.Rules.Remove(ruleName);
        Log.Info($"Rule '{ruleName}' removed");
    }

    public static void RemovePacketHoundRulesFor(string appPath)
    {
        var key = NormalizePath(appPath);
        foreach (var r in GetPacketHoundRules().Where(r => PathEquals(r.ApplicationName, key)))
            RemoveRule(r.Name);
    }

    /// <summary>Removes "until the app quits" rules, for one app or (with null) all of them. Returns how many.</summary>
    public static int RemoveTemporaryRules(string? appPath = null)
    {
        var key = appPath == null ? null : NormalizePath(appPath);
        var rules = GetPacketHoundRules().Where(r => r.IsTemporary && (key == null || PathEquals(r.ApplicationName, key))).ToList();
        foreach (var r in rules) RemoveRule(r.Name);
        return rules.Count;
    }

    public static int RemoveAllPacketHoundRules()
    {
        var rules = GetPacketHoundRules();
        foreach (var r in rules) RemoveRule(r.Name);
        return rules.Count;
    }

    static string BuildRuleName(string displayName, string appPath, RuleDestination? destination = null)
    {
        var name = displayName.Trim();
        if (name.Length > 60) name = name[..60].TrimEnd() + "…";
        var key = NormalizePath(appPath).ToLowerInvariant();
        if (destination != null)
        {
            key += $"|{destination.Scope}|{destination.Target.ToLowerInvariant()}";
            name += " → " + destination.Label;
        }
        var hash = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(key)))[..6].ToLowerInvariant();
        return $"{RulePrefix}{name} [{hash}]";
    }

    /// <summary>
    /// Canonical text for a single IP ("1.2.3.4", "2001:db8::1"), or null if it isn't one. Accepts the
    /// "1.2.3.4/255.255.255.255" and "/128" forms Windows Firewall returns; other ranges are rejected.
    /// </summary>
    public static string? NormalizeAddress(string text)
    {
        var parts = text.Trim().Split('/');
        if (parts.Length > 2 || !IPAddress.TryParse(parts[0], out var ip)) return null;
        if (parts.Length == 2 && parts[1] is not ("255.255.255.255" or "32" or "128")) return null;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        return new IPAddress(ip.GetAddressBytes()).ToString(); // drops any IPv6 scope id
    }

    static HashSet<string> ParseAddresses(string remoteAddresses) =>
        remoteAddresses.Split(',', StringSplitOptions.RemoveEmptyEntries)
            .Select(NormalizeAddress).OfType<string>().ToHashSet();

    public static string NormalizePath(string path)
    {
        path = Environment.ExpandEnvironmentVariables(path.Trim().Trim('"'));
        if (path.Equals("System", StringComparison.OrdinalIgnoreCase)) return "System";
        try { return Path.GetFullPath(path); } catch { return path; }
    }

    public static bool PathEquals(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// A cached view of the firewall's program rules, used to decide quickly whether an app
/// already has a decision. Refreshed every few seconds so edits made in wf.msc are honoured.
/// </summary>
public sealed class RuleSnapshot
{
    readonly Dictionary<string, List<FirewallRuleInfo>> _byApp = new(StringComparer.OrdinalIgnoreCase);
    public DateTime TakenUtc { get; } = DateTime.UtcNow;

    public RuleSnapshot(IEnumerable<FirewallRuleInfo> rules)
    {
        foreach (var r in rules)
        {
            if (!_byApp.TryGetValue(r.ApplicationName, out var list))
                _byApp[r.ApplicationName] = list = new List<FirewallRuleInfo>();
            list.Add(r);
        }
    }

    public static RuleSnapshot Take() => new(FirewallManager.GetOutboundProgramRules());

    IEnumerable<FirewallRuleInfo> For(string path) =>
        _byApp.TryGetValue(FirewallManager.NormalizePath(path), out var l) ? l : Enumerable.Empty<FirewallRuleInfo>();

    /// <summary>
    /// A rule that decides every connection the app makes: an enabled whole-app PacketHound rule, or a
    /// whole-app Block rule someone else created (we respect that rather than asking).
    /// </summary>
    public FirewallRuleInfo? WholeAppRule(string path) =>
        For(path).FirstOrDefault(r => r.Enabled && (r.IsPacketHound && r.Destination == null || !r.IsPacketHound && !r.Allow && !r.IsScoped));

    public bool HasDecision(string path) => WholeAppRule(path) != null;

    public bool HasAllowRule(string path) => For(path).Any(r => r.Enabled && r.Allow && !r.IsScoped);

    /// <summary>The destination rule whose address list already contains this IP (Block wins, as in the firewall).</summary>
    public FirewallRuleInfo? DestinationRuleFor(string path, string address)
    {
        var ip = FirewallManager.NormalizeAddress(address);
        return ip == null ? null : For(path).Where(r => r.Enabled && r.Destination != null && r.Addresses.Contains(ip))
            .OrderBy(r => r.Allow).FirstOrDefault();
    }

    /// <summary>The app's host and domain rules.</summary>
    public List<FirewallRuleInfo> NameRules(string path) =>
        For(path).Where(r => r.Enabled && r.Destination?.Scope is RuleScope.Host or RuleScope.Domain).ToList();
}

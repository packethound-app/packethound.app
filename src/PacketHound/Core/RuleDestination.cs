using System;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;

namespace PacketHound.Core;

public enum RuleScope { Address, Host, Domain }

/// <summary>
/// What a destination-scoped rule covers: one IP address, one host name, or a domain and all its subdomains.
/// Windows Firewall only matches IP addresses, so host and domain rules are kept as a list of addresses that
/// PacketHound extends whenever the app connects to a new address for that name. The scope itself is stored
/// in the rule's description, so the rule stays self-describing in wf.msc.
/// </summary>
public sealed record RuleDestination(RuleScope Scope, string Target)
{
    static readonly Regex DescriptionPattern = new(@"Only connections to (address|host|domain) (\S+)", RegexOptions.CultureInvariant);

    // Second-level labels used under country-code TLDs (example.co.uk, example.com.au...).
    static readonly string[] CountrySecondLevels = { "co", "com", "net", "org", "gov", "ac", "edu", "ne", "or", "go", "gv" };

    /// <summary>How the rule is shown in the prompt and the Rules list.</summary>
    public string Label => Scope == RuleScope.Domain ? $"*.{Target}" : Target;

    public string DescriptionText => Scope switch
    {
        RuleScope.Address => $"Only connections to address {Target}.",
        RuleScope.Host => $"Only connections to host {Target}.",
        _ => $"Only connections to domain {Target} and its subdomains.",
    };

    public bool Matches(string hostName)
    {
        var h = hostName.TrimEnd('.');
        return Scope switch
        {
            RuleScope.Host => h.Equals(Target, StringComparison.OrdinalIgnoreCase),
            RuleScope.Domain => h.Equals(Target, StringComparison.OrdinalIgnoreCase)
                                || h.EndsWith("." + Target, StringComparison.OrdinalIgnoreCase),
            _ => false,
        };
    }

    public static RuleDestination? FromDescription(string description)
    {
        var m = DescriptionPattern.Match(description);
        if (!m.Success) return null;
        var scope = m.Groups[1].Value switch { "address" => RuleScope.Address, "host" => RuleScope.Host, _ => RuleScope.Domain };
        return new RuleDestination(scope, m.Groups[2].Value.TrimEnd('.'));
    }

    /// <summary>
    /// The registrable part of a host name ("cdn.api.example.co.uk" → "example.co.uk"), or null when the
    /// name has a single label. A heuristic rather than the full public-suffix list.
    /// </summary>
    public static string? DomainOf(string hostName)
    {
        var labels = hostName.TrimEnd('.').ToLowerInvariant().Split('.');
        if (labels.Length < 2 || IPAddress.TryParse(hostName, out _)) return null;
        var take = labels.Length >= 3 && labels[^1].Length == 2 && CountrySecondLevels.Contains(labels[^2]) ? 3 : 2;
        return string.Join('.', labels[^take..]);
    }
}

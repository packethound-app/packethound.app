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

    /// <summary>Both cover the same destination (or both are null: any connection).</summary>
    public static bool Same(RuleDestination? a, RuleDestination? b) =>
        a == null ? b == null : b != null && a.Scope == b.Scope && a.Target.Equals(b.Target, StringComparison.OrdinalIgnoreCase);

    /// <summary>Everything <paramref name="other"/> covers is covered by this too (a host by its domain, say).</summary>
    public bool Covers(RuleDestination other) => other.Scope switch
    {
        RuleScope.Host => Matches(other.Target),
        RuleScope.Domain => Scope == RuleScope.Domain && Matches(other.Target),
        _ => Scope == RuleScope.Address && Target == other.Target,
    };

    static readonly Regex HostNamePattern = new(@"^(?=.{1,253}$)[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$",
        RegexOptions.CultureInvariant);

    /// <summary>
    /// Reads what the user typed as a rule's destination. Pasted web addresses ("https://api.example.com/page")
    /// and wildcards ("*.example.com") are accepted. Null when it isn't usable, with the reason in
    /// <paramref name="error"/> (null too while nothing has been typed).
    /// </summary>
    public static RuleDestination? Parse(RuleScope scope, string text, out string? error)
    {
        error = null;
        var t = text.Trim();
        if (t.Contains("://") && Uri.TryCreate(t, UriKind.Absolute, out var uri)) t = uri.Host.Trim('[', ']');
        if (scope != RuleScope.Address && t.StartsWith("*.", StringComparison.Ordinal)) t = t[2..];
        t = t.TrimEnd('.').ToLowerInvariant();
        if (t.Length == 0) return null;

        if (scope == RuleScope.Address)
        {
            // IPAddress also accepts forms like "1234"; only dotted IPv4 and IPv6 are meant here.
            if ((t.Contains('.') || t.Contains(':')) && FirewallManager.NormalizeAddress(t) is { } ip)
                return new RuleDestination(scope, ip);
            error = "Enter a single IP address, such as 203.0.113.7 or 2001:db8::1.";
            return null;
        }
        if (IPAddress.TryParse(t, out _) && (t.Contains('.') || t.Contains(':')))
        {
            error = "That's an IP address. Choose “Only this IP address” for it.";
            return null;
        }
        try
        {
            t = new System.Globalization.IdnMapping().GetAscii(t); // names in other scripts, as DNS sees them
        }
        catch (ArgumentException)
        {
            // Not a valid name; reported below.
        }
        if (!HostNamePattern.IsMatch(t))
        {
            error = scope == RuleScope.Host ? "Enter a host name, such as api.example.com." : "Enter a domain, such as example.com.";
            return null;
        }
        if (scope == RuleScope.Domain && !t.Contains('.'))
        {
            error = "Enter a domain with at least two parts, such as example.com.";
            return null;
        }
        return new RuleDestination(scope, t);
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

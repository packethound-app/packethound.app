using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace PacketHound.Core;

/// <summary>An earlier version of a program, in another versioned folder, that has rules of yours.</summary>
public sealed record PreviousVersion(string Path, IReadOnlyList<FirewallRuleInfo> Rules, bool StillExists)
{
    /// <summary>The folder that differs, e.g. "app-1.0.9150", for showing which version it was.</summary>
    public string FolderName => System.IO.Path.GetFileName(System.IO.Path.GetDirectoryName(Path) ?? Path);

    /// <summary>Who signed it, if that was recorded when its rules were made.</summary>
    public string? Signer => Rules.Select(r => r.Signer).FirstOrDefault(s => s != null);
}

/// <summary>
/// Many apps update by installing each version into a new folder (Discord's "app-1.0.9150", Store apps'
/// "Name_1.2.3.0_x64__…"): the program's path changes, so its rules no longer match. This finds the rules of the
/// earlier version, so the prompt can offer to keep them. Only dotted versions count ("Python312" doesn't), since
/// plain numbers in folder names ("Win32", "Office16") rarely mean a version.
/// </summary>
public static class ProgramVersions
{
    // A folder name with a version number in it: "app-1.0.9150", "130.0.6723.70", "IntelliJ IDEA 2024.2".
    static readonly Regex VersionFolder = new(@"\d+\.\d+", RegexOptions.CultureInvariant);

    /// <summary>
    /// The path with its versioned folders replaced by "*" (lower case), or null when no folder has a version
    /// in its name. Two versions of one app installed side by side get the same key.
    /// </summary>
    public static string? Key(string path)
    {
        var parts = path.Split('\\');
        var found = false;
        for (var i = 0; i < parts.Length - 1; i++) // folders only, not the file name
        {
            if (!VersionFolder.IsMatch(parts[i])) continue;
            parts[i] = "*";
            found = true;
        }
        return found ? string.Join('\\', parts).ToLowerInvariant() : null;
    }

    /// <summary>
    /// The most recent other version of this program with rules of yours (not automatic Windows rules, nor rules
    /// that end by themselves). Null when there's none.
    /// </summary>
    public static PreviousVersion? Find(RuleSnapshot rules, string path)
    {
        if (Key(path) is not { } key) return null;
        return rules.Programs
            .Where(p => !FirewallManager.PathEquals(p.Key, path) && Key(p.Key) == key)
            .Select(p => (Path: p.Key, Rules: p.Value.Where(IsCopyable).ToList()))
            .Where(p => p.Rules.Count > 0)
            .OrderByDescending(p => p.Rules.Max(r => r.Created ?? DateTime.MinValue))
            .Select(p => new PreviousVersion(p.Path, p.Rules, File.Exists(p.Path)))
            .FirstOrDefault();
    }

    static bool IsCopyable(FirewallRuleInfo r) =>
        r.IsPacketHound && !r.IsWindowsAuto && r.Enabled && !r.IsTemporary && r.Expires == null
        && (r.Destination != null || !r.IsScoped); // not PacketHound's own update-check rule
}

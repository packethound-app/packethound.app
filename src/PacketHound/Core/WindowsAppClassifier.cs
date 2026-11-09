using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;

namespace PacketHound.Core;

/// <summary>
/// Decides whether a program is part of Windows itself (allowed silently) or a
/// third-party app (the user is asked).
///
/// A program counts as Windows when ALL of these hold:
///  1. it lives in a Windows-owned location (%SystemRoot%, Program Files\Windows *,
///     the Defender platform folder) but not in the third-party driver store or temp folders;
///  2. its file is owned by TrustedInstaller or SYSTEM, so a regular user or malware
///     running as that user can't have dropped it there;
///  3. it carries a valid Microsoft Windows Authenticode signature (embedded or catalog).
/// Microsoft Store packages published by Microsoft also count (optional, on by default) because
/// the WindowsApps folder can only be written by the system.
/// </summary>
public sealed class WindowsAppClassifier
{
    static readonly string WinDir = WithSlash(Environment.GetFolderPath(Environment.SpecialFolder.Windows));
    static readonly string ProgramFiles = WithSlash(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
    static readonly string ProgramFilesX86 = WithSlash(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));
    static readonly string ProgramData = WithSlash(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
    static readonly string WindowsApps = ProgramFiles + @"WindowsApps\";

    static readonly string[] ExcludedUnderWindows =
    {
        WinDir + @"System32\DriverStore\", // third-party driver packages (vendor services, telemetry...)
        WinDir + @"Temp\",
        WinDir + @"Tasks\",
        WinDir + @"Tracing\",
        WinDir + @"Downloaded Program Files\",
        WinDir + @"Installer\",
    };

    /// <summary>
    /// Windows tools that malware commonly uses to download payloads or phone home.
    /// When AskForScriptingTools is on, these are treated like third-party apps.
    /// </summary>
    public static readonly HashSet<string> ScriptingTools = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe", "powershell_ise.exe", "cmd.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
        "certutil.exe", "bitsadmin.exe", "curl.exe", "wscript.exe", "cscript.exe", "msbuild.exe",
        "installutil.exe", "regasm.exe", "regsvcs.exe", "ftp.exe", "tftp.exe", "finger.exe", "wmic.exe",
        "msxsl.exe", "odbcconf.exe", "cmstp.exe", "hh.exe", "forfiles.exe", "scriptrunner.exe",
        "csc.exe", "vbc.exe", "jsc.exe", "msiexec.exe", "ssh.exe", "scp.exe", "sftp.exe",
    };

    /// <summary>
    /// Programs whose command line says more than their path: the tools above plus script interpreters. The prompt
    /// shows the command line for these, which tells you which script or download is behind the connection.
    /// </summary>
    public static bool ShowsCommandLine(string path)
    {
        var file = Path.GetFileName(path);
        return ScriptingTools.Contains(file) || Interpreters.Contains(file);
    }

    static readonly HashSet<string> Interpreters = new(StringComparer.OrdinalIgnoreCase)
    {
        "pwsh.exe", "python.exe", "pythonw.exe", "py.exe", "pyw.exe", "node.exe", "deno.exe", "bun.exe",
        "java.exe", "javaw.exe", "ruby.exe", "rubyw.exe", "perl.exe", "php.exe", "bash.exe", "sh.exe", "wsl.exe",
        "dotnet.exe",
    };

    // NT SERVICE\TrustedInstaller. Service SIDs are derived from the service name, so this is the same everywhere.
    static readonly SecurityIdentifier TrustedInstaller =
        new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");
    static readonly SecurityIdentifier LocalSystem = new(WellKnownSidType.LocalSystemSid, null);

    readonly Dictionary<string, bool> _cache = new(StringComparer.OrdinalIgnoreCase);

    public bool TreatMicrosoftStoreAppsAsWindows { get; set; } = true;
    public bool AskForScriptingTools { get; set; } = true;

    public void ClearCache() => _cache.Clear();

    public bool IsWindowsComponent(string path)
    {
        if (_cache.TryGetValue(path, out var cached)) return cached;
        var result = Classify(path);
        _cache[path] = result;
        return result;
    }

    bool Classify(string path)
    {
        if (path.Equals("System", StringComparison.OrdinalIgnoreCase)) return true; // the kernel (SMB, etc.)
        if (!Path.IsPathFullyQualified(path) || !File.Exists(path)) return false;

        if (AskForScriptingTools && ScriptingTools.Contains(Path.GetFileName(path))) return false;

        if (IsUnder(path, WindowsApps))
            return TreatMicrosoftStoreAppsAsWindows && IsMicrosoftPackage(path);

        if (!IsWindowsLocation(path)) return false;
        if (!IsOwnedBySystem(path)) return false;
        var signer = Signature.GetVerifiedSigner(path);
        return signer != null && WindowsSigners.Contains(signer);
    }

    /// <summary>
    /// Signers of Windows' own binaries. Deliberately excluded: "Microsoft Windows Hardware Compatibility
    /// Publisher" (WHQL-signed third-party driver software) and the "... Third Party Application Component"
    /// signers (open-source tools bundled with Windows).
    /// </summary>
    static readonly HashSet<string> WindowsSigners = new(StringComparer.Ordinal)
    {
        "Microsoft Windows",
        "Microsoft Windows Publisher",
        "Microsoft Corporation",
    };

    static bool IsWindowsLocation(string path)
    {
        if (IsUnder(path, WinDir))
            return !ExcludedUnderWindows.Any(x => IsUnder(path, x));

        // Program Files\Windows Defender, Windows Mail, Windows Media Player, Windows NT, ...
        foreach (var pf in new[] { ProgramFiles, ProgramFilesX86 })
        {
            if (!IsUnder(path, pf)) continue;
            var top = path[pf.Length..].Split('\\')[0];
            if (top.StartsWith("Windows ", StringComparison.OrdinalIgnoreCase)) return true;
        }

        return IsUnder(path, ProgramData + @"Microsoft\Windows Defender\")
            || IsUnder(path, ProgramData + @"Microsoft\Windows Defender Advanced Threat Protection\");
    }

    static bool IsOwnedBySystem(string path)
    {
        try
        {
            var owner = new FileInfo(path).GetAccessControl(AccessControlSections.Owner)
                .GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
            return owner != null && (owner.Equals(TrustedInstaller) || owner.Equals(LocalSystem));
        }
        catch
        {
            return false;
        }
    }

    static bool IsMicrosoftPackage(string path)
    {
        // C:\Program Files\WindowsApps\Microsoft.WindowsStore_22410.1401.3.0_x64__8wekyb3d8bbwe\...
        var package = path[WindowsApps.Length..].Split('\\')[0];
        return package.EndsWith("_8wekyb3d8bbwe", StringComparison.OrdinalIgnoreCase) // Microsoft's publisher id
            || package.EndsWith("_cw5n1h2txyewy", StringComparison.OrdinalIgnoreCase); // Windows inbox packages
    }

    static bool IsUnder(string path, string folder) => path.StartsWith(folder, StringComparison.OrdinalIgnoreCase);

    static string WithSlash(string p) => p.EndsWith('\\') ? p : p + "\\";
}

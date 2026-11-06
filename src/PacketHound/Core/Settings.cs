using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace PacketHound.Core;

public sealed class Settings
{
    public static string DataDirectory { get; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "PacketHound");

    static string FilePath => Path.Combine(DataDirectory, "settings.json");

    /// <summary>True once the user has answered the first-run question.</summary>
    public bool FirstRunCompleted { get; set; }

    /// <summary>True while PacketHound keeps Windows Firewall in "block outbound by default" mode.</summary>
    public bool ProtectionEnabled { get; set; }

    /// <summary>Microsoft-published Store packages (Photos, Store, Widgets...) count as part of Windows.</summary>
    public bool TreatMicrosoftStoreAppsAsWindows { get; set; } = true;

    /// <summary>Ask before letting Windows tools such as PowerShell, curl or rundll32 connect.</summary>
    public bool AskForScriptingTools { get; set; } = true;

    /// <summary>How long "Decide later" postpones a prompt, in minutes.</summary>
    public int SnoozeMinutes { get; set; } = 10;

    /// <summary>Default outbound action per firewall profile before PacketHound changed it (restored on cleanup).</summary>
    public Dictionary<int, int>? OriginalOutboundActions { get; set; }

    /// <summary>Whether "Filtering Platform Connection" failure auditing was already on before PacketHound.</summary>
    public bool? AuditFailureWasEnabled { get; set; }

    /// <summary>Check the website for a newer version once a week.</summary>
    public bool CheckForUpdates { get; set; } = true;

    /// <summary>When the last update check succeeded (UTC).</summary>
    public DateTime? LastUpdateCheckUtc { get; set; }

    /// <summary>Newest version the tray has already announced, so each version is announced once.</summary>
    public string? AnnouncedVersion { get; set; }

    /// <summary>How each list in the main window is sorted, by list name ("Rules", "Activity").</summary>
    public Dictionary<string, SortSetting> GridSorts { get; set; } = new();

    /// <summary>Main window size and position when it was last closed (null: default size, centered).</summary>
    public WindowPlacement? MainWindowPlacement { get; set; }

    /// <summary>When a timed pause ends and protection turns back on by itself (null: not a timed pause).</summary>
    public DateTime? PausedUntil { get; set; }

    /// <summary>Decisions that apply to any copy of a program with the same file name and signer.</summary>
    public List<SignedCopyRule> SignedCopyRules { get; set; } = new();

    public static Settings Load()
    {
        try
        {
            if (File.Exists(FilePath))
                return JsonSerializer.Deserialize<Settings>(File.ReadAllText(FilePath)) ?? new Settings();
        }
        catch (Exception ex)
        {
            Log.Error("Could not read settings, using defaults", ex);
        }
        return new Settings();
    }

    public void Save()
    {
        Directory.CreateDirectory(DataDirectory);
        var tmp = FilePath + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
        File.Move(tmp, FilePath, overwrite: true);
    }
}

/// <summary>A list's sort: the row property it's sorted by and the direction.</summary>
public sealed record SortSetting(string Member, bool Descending);

/// <summary>
/// "Allow (or block) any copy of FileName signed by Signer", wherever it runs from. Windows Firewall can
/// only match paths, so PacketHound turns a match into a rule for that copy's path when it first connects.
/// </summary>
public sealed class SignedCopyRule
{
    public string FileName { get; set; } = "";
    /// <summary>Verified Authenticode signer (certificate common name).</summary>
    public string Signer { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public bool Allow { get; set; }
    public DateTime Created { get; set; }

    [System.Text.Json.Serialization.JsonIgnore]
    public string Key => $"{FileName}|{Signer}".ToLowerInvariant();

    public bool Matches(string path, string? signer) =>
        signer != null
        && string.Equals(Path.GetFileName(path), FileName, StringComparison.OrdinalIgnoreCase)
        && string.Equals(signer, Signer, StringComparison.Ordinal);
}

/// <summary>A window's normal (not maximized) bounds in device-independent pixels, and whether it was maximized.</summary>
public sealed record WindowPlacement(double Left, double Top, double Width, double Height, bool Maximized);

public static class Log
{
    static readonly object Gate = new();
    static string FilePath => Path.Combine(Settings.DataDirectory, "packethound.log");

    public static void Info(string message) => Write("INFO ", message);

    public static void Error(string message, Exception? ex = null) =>
        Write("ERROR", ex == null ? message : $"{message}: {ex}");

    static void Write(string level, string message)
    {
        try
        {
            lock (Gate)
            {
                Directory.CreateDirectory(Settings.DataDirectory);
                var info = new FileInfo(FilePath);
                if (info.Exists && info.Length > 2_000_000)
                    File.Move(FilePath, FilePath + ".old", overwrite: true);
                File.AppendAllText(FilePath, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {level} {message}{Environment.NewLine}");
            }
        }
        catch
        {
            // Logging must never take the app down.
        }
    }
}

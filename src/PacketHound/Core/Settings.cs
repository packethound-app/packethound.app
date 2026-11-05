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

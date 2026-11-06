using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace PacketHound.Core;

/// <summary>
/// Recognises programs running from a temporary folder. Installers and updaters often unpack
/// themselves into a new randomly named folder there on every run, so a rule for that exact path
/// is useless the next time.
/// </summary>
public static class TempFolders
{
    static readonly string WinDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    static readonly string[] Roots =
    {
        WithSlash(Path.Combine(WinDir, "Temp")),
        WithSlash(Path.Combine(WinDir, "SystemTemp")),
        WithSlash(Path.GetTempPath()),
    };
    // Any user's temp folder, not just the one PacketHound runs as.
    static readonly Regex UserTemp = new(@"^[a-z]:\\Users\\[^\\]+\\AppData\\Local\\Temp\\",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public static bool Contains(string path)
    {
        foreach (var root in Roots)
            if (path.StartsWith(root, StringComparison.OrdinalIgnoreCase)) return true;
        return UserTemp.IsMatch(path);
    }

    /// <summary>The temp folders that exist on this PC: Windows' own, and every user profile's.</summary>
    public static List<string> Existing()
    {
        var folders = new List<string>(Roots);
        try
        {
            var users = Path.GetDirectoryName(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile).TrimEnd('\\'));
            if (users != null)
                foreach (var profile in Directory.EnumerateDirectories(users))
                    folders.Add(WithSlash(Path.Combine(profile, @"AppData\Local\Temp")));
        }
        catch (Exception ex)
        {
            Log.Error("Could not list user profiles", ex);
        }
        return folders.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    static string WithSlash(string path) => path.EndsWith('\\') ? path : path + '\\';
}

/// <summary>
/// Reports .exe files appearing in the temp folders, so a remembered installer or updater can get its
/// rule before it runs. Without that, its first connection is blocked and many installers give up.
/// Events are raised on a thread-pool thread.
/// </summary>
public sealed class TempFolderWatcher : IDisposable
{
    readonly List<FileSystemWatcher> _watchers = new();

    public event Action<string>? ExeAppeared;

    public bool IsRunning => _watchers.Count > 0;

    public void Start()
    {
        if (IsRunning) return;
        foreach (var folder in TempFolders.Existing())
        {
            try
            {
                var watcher = new FileSystemWatcher(folder, "*.exe")
                {
                    IncludeSubdirectories = true,
                    NotifyFilter = NotifyFilters.FileName,
                    InternalBufferSize = 64 * 1024,
                };
                watcher.Created += (_, e) => ExeAppeared?.Invoke(e.FullPath);
                watcher.Renamed += (_, e) => ExeAppeared?.Invoke(e.FullPath);
                watcher.Error += (_, e) => Log.Error($"Temp folder watcher error in {folder}", e.GetException());
                watcher.EnableRaisingEvents = true;
                _watchers.Add(watcher);
            }
            catch (Exception ex)
            {
                Log.Error($"Could not watch {folder}", ex);
            }
        }
    }

    public void Stop()
    {
        foreach (var watcher in _watchers) watcher.Dispose();
        _watchers.Clear();
    }

    public void Dispose() => Stop();
}

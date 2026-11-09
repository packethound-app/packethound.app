using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace PacketHound.Core;

/// <summary>
/// Keeps the Activity list across restarts, in activity.jsonl in the data folder (one entry per line), for as
/// many days as the user chose (0: this session only). New entries are written a few seconds after they're
/// added, so a host name looked up meanwhile is saved with them. All methods run on the UI thread.
/// </summary>
public sealed class ActivityLog
{
    static string FilePath => Path.Combine(Settings.DataDirectory, "activity.jsonl");
    static readonly TimeSpan WriteDelay = TimeSpan.FromSeconds(5);
    static readonly TimeSpan PruneEvery = TimeSpan.FromHours(1);
    const int MaxLines = 50_000; // a ceiling on the file, whatever the number of days

    readonly List<(ActivityEntry Entry, DateTime Added)> _unwritten = new();
    DateTime _lastPrune = DateTime.MinValue;

    /// <summary>How many days entries are kept; 0 keeps nothing on disk.</summary>
    public int KeepDays { get; private set; }

    /// <summary>
    /// Reads the entries still within <paramref name="keepDays"/>, oldest first, at most <paramref name="max"/>
    /// of them, and trims the file to what's kept.
    /// </summary>
    public List<ActivityEntry> Load(int keepDays, int max)
    {
        KeepDays = keepDays;
        if (keepDays <= 0)
        {
            Delete();
            return new List<ActivityEntry>();
        }
        var kept = ReadKept();
        Rewrite(kept);
        _lastPrune = DateTime.Now;
        return kept.Count > max ? kept.GetRange(kept.Count - max, max) : kept;
    }

    public void Add(ActivityEntry entry)
    {
        if (KeepDays > 0) _unwritten.Add((entry, DateTime.Now));
    }

    /// <summary>Writes entries added a few seconds ago or more (every one, with <paramref name="all"/>), and trims the file hourly.</summary>
    public void Flush(bool all = false)
    {
        if (KeepDays <= 0)
        {
            _unwritten.Clear();
            return;
        }
        var now = DateTime.Now;
        var ready = all ? _unwritten.Count : _unwritten.TakeWhile(u => now - u.Added >= WriteDelay).Count();
        if (ready > 0)
        {
            try
            {
                Directory.CreateDirectory(Settings.DataDirectory);
                File.AppendAllLines(FilePath, _unwritten.Take(ready).Select(u => Serialize(u.Entry)));
                _unwritten.RemoveRange(0, ready);
            }
            catch (Exception ex)
            {
                // Tried again next time; a full disk or a locked file shouldn't take the app down.
                Log.Error("Could not save the Activity list", ex);
            }
        }
        if (now - _lastPrune > PruneEvery)
        {
            _lastPrune = now;
            Rewrite(ReadKept());
        }
    }

    /// <summary>Changes how long entries are kept; 0 deletes the file.</summary>
    public void SetKeepDays(int days)
    {
        KeepDays = days;
        if (days <= 0)
        {
            Clear();
            return;
        }
        Flush(all: true);
        Rewrite(ReadKept());
        _lastPrune = DateTime.Now;
    }

    public void Clear()
    {
        _unwritten.Clear();
        Delete();
    }

    // ---------------------------------------------------------------- file

    sealed record Line(DateTime Time, string App, string Path, string Address, int Port, string Protocol, string Result, string? Host);

    static string Serialize(ActivityEntry e) => JsonSerializer.Serialize(
        new Line(e.Time, e.AppName, e.AppPath, e.RemoteAddress, e.RemotePort, e.Protocol, e.Result, e.HostName));

    /// <summary>The file's entries newer than KeepDays, oldest first. Unreadable lines are skipped.</summary>
    List<ActivityEntry> ReadKept()
    {
        var kept = new List<ActivityEntry>();
        try
        {
            if (!File.Exists(FilePath)) return kept;
            var since = DateTime.Now.AddDays(-KeepDays);
            foreach (var text in File.ReadLines(FilePath))
            {
                Line? line;
                try
                {
                    line = JsonSerializer.Deserialize<Line>(text);
                }
                catch (JsonException)
                {
                    continue; // e.g. half a line from a crash mid-write
                }
                if (line == null || line.Time < since) continue;
                kept.Add(new ActivityEntry
                {
                    Time = line.Time, AppName = line.App, AppPath = line.Path, RemoteAddress = line.Address,
                    RemotePort = line.Port, Protocol = line.Protocol, Result = line.Result, HostName = line.Host,
                });
            }
        }
        catch (Exception ex)
        {
            Log.Error("Could not read the saved Activity list", ex);
        }
        kept.Sort((a, b) => a.Time.CompareTo(b.Time));
        return kept;
    }

    static void Rewrite(List<ActivityEntry> entries)
    {
        try
        {
            Directory.CreateDirectory(Settings.DataDirectory);
            var tmp = FilePath + ".tmp";
            File.WriteAllLines(tmp, entries.Skip(Math.Max(0, entries.Count - MaxLines)).Select(Serialize));
            File.Move(tmp, FilePath, overwrite: true);
        }
        catch (Exception ex)
        {
            Log.Error("Could not trim the saved Activity list", ex);
        }
    }

    static void Delete()
    {
        try
        {
            File.Delete(FilePath);
        }
        catch (Exception ex)
        {
            Log.Error("Could not delete the saved Activity list", ex);
        }
    }
}

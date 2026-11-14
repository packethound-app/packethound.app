using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Threading;
using PacketHound.UI;

namespace PacketHound.Core;

/// <summary>
/// The heart of PacketHound. All methods run on the UI thread.
///
/// How it works:
///   1. Windows Firewall's default outbound action is switched to Block (all profiles).
///   2. Failure auditing for "Filtering Platform Connection" is turned on, so each blocked
///      attempt is written to the Security log as event 5157.
///   3. For each blocked outbound attempt by a program with no rule yet:
///        - Windows components get an Allow rule silently;
///        - third-party apps get a prompt, and the answer becomes an Allow/Block rule, for the whole
///          app or one IP/host/domain, kept forever or until the app quits.
/// </summary>
public sealed class Controller
{
    // Entries shown in the Activity list (more can be in the saved file when keeping it for days).
    const int MaxActivity = 5000;
    static readonly TimeSpan SnapshotLifetime = TimeSpan.FromSeconds(5);

    /// <summary>Windows binaries pre-allowed when protection is turned on, so core services never stall.</summary>
    static readonly string[] SeedWindowsBinaries =
    {
        "svchost.exe", "lsass.exe", "services.exe", "spoolsv.exe", "explorer.exe", "taskhostw.exe",
        "backgroundTaskHost.exe", "RuntimeBroker.exe", "wermgr.exe", "smartscreen.exe", "dllhost.exe",
        "sihclient.exe", "MoUsoCoreWorker.exe", "usoclient.exe", "wuauclt.exe", "SearchProtocolHost.exe",
        "SearchIndexer.exe", "WWAHost.exe", "CompPkgSrv.exe", "deviceenroller.exe", "omadmclient.exe",
        "WerFault.exe", "consent.exe", "SecurityHealthService.exe", "MpDefenderCoreService.exe",
    };

    readonly Dispatcher _dispatcher;
    readonly ConnectionMonitor _monitor = new();
    readonly WindowsAppClassifier _classifier = new();
    // Every undecided app: either in the prompt queue or in Deferred ("Decide later").
    readonly Dictionary<string, PendingRequest> _pending = new(StringComparer.OrdinalIgnoreCase);
    readonly List<PendingRequest> _queue = new();
    readonly DispatcherTimer _deferredTimer;
    readonly DispatcherTimer _resumeTimer;
    // Programs whose signature is being checked against the signed-copy rules right now.
    readonly HashSet<string> _signatureChecks = new(StringComparer.OrdinalIgnoreCase);
    readonly HashSet<string> _autoAllowFailed = new(StringComparer.OrdinalIgnoreCase);
    // Apps that just got a rule: events already queued for them are stale and ignored for a moment.
    readonly Dictionary<string, DateTime> _justDecided = new(StringComparer.OrdinalIgnoreCase);
    // Apps with "until the app quits" rules, checked every few seconds while any exist.
    readonly Dictionary<string, TemporaryApp> _temporaryApps = new(StringComparer.OrdinalIgnoreCase);
    // A rule made before its program starts is kept this long even if the program hasn't been seen running.
    static readonly TimeSpan TemporaryGrace = TimeSpan.FromMinutes(1);
    // Remembered installers/updaters allowed automatically: their file is held open (no writing, deleting
    // or renaming) for as long as the rule exists, so nothing can swap in a different program at that path.
    readonly Dictionary<string, FileStream> _locks = new(StringComparer.OrdinalIgnoreCase);
    // Notices remembered installers/updaters being unpacked, so their rule exists before they connect.
    readonly TempFolderWatcher _tempWatcher = new();
    readonly HashSet<string> _preparing = new(StringComparer.OrdinalIgnoreCase);
    readonly DispatcherTimer _temporaryTimer;
    // Fires when the next timed rule ("for 1 hour") ends, and when quiet mode ends.
    readonly DispatcherTimer _expiryTimer;
    readonly DispatcherTimer _quietTimer;
    // Saves the Activity list, so it survives a restart.
    readonly ActivityLog _activityLog = new();
    readonly DispatcherTimer _activityTimer;
    RuleSnapshot? _snapshot;
    PromptWindow? _prompt;

    public Controller(Dispatcher dispatcher)
    {
        _dispatcher = dispatcher;
        Settings = Settings.Load();
        Updates = new UpdateService(Settings);
        ApplyClassifierSettings();
        // Every second, so a locked installer file is released quickly after it quits (and its folder can be cleaned up).
        _temporaryTimer = new DispatcherTimer(DispatcherPriority.Background, dispatcher) { Interval = TimeSpan.FromSeconds(1) };
        _temporaryTimer.Tick += (_, _) => CheckTemporaryRules();
        _deferredTimer = new DispatcherTimer(DispatcherPriority.Background, dispatcher) { Interval = TimeSpan.FromSeconds(15) };
        _deferredTimer.Tick += (_, _) => CheckDeferred();
        _resumeTimer = new DispatcherTimer(DispatcherPriority.Background, dispatcher) { Interval = TimeSpan.FromSeconds(5) };
        _resumeTimer.Tick += (_, _) => CheckResume();
        _expiryTimer = new DispatcherTimer(DispatcherPriority.Background, dispatcher);
        _expiryTimer.Tick += (_, _) => CheckExpiredRules();
        _quietTimer = new DispatcherTimer(DispatcherPriority.Background, dispatcher);
        _quietTimer.Tick += (_, _) => CheckQuiet();
        _activityTimer = new DispatcherTimer(DispatcherPriority.Background, dispatcher) { Interval = TimeSpan.FromSeconds(5) };
        _activityTimer.Tick += (_, _) => _activityLog.Flush();

        _monitor.Blocked += c => _dispatcher.InvokeAsync(() => OnBlocked(c));
        _tempWatcher.ExeAppeared += path => _dispatcher.InvokeAsync(() => OnTempExeAppeared(path));
        _monitor.Failed += ex => _dispatcher.InvokeAsync(() => SetError("Event monitor error: " + ex.Message, ex));
    }

    public Settings Settings { get; }
    public UpdateService Updates { get; }
    public ObservableCollection<ActivityEntry> Activity { get; } = new();
    public string? LastError { get; private set; }
    public bool ProtectionEnabled => Settings.ProtectionEnabled;
    public int PendingCount => _queue.Count;

    /// <summary>When a timed pause ends (null when protection is on, or paused until turned back on).</summary>
    public DateTime? PausedUntil => Settings.ProtectionEnabled ? null : Settings.PausedUntil;

    /// <summary>The pause lengths offered in the tray and main window. Null: until turned back on.</summary>
    public static readonly (string Label, TimeSpan? Duration)[] PauseChoices =
    {
        ("For 5 minutes", TimeSpan.FromMinutes(5)),
        ("For 15 minutes", TimeSpan.FromMinutes(15)),
        ("For 1 hour", TimeSpan.FromHours(1)),
        ("Until I turn it back on", null),
    };

    /// <summary>The lengths offered for quiet mode. Null: until turned off.</summary>
    public static readonly (string Label, TimeSpan? Duration)[] QuietChoices =
    {
        ("For 30 minutes", TimeSpan.FromMinutes(30)),
        ("For 1 hour", TimeSpan.FromHours(1)),
        ("For 3 hours", TimeSpan.FromHours(3)),
        ("Until I turn it off", null),
    };

    /// <summary>
    /// Quiet mode: new apps stay blocked without a prompt and go on the "decide later" list, until this time
    /// (DateTime.MaxValue: until turned off). Null when off. Not kept across restarts.
    /// </summary>
    public DateTime? QuietUntil { get; private set; }

    public bool IsQuiet => QuietUntil is { } until && until > DateTime.Now;

    public IReadOnlyList<SignedCopyRule> SignedCopyRules => Settings.SignedCopyRules;

    /// <summary>Apps the user chose to decide later about. They stay blocked until decided.</summary>
    public ObservableCollection<PendingRequest> Deferred { get; } = new();

    /// <summary>Protection state, error text, pending count or the Deferred list changed.</summary>
    public event EventHandler? StateChanged;

    /// <summary>PacketHound rules were added/changed/removed.</summary>
    public event EventHandler? RulesChanged;

    /// <summary>
    /// The user allowed a program running from a temp folder (its display name). Its first attempt was
    /// blocked, and installers often give up after that, so the tray offers a one-click pause.
    /// </summary>
    public event EventHandler<string>? InstallerAllowed;

    public void Start()
    {
        // The saved list first, so this session's entries go on top of it.
        foreach (var entry in _activityLog.Load(Settings.ActivityKeepDays, MaxActivity)) Activity.Insert(0, entry);
        _activityTimer.Start();
        Updates.Start();
        RemoveAllTemporaryRules("left over from the last session");
        CheckExpiredRules(); // ended while PacketHound wasn't running, and schedules the next
        if (!Settings.ProtectionEnabled)
        {
            // A timed pause that was running when PacketHound closed (or the PC restarted).
            if (Settings.PausedUntil != null)
            {
                _resumeTimer.Start();
                CheckResume();
            }
            return;
        }
        try
        {
            // Re-assert everything at startup in case something (an update, another tool) reset it.
            ApplyProtection();
        }
        catch (Exception ex)
        {
            SetError("Could not start protection: " + ex.Message, ex);
        }
    }

    public void Shutdown()
    {
        Updates.Stop();
        _monitor.Dispose();
        _tempWatcher.Dispose();
        ClearPending();
        if (_temporaryApps.Count > 0) RemoveAllTemporaryRules("PacketHound is exiting");
        ReleaseAllLocks();
        _activityTimer.Stop();
        _activityLog.Flush(all: true);
    }

    /// <summary>Empties the Activity list, the saved copy included.</summary>
    public void ClearActivity()
    {
        Activity.Clear();
        _activityLog.Clear();
    }

    /// <summary>How many days the Activity list is kept across restarts (0: this session only).</summary>
    public void SetActivityKeepDays(int days)
    {
        if (days == Settings.ActivityKeepDays) return;
        Settings.ActivityKeepDays = days;
        SaveSettings();
        _activityLog.SetKeepDays(days);
        Log.Info(days == 0 ? "Activity kept for this session only" : $"Activity kept for {days} day(s)");
    }

    public void SetDefaultPromptDuration(PromptDuration duration)
    {
        if (duration == Settings.DefaultPromptDuration) return;
        Settings.DefaultPromptDuration = duration;
        SaveSettings();
    }

    // ---------------------------------------------------------------- protection on/off

    public void EnableProtection()
    {
        try
        {
            ApplyProtection();
        }
        catch
        {
            // Don't leave apps silently blocked while PacketHound says protection is paused.
            if (!Settings.ProtectionEnabled)
            {
                try { SetPaused(); }
                catch (Exception ex) { Log.Error("Could not undo a failed start of protection", ex); }
            }
            throw;
        }
        Settings.ProtectionEnabled = true;
        Settings.FirstRunCompleted = true;
        Settings.PausedUntil = null;
        Settings.Save();
        _resumeTimer.Stop();
        LastError = null;
        Log.Info("Protection enabled");
        StateChanged?.Invoke(this, EventArgs.Empty);
    }

    void ApplyProtection()
    {
        // Remember the original firewall/audit configuration once, so it can be restored later.
        if (Settings.OriginalOutboundActions == null)
        {
            Settings.OriginalOutboundActions = FirewallManager.Profiles.ToDictionary(p => p, FirewallManager.GetDefaultOutboundAction);
            Settings.Save();
        }
        if (Settings.AuditFailureWasEnabled == null)
        {
            Settings.AuditFailureWasEnabled = AuditPolicy.IsFailureAuditingEnabled() ?? false;
            Settings.Save();
        }

        SeedWindowsRules();
        try
        {
            if (Environment.ProcessPath is { } self) FirewallManager.EnsureSelfRule(self);
        }
        catch (Exception ex)
        {
            Log.Error("Could not create the update-check rule", ex);
        }
        AuditPolicy.SetFailureAuditing(true);
        foreach (var p in FirewallManager.Profiles)
            FirewallManager.SetDefaultOutboundAction(p, FirewallManager.ActionBlock);
        _monitor.Start();
        _tempWatcher.Start();
    }

    /// <summary>
    /// Lets every app without a rule connect again. Your Block rules keep working. With a duration,
    /// protection turns itself back on afterwards (also across a restart).
    /// </summary>
    public void PauseProtection(TimeSpan? duration = null)
    {
        try
        {
            SetPaused();
        }
        catch
        {
            // Don't leave apps unwatched (or half the profiles open) while PacketHound says protection is on.
            if (Settings.ProtectionEnabled)
            {
                try { ApplyProtection(); }
                catch (Exception ex) { Log.Error("Could not undo a failed pause", ex); }
            }
            throw;
        }
        Settings.ProtectionEnabled = false;
        Settings.PausedUntil = duration == null ? null : DateTime.Now + duration;
        Settings.Save();
        ClearPending();
        if (duration != null) _resumeTimer.Start();
        else _resumeTimer.Stop();
        Log.Info(Settings.PausedUntil is { } until ? $"Protection paused until {until:HH:mm}" : "Protection paused");
        StateChanged?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>Stops watching and lets apps without a rule connect (the firewall side of pausing).</summary>
    void SetPaused()
    {
        _monitor.Stop();
        _tempWatcher.Stop();
        foreach (var p in FirewallManager.Profiles)
            FirewallManager.SetDefaultOutboundAction(p, FirewallManager.ActionAllow);
    }

    /// <summary>Ends a timed pause once its time is up.</summary>
    void CheckResume()
    {
        if (Settings.ProtectionEnabled || Settings.PausedUntil is not { } until)
        {
            _resumeTimer.Stop();
            return;
        }
        if (DateTime.Now < until) return;
        try
        {
            EnableProtection();
            Log.Info("Protection turned back on after a timed pause");
        }
        catch (Exception ex)
        {
            _resumeTimer.Stop();
            SetError("Could not turn protection back on after the pause: " + ex.Message, ex);
        }
    }

    /// <summary>Puts Windows back the way it was before PacketHound (for uninstalling).</summary>
    public int RestoreWindowsDefaults(bool removeRules)
    {
        _monitor.Stop();
        _tempWatcher.Stop();
        ClearPending();
        _resumeTimer.Stop();
        Settings.PausedUntil = null;

        foreach (var p in FirewallManager.Profiles)
        {
            var original = Settings.OriginalOutboundActions != null && Settings.OriginalOutboundActions.TryGetValue(p, out var a)
                ? a : FirewallManager.ActionAllow;
            FirewallManager.SetDefaultOutboundAction(p, original);
        }
        if (Settings.AuditFailureWasEnabled != true)
            AuditPolicy.SetFailureAuditing(false);

        // Temporary rules can't stay behind even when keeping rules: nothing would be left to remove them.
        // (The uninstaller closes a running PacketHound by force, so its own clean-up doesn't run.)
        RemoveAllTemporaryRules("restoring Windows defaults");
        // Timed rules too: with PacketHound gone, nothing would remove them when their time is up.
        try
        {
            var timed = FirewallManager.RemoveTimedRules(upTo: null);
            if (timed.Count > 0) Log.Info($"Removed {timed.Count} timed rule(s): restoring Windows defaults");
        }
        catch (Exception ex)
        {
            Log.Error("Could not remove timed rules", ex);
        }
        _expiryTimer.Stop();
        ReleaseAllLocks();
        var removed = removeRules ? FirewallManager.RemoveAllPacketHoundRules() : 0;
        if (removeRules) Settings.SignedCopyRules.Clear();
        try { AutoStart.Disable(); } catch (Exception ex) { Log.Error("Could not remove startup task", ex); }

        Settings.ProtectionEnabled = false;
        Settings.OriginalOutboundActions = null;
        Settings.AuditFailureWasEnabled = null;
        Settings.Save();
        InvalidateRules();
        Log.Info($"Windows defaults restored (removed {removed} rules)");
        StateChanged?.Invoke(this, EventArgs.Empty);
        return removed;
    }

    public void ApplyClassifierSettings()
    {
        _classifier.TreatMicrosoftStoreAppsAsWindows = Settings.TreatMicrosoftStoreAppsAsWindows;
        _classifier.AskForScriptingTools = Settings.AskForScriptingTools;
        _classifier.ClearCache();
    }

    /// <summary>Firewall profiles that are switched off (in which case nothing can be filtered).</summary>
    public List<string> DisabledFirewallProfiles()
    {
        try
        {
            return FirewallManager.Profiles.Where(p => !FirewallManager.IsFirewallEnabled(p))
                .Select(FirewallManager.ProfileName).ToList();
        }
        catch
        {
            return new List<string>();
        }
    }

    void SeedWindowsRules()
    {
        var existing = RuleSnapshot.Take();
        var candidates = new List<string> { "System" };
        candidates.AddRange(SeedWindowsBinaries.Select(b => Path.Combine(Environment.SystemDirectory, b)));

        foreach (var path in candidates)
        {
            try
            {
                if (existing.HasDecision(path) || existing.HasAllowRule(path)) continue;
                if (path != "System" && !File.Exists(path)) continue;
                if (!_classifier.IsWindowsComponent(path)) continue;
                FirewallManager.SetAppRule(path, AppDetails.For(path).DisplayName, allow: true, windowsComponent: true);
            }
            catch (Exception ex)
            {
                Log.Error($"Could not pre-allow {path}", ex);
            }
        }
        InvalidateRules();
    }

    // ---------------------------------------------------------------- blocked connections

    async void OnBlocked(BlockedConnection c)
    {
        try
        {
            await HandleBlocked(c);
        }
        catch (Exception ex)
        {
            Log.Error($"Could not handle a blocked connection from {c.AppPath}", ex);
        }
    }

    async Task HandleBlocked(BlockedConnection c)
    {
        if (!Settings.ProtectionEnabled) return;
        if (IPAddress.TryParse(c.RemoteAddress, out var ip) && IPAddress.IsLoopback(ip)) return;

        var path = c.AppPath;
        if (path.StartsWith(@"\device\", StringComparison.OrdinalIgnoreCase))
        {
            Log.Error("Could not map device path " + path);
            return;
        }

        var app = AppDetails.For(path);
        var rules = Rules();

        // A rule already covers this connection. Attempts made just before the rule existed arrive
        // a moment later; those are stale and skipped quietly.
        if (rules.HasDecision(path))
        {
            if (!RecentlyDecided(path))
                AddActivity(c, app, rules.HasAllowRule(path) ? "Blocked by another firewall rule" : "Blocked by your rule");
            return;
        }
        if (rules.DestinationRuleFor(path, c.RemoteAddress) is { } covering)
        {
            if (!RecentlyDecided(path))
                AddActivity(c, app, covering.Allow ? "Blocked by another firewall rule" : $"Blocked by your rule for {covering.Destination!.Label}");
            return;
        }

        // A host or domain rule covers this connection's name but not yet this IP: add the IP to it.
        var nameRules = rules.NameRules(path);
        if (nameRules.Count > 0)
        {
            var host = await HostNames.LookupAsync(c.RemoteAddress);
            if (!Settings.ProtectionEnabled) return;
            var match = host == null ? null : nameRules
                .Where(r => r.Destination!.Matches(host))
                .OrderBy(r => r.Destination!.Scope == RuleScope.Host ? 0 : 1) // most specific first
                .ThenByDescending(r => r.Destination!.Target.Length)
                .ThenBy(r => r.Allow)
                .FirstOrDefault();
            if (match != null)
            {
                ExtendRule(c, app, match, host!);
                return;
            }
        }

        // Already undecided: update the details. A deferred app whose wait is over is asked about again.
        if (_pending.TryGetValue(path, out var waiting))
        {
            var previousProcess = waiting.ProcessId;
            waiting.Update(c);
            LookUpHostName(waiting);
            if (waiting.ShowsCommandLine && waiting.ProcessId != previousProcess) LookUpCommandLine(waiting);
            if (waiting.IsSnoozed)
            {
                AddActivity(c, app, waiting.QuietDeferred ? QuietResult : "Blocked · you chose to decide later");
                return;
            }
            if (!_queue.Contains(waiting) && IsQuiet)
            {
                DeferQuietly(waiting);
                AddActivity(c, app, QuietResult);
                return;
            }
            AddActivity(c, app, "Blocked · waiting for your decision");
            if (!_queue.Contains(waiting)) Ask(waiting);
            return;
        }

        if (_classifier.IsWindowsComponent(path))
        {
            if (_autoAllowFailed.Contains(path)) return;
            try
            {
                FirewallManager.SetAppRule(path, app.DisplayName, allow: true, windowsComponent: true);
                InvalidateRules();
                _justDecided[path] = DateTime.UtcNow;
                AddActivity(c, app, "Windows component · allowed automatically");
                RulesChanged?.Invoke(this, EventArgs.Empty);
            }
            catch (Exception ex)
            {
                _autoAllowFailed.Add(path);
                SetError($"Could not allow Windows component {path}: {ex.Message}", ex);
            }
            return;
        }

        // A new copy of an installer/updater you allowed before, unpacked to a new temp folder.
        if (MightBeRemembered(path))
        {
            if (!_signatureChecks.Add(path))
            {
                AddActivity(c, app, "Blocked · checking its signature");
                return;
            }
            FileStream? fileLock = null;
            string? signer;
            try
            {
                // Lock first, then check: the file that was checked is the one that stays there.
                (fileLock, signer) = await Task.Run(() =>
                {
                    var locked = TryLock(path);
                    return (locked, locked == null ? null : Signature.GetVerifiedSigner(path));
                });
            }
            finally
            {
                _signatureChecks.Remove(path);
            }
            if (Settings.ProtectionEnabled && !_pending.ContainsKey(path) && fileLock != null
                && Settings.SignedCopyRules.FirstOrDefault(r => r.Matches(path, signer)) is { } signedRule)
            {
                ApplySignedCopyRule(signedRule, app, c, hostName: null, fileLock);
                return;
            }
            fileLock?.Dispose();
            if (!Settings.ProtectionEnabled || _pending.ContainsKey(path)) return; // paused, or asked about meanwhile
        }

        var request = new PendingRequest(app, c) { PreviousVersion = FindPreviousVersion(path) };
        _pending[path] = request;
        LookUpHostName(request);
        LookUpSigner(request);
        if (request.ShowsCommandLine) LookUpCommandLine(request);
        if (IsQuiet)
        {
            DeferQuietly(request);
            AddActivity(c, app, QuietResult);
            return;
        }
        AddActivity(c, app, "Blocked · waiting for your decision");
        Ask(request);
    }

    const string QuietResult = "Blocked · quiet mode, listed to decide later";

    PreviousVersion? FindPreviousVersion(string path)
    {
        try
        {
            return ProgramVersions.Find(Rules(), path);
        }
        catch (Exception ex)
        {
            Log.Error($"Could not look for an earlier version of {path}", ex);
            return null;
        }
    }

    async void LookUpCommandLine(PendingRequest request)
    {
        var pid = request.ProcessId;
        try
        {
            request.SetCommandLine(pid, await Task.Run(() => RunningPrograms.CommandLine(pid)));
        }
        catch (Exception ex)
        {
            Log.Error($"Could not read the command line of process {pid}", ex);
        }
    }

    /// <summary>Quick name check before the (slower) signature check: a temp-folder file named like a remembered installer.</summary>
    bool MightBeRemembered(string path)
    {
        if (!TempFolders.Contains(path)) return false;
        var fileName = Path.GetFileName(path);
        return Settings.SignedCopyRules.Any(r => string.Equals(r.FileName, fileName, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Opens the file so it can't be changed, deleted or renamed (nor its folder) while open; it can still be
    /// read and run. Null if that's not possible right now (e.g. something is still writing it).
    /// </summary>
    static FileStream? TryLock(string path)
    {
        try
        {
            return new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>
    /// Gives a new copy of a remembered installer/updater its rule, for this copy's path, removed when it quits.
    /// <paramref name="fileLock"/> keeps the checked file in place for as long as the rule exists.
    /// <paramref name="inAdvance"/>: made when its file appeared, before it ran (null connection).
    /// </summary>
    void ApplySignedCopyRule(SignedCopyRule rule, AppDetails app, BlockedConnection? c, string? hostName, FileStream fileLock,
        bool inAdvance = false)
    {
        var path = app.Path;
        try
        {
            FirewallManager.SetAppRule(path, app.DisplayName, rule.Allow, windowsComponent: false, temporary: true,
                note: $" (copy of {rule.FileName} signed by {rule.Signer})");
            ReleaseLock(path);
            _locks[path] = fileLock;
            TrackTemporary(path);
            _justDecided[path] = DateTime.UtcNow;
            InvalidateRules();
            AddActivity(c ?? new BlockedConnection(), app,
                inAdvance ? $"{(rule.Allow ? "Allowed" : "Blocked")} in advance · installer/updater you {(rule.Allow ? "allowed" : "blocked")} before"
                : rule.Allow ? "Allowed automatically · installer/updater you allowed before, it may need to retry"
                : "Blocked automatically · installer/updater you blocked before", hostName);
            RulesChanged?.Invoke(this, EventArgs.Empty);
            // Too late to be ready before it connected: an installer has probably given up, so offer the pause.
            if (!inAdvance && rule.Allow) InstallerAllowed?.Invoke(this, app.DisplayName);
        }
        catch (Exception ex)
        {
            if (!_locks.ContainsValue(fileLock)) fileLock.Dispose();
            SetError($"Could not create the firewall rule for {app.DisplayName}: {ex.Message}", ex);
        }
    }

    void ReleaseLock(string path)
    {
        if (_locks.Remove(path, out var fileLock)) fileLock.Dispose();
    }

    void ReleaseAllLocks()
    {
        foreach (var fileLock in _locks.Values) fileLock.Dispose();
        _locks.Clear();
    }

    /// <summary>
    /// An .exe appeared in a temp folder. If it's a remembered installer/updater (same file name, and once
    /// it's fully written, a valid signature from the same signer), make its rule now, before it runs.
    /// </summary>
    async void OnTempExeAppeared(string path)
    {
        try
        {
            if (!Settings.ProtectionEnabled || !MightBeRemembered(path)) return;
            if (!_preparing.Add(path)) return;
            FileStream? fileLock = null;
            try
            {
                // Lock once it's fully written, then check: the file that was checked is the one that stays there.
                string? signer;
                (fileLock, signer) = await Task.Run(() =>
                {
                    var locked = LockWhenWritten(path);
                    return (locked, locked == null ? null : Signature.GetVerifiedSigner(path));
                });
                if (fileLock == null || !Settings.ProtectionEnabled) return;
                if (Settings.SignedCopyRules.FirstOrDefault(r => r.Matches(path, signer)) is not { } rule) return;
                if (Rules().HasDecision(path) || _pending.ContainsKey(path)) return;
                ApplySignedCopyRule(rule, AppDetails.For(path), null, null, fileLock, inAdvance: true);
                fileLock = null; // kept until the rule goes
            }
            finally
            {
                fileLock?.Dispose();
                _preparing.Remove(path);
            }
        }
        catch (Exception ex)
        {
            Log.Error($"Could not prepare a rule for {path}", ex);
        }
    }

    /// <summary>
    /// Waits (up to ~10 s) until nothing is writing the file any more, and returns it locked (see <see cref="TryLock"/>).
    /// Null if it vanished or never finished.
    /// </summary>
    static FileStream? LockWhenWritten(string path)
    {
        for (var i = 0; i < 200; i++)
        {
            try
            {
                // Fails while another handle can still write to (or delete) the file.
                return new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            }
            catch (FileNotFoundException) { return null; }
            catch (DirectoryNotFoundException) { return null; }
            catch (UnauthorizedAccessException) { return null; }
            catch (IOException) { }
            Thread.Sleep(50);
        }
        return null;
    }

    async void LookUpSigner(PendingRequest request)
    {
        try
        {
            request.SetSigner(await Task.Run(() => Signature.GetVerifiedSigner(request.AppPath)));
        }
        catch (Exception ex)
        {
            Log.Error($"Could not check the signature of {request.AppPath}", ex);
        }
    }

    // ---------------------------------------------------------------- signed-copy rules

    /// <summary>
    /// Remembers an installer/updater the user allowed, and applies that to matching copies already waiting.
    /// Only Allow is remembered: a remembered Block would make the installer fail silently on every later run.
    /// </summary>
    void RememberInstaller(PendingRequest request)
    {
        var rule = new SignedCopyRule
        {
            FileName = request.FileName, Signer = request.Signer!, DisplayName = request.DisplayName,
            Allow = true, Created = DateTime.Now,
        };
        Settings.SignedCopyRules.RemoveAll(r => r.Key == rule.Key);
        Settings.SignedCopyRules.Add(rule);
        SaveSettings();
        Log.Info($"Remembered installer/updater: {rule.FileName} signed by {rule.Signer}");

        // Other copies already waiting (in the queue or decided later) get the same answer, once their file
        // is locked and its signature checked again.
        foreach (var waiting in _pending.Values.Where(p => p != request && rule.Matches(p.AppPath, p.Signer)).ToList())
        {
            var fileLock = TryLock(waiting.AppPath);
            if (fileLock == null || !rule.Matches(waiting.AppPath, Signature.GetVerifiedSigner(waiting.AppPath)))
            {
                fileLock?.Dispose();
                continue;
            }
            _queue.Remove(waiting);
            Deferred.Remove(waiting);
            _pending.Remove(waiting.AppPath);
            ApplySignedCopyRule(rule, waiting.App, new BlockedConnection
            {
                RemoteAddress = waiting.RemoteAddress, RemotePort = waiting.RemotePort, ProcessId = waiting.ProcessId,
            }, waiting.HostName, fileLock);
        }
    }

    public void SetSignedCopyAction(string key, bool allow)
    {
        foreach (var rule in Settings.SignedCopyRules.Where(r => r.Key == key)) rule.Allow = allow;
        SaveSettings();
        RulesChanged?.Invoke(this, EventArgs.Empty);
    }

    public void RemoveSignedCopyRule(string key)
    {
        if (Settings.SignedCopyRules.RemoveAll(r => r.Key == key) == 0) return;
        SaveSettings();
        Log.Info($"Signed-copy rule removed: {key}");
        RulesChanged?.Invoke(this, EventArgs.Empty);
    }

    void SaveSettings()
    {
        try
        {
            Settings.Save();
        }
        catch (Exception ex)
        {
            SetError("Could not save settings: " + ex.Message, ex);
        }
    }

    /// <summary>Queues an undecided app for the prompt; next in line when <paramref name="next"/>.</summary>
    void Ask(PendingRequest request, bool next = false)
    {
        Deferred.Remove(request);
        request.QuietDeferred = false;
        request.SnoozedUntil = null;
        // While a prompt is open, it shows _queue[0].
        if (next) _queue.Insert(_prompt != null && _queue.Count > 0 ? 1 : 0, request);
        else _queue.Add(request);
        ShowNextPrompt();
        StateChanged?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Brings up the prompt for an undecided app (deferred or queued). Returns false if the app has
    /// nothing waiting. A prompt already on screen for another app is finished first.
    /// </summary>
    public bool DecideNow(string appPath)
    {
        if (!_pending.TryGetValue(appPath, out var request)) return false;
        if (!_queue.Contains(request))
        {
            Ask(request, next: true);
        }
        else if (_queue.IndexOf(request) > 1)
        {
            _queue.Remove(request);
            _queue.Insert(_prompt != null ? 1 : 0, request);
        }
        _prompt?.Activate();
        return true;
    }

    public bool IsUndecided(string appPath) => _pending.ContainsKey(appPath);

    /// <summary>
    /// When a deferred app's wait is over: ask again if it's still running, otherwise wait until it
    /// next connects. Drops apps that got a rule some other way (e.g. in wf.msc).
    /// </summary>
    void CheckDeferred()
    {
        foreach (var request in Deferred.ToList())
        {
            if (Rules().HasDecision(request.AppPath))
            {
                Deferred.Remove(request);
                _pending.Remove(request.AppPath);
                StateChanged?.Invoke(this, EventArgs.Empty);
                continue;
            }
            if (request.SnoozedUntil is not { } until || until > DateTime.Now) continue;

            bool running;
            try
            {
                running = RunningPrograms.IsRunning(request.AppPath);
            }
            catch (Exception ex)
            {
                Log.Error($"Could not check whether {request.AppPath} is running", ex);
                running = false;
            }
            if (!running) request.SnoozedUntil = null;
            else if (IsQuiet) DeferQuietly(request);
            else Ask(request);
        }
        if (!Deferred.Any(r => r.SnoozedUntil != null)) _deferredTimer.Stop();
    }

    bool RecentlyDecided(string path)
    {
        if (!_justDecided.TryGetValue(path, out var at)) return false;
        if (DateTime.UtcNow - at < TimeSpan.FromSeconds(5)) return true;
        _justDecided.Remove(path);
        return false;
    }

    void ExtendRule(BlockedConnection c, AppDetails app, FirewallRuleInfo rule, string host)
    {
        var label = rule.Destination!.Label;
        try
        {
            if (FirewallManager.AddRemoteAddresses(rule.Name, new[] { c.RemoteAddress }))
            {
                _justDecided[c.AppPath] = DateTime.UtcNow;
                NotifyRulesChanged();
            }
            AddActivity(c, app, rule.Allow ? $"New address for {label} · allowed, the app may retry" : $"Blocked by your rule for {label}", host);
        }
        catch (Exception ex)
        {
            SetError($"Could not add {c.RemoteAddress} to the rule for {label}: {ex.Message}", ex);
        }
    }

    /// <summary>Adds the addresses a host or domain resolves to now, so the first connections don't have to be blocked.</summary>
    async void AddResolvedAddresses(string ruleName, RuleDestination destination, string? hostName)
    {
        var addresses = await ResolveAsync(new[] { destination.Target, hostName }.OfType<string>());
        try
        {
            if (addresses.Count > 0 && FirewallManager.AddRemoteAddresses(ruleName, addresses)) NotifyRulesChanged();
        }
        catch (Exception ex)
        {
            Log.Error($"Could not add resolved addresses to rule '{ruleName}'", ex);
        }
    }

    /// <summary>The addresses these names resolve to now (each lookup gives up after 3 s). Names that don't resolve add nothing.</summary>
    static async Task<List<string>> ResolveAsync(IEnumerable<string> names)
    {
        var lookups = names.Distinct(StringComparer.OrdinalIgnoreCase).Select(async name =>
        {
            try
            {
                var lookup = Dns.GetHostAddressesAsync(name);
                if (await Task.WhenAny(lookup, Task.Delay(3000)) == lookup && lookup.IsCompletedSuccessfully)
                    return lookup.Result.Select(a => a.ToString()).ToList();
            }
            catch
            {
                // Doesn't resolve; addresses get added as the app connects.
            }
            return new List<string>();
        });
        return (await Task.WhenAll(lookups)).SelectMany(a => a).Distinct().ToList();
    }

    async void LookUpHostName(PendingRequest request)
    {
        var address = request.RemoteAddress;
        var name = await HostNames.LookupAsync(address);
        request.SetHostName(address, name);
        if (name != null)
            foreach (var a in Activity.Take(50).Where(a => a.RemoteAddress == address && a.HostName == null))
                a.HostName = name;
    }

    void ShowNextPrompt()
    {
        if (_prompt != null)
        {
            _prompt.SetQueueCount(_queue.Count - 1);
            return;
        }
        if (_queue.Count == 0) return;

        var request = _queue[0];
        var duration = Settings.DefaultPromptDuration == PromptDuration.LastUsed ? Settings.LastPromptDuration : Settings.DefaultPromptDuration;
        var prompt = new PromptWindow(request, duration);
        prompt.SetQueueCount(_queue.Count - 1);
        prompt.Closed += (_, _) =>
        {
            _prompt = null;
            // A temp-folder copy is always "until it quits" (there's no choice), so it isn't the user's pick.
            if (prompt.Decision is PromptDecision.Allow or PromptDecision.Block && !request.InTempFolder
                && prompt.Duration != Settings.LastPromptDuration)
            {
                Settings.LastPromptDuration = prompt.Duration;
                SaveSettings();
            }
            Decide(request, prompt.Decision, prompt.Scope, prompt.UntilQuit, prompt.Expires);
            ShowNextPrompt();
        };
        _prompt = prompt;
        prompt.Show();
    }

    /// <param name="untilQuit">The rule is removed when the app quits.</param>
    /// <param name="expires">The rule is removed at this time ("for 1 hour").</param>
    void Decide(PendingRequest request, PromptDecision decision, ScopeOption? scope, bool untilQuit, DateTime? expires)
    {
        if (decision == PromptDecision.Dismiss) return;

        _queue.Remove(request);

        if (decision == PromptDecision.Later)
        {
            // Stays undecided (and blocked) and is listed on the Rules tab until the user decides.
            request.SnoozedUntil = DateTime.Now.AddMinutes(Math.Max(1, Settings.SnoozeMinutes));
            Deferred.Add(request);
            _deferredTimer.Start();
            StateChanged?.Invoke(this, EventArgs.Empty);
            return;
        }

        _pending.Remove(request.AppPath);
        switch (decision)
        {
            case PromptDecision.SameAsBefore when request.PreviousVersion is { } previous:
                ApplyPreviousVersion(request, previous);
                break;

            case PromptDecision.Allow:
            case PromptDecision.Block:
                var allow = decision == PromptDecision.Allow;
                var destination = scope?.Destination;
                // Recorded so a later version of the app (in a new folder) can be recognised as the same publisher's.
                var note = FirewallManager.SignerNote(request.Signer);
                try
                {
                    if (destination == null)
                    {
                        FirewallManager.SetAppRule(request.AppPath, request.DisplayName, allow, windowsComponent: false, temporary: untilQuit,
                            note: note, expires: expires);
                    }
                    else
                    {
                        // The destination picked can be any the app tried, not just the latest attempt.
                        var ruleName = FirewallManager.SetDestinationRule(request.AppPath, request.DisplayName, allow, destination,
                            request.AddressesFor(destination, scope!.Address), untilQuit, expires, note);
                        if (destination.Scope != RuleScope.Address) AddResolvedAddresses(ruleName, destination, scope.HostName);
                    }
                    if (untilQuit) TrackTemporary(request.AppPath);
                    if (expires != null) CheckExpiredRules();
                    _justDecided[request.AppPath] = DateTime.UtcNow;
                    InvalidateRules();
                    var what = destination == null ? "this app" : destination.Label;
                    var address = destination == null ? request.RemoteAddress : scope!.Address;
                    var lifetime = untilQuit ? " until it quits" : expires is { } e ? $" until {TimeText.When(e)}" : "";
                    AddActivity(new BlockedConnection
                    {
                        RemoteAddress = address, RemotePort = request.PortFor(address), ProcessId = request.ProcessId,
                    }, request.App, $"You {(allow ? "allowed" : "blocked")} {what}{lifetime}",
                        destination == null ? request.HostName : scope!.HostName);
                    if (request.InTempFolder)
                    {
                        // Installers and updaters unpack to a new temp folder each run: a signed one you allow is
                        // allowed next time without asking (same file name and signer). Blocks aren't remembered.
                        if (allow && destination == null && request.Signer != null) RememberInstaller(request);
                        if (allow) InstallerAllowed?.Invoke(this, request.DisplayName);
                    }
                    RulesChanged?.Invoke(this, EventArgs.Empty);
                }
                catch (Exception ex)
                {
                    SetError($"Could not create the firewall rule for {request.DisplayName}: {ex.Message}", ex);
                    System.Windows.MessageBox.Show(
                        $"PacketHound could not create the firewall rule for {request.DisplayName}.\n\n{ex.Message}",
                        "PacketHound", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
                }
                break;
        }
        StateChanged?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// "Same as before": gives the app the rules its earlier version had. If the earlier version is gone from
    /// this PC, its rules are removed (they've moved); if it's still installed, they stay.
    /// </summary>
    void ApplyPreviousVersion(PendingRequest request, PreviousVersion previous)
    {
        try
        {
            var note = FirewallManager.SignerNote(request.Signer);
            // A whole-app rule replaces the app's other rules, so it goes first.
            foreach (var rule in previous.Rules.OrderBy(r => r.Destination == null ? 0 : 1))
            {
                if (rule.Destination is { } destination)
                    FirewallManager.SetDestinationRule(request.AppPath, request.DisplayName, rule.Allow, destination, rule.Addresses,
                        temporary: false, note: note);
                else
                    FirewallManager.SetAppRule(request.AppPath, request.DisplayName, rule.Allow, windowsComponent: false, note: note);
            }
            if (!previous.StillExists)
                foreach (var rule in previous.Rules) FirewallManager.RemoveRule(rule.Name);
            _justDecided[request.AppPath] = DateTime.UtcNow;
            InvalidateRules();
            Log.Info($"Rules of {previous.Path} {(previous.StillExists ? "copied" : "moved")} to {request.AppPath}");
            AddActivity(new BlockedConnection
            {
                RemoteAddress = request.RemoteAddress, RemotePort = request.RemotePort, ProcessId = request.ProcessId,
            }, request.App, $"You kept the rules of the earlier version ({previous.FolderName})", request.HostName);
            RulesChanged?.Invoke(this, EventArgs.Empty);
        }
        catch (Exception ex)
        {
            NotifyRulesChanged(); // some may have been made
            SetError($"Could not copy the earlier version's rules to {request.DisplayName}: {ex.Message}", ex);
            System.Windows.MessageBox.Show(
                $"PacketHound could not copy the earlier version's rules to {request.DisplayName}.\n\n{ex.Message}",
                "PacketHound", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
        }
    }

    public void ShowPrompt() => _prompt?.Activate();

    // ---------------------------------------------------------------- quiet mode

    /// <summary>
    /// Stops asking about new apps for a while: they stay blocked and go on the "decide later" list. Whatever is
    /// waiting now, the prompt on screen included, goes there too. <paramref name="duration"/> null: until turned off.
    /// </summary>
    public void StartQuiet(TimeSpan? duration)
    {
        QuietUntil = duration is { } d ? DateTime.Now + d : DateTime.MaxValue;
        foreach (var request in _queue.ToList()) DeferQuietly(request);
        _queue.Clear(); // first, so closing the prompt doesn't open the next one
        ClosePrompt();
        ScheduleQuietEnd();
        Log.Info(duration == null ? "Quiet mode on" : $"Quiet mode on until {QuietUntil:HH:mm}");
        StateChanged?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>Ends quiet mode. Apps put aside by it that are still running are asked about now.</summary>
    public void StopQuiet()
    {
        if (QuietUntil == null) return;
        QuietUntil = null;
        _quietTimer.Stop();
        foreach (var request in Deferred.Where(r => r.QuietDeferred).ToList())
        {
            request.QuietDeferred = false;
            request.SnoozedUntil = DateTime.Now; // due: CheckDeferred asks if it's running
        }
        Log.Info("Quiet mode off");
        CheckDeferred();
        StateChanged?.Invoke(this, EventArgs.Empty);
    }

    void DeferQuietly(PendingRequest request)
    {
        _queue.Remove(request);
        request.QuietDeferred = true;
        request.SnoozedUntil = DateTime.MaxValue; // until quiet mode ends
        if (!Deferred.Contains(request)) Deferred.Add(request);
        _deferredTimer.Start();
        StateChanged?.Invoke(this, EventArgs.Empty);
    }

    void CheckQuiet()
    {
        if (QuietUntil is { } until && until <= DateTime.Now) StopQuiet();
        else ScheduleQuietEnd();
    }

    void ScheduleQuietEnd()
    {
        _quietTimer.Stop();
        if (QuietUntil is not { } until || until == DateTime.MaxValue) return;
        _quietTimer.Interval = ClampWait(until - DateTime.Now);
        _quietTimer.Start();
    }

    /// <summary>
    /// How long a timer waits: at least a second, and at most 10 minutes, so the time is checked again after the
    /// PC sleeps or its clock changes.
    /// </summary>
    static TimeSpan ClampWait(TimeSpan wait) =>
        wait < TimeSpan.FromSeconds(1) ? TimeSpan.FromSeconds(1) : wait > TimeSpan.FromMinutes(10) ? TimeSpan.FromMinutes(10) : wait;

    // ---------------------------------------------------------------- timed rules ("for 1 hour")

    /// <summary>Removes timed rules whose time is up, and sets the timer for the next one.</summary>
    void CheckExpiredRules()
    {
        _expiryTimer.Stop();
        try
        {
            var expired = FirewallManager.RemoveTimedRules(DateTime.Now);
            foreach (var rule in expired)
            {
                var label = rule.Destination == null ? "" : $" for {rule.Destination.Label}";
                AddNote(rule.DisplayName, rule.ApplicationName, $"Time's up · {(rule.Allow ? "Allow" : "Block")} rule{label} removed");
            }
            if (expired.Count > 0)
            {
                Log.Info($"Removed {expired.Count} timed rule(s) whose time was up");
                NotifyRulesChanged();
            }
            var next = FirewallManager.GetPacketHoundRules().Select(r => r.Expires).Where(e => e != null).Min();
            if (next is not { } n) return;
            _expiryTimer.Interval = ClampWait(n - DateTime.Now);
            _expiryTimer.Start();
        }
        catch (Exception ex)
        {
            SetError("Could not remove timed rules: " + ex.Message, ex);
            _expiryTimer.Interval = TimeSpan.FromMinutes(1);
            _expiryTimer.Start();
        }
    }

    // ---------------------------------------------------------------- "until the app quits" rules

    sealed class TemporaryApp
    {
        public DateTime Made { get; } = DateTime.UtcNow;
        public bool SeenRunning { get; set; }
    }

    void TrackTemporary(string path)
    {
        _temporaryApps[path] = new TemporaryApp();
        _temporaryTimer.Start();
    }

    /// <summary>
    /// Removes an app's temporary rules once no process of that program is running. A rule made before its
    /// program started is kept for a short grace period until the program has been seen running.
    /// </summary>
    void CheckTemporaryRules()
    {
        foreach (var (path, app) in _temporaryApps.ToList())
        {
            try
            {
                if (RunningPrograms.IsRunning(path))
                {
                    app.SeenRunning = true;
                    continue;
                }
                if (!app.SeenRunning && DateTime.UtcNow - app.Made < TemporaryGrace) continue;
                _temporaryApps.Remove(path);
                ReleaseLock(path);
                var removed = FirewallManager.RemoveTemporaryRules(path);
                if (removed == 0) continue;
                Log.Info($"{path} quit: removed {removed} temporary rule(s)");
                AddActivity(new BlockedConnection(), AppDetails.For(path), "App quit · temporary rule removed");
                NotifyRulesChanged();
            }
            catch (Exception ex)
            {
                SetError($"Could not remove the temporary rule for {path}: {ex.Message}", ex);
            }
        }
        if (_temporaryApps.Count == 0) _temporaryTimer.Stop();
    }

    /// <summary>Temporary rules can't outlive PacketHound, since nothing would be left to remove them.</summary>
    void RemoveAllTemporaryRules(string reason)
    {
        try
        {
            var removed = FirewallManager.RemoveTemporaryRules();
            if (removed > 0) Log.Info($"Removed {removed} temporary rule(s): {reason}");
        }
        catch (Exception ex)
        {
            Log.Error("Could not remove temporary rules", ex);
        }
        _temporaryApps.Clear();
        _temporaryTimer.Stop();
        ReleaseAllLocks();
    }

    void ClosePrompt()
    {
        if (_prompt == null) return;
        _prompt.Decision = PromptDecision.Dismiss;
        _prompt.Close();
        _prompt = null;
    }

    void ClearPending()
    {
        // Empty the queue first so closing the prompt doesn't open the next one.
        _queue.Clear();
        _pending.Clear();
        Deferred.Clear();
        _deferredTimer.Stop();
        ClosePrompt();
    }

    // ---------------------------------------------------------------- rules

    RuleSnapshot Rules()
    {
        if (_snapshot == null || DateTime.UtcNow - _snapshot.TakenUtc > SnapshotLifetime)
        {
            try
            {
                _snapshot = RuleSnapshot.Take();
            }
            catch (Exception ex)
            {
                SetError("Could not read firewall rules: " + ex.Message, ex);
                _snapshot ??= new RuleSnapshot(Array.Empty<FirewallRuleInfo>());
            }
        }
        return _snapshot;
    }

    public void InvalidateRules() => _snapshot = null;

    /// <summary>
    /// Applies a change made in the Edit dialog and returns the name of the rule that now holds it.
    ///   - Same destination: the rule is changed in place (action, and "until it quits" made permanent).
    ///   - "Any connection": a whole-app rule replaces every rule the app has, as when answering the prompt.
    ///   - Another destination: the new rule is made first and the old one removed after, so a failure leaves
    ///     the old rule in place. A rule the app already had for that destination is replaced.
    /// </summary>
    public async Task<string> EditRuleAsync(FirewallRuleInfo original, RuleEdit edit)
    {
        var path = original.ApplicationName;
        var app = AppDetails.For(path);
        var note = FirewallManager.SignerNote(original.Signer);
        string name;
        try
        {
            if (RuleDestination.Same(original.Destination, edit.Destination))
            {
                // Editing an automatic Windows rule makes it the user's decision, even with the same action.
                if (original.Allow != edit.Allow || original.IsWindowsAuto) FirewallManager.ChangeRuleAction(original.Name, edit.Allow);
                if (original.IsTemporary && !edit.Temporary || original.Expires != null && edit.Expires == null)
                    FirewallManager.MakePermanent(original.Name);
                name = original.Name;
            }
            else if (edit.Destination is not { } destination)
            {
                name = FirewallManager.SetAppRule(path, app.DisplayName, edit.Allow, windowsComponent: false, temporary: edit.Temporary,
                    note: note, expires: edit.Expires);
            }
            else
            {
                var addresses = destination.Scope == RuleScope.Address ? new List<string> { destination.Target } : new List<string>();
                if (destination.Scope != RuleScope.Address)
                {
                    // Widening (a host to its domain, say): the addresses collected so far still belong.
                    if (original.Destination is { } old && destination.Covers(old)) addresses.AddRange(original.Addresses);
                    addresses.AddRange(await ResolveAsync(new[] { destination.Target }));
                    if (addresses.Count == 0)
                        throw new InvalidOperationException($"No IP addresses were found for {destination.Target}, and Windows Firewall needs at least one. "
                                                            + "Check the name, or try again once this PC is online.");
                }
                var replaced = FirewallManager.GetPacketHoundRules()
                    .Where(r => FirewallManager.PathEquals(r.ApplicationName, path) && r.Name != original.Name
                                && RuleDestination.Same(r.Destination, destination))
                    .ToList();
                name = FirewallManager.SetDestinationRule(path, app.DisplayName, edit.Allow, destination, addresses, edit.Temporary,
                    edit.Expires, note);
                foreach (var r in replaced.Where(r => r.Name != name)) FirewallManager.RemoveRule(r.Name);
                if (original.Name != name) FirewallManager.RemoveRule(original.Name);
            }
        }
        finally
        {
            // Also after a failure part-way, so the list shows what's really there.
            NotifyRulesChanged();
        }

        if (edit.Temporary) TrackTemporary(path);
        CheckExpiredRules(); // the next timed rule may have changed
        _justDecided[path] = DateTime.UtcNow;
        var lifetime = edit.Temporary ? " until it quits" : edit.Expires is { } e ? $" until {TimeText.When(e)}" : "";
        AddActivity(new BlockedConnection(), app,
            $"You changed the rule · {(edit.Allow ? "allow" : "block")} {edit.Destination?.Label ?? "any connection"}{lifetime}");
        DropAnsweredRequest(path);
        return name;
    }

    /// <summary>
    /// An app waiting for a decision that now has a whole-app rule (made on the Rules tab) stops waiting,
    /// unless its prompt is on screen; answering that replaces the rule as usual.
    /// </summary>
    void DropAnsweredRequest(string path)
    {
        if (!_pending.TryGetValue(path, out var waiting) || !Rules().HasDecision(path)) return;
        if (_prompt != null && _queue.Count > 0 && _queue[0] == waiting) return;
        _queue.Remove(waiting);
        Deferred.Remove(waiting);
        _pending.Remove(path);
        ShowNextPrompt(); // updates the "more apps waiting" count
        StateChanged?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>Deletes rules whose program is no longer on this PC, noting each in Activity. Returns how many were removed.</summary>
    public int RemoveMissingProgramRules(IEnumerable<FirewallRuleInfo> rules)
    {
        var removed = 0;
        try
        {
            foreach (var rule in rules)
            {
                FirewallManager.RemoveRule(rule.Name);
                removed++;
                var label = rule.Destination == null ? "" : $" ({rule.Destination.Label})";
                AddNote(rule.DisplayName, rule.ApplicationName, $"Program no longer exists · rule{label} removed");
            }
        }
        finally
        {
            Log.Info($"Removed {removed} rule(s) for programs that no longer exist");
            NotifyRulesChanged();
        }
        return removed;
    }

    public void NotifyRulesChanged()
    {
        InvalidateRules();
        RulesChanged?.Invoke(this, EventArgs.Empty);
    }

    // ---------------------------------------------------------------- helpers

    void AddActivity(BlockedConnection c, AppDetails app, string result, string? hostName = null)
    {
        // Collapse retries: same app, destination and outcome within 30 seconds.
        if (Activity.Count > 0)
        {
            var top = Activity[0];
            if (top.AppPath == app.Path && top.RemoteAddress == c.RemoteAddress && top.RemotePort == c.RemotePort
                && top.Result == result && (c.Time - top.Time).Duration() < TimeSpan.FromSeconds(30))
                return;
        }

        Insert(new ActivityEntry
        {
            Time = c.Time,
            AppName = app.DisplayName,
            AppPath = app.Path,
            RemoteAddress = c.RemoteAddress,
            RemotePort = c.RemotePort,
            Protocol = c.Protocol == 0 ? "" : c.ProtocolName,
            Result = result,
            HostName = hostName,
        });
    }

    /// <summary>An Activity entry that isn't about a connection (a rule removed, say).</summary>
    void AddNote(string appName, string appPath, string result) =>
        Insert(new ActivityEntry { Time = DateTime.Now, AppName = appName, AppPath = appPath, Result = result });

    void Insert(ActivityEntry entry)
    {
        Activity.Insert(0, entry);
        while (Activity.Count > MaxActivity) Activity.RemoveAt(Activity.Count - 1);
        _activityLog.Add(entry);
    }

    void SetError(string message, Exception? ex = null)
    {
        Log.Error(message, ex);
        LastError = message;
        StateChanged?.Invoke(this, EventArgs.Empty);
    }
}

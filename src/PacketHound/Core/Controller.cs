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
    const int MaxActivity = 1000;
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
    // Value: when the rule was made. A rule made before the program starts gets a grace period.
    readonly Dictionary<string, DateTime> _temporaryApps = new(StringComparer.OrdinalIgnoreCase);
    static readonly TimeSpan TemporaryGrace = TimeSpan.FromMinutes(1);
    // Notices remembered installers/updaters being unpacked, so their rule exists before they connect.
    readonly TempFolderWatcher _tempWatcher = new();
    readonly HashSet<string> _preparing = new(StringComparer.OrdinalIgnoreCase);
    readonly DispatcherTimer _temporaryTimer;
    RuleSnapshot? _snapshot;
    PromptWindow? _prompt;

    public Controller(Dispatcher dispatcher)
    {
        _dispatcher = dispatcher;
        Settings = Settings.Load();
        Updates = new UpdateService(Settings);
        ApplyClassifierSettings();
        _temporaryTimer = new DispatcherTimer(DispatcherPriority.Background, dispatcher) { Interval = TimeSpan.FromSeconds(3) };
        _temporaryTimer.Tick += (_, _) => CheckTemporaryRules();
        _deferredTimer = new DispatcherTimer(DispatcherPriority.Background, dispatcher) { Interval = TimeSpan.FromSeconds(15) };
        _deferredTimer.Tick += (_, _) => CheckDeferred();
        _resumeTimer = new DispatcherTimer(DispatcherPriority.Background, dispatcher) { Interval = TimeSpan.FromSeconds(5) };
        _resumeTimer.Tick += (_, _) => CheckResume();

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
        Updates.Start();
        RemoveAllTemporaryRules("left over from the last session");
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
    }

    // ---------------------------------------------------------------- protection on/off

    public void EnableProtection()
    {
        ApplyProtection();
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
        _monitor.Stop();
        _tempWatcher.Stop();
        foreach (var p in FirewallManager.Profiles)
            FirewallManager.SetDefaultOutboundAction(p, FirewallManager.ActionAllow);
        Settings.ProtectionEnabled = false;
        Settings.PausedUntil = duration == null ? null : DateTime.Now + duration;
        Settings.Save();
        ClearPending();
        if (duration != null) _resumeTimer.Start();
        else _resumeTimer.Stop();
        Log.Info(Settings.PausedUntil is { } until ? $"Protection paused until {until:HH:mm}" : "Protection paused");
        StateChanged?.Invoke(this, EventArgs.Empty);
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

        var removed = removeRules ? FirewallManager.RemoveAllPacketHoundRules() : 0;
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
            waiting.Update(c);
            LookUpHostName(waiting);
            if (waiting.IsSnoozed)
            {
                AddActivity(c, app, "Blocked · you chose to decide later");
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

        // A new copy of a program you decided about by signature (e.g. an updater unpacked to a new temp folder).
        var fileName = Path.GetFileName(path);
        if (Settings.SignedCopyRules.Any(r => string.Equals(r.FileName, fileName, StringComparison.OrdinalIgnoreCase)))
        {
            if (!_signatureChecks.Add(path))
            {
                AddActivity(c, app, "Blocked · checking its signature");
                return;
            }
            string? signer;
            try
            {
                signer = await Task.Run(() => Signature.GetVerifiedSigner(path));
            }
            finally
            {
                _signatureChecks.Remove(path);
            }
            if (!Settings.ProtectionEnabled) return;
            if (Settings.SignedCopyRules.FirstOrDefault(r => r.Matches(path, signer)) is { } signedRule && !_pending.ContainsKey(path))
            {
                ApplySignedCopyRule(signedRule, app, c, hostName: null);
                return;
            }
            if (_pending.ContainsKey(path)) return; // asked about while the signature was being checked
        }

        var request = new PendingRequest(app, c);
        _pending[path] = request;
        LookUpHostName(request);
        LookUpSigner(request);
        AddActivity(c, app, "Blocked · waiting for your decision");
        Ask(request);
    }

    /// <summary>
    /// Gives a new copy of a program the decision from a signed-copy rule, as a rule for this copy's path.
    /// <paramref name="inAdvance"/>: made when its file appeared, before it ran (null connection).
    /// </summary>
    void ApplySignedCopyRule(SignedCopyRule rule, AppDetails app, BlockedConnection? c, string? hostName, bool inAdvance = false)
    {
        var path = app.Path;
        // Copies in temp folders are gone after one run, so their rule goes when they quit.
        var temporary = TempFolders.Contains(path);
        try
        {
            FirewallManager.SetAppRule(path, app.DisplayName, rule.Allow, windowsComponent: false, temporary,
                note: $" (copy of {rule.FileName} signed by {rule.Signer})");
            if (temporary) TrackTemporary(path);
            _justDecided[path] = DateTime.UtcNow;
            InvalidateRules();
            AddActivity(c ?? new BlockedConnection(), app,
                inAdvance ? $"{(rule.Allow ? "Allowed" : "Blocked")} in advance · installer/updater you {(rule.Allow ? "allowed" : "blocked")} before"
                : rule.Allow ? "Allowed automatically · installer/updater you allowed before, it may need to retry"
                : "Blocked automatically · installer/updater you blocked before", hostName);
            RulesChanged?.Invoke(this, EventArgs.Empty);
            // Too late to be ready before it connected: an installer has probably given up, so offer the pause.
            if (!inAdvance && rule.Allow && temporary) InstallerAllowed?.Invoke(this, app.DisplayName);
        }
        catch (Exception ex)
        {
            SetError($"Could not create the firewall rule for {app.DisplayName}: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// An .exe appeared in a temp folder. If it's a remembered installer/updater (same file name, and once
    /// it's fully written, a valid signature from the same signer), make its rule now, before it runs.
    /// </summary>
    async void OnTempExeAppeared(string path)
    {
        try
        {
            if (!Settings.ProtectionEnabled) return;
            var fileName = Path.GetFileName(path);
            if (!Settings.SignedCopyRules.Any(r => string.Equals(r.FileName, fileName, StringComparison.OrdinalIgnoreCase))) return;
            if (!_preparing.Add(path)) return;
            try
            {
                var signer = await Task.Run(() => WaitUntilWritten(path) ? Signature.GetVerifiedSigner(path) : null);
                if (!Settings.ProtectionEnabled || signer == null) return;
                if (Settings.SignedCopyRules.FirstOrDefault(r => r.Matches(path, signer)) is not { } rule) return;
                if (Rules().HasDecision(path) || _pending.ContainsKey(path)) return;
                ApplySignedCopyRule(rule, AppDetails.For(path), null, null, inAdvance: true);
            }
            finally
            {
                _preparing.Remove(path);
            }
        }
        catch (Exception ex)
        {
            Log.Error($"Could not prepare a rule for {path}", ex);
        }
    }

    /// <summary>Waits (up to ~10 s) until nothing is writing the file any more. False if it vanished or never finished.</summary>
    static bool WaitUntilWritten(string path)
    {
        for (var i = 0; i < 200; i++)
        {
            try
            {
                // Fails while another handle can still write to the file.
                using (new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete)) return true;
            }
            catch (FileNotFoundException) { return false; }
            catch (DirectoryNotFoundException) { return false; }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { return false; }
            Thread.Sleep(50);
        }
        return false;
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

    /// <summary>Adds or replaces the signed-copy rule for a program, and applies it to matching apps already waiting.</summary>
    void AddSignedCopyRule(PendingRequest request, bool allow)
    {
        var rule = new SignedCopyRule
        {
            FileName = request.FileName, Signer = request.Signer!, DisplayName = request.DisplayName,
            Allow = allow, Created = DateTime.Now,
        };
        Settings.SignedCopyRules.RemoveAll(r => r.Key == rule.Key);
        Settings.SignedCopyRules.Add(rule);
        SaveSettings();
        Log.Info($"Signed-copy rule: {(allow ? "allow" : "block")} {rule.FileName} signed by {rule.Signer}");

        // Other copies already waiting (in the queue or decided later) get the same answer.
        foreach (var waiting in _pending.Values.Where(p => p != request && rule.Matches(p.AppPath, p.Signer)).ToList())
        {
            _queue.Remove(waiting);
            Deferred.Remove(waiting);
            _pending.Remove(waiting.AppPath);
            ApplySignedCopyRule(rule, waiting.App, new BlockedConnection
            {
                RemoteAddress = waiting.RemoteAddress, RemotePort = waiting.RemotePort, ProcessId = waiting.ProcessId,
            }, waiting.HostName);
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
            if (running) Ask(request);
            else request.SnoozedUntil = null;
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
        var addresses = new List<string>();
        foreach (var name in new[] { destination.Target, hostName }.OfType<string>().Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                var lookup = Dns.GetHostAddressesAsync(name);
                if (await Task.WhenAny(lookup, Task.Delay(3000)) == lookup && lookup.IsCompletedSuccessfully)
                    addresses.AddRange(lookup.Result.Select(a => a.ToString()));
            }
            catch
            {
                // Doesn't resolve; addresses get added as the app connects.
            }
        }
        try
        {
            if (addresses.Count > 0 && FirewallManager.AddRemoteAddresses(ruleName, addresses)) NotifyRulesChanged();
        }
        catch (Exception ex)
        {
            Log.Error($"Could not add resolved addresses to rule '{ruleName}'", ex);
        }
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
        var prompt = new PromptWindow(request);
        prompt.SetQueueCount(_queue.Count - 1);
        prompt.Closed += (_, _) =>
        {
            _prompt = null;
            Decide(request, prompt.Decision, prompt.Scope, prompt.UntilQuit);
            ShowNextPrompt();
        };
        _prompt = prompt;
        prompt.Show();
    }

    void Decide(PendingRequest request, PromptDecision decision, ScopeOption? scope, bool untilQuit)
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
            case PromptDecision.Allow:
            case PromptDecision.Block:
                var allow = decision == PromptDecision.Allow;
                var destination = scope?.Destination;
                try
                {
                    if (destination == null)
                    {
                        FirewallManager.SetAppRule(request.AppPath, request.DisplayName, allow, windowsComponent: false, temporary: untilQuit);
                    }
                    else
                    {
                        var ruleName = FirewallManager.SetDestinationRule(request.AppPath, request.DisplayName, allow, destination,
                            new[] { scope!.Address }, untilQuit);
                        if (destination.Scope != RuleScope.Address) AddResolvedAddresses(ruleName, destination, scope.HostName);
                    }
                    if (untilQuit) TrackTemporary(request.AppPath);
                    _justDecided[request.AppPath] = DateTime.UtcNow;
                    InvalidateRules();
                    var what = destination == null ? "this app" : destination.Label;
                    AddActivity(new BlockedConnection
                    {
                        RemoteAddress = request.RemoteAddress, RemotePort = request.RemotePort, ProcessId = request.ProcessId,
                    }, request.App, $"You {(allow ? "allowed" : "blocked")} {what}{(untilQuit ? " until it quits" : "")}", request.HostName);
                    if (request.InTempFolder)
                    {
                        // Installers and updaters unpack to a new temp folder each run: a signed one gets the same
                        // answer next time without asking (same file name and signer).
                        if (destination == null && request.Signer != null) AddSignedCopyRule(request, allow);
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

    public void ShowPrompt() => _prompt?.Activate();

    // ---------------------------------------------------------------- "until the app quits" rules

    void TrackTemporary(string path)
    {
        _temporaryApps[path] = DateTime.UtcNow;
        _temporaryTimer.Start();
    }

    /// <summary>Removes an app's temporary rules once no process of that program is running.</summary>
    void CheckTemporaryRules()
    {
        foreach (var (path, made) in _temporaryApps.ToList())
        {
            try
            {
                if (DateTime.UtcNow - made < TemporaryGrace || RunningPrograms.IsRunning(path)) continue;
                _temporaryApps.Remove(path);
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
                Activity.Insert(0, new ActivityEntry
                {
                    Time = DateTime.Now,
                    AppName = rule.DisplayName,
                    AppPath = rule.ApplicationName,
                    Result = $"Program no longer exists · rule{label} removed",
                });
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

        Activity.Insert(0, new ActivityEntry
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
        while (Activity.Count > MaxActivity) Activity.RemoveAt(Activity.Count - 1);
    }

    void SetError(string message, Exception? ex = null)
    {
        Log.Error(message, ex);
        LastError = message;
        StateChanged?.Invoke(this, EventArgs.Empty);
    }
}

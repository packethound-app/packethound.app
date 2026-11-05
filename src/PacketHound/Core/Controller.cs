using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Net;
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
///        - third-party apps get a prompt, and the answer becomes a permanent Allow/Block rule.
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
    readonly Dictionary<string, PendingRequest> _pending = new(StringComparer.OrdinalIgnoreCase);
    readonly List<PendingRequest> _queue = new();
    readonly Dictionary<string, DateTime> _snoozedUntil = new(StringComparer.OrdinalIgnoreCase);
    readonly HashSet<string> _autoAllowFailed = new(StringComparer.OrdinalIgnoreCase);
    // Apps that just got a rule: events already queued for them are stale and ignored for a moment.
    readonly Dictionary<string, DateTime> _justDecided = new(StringComparer.OrdinalIgnoreCase);
    RuleSnapshot? _snapshot;
    PromptWindow? _prompt;

    public Controller(Dispatcher dispatcher)
    {
        _dispatcher = dispatcher;
        Settings = Settings.Load();
        Updates = new UpdateService(Settings);
        ApplyClassifierSettings();

        _monitor.Blocked += c => _dispatcher.InvokeAsync(() => OnBlocked(c));
        _monitor.Failed += ex => _dispatcher.InvokeAsync(() => SetError("Event monitor error: " + ex.Message, ex));
    }

    public Settings Settings { get; }
    public UpdateService Updates { get; }
    public ObservableCollection<ActivityEntry> Activity { get; } = new();
    public string? LastError { get; private set; }
    public bool ProtectionEnabled => Settings.ProtectionEnabled;
    public int PendingCount => _queue.Count;

    /// <summary>Protection state, error text or pending count changed.</summary>
    public event EventHandler? StateChanged;

    /// <summary>PacketHound rules were added/changed/removed.</summary>
    public event EventHandler? RulesChanged;

    public void Start()
    {
        Updates.Start();
        if (!Settings.ProtectionEnabled) return;
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
        ClearPending();
    }

    // ---------------------------------------------------------------- protection on/off

    public void EnableProtection()
    {
        ApplyProtection();
        Settings.ProtectionEnabled = true;
        Settings.FirstRunCompleted = true;
        Settings.Save();
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
    }

    /// <summary>Lets every app without a rule connect again. Your Block rules keep working.</summary>
    public void PauseProtection()
    {
        _monitor.Stop();
        foreach (var p in FirewallManager.Profiles)
            FirewallManager.SetDefaultOutboundAction(p, FirewallManager.ActionAllow);
        Settings.ProtectionEnabled = false;
        Settings.Save();
        ClearPending();
        Log.Info("Protection paused");
        StateChanged?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>Puts Windows back the way it was before PacketHound (for uninstalling).</summary>
    public int RestoreWindowsDefaults(bool removeRules)
    {
        _monitor.Stop();
        ClearPending();

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

    void OnBlocked(BlockedConnection c)
    {
        if (!Settings.ProtectionEnabled) return;
        if (IPAddress.TryParse(c.RemoteAddress, out var ip) && IPAddress.IsLoopback(ip)) return;

        var path = c.AppPath;
        if (path.StartsWith(@"\device\", StringComparison.OrdinalIgnoreCase))
        {
            Log.Error("Could not map device path " + path);
            return;
        }
        if (_justDecided.TryGetValue(path, out var decidedAt))
        {
            if (DateTime.UtcNow - decidedAt < TimeSpan.FromSeconds(5)) return;
            _justDecided.Remove(path);
        }

        var app = AppDetails.For(path);

        // Already on screen / in the queue: just update the details.
        if (_pending.TryGetValue(path, out var waiting))
        {
            waiting.Update(c);
            LookUpHostName(waiting);
            AddActivity(c, app, "Blocked · waiting for your decision");
            return;
        }

        var rules = Rules();
        if (rules.HasDecision(path))
        {
            AddActivity(c, app, rules.HasAllowRule(path) ? "Blocked by another firewall rule" : "Blocked by your rule");
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

        if (_snoozedUntil.TryGetValue(path, out var until) && until > DateTime.Now)
        {
            AddActivity(c, app, "Blocked · you chose to decide later");
            return;
        }

        var request = new PendingRequest(app, c);
        _pending[path] = request;
        _queue.Add(request);
        LookUpHostName(request);
        AddActivity(c, app, "Blocked · waiting for your decision");
        ShowNextPrompt();
        StateChanged?.Invoke(this, EventArgs.Empty);
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
            Decide(request, prompt.Decision);
            ShowNextPrompt();
        };
        _prompt = prompt;
        prompt.Show();
    }

    void Decide(PendingRequest request, PromptDecision decision)
    {
        if (decision == PromptDecision.Dismiss) return;

        _queue.Remove(request);
        _pending.Remove(request.AppPath);

        switch (decision)
        {
            case PromptDecision.Allow:
            case PromptDecision.Block:
                var allow = decision == PromptDecision.Allow;
                try
                {
                    FirewallManager.SetAppRule(request.AppPath, request.DisplayName, allow, windowsComponent: false);
                    _snoozedUntil.Remove(request.AppPath);
                    _justDecided[request.AppPath] = DateTime.UtcNow;
                    InvalidateRules();
                    AddActivity(new BlockedConnection
                    {
                        RemoteAddress = request.RemoteAddress, RemotePort = request.RemotePort, ProcessId = request.ProcessId,
                    }, request.App, allow ? "You allowed this app" : "You blocked this app", request.HostName);
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

            case PromptDecision.Later:
                _snoozedUntil[request.AppPath] = DateTime.Now.AddMinutes(Math.Max(1, Settings.SnoozeMinutes));
                break;
        }
        StateChanged?.Invoke(this, EventArgs.Empty);
    }

    public void ShowPrompt() => _prompt?.Activate();

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
        _snoozedUntil.Clear();
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

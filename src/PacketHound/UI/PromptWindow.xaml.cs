using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Interop;
using System.Windows.Threading;
using PacketHound.Core;

namespace PacketHound.UI;

public partial class PromptWindow : Window
{
    readonly PendingRequest _request;

    public PromptWindow(PendingRequest request)
    {
        InitializeComponent();
        _request = request;
        DataContext = request;
        UntilQuitItem.Content = $"Until {request.DisplayName} quits";
        if (request.InTempFolder)
        {
            // A copy in a temp folder is gone after this run, so its rule always lasts until it quits.
            TempNote.Visibility = Visibility.Visible;
            DurationBox.SelectedItem = UntilQuitItem;
            DurationBox.Visibility = DurationLabel.Visibility = Visibility.Collapsed;
        }
        if (request.ShowsCommandLine) CommandLabel.Visibility = CommandBox.Visibility = Visibility.Visible;
        BuildScopeOptions();
        UpdateTempNote();
        UpdatePreviousNote();
        _copiedTimer.Tick += (_, _) => { _copiedTimer.Stop(); CopyRun.Text = "Copy"; };
        Closed += (_, _) => _copiedTimer.Stop();
        request.PropertyChanged += OnRequestChanged;
        Closed += (_, _) => request.PropertyChanged -= OnRequestChanged;
        // Not activated on purpose: a prompt popping up mid-typing must not swallow keystrokes.
        SourceInitialized += (_, _) =>
        {
            RemoveCloseButton();
            Flash();
        };
        // The user has to pick Allow, Block or Decide later; Alt+F4 doesn't dismiss the prompt either.
        // PacketHound itself can still close it (Decision = Dismiss), and app shutdown ignores the cancel.
        Closing += (_, e) => e.Cancel = !_finished && Decision != PromptDecision.Dismiss;
    }

    bool _finished;

    /// <summary>What the user chose.</summary>
    public PromptDecision Decision { get; set; } = PromptDecision.Later;

    /// <summary>What the rule covers, as selected when Allow or Block was clicked.</summary>
    public ScopeOption? Scope { get; private set; }

    /// <summary>The rule should be removed when the app quits.</summary>
    public bool UntilQuit { get; private set; }

    /// <summary>A timed rule: when it's removed. Null for other durations.</summary>
    public DateTime? Expires { get; private set; }

    void OnRequestChanged(object? sender, PropertyChangedEventArgs e)
    {
        BuildScopeOptions();
        UpdateTempNote();
        UpdatePreviousNote();
    }

    /// <summary>
    /// When an earlier version of this app (in another versioned folder) has rules: offers to keep them. Not when
    /// the publisher recorded for the earlier version differs from this one's (checked a moment after opening).
    /// </summary>
    void UpdatePreviousNote()
    {
        if (_request.PreviousVersion is not { } previous) return;
        PreviousNote.Visibility = Visibility.Visible;

        var rules = previous.Rules;
        var what = rules.Count == 1 && rules[0].Destination == null
            ? $"You {(rules[0].Allow ? "allowed" : "blocked")} the earlier version ({previous.FolderName}) for any connection."
            : $"You made {rules.Count} rules for the earlier version ({previous.FolderName}): "
              + string.Join(", ", rules.Take(3).Select(r => $"{(r.Allow ? "allow" : "block")} {r.Destination?.Label ?? "any connection"}"))
              + (rules.Count > 3 ? $" and {rules.Count - 3} more." : ".");

        var differentPublisher = previous.Signer != null && _request.SignerChecked && _request.Signer != previous.Signer;
        SameAsBeforeButton.Visibility = differentPublisher ? Visibility.Collapsed : Visibility.Visible;
        PreviousText.Text = "This looks like an update. " + what + (differentPublisher
            ? $" But that one was signed by {previous.Signer}, and this one {(_request.Signer is { } s ? $"by {s}" : "isn't signed")}, so decide again."
            : previous.StillExists ? " That version is still installed, and its rules stay." : " Its rules move to this version.");
    }

    void SameAsBefore_Click(object sender, RoutedEventArgs e) => Finish(PromptDecision.SameAsBefore);

    /// <summary>
    /// For installers and updaters in a temp folder. If a signed one (checked in the background, so this can
    /// change a moment after the prompt opens) is allowed for any connection, future copies are allowed too.
    /// </summary>
    void UpdateTempNote()
    {
        if (!_request.InTempFolder) return;
        var remembered = _request.Signer != null && (ScopeBox.SelectedItem as ScopeOption)?.Destination == null;
        TempText.Text = "This looks like an installer or updater."
                        + (remembered ? " If you allow it, PacketHound will remember that the next time it runs." : "");
    }

    bool _rebuildWhenClosed;

    /// <summary>
    /// Fills "Applies to" with every destination the app has tried while waiting (its IP, and its host and domain
    /// once the name is known), in the order first tried. Rebuilt as attempts and names arrive, but never while
    /// the list is open, and the choice stays on the exact destination picked.
    /// </summary>
    void BuildScopeOptions()
    {
        if (ScopeBox.IsDropDownOpen)
        {
            _rebuildWhenClosed = true;
            return;
        }
        var options = new List<ScopeOption> { new("Any connection", null, "", null) };
        void Add(string label, RuleDestination destination, string address, string? host)
        {
            // Two hosts in one domain offer that domain once.
            if (!options.Any(o => RuleDestination.Same(o.Destination, destination))) options.Add(new(label, destination, address, host));
        }
        foreach (var d in _request.Destinations)
        {
            if (FirewallManager.NormalizeAddress(d.Address) is not { } ip) continue;
            var host = d.HostName?.TrimEnd('.').ToLowerInvariant();
            Add($"Only {ip}", new RuleDestination(RuleScope.Address, ip), ip, host);
            if (host == null) continue;
            Add($"Only {host}", new RuleDestination(RuleScope.Host, host), ip, host);
            if (RuleDestination.DomainOf(host) is { } domain)
                Add($"Only {domain} and its subdomains", new RuleDestination(RuleScope.Domain, domain), ip, host);
        }

        if (ScopeBox.ItemsSource is IEnumerable<ScopeOption> current && current.SequenceEqual(options)) return;
        var picked = (ScopeBox.SelectedItem as ScopeOption)?.Destination;
        ScopeBox.ItemsSource = options;
        ScopeBox.SelectedItem = options.FirstOrDefault(o => RuleDestination.Same(o.Destination, picked)) ?? options[0];
    }

    void Scope_DropDownClosed(object? sender, EventArgs e)
    {
        if (!_rebuildWhenClosed) return;
        _rebuildWhenClosed = false;
        BuildScopeOptions();
    }

    void Options_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (NoteText == null || ScopeBox == null || DurationBox == null || TempText == null) return; // still loading
        UpdateTempNote();

        var text = (ScopeBox.SelectedItem as ScopeOption)?.Destination switch
        {
            null => "Your choice is saved as a Windows Firewall rule for every connection this program makes.",
            { Scope: RuleScope.Address } => "Your choice covers only this IP address. Connections anywhere else will ask again.",
            _ => "Windows Firewall only matches IP addresses, so PacketHound adds this name's addresses to the rule "
                 + "as the program connects to them. Connections anywhere else will ask again.",
        };
        if (DurationBox.SelectedItem == UntilQuitItem && !_request.InTempFolder)
            text += $" The rule is removed when {_request.DisplayName} quits, or when PacketHound exits.";
        else if (ExpiresFor(DurationBox.SelectedItem) is { } expires)
            text += $" The rule is removed at {TimeText.When(expires)}, and PacketHound asks again after that.";
        NoteText.Text = text + " If you allow it, the program may need to retry.";
    }

    // ---------------------------------------------------------------- copying the destination or program

    readonly DispatcherTimer _copiedTimer = new() { Interval = TimeSpan.FromSeconds(2) };

    void CopyLink_Click(object sender, RoutedEventArgs e) => OpenCopyMenu(CopyLink.Parent as UIElement, PlacementMode.Bottom);

    void CopyArea_RightClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        e.Handled = true;
        OpenCopyMenu(sender as UIElement, PlacementMode.MousePoint);
    }

    /// <summary>Built when opened, so it shows the current destination (it changes as more attempts arrive).</summary>
    void OpenCopyMenu(UIElement? target, PlacementMode placement)
    {
        var menu = new ContextMenu { PlacementTarget = target, Placement = placement };
        void Add(string label, string value)
        {
            // A TextBlock header, so underscores in host names aren't taken as access keys.
            var item = new MenuItem { Header = new TextBlock { Text = label } };
            item.Click += (_, _) => Copy(value);
            menu.Items.Add(item);
        }
        if (_request.RemoteAddress.Length > 0) Add($"Copy IP address  ({_request.RemoteAddress})", _request.RemoteAddress);
        if (_request.HostName is { } host) Add($"Copy host name  ({Shorten(host)})", host);
        Add("Copy program path", _request.AppPath);
        if (_request.CommandLine is { } commandLine) Add("Copy command line", commandLine);
        menu.IsOpen = true;
    }

    static string Shorten(string text) => text.Length <= 60 ? text : text[..57] + "…";

    void Copy(string text)
    {
        try
        {
            Clipboard.SetText(text);
            CopyRun.Text = "Copied";
        }
        catch (Exception ex)
        {
            // Another app can hold the clipboard open for a moment.
            Log.Error("Could not copy to the clipboard", ex);
            CopyRun.Text = "Couldn't copy, try again";
        }
        _copiedTimer.Stop();
        _copiedTimer.Start();
    }

    public void SetQueueCount(int othersWaiting)
    {
        QueueText.Text = othersWaiting == 1 ? "1 more app is waiting" : $"{othersWaiting} more apps are waiting";
        QueueText.Visibility = othersWaiting > 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    void Allow_Click(object sender, RoutedEventArgs e) => Finish(PromptDecision.Allow);
    void Block_Click(object sender, RoutedEventArgs e) => Finish(PromptDecision.Block);
    void Later_Click(object sender, RoutedEventArgs e) => Finish(PromptDecision.Later);

    /// <summary>When a timed duration ends, counted from now (a prompt can stay open a while). Null for the others.</summary>
    DateTime? ExpiresFor(object? durationItem) =>
        durationItem == HourItem ? DateTime.Now.AddHours(1)
        : durationItem == TodayItem ? DateTime.Today.AddDays(1).AddMinutes(-1) // 23:59: the end of today
        : null;

    void Finish(PromptDecision decision)
    {
        Decision = decision;
        Scope = ScopeBox.SelectedItem as ScopeOption;
        UntilQuit = DurationBox.SelectedItem == UntilQuitItem;
        Expires = ExpiresFor(DurationBox.SelectedItem);
        _finished = true;
        Close();
    }

    /// <summary>Drops the title bar's system menu, which removes the X (and the icon) from the title bar.</summary>
    void RemoveCloseButton()
    {
        const int GWL_STYLE = -16, WS_SYSMENU = 0x80000;
        var hwnd = new WindowInteropHelper(this).Handle;
        SetWindowLong(hwnd, GWL_STYLE, GetWindowLong(hwnd, GWL_STYLE) & ~WS_SYSMENU);
    }

    [DllImport("user32.dll")]
    static extern int GetWindowLong(IntPtr hWnd, int nIndex);

    [DllImport("user32.dll")]
    static extern int SetWindowLong(IntPtr hWnd, int nIndex, int dwNewLong);

    void Flash()
    {
        var info = new FLASHWINFO
        {
            cbSize = (uint)Marshal.SizeOf<FLASHWINFO>(),
            hwnd = new WindowInteropHelper(this).Handle,
            dwFlags = 0x3 | 0xC, // FLASHW_ALL | FLASHW_TIMERNOFG
        };
        FlashWindowEx(ref info);
    }

    [StructLayout(LayoutKind.Sequential)]
    struct FLASHWINFO
    {
        public uint cbSize;
        public IntPtr hwnd;
        public uint dwFlags;
        public uint uCount;
        public uint dwTimeout;
    }

    [DllImport("user32.dll")]
    static extern bool FlashWindowEx(ref FLASHWINFO pwfi);
}

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
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
        BuildScopeOptions();
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

    void OnRequestChanged(object? sender, PropertyChangedEventArgs e) => BuildScopeOptions();

    /// <summary>
    /// Fills "Applies to" from the current destination. Rebuilt when the destination or its host name
    /// changes; the kind of choice (IP, host, domain) the user picked is kept.
    /// </summary>
    void BuildScopeOptions()
    {
        var r = _request;
        var ip = FirewallManager.NormalizeAddress(r.RemoteAddress);
        var options = new List<ScopeOption> { new("Any connection", null, r.RemoteAddress, r.HostName) };
        if (ip != null)
        {
            options.Add(new($"Only {ip}", new RuleDestination(RuleScope.Address, ip), ip, r.HostName));
            if (r.HostName is { } name)
            {
                var host = name.TrimEnd('.').ToLowerInvariant();
                options.Add(new($"Only {host}", new RuleDestination(RuleScope.Host, host), ip, host));
                if (RuleDestination.DomainOf(host) is { } domain)
                    options.Add(new($"Only {domain} and its subdomains", new RuleDestination(RuleScope.Domain, domain), ip, host));
            }
        }

        if (ScopeBox.ItemsSource is IEnumerable<ScopeOption> current && current.SequenceEqual(options)) return;
        var picked = (ScopeBox.SelectedItem as ScopeOption)?.Destination?.Scope; // null = Any connection
        ScopeBox.ItemsSource = options;
        ScopeBox.SelectedItem = options.FirstOrDefault(o => o.Destination?.Scope == picked) ?? options[0];
    }

    void Options_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (NoteText == null || ScopeBox == null || DurationBox == null) return; // still loading

        var text = (ScopeBox.SelectedItem as ScopeOption)?.Destination switch
        {
            null => "Your choice is saved as a Windows Firewall rule for every connection this program makes.",
            { Scope: RuleScope.Address } => "Your choice covers only this IP address. Connections anywhere else will ask again.",
            _ => "Windows Firewall only matches IP addresses, so PacketHound adds this name's addresses to the rule "
                 + "as the program connects to them. Connections anywhere else will ask again.",
        };
        if (DurationBox.SelectedItem == UntilQuitItem)
            text += $" The rule is removed when {_request.DisplayName} quits, or when PacketHound exits.";
        NoteText.Text = text + " If you allow it, the program may need to retry.";
    }

    public void SetQueueCount(int othersWaiting)
    {
        QueueText.Text = othersWaiting == 1 ? "1 more app is waiting" : $"{othersWaiting} more apps are waiting";
        QueueText.Visibility = othersWaiting > 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    void Allow_Click(object sender, RoutedEventArgs e) => Finish(PromptDecision.Allow);
    void Block_Click(object sender, RoutedEventArgs e) => Finish(PromptDecision.Block);
    void Later_Click(object sender, RoutedEventArgs e) => Finish(PromptDecision.Later);

    void Finish(PromptDecision decision)
    {
        Decision = decision;
        Scope = ScopeBox.SelectedItem as ScopeOption;
        UntilQuit = DurationBox.SelectedItem == UntilQuitItem;
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

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using PacketHound.Core;

namespace PacketHound.UI;

public partial class MainWindow : Window
{
    readonly Controller _controller;
    readonly GridSorting _rulesSort;
    readonly GridSorting _activitySort;
    readonly DispatcherTimer _copiedTimer = new() { Interval = TimeSpan.FromSeconds(3) };
    ICollectionView? _rulesView;

    public MainWindow(Controller controller)
    {
        InitializeComponent();
        Title = $"PacketHound v{UpdateService.CurrentVersion}";
        _controller = controller;
        RestorePlacement();
        StateChanged += (_, _) => { if (WindowState != WindowState.Minimized) _maximized = WindowState == WindowState.Maximized; };
        Closing += (_, _) => SavePlacement();

        var cellText = (Style)FindResource("CellText");
        foreach (var column in RulesGrid.Columns.Concat(ActivityGrid.Columns).OfType<DataGridTextColumn>())
            column.ElementStyle = cellText;

        _rulesSort = new GridSorting(RulesGrid, controller.Settings, "Rules", new SortSetting("CreatedDate", Descending: true));
        _activitySort = new GridSorting(ActivityGrid, controller.Settings, "Activity", new SortSetting("Time", Descending: true));
        ActivityGrid.ItemsSource = controller.Activity;
        _activitySort.Apply();
        DeferredList.ItemsSource = controller.Deferred;

        _copiedTimer.Tick += (_, _) => { _copiedTimer.Stop(); CopiedText.Visibility = Visibility.Collapsed; };

        controller.StateChanged += OnStateChanged;
        controller.RulesChanged += OnRulesChanged;
        controller.Updates.Changed += OnUpdatesChanged;
        Closed += (_, _) =>
        {
            controller.StateChanged -= OnStateChanged;
            controller.RulesChanged -= OnRulesChanged;
            controller.Updates.Changed -= OnUpdatesChanged;
        };

        Reload();
    }

    public void Reload()
    {
        StoreAppsAsWindows.IsChecked = _controller.Settings.TreatMicrosoftStoreAppsAsWindows;
        AskForTools.IsChecked = _controller.Settings.AskForScriptingTools;
        CheckForUpdates.IsChecked = _controller.Settings.CheckForUpdates;
        UpdateUpdates();
        try { StartAtLogon.IsChecked = AutoStart.IsEnabled(); } catch { StartAtLogon.IsChecked = false; }
        UpdateStatus();
        LoadRules();
    }

    // ---------------------------------------------------------------- window size and position

    // Maximized the last time it wasn't minimized, so closing while minimized remembers it.
    bool _maximized;

    void RestorePlacement()
    {
        if (_controller.Settings.MainWindowPlacement is not { } p) return;
        Width = Math.Max(MinWidth, p.Width);
        Height = Math.Max(MinHeight, p.Height);

        // Only reuse the position if the title bar would be on screen (a monitor may have been unplugged).
        var screen = new Rect(SystemParameters.VirtualScreenLeft, SystemParameters.VirtualScreenTop,
            SystemParameters.VirtualScreenWidth, SystemParameters.VirtualScreenHeight);
        var titleBar = new Rect(p.Left + 40, p.Top, Math.Max(0, Width - 80), 30);
        if (screen.IntersectsWith(titleBar))
        {
            WindowStartupLocation = WindowStartupLocation.Manual;
            Left = p.Left;
            Top = p.Top;
        }
        if (p.Maximized) WindowState = WindowState.Maximized;
        _maximized = p.Maximized;
    }

    void SavePlacement()
    {
        var bounds = WindowState == WindowState.Normal ? new Rect(Left, Top, ActualWidth, ActualHeight) : RestoreBounds;
        if (bounds.IsEmpty || bounds.Width <= 0 || bounds.Height <= 0) return;
        _controller.Settings.MainWindowPlacement = new WindowPlacement(bounds.Left, bounds.Top, bounds.Width, bounds.Height, _maximized);
        try
        {
            _controller.Settings.Save();
        }
        catch (Exception ex)
        {
            Log.Error("Could not save the window size", ex);
        }
    }

    void OnStateChanged(object? s, EventArgs e) => UpdateStatus();
    void OnRulesChanged(object? s, EventArgs e) => LoadRules();

    // ---------------------------------------------------------------- status

    void UpdateStatus()
    {
        var on = _controller.ProtectionEnabled;
        var until = _controller.PausedUntil;
        StatusDot.Fill = (System.Windows.Media.Brush)FindResource(on ? "Success" : "Warning");
        StatusTitle.Text = on ? "Protection is on" : until is { } t ? $"Protection is paused until {t:t}" : "Protection is paused";
        StatusDetail.Text = on
            ? "Apps you haven't decided about yet are blocked, and PacketHound asks you about them. Windows itself is allowed automatically."
            : "Apps without a rule can connect freely. Your Block rules still apply."
              + (until != null ? " Protection turns back on by itself." : "");
        ToggleButton.Content = on ? "Pause protection ▾" : "Turn protection on";
        ToggleButton.Style = (Style)FindResource(on ? "BaseButton" : "PrimaryButton");

        var disabled = _controller.DisabledFirewallProfiles();
        var error = _controller.LastError;
        if (disabled.Count > 0)
            error = $"Windows Firewall is turned off for the {string.Join(", ", disabled)} profile(s), so nothing can be filtered there. Turn it on in Windows Security. "
                    + (error ?? "");
        ErrorText.Text = error ?? "";
        ErrorText.Visibility = string.IsNullOrWhiteSpace(error) ? Visibility.Collapsed : Visibility.Visible;

        var pending = _controller.PendingCount;
        PendingRun.Text = pending == 1 ? "1 app is waiting for your decision" : $"{pending} apps are waiting for your decision";
        PendingText.Visibility = pending > 0 ? Visibility.Visible : Visibility.Collapsed;

        var deferred = _controller.Deferred.Count;
        DeferredRun.Text = deferred == 1 ? "1 app you chose to decide later" : $"{deferred} apps you chose to decide later";
        DeferredText.Visibility = deferred > 0 ? Visibility.Visible : Visibility.Collapsed;
        DeferredPanel.Visibility = DeferredText.Visibility;

        try
        {
            FirewallInfo.Text = string.Join("    ", FirewallManager.Profiles.Select(p =>
                $"{FirewallManager.ProfileName(p)}: {(FirewallManager.IsFirewallEnabled(p) ? "on" : "OFF")}, outbound default {(FirewallManager.GetDefaultOutboundAction(p) == FirewallManager.ActionBlock ? "block" : "allow")}"));
        }
        catch (Exception ex)
        {
            FirewallInfo.Text = "Could not read firewall state: " + ex.Message;
        }
    }

    void Toggle_Click(object sender, RoutedEventArgs e)
    {
        if (!_controller.ProtectionEnabled)
        {
            ChangeProtection(() => _controller.EnableProtection());
            return;
        }

        // Pausing: pick how long.
        var menu = new ContextMenu { PlacementTarget = ToggleButton, Placement = PlacementMode.Bottom };
        foreach (var (label, duration) in Controller.PauseChoices)
        {
            var item = new MenuItem { Header = label };
            item.Click += (_, _) => ChangeProtection(() => _controller.PauseProtection(duration));
            menu.Items.Add(item);
        }
        menu.IsOpen = true;
    }

    void ChangeProtection(Action change)
    {
        try
        {
            using (new WaitCursor()) change();
        }
        catch (Exception ex)
        {
            ShowError("Could not change protection", ex);
        }
        UpdateStatus();
        LoadRules();
    }

    void ShowPrompt_Click(object sender, RoutedEventArgs e) => _controller.ShowPrompt();
    void ShowDeferred_Click(object sender, RoutedEventArgs e) => ShowDeferred();

    /// <summary>Switches to the Rules tab, where the "decide later" apps are listed.</summary>
    public void ShowDeferred() => Tabs.SelectedItem = RulesTab;

    void DecideNow_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { DataContext: PendingRequest request })
            _controller.DecideNow(request.AppPath);
    }

    // ---------------------------------------------------------------- rules

    void LoadRules()
    {
        try
        {
            var selected = RulesGrid.SelectedItems.Cast<RuleRow>().Select(r => r.Name).ToHashSet();
            var programs = new Dictionary<string, ProgramState>(StringComparer.OrdinalIgnoreCase);
            var rows = FirewallManager.GetPacketHoundRules().Select(r => new RuleRow
            {
                Rule = r,
                Program = programs.TryGetValue(r.ApplicationName, out var state)
                    ? state : programs[r.ApplicationName] = ProgramPresence.Check(r.ApplicationName),
            }).ToList();
            rows.AddRange(_controller.SignedCopyRules.Select(s => new RuleRow { SignedCopy = s }));
            RulesGrid.ItemsSource = rows;
            _rulesView = CollectionViewSource.GetDefaultView(rows);
            _rulesView.Filter = FilterRule;
            _rulesSort.Apply();
            foreach (var row in rows.Where(r => selected.Contains(r.Name)))
                RulesGrid.SelectedItems.Add(row);
            UpdateRemoveMissing();
        }
        catch (Exception ex)
        {
            ShowError("Could not read firewall rules", ex);
        }
    }

    bool FilterRule(object o)
    {
        var row = (RuleRow)o;
        if (row.IsWindowsAuto && ShowWindowsRules.IsChecked != true) return false;
        var q = SearchBox.Text.Trim();
        return q.Length == 0
               || row.AppName.Contains(q, StringComparison.CurrentCultureIgnoreCase)
               || row.Path.Contains(q, StringComparison.CurrentCultureIgnoreCase)
               || row.AppliesTo.Contains(q, StringComparison.CurrentCultureIgnoreCase);
    }

    void Search_TextChanged(object sender, TextChangedEventArgs e) => RefreshRulesView();
    void Filter_Changed(object sender, RoutedEventArgs e) => RefreshRulesView();

    void RefreshRulesView()
    {
        _rulesView?.Refresh();
        UpdateRemoveMissing();
    }

    /// <summary>Rules on screen (after search and filter) whose program is gone.</summary>
    List<RuleRow> VisibleMissingRules() =>
        _rulesView?.Cast<RuleRow>().Where(r => r.IsMissing).ToList() ?? new List<RuleRow>();

    void UpdateRemoveMissing()
    {
        var count = VisibleMissingRules().Count;
        RemoveMissingButton.Content = $"Remove missing ({count})";
        RemoveMissingButton.Visibility = count > 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    void RemoveMissing_Click(object sender, RoutedEventArgs e)
    {
        var rows = VisibleMissingRules();
        if (rows.Count == 0) return;
        const int listed = 10;
        var list = string.Join("\n", rows.Take(listed).Select(r => $"•  {r.AppName}  ({r.Path})"));
        if (rows.Count > listed) list += $"\n…and {rows.Count - listed} more";
        var what = rows.Count == 1 ? "the rule for a program that is" : $"{rows.Count} rules for programs that are";
        if (MessageBox.Show(this, $"Delete {what} no longer on this PC?\n\n{list}\n\nIf you reinstall one, PacketHound will ask about it again.",
                "Remove missing programs", MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK) return;
        try
        {
            _controller.RemoveMissingProgramRules(rows.Select(r => r.Rule).OfType<FirewallRuleInfo>());
        }
        catch (Exception ex)
        {
            ShowError("Could not delete all of the rules", ex);
        }
    }
    void Refresh_Click(object sender, RoutedEventArgs e) { _controller.InvalidateRules(); LoadRules(); UpdateStatus(); }

    void Allow_Click(object sender, RoutedEventArgs e) => ChangeSelected(allow: true);
    void Block_Click(object sender, RoutedEventArgs e) => ChangeSelected(allow: false);

    static T? FindAncestor<T>(object source) where T : DependencyObject
    {
        // Text elements such as a Run inside a TextBlock aren't visuals; walk them via the logical tree.
        for (var d = source as DependencyObject; d != null;
             d = d is Visual ? VisualTreeHelper.GetParent(d) : LogicalTreeHelper.GetParent(d))
            if (d is T match) return match;
        return null;
    }

    void RuleSwitch_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not CheckBox { DataContext: RuleRow row } box) return;
        try
        {
            SetAction(row, allow: box.IsChecked == true);
        }
        catch (Exception ex)
        {
            ShowError("Could not change the rule", ex);
        }
        _controller.NotifyRulesChanged();
    }

    void ChangeSelected(bool allow)
    {
        var rows = RulesGrid.SelectedItems.Cast<RuleRow>().ToList();
        if (rows.Count == 0) return;
        try
        {
            foreach (var row in rows) SetAction(row, allow);
        }
        catch (Exception ex)
        {
            ShowError("Could not change the rule", ex);
        }
        _controller.NotifyRulesChanged();
    }

    void SetAction(RuleRow row, bool allow)
    {
        if (row.SignedCopy != null) _controller.SetSignedCopyAction(row.SignedCopy.Key, allow);
        else FirewallManager.ChangeRuleAction(row.Name, allow);
    }

    void Delete_Click(object sender, RoutedEventArgs e)
    {
        var rows = RulesGrid.SelectedItems.Cast<RuleRow>().ToList();
        if (rows.Count == 0) return;
        var what = rows.Count == 1 ? $"the rule for {rows[0].AppName}" : $"{rows.Count} rules";
        if (MessageBox.Show(this, $"Delete {what}? PacketHound will ask again the next time the app connects.",
                "Delete rules", MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK) return;
        try
        {
            foreach (var row in rows)
            {
                if (row.SignedCopy != null) _controller.RemoveSignedCopyRule(row.SignedCopy.Key);
                else FirewallManager.RemoveRule(row.Name);
            }
        }
        catch (Exception ex)
        {
            ShowError("Could not delete the rule", ex);
        }
        _controller.NotifyRulesChanged();
    }

    void ClearActivity_Click(object sender, RoutedEventArgs e) => _controller.Activity.Clear();

    void ActivityGrid_DoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (FindAncestor<DataGridRow>(e.OriginalSource)?.Item is ActivityEntry entry) CopyAddress(entry);
    }

    void ActivityGrid_ContextMenuOpening(object sender, ContextMenuEventArgs e)
    {
        // Act on the row under the mouse; no menu outside the rows.
        if (FindAncestor<DataGridRow>(e.OriginalSource) is not { Item: ActivityEntry entry } row)
        {
            e.Handled = true;
            return;
        }
        if (!row.IsSelected)
        {
            ActivityGrid.SelectedItems.Clear();
            row.IsSelected = true;
        }
        DecideNowItem.IsEnabled = _controller.IsUndecided(entry.AppPath);
        CopyAddressItem.IsEnabled = entry.RemoteAddress.Length > 0;
    }

    void ActivityDecideNow_Click(object sender, RoutedEventArgs e)
    {
        if (ActivityGrid.SelectedItem is ActivityEntry entry) _controller.DecideNow(entry.AppPath);
    }

    void ActivityCopy_Click(object sender, RoutedEventArgs e)
    {
        if (ActivityGrid.SelectedItem is ActivityEntry entry) CopyAddress(entry);
    }

    void CopyAddress(ActivityEntry entry)
    {
        if (entry.RemoteAddress.Length == 0) return;
        try
        {
            Clipboard.SetText(entry.RemoteAddress);
            CopiedText.Text = $"Copied {entry.RemoteAddress}";
        }
        catch (Exception ex)
        {
            // Another app can hold the clipboard open for a moment.
            Log.Error("Could not copy to the clipboard", ex);
            CopiedText.Text = "Couldn't copy, try again";
        }
        CopiedText.Visibility = Visibility.Visible;
        _copiedTimer.Stop();
        _copiedTimer.Start();
    }

    // ---------------------------------------------------------------- settings

    void StartAtLogon_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            if (StartAtLogon.IsChecked == true) AutoStart.Enable();
            else AutoStart.Disable();
        }
        catch (Exception ex)
        {
            ShowError("Could not change the startup task", ex);
        }
        try { StartAtLogon.IsChecked = AutoStart.IsEnabled(); } catch { }
    }

    void OnUpdatesChanged(object? s, EventArgs e) => UpdateUpdates();

    void UpdateUpdates()
    {
        var updates = _controller.Updates;
        var available = updates.Available;

        UpdateBanner.Visibility = available != null ? Visibility.Visible : Visibility.Collapsed;
        if (available != null) UpdateBannerRun.Text = $"PacketHound {available.Version} is available. ";
        DownloadUpdateButton.Visibility = UpdateBanner.Visibility;

        CheckNowButton.IsEnabled = !updates.IsChecking;
        UpdateCheckText.Text = updates.Status.Length > 0
            ? updates.Status
            : $"Version {UpdateService.CurrentVersion}."
              + (_controller.Settings.LastUpdateCheckUtc is { } last ? $" Last checked {last.ToLocalTime():g}." : "");
    }

    async void CheckNow_Click(object sender, RoutedEventArgs e) => await _controller.Updates.CheckAsync(manual: true);

    void DownloadUpdate_Click(object sender, RoutedEventArgs e)
    {
        try { UpdateService.OpenDownloadPage(); }
        catch (Exception ex) { ShowError("Could not open the download page", ex); }
    }

    void CheckForUpdates_Click(object sender, RoutedEventArgs e)
    {
        _controller.Settings.CheckForUpdates = CheckForUpdates.IsChecked == true;
        _controller.Settings.Save();
    }

    void ClassifierSetting_Click(object sender, RoutedEventArgs e)
    {
        _controller.Settings.TreatMicrosoftStoreAppsAsWindows = StoreAppsAsWindows.IsChecked == true;
        _controller.Settings.AskForScriptingTools = AskForTools.IsChecked == true;
        _controller.Settings.Save();
        _controller.ApplyClassifierSettings();
    }

    void OpenWfMsc_Click(object sender, RoutedEventArgs e) =>
        Process.Start(new ProcessStartInfo("wf.msc") { UseShellExecute = true });

    void OpenLogs_Click(object sender, RoutedEventArgs e)
    {
        System.IO.Directory.CreateDirectory(Settings.DataDirectory);
        Process.Start(new ProcessStartInfo("explorer.exe", $"\"{Settings.DataDirectory}\"") { UseShellExecute = true });
    }

    void RestoreKeep_Click(object sender, RoutedEventArgs e) => Restore(removeRules: false);
    void RestoreRemove_Click(object sender, RoutedEventArgs e) => Restore(removeRules: true);

    void Restore(bool removeRules)
    {
        var msg = "This turns PacketHound's protection off and puts Windows Firewall's outbound default and audit settings back to how they were before PacketHound"
                  + (removeRules ? ", and deletes every rule PacketHound created." : ". Your PacketHound rules stay in Windows Firewall.");
        if (MessageBox.Show(this, msg + "\n\nContinue?", "Restore Windows defaults", MessageBoxButton.OKCancel,
                MessageBoxImage.Warning) != MessageBoxResult.OK) return;
        try
        {
            int removed;
            using (new WaitCursor()) removed = _controller.RestoreWindowsDefaults(removeRules);
            StartAtLogon.IsChecked = false;
            MessageBox.Show(this, removeRules ? $"Done. {removed} rules removed." : "Done.", "PacketHound",
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            ShowError("Could not restore the defaults", ex);
        }
        UpdateStatus();
        LoadRules();
    }

    void ShowError(string what, Exception ex)
    {
        Log.Error(what, ex);
        MessageBox.Show(this, $"{what}.\n\n{ex.Message}", "PacketHound", MessageBoxButton.OK, MessageBoxImage.Error);
    }

    sealed class WaitCursor : IDisposable
    {
        public WaitCursor() => Mouse.OverrideCursor = Cursors.Wait;
        public void Dispose() => Mouse.OverrideCursor = null;
    }
}

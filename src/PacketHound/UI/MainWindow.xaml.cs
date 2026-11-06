using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
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

        var cellText = (Style)FindResource("CellText");
        foreach (var column in RulesGrid.Columns.Concat(ActivityGrid.Columns).OfType<DataGridTextColumn>())
            column.ElementStyle = cellText;

        _rulesSort = new GridSorting(RulesGrid, controller.Settings, "Rules", new SortSetting("CreatedDate", Descending: true));
        _activitySort = new GridSorting(ActivityGrid, controller.Settings, "Activity", new SortSetting("Time", Descending: true));
        ActivityGrid.ItemsSource = controller.Activity;
        _activitySort.Apply();

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

    void OnStateChanged(object? s, EventArgs e) => UpdateStatus();
    void OnRulesChanged(object? s, EventArgs e) => LoadRules();

    // ---------------------------------------------------------------- status

    void UpdateStatus()
    {
        var on = _controller.ProtectionEnabled;
        StatusDot.Fill = (System.Windows.Media.Brush)FindResource(on ? "Success" : "Warning");
        StatusTitle.Text = on ? "Protection is on" : "Protection is paused";
        StatusDetail.Text = on
            ? "Apps you haven't decided about yet are blocked, and PacketHound asks you about them. Windows itself is allowed automatically."
            : "Apps without a rule can connect freely. Your Block rules still apply.";
        ToggleButton.Content = on ? "Pause protection" : "Turn protection on";
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
        try
        {
            using (new WaitCursor())
            {
                if (_controller.ProtectionEnabled) _controller.PauseProtection();
                else _controller.EnableProtection();
            }
        }
        catch (Exception ex)
        {
            ShowError("Could not change protection", ex);
        }
        UpdateStatus();
        LoadRules();
    }

    void ShowPrompt_Click(object sender, RoutedEventArgs e) => _controller.ShowPrompt();

    // ---------------------------------------------------------------- rules

    void LoadRules()
    {
        try
        {
            var selected = RulesGrid.SelectedItems.Cast<RuleRow>().Select(r => r.Name).ToHashSet();
            var rows = FirewallManager.GetPacketHoundRules().Select(r => new RuleRow { Rule = r }).ToList();
            RulesGrid.ItemsSource = rows;
            _rulesView = CollectionViewSource.GetDefaultView(rows);
            _rulesView.Filter = FilterRule;
            _rulesSort.Apply();
            foreach (var row in rows.Where(r => selected.Contains(r.Name)))
                RulesGrid.SelectedItems.Add(row);
        }
        catch (Exception ex)
        {
            ShowError("Could not read firewall rules", ex);
        }
    }

    bool FilterRule(object o)
    {
        var row = (RuleRow)o;
        if (row.Rule.IsWindowsAuto && ShowWindowsRules.IsChecked != true) return false;
        var q = SearchBox.Text.Trim();
        return q.Length == 0
               || row.AppName.Contains(q, StringComparison.CurrentCultureIgnoreCase)
               || row.Path.Contains(q, StringComparison.CurrentCultureIgnoreCase)
               || row.AppliesTo.Contains(q, StringComparison.CurrentCultureIgnoreCase);
    }

    void Search_TextChanged(object sender, TextChangedEventArgs e) => _rulesView?.Refresh();
    void Filter_Changed(object sender, RoutedEventArgs e) => _rulesView?.Refresh();
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
            FirewallManager.ChangeRuleAction(row.Name, allow: box.IsChecked == true);
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
            foreach (var row in rows) FirewallManager.ChangeRuleAction(row.Name, allow);
        }
        catch (Exception ex)
        {
            ShowError("Could not change the rule", ex);
        }
        _controller.NotifyRulesChanged();
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
            foreach (var row in rows) FirewallManager.RemoveRule(row.Name);
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
        if (FindAncestor<DataGridRow>(e.OriginalSource)?.Item is not ActivityEntry entry || entry.RemoteAddress.Length == 0) return;
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

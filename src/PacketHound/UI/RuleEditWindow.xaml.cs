using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Windows;
using System.Windows.Controls;
using PacketHound.Core;

namespace PacketHound.UI;

/// <summary>
/// Changes a rule from the Rules tab: Allow or Block, what it applies to (any connection, an IP, a host or a domain),
/// and whether an "until the app quits" rule should stay. Saving goes through <see cref="Controller.EditRuleAsync"/>.
/// </summary>
public partial class RuleEditWindow : Window
{
    readonly Controller _controller;
    readonly FirewallRuleInfo _rule;
    readonly List<FirewallRuleInfo> _otherRules;
    readonly string _appName;
    // What's typed for each kind of destination, kept while switching between them.
    readonly Dictionary<RuleScope, string> _targets = new();
    RuleScope? _shownScope;
    bool _loading = true;
    bool _saving;

    /// <param name="appRules">All of the app's PacketHound rules, this one included.</param>
    public RuleEditWindow(Controller controller, FirewallRuleInfo rule, IEnumerable<FirewallRuleInfo> appRules)
    {
        InitializeComponent();
        _controller = controller;
        _rule = rule;
        _otherRules = appRules.Where(r => r.Name != rule.Name).ToList();

        var app = AppDetails.For(rule.ApplicationName);
        _appName = app.DisplayName;
        AppIcon.Source = app.Icon;
        AppNameText.Text = app.DisplayName;
        AppPathText.Text = rule.ApplicationName;

        var d = rule.Destination;
        _targets[RuleScope.Address] = d?.Scope == RuleScope.Address ? d.Target : rule.Addresses.Count == 1 ? rule.Addresses.First() : "";
        _targets[RuleScope.Host] = d?.Scope is RuleScope.Host or RuleScope.Domain ? d.Target : "";
        _targets[RuleScope.Domain] = d?.Scope switch
        {
            RuleScope.Domain => d.Target,
            RuleScope.Host => RuleDestination.DomainOf(d.Target) ?? d.Target,
            _ => "",
        };

        ActionBox.SelectedIndex = rule.Allow ? 0 : 1;
        ScopeBox.SelectedIndex = d == null ? 0 : (int)d.Scope + 1;
        ShowTarget();

        // A copy in a temp folder is gone after this run, so its rule can't usefully stay.
        if (rule.IsTemporary && !TempFolders.Contains(rule.ApplicationName))
        {
            KeepBox.Content = $"Keep this rule after {_appName} quits";
            KeepBox.Visibility = Visibility.Visible;
        }
        else if (rule.Expires is { } expires)
        {
            KeepBox.Content = $"Keep this rule after {TimeText.When(expires)}";
            KeepBox.Visibility = Visibility.Visible;
        }

        if (d?.Scope is RuleScope.Host or RuleScope.Domain)
        {
            AddressesTitle.Text = rule.Addresses.Count == 1
                ? "1 IP address collected for this name so far:"
                : $"{rule.Addresses.Count} IP addresses collected for this name so far:";
            AddressesList.ItemsSource = rule.Addresses
                .OrderBy(a => a.Contains(':') ? 1 : 0)
                .ThenBy(a => Convert.ToHexString(IPAddress.Parse(a).GetAddressBytes()))
                .ToList();
            AddressesPanel.Visibility = Visibility.Visible;
        }

        // An IP rule: suggest its name in case the user widens it to the host or domain.
        if (d?.Scope == RuleScope.Address) SuggestName(d.Target);

        Closing += (_, e) => e.Cancel = _saving;
        _loading = false;
        Refresh();
        Loaded += (_, _) => ((Control)(TargetBox.IsVisible ? TargetBox : ActionBox)).Focus();
    }

    /// <summary>The name saved; set when the dialog closes with Save.</summary>
    public string? SavedRuleName { get; private set; }

    RuleScope? SelectedScope => ScopeBox.SelectedIndex <= 0 ? null : (RuleScope)(ScopeBox.SelectedIndex - 1);

    async void SuggestName(string ip)
    {
        try
        {
            if (await HostNames.LookupAsync(ip) is not { } found) return;
            var name = found.TrimEnd('.').ToLowerInvariant();
            Suggest(RuleScope.Host, name);
            Suggest(RuleScope.Domain, RuleDestination.DomainOf(name) ?? name);
        }
        catch (Exception ex)
        {
            Log.Error($"Could not look up the name for {ip}", ex);
        }
    }

    /// <summary>Fills in a destination the user hasn't typed anything for yet.</summary>
    void Suggest(RuleScope scope, string text)
    {
        if (_targets[scope].Trim().Length > 0) return;
        _targets[scope] = text;
        if (_shownScope == scope) TargetBox.Text = text;
    }

    void Scope_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (_loading) return;
        ShowTarget();
        Refresh();
    }

    void ShowTarget()
    {
        _shownScope = SelectedScope;
        var visibility = _shownScope == null ? Visibility.Collapsed : Visibility.Visible;
        TargetLabel.Visibility = TargetBox.Visibility = visibility;
        if (_shownScope is not { } scope) return;
        TargetLabel.Text = scope switch { RuleScope.Address => "IP address", RuleScope.Host => "Host name", _ => "Domain" };
        TargetBox.Text = _targets[scope];
    }

    void Target_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (_shownScope is { } scope) _targets[scope] = TargetBox.Text;
        Refresh();
    }

    void Option_Changed(object sender, RoutedEventArgs e) => Refresh();

    /// <summary>The rule as currently filled in; null while the destination isn't valid.</summary>
    RuleEdit? CurrentEdit(out string? error)
    {
        error = null;
        RuleDestination? destination = null;
        if (SelectedScope is { } scope && (destination = RuleDestination.Parse(scope, TargetBox.Text, out error)) == null) return null;
        var keep = KeepBox.IsChecked == true;
        return new RuleEdit(ActionBox.SelectedIndex == 0, destination, _rule.IsTemporary && !keep, keep ? null : _rule.Expires);
    }

    bool IsChange(RuleEdit edit) =>
        edit.Allow != _rule.Allow || edit.Temporary != _rule.IsTemporary || edit.Expires != _rule.Expires
        || !RuleDestination.Same(edit.Destination, _rule.Destination);

    void Refresh()
    {
        if (_loading) return;
        var edit = CurrentEdit(out var error);
        TargetError.Text = error ?? "";
        TargetError.Visibility = error != null ? Visibility.Visible : Visibility.Collapsed;
        SaveError.Visibility = Visibility.Collapsed;
        SaveButton.IsEnabled = edit != null && IsChange(edit);

        NoteText.Text = edit == null ? "" : Describe(edit);
        var warnings = edit == null || !IsChange(edit) ? new List<string>() : Warnings(edit);
        WarningText.Text = string.Join("\n\n", warnings);
        WarningBox.Visibility = warnings.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    string Describe(RuleEdit edit)
    {
        var text = edit.Destination?.Scope switch
        {
            null => $"Covers every connection {_appName} makes.",
            RuleScope.Address => "Covers only this IP address. Connections anywhere else will ask again.",
            _ => "Windows Firewall only matches IP addresses, so PacketHound looks up this name's addresses when you save, "
                 + "and adds new ones as the program connects to them. Connections anywhere else will ask again.",
        };
        if (edit.Temporary) text += $" The rule is removed when {_appName} quits, or when PacketHound exits.";
        else if (edit.Expires is { } expires) text += $" The rule is removed at {TimeText.When(expires)}.";
        return text;
    }

    List<string> Warnings(RuleEdit edit)
    {
        var warnings = new List<string>();
        if (_rule.IsWindowsAuto)
            warnings.Add("This rule was made automatically for a Windows component. Saving makes it your own decision.");

        if (edit.Destination == null && _rule.Destination != null && _otherRules.Count > 0)
            warnings.Add($"“Any connection” replaces this app's other {(_otherRules.Count == 1 ? "rule" : $"{_otherRules.Count} rules")}: "
                         + Describe(_otherRules) + ".");

        if (edit.Destination != null && !RuleDestination.Same(edit.Destination, _rule.Destination))
        {
            var replaced = _otherRules.Where(r => RuleDestination.Same(r.Destination, edit.Destination)).ToList();
            if (replaced.Count > 0) warnings.Add($"This replaces your existing rule: {Describe(replaced)}.");
        }
        return warnings;
    }

    static string Describe(List<FirewallRuleInfo> rules)
    {
        const int listed = 4;
        var text = string.Join(", ", rules.Take(listed).Select(r =>
            $"{(r.Allow ? "allow" : "block")} {r.Destination?.Label ?? "any connection"}"));
        return rules.Count > listed ? $"{text} and {rules.Count - listed} more" : text;
    }

    async void Save_Click(object sender, RoutedEventArgs e)
    {
        if (CurrentEdit(out _) is not { } edit || !IsChange(edit)) return;
        _saving = true;
        SaveButton.IsEnabled = CancelButton.IsEnabled = false;
        SaveButton.Content = "Saving…";
        try
        {
            SavedRuleName = await _controller.EditRuleAsync(_rule, edit);
            _saving = false;
            DialogResult = true;
        }
        catch (Exception ex)
        {
            Log.Error($"Could not change the rule '{_rule.Name}'", ex);
            _saving = false;
            SaveError.Text = "Could not save the rule. " + ex.Message;
            SaveError.Visibility = Visibility.Visible;
            SaveButton.Content = "Save";
            SaveButton.IsEnabled = CancelButton.IsEnabled = true;
        }
    }
}

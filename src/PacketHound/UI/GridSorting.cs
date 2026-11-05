using System;
using System.ComponentModel;
using System.Linq;
using System.Windows.Controls;
using System.Windows.Data;
using PacketHound.Core;

namespace PacketHound.UI;

/// <summary>
/// Remembers a grid's sort column and direction in <see cref="Settings"/>, so it survives reloads
/// and restarts, and keeps the header arrow in step. Clicking a header sorts ascending; clicking
/// it again reverses the direction.
/// </summary>
sealed class GridSorting
{
    readonly DataGrid _grid;
    readonly Settings _settings;
    readonly string _key;
    readonly SortSetting _default;

    public GridSorting(DataGrid grid, Settings settings, string key, SortSetting defaultSort)
    {
        _grid = grid;
        _settings = settings;
        _key = key;
        _default = defaultSort;
        grid.Sorting += OnSorting;
    }

    SortSetting Current
    {
        get
        {
            // Ignore a saved column that no longer exists.
            return _settings.GridSorts.TryGetValue(_key, out var s) && _grid.Columns.Any(c => c.SortMemberPath == s.Member)
                ? s : _default;
        }
    }

    void OnSorting(object? sender, DataGridSortingEventArgs e)
    {
        e.Handled = true;
        var member = e.Column.SortMemberPath;
        if (string.IsNullOrEmpty(member)) return;

        var current = Current;
        _settings.GridSorts[_key] = new SortSetting(member, current.Member == member && !current.Descending);
        try { _settings.Save(); }
        catch (Exception ex) { Log.Error("Could not save the sort order", ex); }
        Apply();
    }

    /// <summary>Sorts the grid's current items. Call again whenever ItemsSource is replaced.</summary>
    public void Apply()
    {
        if (_grid.ItemsSource == null) return;
        var view = CollectionViewSource.GetDefaultView(_grid.ItemsSource);
        var sort = Current;
        var direction = sort.Descending ? ListSortDirection.Descending : ListSortDirection.Ascending;

        using (view.DeferRefresh())
        {
            view.SortDescriptions.Clear();
            view.SortDescriptions.Add(new SortDescription(sort.Member, direction));
            // Ties (same action, same type...) fall back to alphabetical by app.
            if (sort.Member != "AppName") view.SortDescriptions.Add(new SortDescription("AppName", ListSortDirection.Ascending));
        }
        foreach (var column in _grid.Columns)
            column.SortDirection = column.SortMemberPath == sort.Member ? direction : null;
    }
}

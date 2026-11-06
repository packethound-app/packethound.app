using System;
using System.Drawing;
using PacketHound.Core;
using WinForms = System.Windows.Forms;

namespace PacketHound.UI;

/// <summary>Notification-area icon with a small menu.</summary>
public sealed class TrayIcon : IDisposable
{
    readonly Controller _controller;
    readonly WinForms.NotifyIcon _icon;
    readonly WinForms.ToolStripMenuItem _pauseItem;
    readonly WinForms.ToolStripMenuItem _resumeItem;
    readonly WinForms.ToolStripMenuItem _updateItem;
    readonly WinForms.ToolStripMenuItem _deferredItem;
    Action? _balloonClick; // what clicking the current notification does (error notifications do nothing)
    readonly Action _openMain;
    readonly Action _openDeferred;
    readonly Action _exit;
    readonly Icon _onIcon = LoadIcon("PacketHound.ico");
    readonly Icon _pausedIcon = LoadIcon("PacketHound-paused.ico");

    /// <param name="openDeferred">Opens the main window where the "decide later" apps are listed.</param>
    public TrayIcon(Controller controller, Action openMain, Action openDeferred, Action exit)
    {
        _controller = controller;
        _openMain = openMain;
        _openDeferred = openDeferred;
        _exit = exit;

        var menu = new WinForms.ContextMenuStrip();
        var open = new WinForms.ToolStripMenuItem("Open PacketHound", null, (_, _) => _openMain());
        open.Font = new Font(open.Font, FontStyle.Bold);
        _pauseItem = new WinForms.ToolStripMenuItem("Pause protection");
        foreach (var (label, duration) in Controller.PauseChoices)
            _pauseItem.DropDownItems.Add(new WinForms.ToolStripMenuItem(label, null, (_, _) => Change(() => _controller.PauseProtection(duration))));
        _resumeItem = new WinForms.ToolStripMenuItem("Turn protection on", null, (_, _) => Change(_controller.EnableProtection));
        _updateItem = new WinForms.ToolStripMenuItem("", null, (_, _) => OpenDownloadPage()) { Visible = false };
        _deferredItem = new WinForms.ToolStripMenuItem("", null, (_, _) => _openDeferred()) { Visible = false };
        menu.Items.Add(open);
        menu.Items.Add(_deferredItem);
        menu.Items.Add(_updateItem);
        menu.Items.Add(_pauseItem);
        menu.Items.Add(_resumeItem);
        menu.Items.Add(new WinForms.ToolStripSeparator());
        menu.Items.Add(new WinForms.ToolStripMenuItem("Exit", null, (_, _) => _exit()));

        _icon = new WinForms.NotifyIcon { ContextMenuStrip = menu, Visible = true };
        _icon.MouseClick += (_, e) =>
        {
            if (e.Button != WinForms.MouseButtons.Left) return;
            if (_controller.PendingCount > 0) _controller.ShowPrompt();
            else if (_controller.Deferred.Count > 0) _openDeferred();
            else _openMain();
        };

        controller.StateChanged += (_, _) => Update();
        controller.Updates.Changed += (_, _) => Update();
        controller.Updates.Announce += (_, update) =>
        {
            _balloonClick = OpenDownloadPage;
            _icon.ShowBalloonTip(10000, $"PacketHound {update.Version} is available",
                "Click here to open the download page.", WinForms.ToolTipIcon.Info);
        };
        // An installer usually gives up after its first (blocked) attempt; offer the pause it needs.
        controller.InstallerAllowed += (_, name) =>
        {
            _balloonClick = () => Change(() => _controller.PauseProtection(TimeSpan.FromMinutes(5)));
            _icon.ShowBalloonTip(15000, $"{name} is allowed",
                "If the installer says it failed, click here to pause protection for 5 minutes, then run it again.",
                WinForms.ToolTipIcon.Info);
        };
        _icon.BalloonTipClicked += (_, _) => { var click = _balloonClick; _balloonClick = null; click?.Invoke(); };
        _icon.BalloonTipClosed += (_, _) => _balloonClick = null;
        Update();
    }

    void OpenDownloadPage()
    {
        try { UpdateService.OpenDownloadPage(); }
        catch (Exception ex) { Log.Error("Could not open the download page", ex); }
    }

    void Change(Action change)
    {
        try
        {
            change();
        }
        catch (Exception ex)
        {
            Log.Error("Changing protection from the tray failed", ex);
            _balloonClick = null;
            _icon.ShowBalloonTip(5000, "PacketHound", ex.Message, WinForms.ToolTipIcon.Error);
        }
    }

    void Update()
    {
        var on = _controller.ProtectionEnabled;
        _icon.Icon = on ? _onIcon : _pausedIcon;
        var text = on ? "PacketHound · protection on"
            : _controller.PausedUntil is { } until ? $"PacketHound · paused until {until:t}" : "PacketHound · paused";
        var waiting = _controller.PendingCount + _controller.Deferred.Count;
        if (waiting > 0) text += $" · {waiting} waiting";
        _icon.Text = text.Length > 63 ? text[..63] : text;
        var deferred = _controller.Deferred.Count;
        _deferredItem.Visible = deferred > 0;
        _deferredItem.Text = deferred == 1 ? "1 app waiting for your decision…" : $"{deferred} apps waiting for your decision…";
        _pauseItem.Visible = on;
        _resumeItem.Visible = !on;
        var update = _controller.Updates.Available;
        _updateItem.Visible = update != null;
        if (update != null) _updateItem.Text = $"Download PacketHound {update.Version}…";
    }

    /// <summary>Loads an icon from Assets at the tray's size for the current DPI.</summary>
    static Icon LoadIcon(string name)
    {
        var uri = new Uri($"pack://application:,,,/Assets/{name}");
        using var stream = System.Windows.Application.GetResourceStream(uri).Stream;
        return new Icon(stream, WinForms.SystemInformation.SmallIconSize);
    }

    public void Dispose()
    {
        _icon.Visible = false;
        _icon.Dispose();
        _onIcon.Dispose();
        _pausedIcon.Dispose();
    }
}

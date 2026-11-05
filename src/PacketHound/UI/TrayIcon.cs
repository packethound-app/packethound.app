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
    readonly WinForms.ToolStripMenuItem _toggleItem;
    readonly WinForms.ToolStripMenuItem _updateItem;
    bool _balloonOpensDownload; // error balloons share the same click event
    readonly Action _openMain;
    readonly Action _exit;
    readonly Icon _onIcon = LoadIcon("PacketHound.ico");
    readonly Icon _pausedIcon = LoadIcon("PacketHound-paused.ico");

    public TrayIcon(Controller controller, Action openMain, Action exit)
    {
        _controller = controller;
        _openMain = openMain;
        _exit = exit;

        var menu = new WinForms.ContextMenuStrip();
        var open = new WinForms.ToolStripMenuItem("Open PacketHound", null, (_, _) => _openMain());
        open.Font = new Font(open.Font, FontStyle.Bold);
        _toggleItem = new WinForms.ToolStripMenuItem("", null, (_, _) => Toggle());
        _updateItem = new WinForms.ToolStripMenuItem("", null, (_, _) => OpenDownloadPage()) { Visible = false };
        menu.Items.Add(open);
        menu.Items.Add(_updateItem);
        menu.Items.Add(_toggleItem);
        menu.Items.Add(new WinForms.ToolStripSeparator());
        menu.Items.Add(new WinForms.ToolStripMenuItem("Exit", null, (_, _) => _exit()));

        _icon = new WinForms.NotifyIcon { ContextMenuStrip = menu, Visible = true };
        _icon.MouseClick += (_, e) =>
        {
            if (e.Button != WinForms.MouseButtons.Left) return;
            if (_controller.PendingCount > 0) _controller.ShowPrompt();
            else _openMain();
        };

        controller.StateChanged += (_, _) => Update();
        controller.Updates.Changed += (_, _) => Update();
        controller.Updates.Announce += (_, update) =>
        {
            _balloonOpensDownload = true;
            _icon.ShowBalloonTip(10000, $"PacketHound {update.Version} is available",
                "Click here to open the download page.", WinForms.ToolTipIcon.Info);
        };
        _icon.BalloonTipClicked += (_, _) => { if (_balloonOpensDownload) OpenDownloadPage(); };
        _icon.BalloonTipClosed += (_, _) => _balloonOpensDownload = false;
        Update();
    }

    void OpenDownloadPage()
    {
        try { UpdateService.OpenDownloadPage(); }
        catch (Exception ex) { Log.Error("Could not open the download page", ex); }
    }

    void Toggle()
    {
        try
        {
            if (_controller.ProtectionEnabled) _controller.PauseProtection();
            else _controller.EnableProtection();
        }
        catch (Exception ex)
        {
            Log.Error("Toggle from tray failed", ex);
            _icon.ShowBalloonTip(5000, "PacketHound", ex.Message, WinForms.ToolTipIcon.Error);
        }
    }

    void Update()
    {
        var on = _controller.ProtectionEnabled;
        _icon.Icon = on ? _onIcon : _pausedIcon;
        var text = on ? "PacketHound · protection on" : "PacketHound · paused";
        if (_controller.PendingCount > 0) text += $" · {_controller.PendingCount} waiting";
        _icon.Text = text.Length > 63 ? text[..63] : text;
        _toggleItem.Text = on ? "Pause protection" : "Turn protection on";
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

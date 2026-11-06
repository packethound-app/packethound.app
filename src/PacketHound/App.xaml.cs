using System;
using System.Linq;
using System.Security.Principal;
using System.Threading;
using System.Windows;
using System.Windows.Threading;
using PacketHound.Core;
using PacketHound.UI;

namespace PacketHound;

public partial class App : Application
{
    const string InstanceMutexName = @"Local\PacketHound.SingleInstance";
    const string ShowEventName = @"Local\PacketHound.Show";

    Mutex? _instanceMutex;
    EventWaitHandle? _showEvent;
    RegisteredWaitHandle? _showWait;
    Controller? _controller;
    TrayIcon? _tray;
    MainWindow? _main;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        if (e.Args.Contains("--uninstall", StringComparer.OrdinalIgnoreCase))
        {
            Shutdown(UninstallCleanup(keepRules: e.Args.Contains("--keep-rules", StringComparer.OrdinalIgnoreCase)));
            return;
        }

        _instanceMutex = new Mutex(true, InstanceMutexName, out var firstInstance);
        if (!firstInstance)
        {
            // Already running: ask the existing instance to show its window.
            try { EventWaitHandle.OpenExisting(ShowEventName).Set(); } catch { }
            Shutdown();
            return;
        }

        if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
        {
            MessageBox.Show("PacketHound needs to run as administrator to manage Windows Firewall.", "PacketHound",
                MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown();
            return;
        }

        DispatcherUnhandledException += OnUnhandledException;
        Log.Info("PacketHound starting");

        _controller = new Controller(Dispatcher);
        _tray = new TrayIcon(_controller, ShowMain, ShowDeferred, ExitApp);
        _controller.Start();

        _showEvent = new EventWaitHandle(false, EventResetMode.AutoReset, ShowEventName);
        _showWait = ThreadPool.RegisterWaitForSingleObject(_showEvent,
            (_, _) => Dispatcher.InvokeAsync(ShowMain), null, Timeout.Infinite, executeOnlyOnce: false);

        if (!_controller.Settings.FirstRunCompleted)
            FirstRun();
        else if (!e.Args.Contains("--background", StringComparer.OrdinalIgnoreCase))
            ShowMain();
    }

    void FirstRun()
    {
        ShowMain();
        var answer = MessageBox.Show(_main!,
            "PacketHound will:\n\n" +
            "  • set Windows Firewall to block outgoing connections by default,\n" +
            "  • allow Windows itself automatically, and\n" +
            "  • ask you to Allow or Block each other app the first time it connects.\n\n" +
            "Each answer is saved as a normal Windows Firewall rule. You can pause protection or restore the original settings at any time.\n\n" +
            "Turn protection on now?",
            "Welcome to PacketHound", MessageBoxButton.YesNo, MessageBoxImage.Question);

        _controller!.Settings.FirstRunCompleted = true;
        _controller.Settings.Save();
        if (answer != MessageBoxResult.Yes) return;

        try
        {
            _controller.EnableProtection();
            if (MessageBox.Show(_main!, "Start PacketHound automatically when you sign in?\n\nWithout it, apps that don't have a rule yet stay blocked (silently) whenever PacketHound isn't running.",
                    "PacketHound", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
                AutoStart.Enable();
        }
        catch (Exception ex)
        {
            Log.Error("First-run setup failed", ex);
            MessageBox.Show(_main!, "Setup failed: " + ex.Message, "PacketHound", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        _main?.Reload();
    }

    void ShowMain()
    {
        if (_controller == null) return;
        if (_main == null)
        {
            _main = new MainWindow(_controller);
            _main.Closed += (_, _) => _main = null;
            _main.Show();
        }
        // A real "restore", so a window that was maximized before it was minimized comes back maximized.
        if (_main.WindowState == WindowState.Minimized) SystemCommands.RestoreWindow(_main);
        _main.Activate();
    }

    void ShowDeferred()
    {
        ShowMain();
        _main?.ShowDeferred();
    }

    void ExitApp()
    {
        if (_controller == null) return;
        if (_controller.PausedUntil is { } until)
        {
            // Only a running PacketHound can end a timed pause.
            var answer = MessageBox.Show(
                $"Protection is paused until {until:t}, but PacketHound has to be running to turn it back on.\n\n" +
                "Turn protection back on now before exiting?\n\n" +
                "Yes: turn it on now (apps without a rule are blocked while PacketHound is closed).\n" +
                "No: exit and leave it paused until PacketHound next starts.",
                "Exit PacketHound", MessageBoxButton.YesNoCancel, MessageBoxImage.Question);
            if (answer == MessageBoxResult.Cancel) return;
            if (answer == MessageBoxResult.Yes)
            {
                try { _controller.EnableProtection(); }
                catch (Exception ex)
                {
                    Log.Error("Turning protection on at exit failed", ex);
                    MessageBox.Show("Could not turn protection back on: " + ex.Message, "PacketHound",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }
            }
        }
        else if (_controller.ProtectionEnabled)
        {
            var answer = MessageBox.Show(
                "Keep blocking apps that don't have a rule while PacketHound is closed?\n\n" +
                "Yes: apps without a rule stay blocked (you just won't be asked).\n" +
                "No: pause protection, so apps without a rule can connect until you start PacketHound again.\n\n" +
                "Either way, your rules stay active: apps you blocked stay blocked, and apps you allowed can still connect.",
                "Exit PacketHound", MessageBoxButton.YesNoCancel, MessageBoxImage.Question);
            if (answer == MessageBoxResult.Cancel) return;
            if (answer == MessageBoxResult.No)
            {
                try { _controller.PauseProtection(); }
                catch (Exception ex) { Log.Error("Pause on exit failed", ex); }
            }
        }
        Shutdown();
    }

    /// <summary>
    /// Run by the uninstaller (no UI): closes any running PacketHound, then puts Windows Firewall's
    /// outbound default and audit setting back, removes the startup task and, unless asked to keep
    /// them, deletes PacketHound's rules. Returns the process exit code.
    /// </summary>
    int UninstallCleanup(bool keepRules)
    {
        try
        {
            foreach (var other in System.Diagnostics.Process.GetProcessesByName("PacketHound")
                         .Where(p => p.Id != Environment.ProcessId))
            {
                using (other)
                {
                    other.Kill();
                    other.WaitForExit(5000);
                }
            }
            var removed = new Controller(Dispatcher).RestoreWindowsDefaults(removeRules: !keepRules);
            Log.Info($"Uninstall cleanup done ({removed} rules removed)");
            return 0;
        }
        catch (Exception ex)
        {
            Log.Error("Uninstall cleanup failed", ex);
            return 1;
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _showWait?.Unregister(null);
        _showEvent?.Dispose();
        _controller?.Shutdown();
        _tray?.Dispose();
        Log.Info("PacketHound stopped");
        base.OnExit(e);
    }

    void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        Log.Error("Unhandled exception", e.Exception);
        MessageBox.Show("Unexpected error: " + e.Exception.Message, "PacketHound", MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }
}

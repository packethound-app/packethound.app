using System;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using Microsoft.Win32;
using PacketHound.Core;

namespace PacketHound.UI;

/// <summary>
/// Light or dark colours for every window. Swaps the colour dictionary in App.xaml (the controls use the
/// colours through DynamicResource, so open windows change straight away) and colours the title bars to match.
/// "Same as Windows" follows the Windows app mode, including when it changes while PacketHound is running.
/// </summary>
public static class ThemeManager
{
    static ThemeChoice _choice = ThemeChoice.System;
    static bool? _dark; // what's showing now (null: nothing applied yet)

    public static bool IsDark => _dark == true;

    public static void Initialize(ThemeChoice choice)
    {
        _choice = choice;
        // Raised on SystemEvents' own thread when Windows settings change (the app mode is a "General" change).
        SystemEvents.UserPreferenceChanged += (_, e) =>
        {
            if (e.Category == UserPreferenceCategory.General) Application.Current?.Dispatcher.InvokeAsync(Refresh);
        };
        Refresh();
    }

    public static void Set(ThemeChoice choice)
    {
        _choice = choice;
        Refresh();
    }

    /// <summary>Call from a window's constructor so its title bar matches from the start.</summary>
    public static void Attach(Window window) => window.SourceInitialized += (_, _) => ApplyTitleBar(window);

    static void Refresh()
    {
        var dark = _choice switch
        {
            ThemeChoice.Dark => true,
            ThemeChoice.Light => false,
            _ => WindowsAppsUseDarkMode(),
        };
        if (dark == _dark) return;
        _dark = dark;

        var app = Application.Current;
        if (app == null) return;
        app.Resources.MergedDictionaries[0] = new ResourceDictionary
        {
            Source = new Uri($"pack://application:,,,/PacketHound;component/Themes/{(dark ? "Dark" : "Light")}.xaml", UriKind.Absolute),
        };
        foreach (Window window in app.Windows) ApplyTitleBar(window);
    }

    static bool WindowsAppsUseDarkMode()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return key?.GetValue("AppsUseLightTheme") is int light && light == 0;
        }
        catch
        {
            return false;
        }
    }

    static void ApplyTitleBar(Window window)
    {
        var hwnd = new WindowInteropHelper(window).Handle;
        if (hwnd == IntPtr.Zero) return;
        var on = IsDark ? 1 : 0;
        // Windows 10 20H1 and later; older versions ignore it and keep a light title bar.
        DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ref on, sizeof(int));
    }

    const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;

    [DllImport("dwmapi.dll")]
    static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);
}

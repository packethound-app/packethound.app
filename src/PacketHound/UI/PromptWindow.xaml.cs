using System;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using PacketHound.Core;

namespace PacketHound.UI;

public partial class PromptWindow : Window
{
    public PromptWindow(PendingRequest request)
    {
        InitializeComponent();
        DataContext = request;
        // Not activated on purpose: a prompt popping up mid-typing must not swallow keystrokes.
        SourceInitialized += (_, _) => Flash();
    }

    /// <summary>What the user chose. Closing the window with X counts as "Decide later".</summary>
    public PromptDecision Decision { get; set; } = PromptDecision.Later;

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
        Close();
    }

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

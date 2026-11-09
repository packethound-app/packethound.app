using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace PacketHound.Core;

/// <summary>Checks whether any process of a given program (by full path) is still running.</summary>
public static class RunningPrograms
{
    const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    public static bool IsRunning(string appPath)
    {
        if (appPath.Equals("System", StringComparison.OrdinalIgnoreCase)) return true;

        var target = FirewallManager.NormalizePath(appPath);
        foreach (var p in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(target)))
        {
            using (p)
            {
                var image = ImagePath(p.Id);
                // A same-named process we can't inspect might be it: count it as running rather than end the rule early.
                if (image == null || FirewallManager.PathEquals(FirewallManager.NormalizePath(image), target)) return true;
            }
        }
        return false;
    }

    /// <summary>
    /// The command line a process was started with, or null if it has exited (or can't be read). Slow-ish
    /// (a WMI query), so call it off the UI thread.
    /// </summary>
    public static string? CommandLine(int pid)
    {
        if (pid <= 4) return null; // System Idle / System
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
            using var results = searcher.Get();
            return results.Cast<System.Management.ManagementObject>().Select(o => o["CommandLine"] as string)
                .FirstOrDefault(c => !string.IsNullOrWhiteSpace(c))?.Trim();
        }
        catch
        {
            return null;
        }
    }

    static string? ImagePath(int pid)
    {
        var handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (handle == IntPtr.Zero) return null;
        try
        {
            var buffer = new StringBuilder(1024);
            var size = buffer.Capacity;
            return QueryFullProcessImageName(handle, 0, buffer, ref size) ? buffer.ToString(0, size) : null;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint access, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder exeName, ref int size);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);
}

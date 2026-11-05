using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace PacketHound.Core;

/// <summary>
/// The Filtering Platform reports programs by NT device path
/// (\device\harddiskvolume3\program files\app\app.exe). Firewall rules need Win32 paths.
/// </summary>
public static class DevicePaths
{
    static readonly object Gate = new();
    static Dictionary<string, string> _map = new(StringComparer.OrdinalIgnoreCase);

    public static string ToWin32Path(string devicePath)
    {
        if (devicePath.Equals("System", StringComparison.OrdinalIgnoreCase)) return "System";
        if (!devicePath.StartsWith(@"\device\", StringComparison.OrdinalIgnoreCase)) return devicePath;

        if (devicePath.StartsWith(@"\device\mup\", StringComparison.OrdinalIgnoreCase))
            return @"\\" + devicePath[@"\device\mup\".Length..];

        var resolved = TryMap(devicePath);
        if (resolved == null)
        {
            Refresh(); // a drive may have been mounted since we last looked
            resolved = TryMap(devicePath);
        }
        return resolved == null ? devicePath : ActualCase(resolved);
    }

    static string? TryMap(string devicePath)
    {
        lock (Gate)
        {
            if (_map.Count == 0) RefreshLocked();
            foreach (var (device, drive) in _map)
            {
                if (devicePath.Length > device.Length
                    && devicePath.StartsWith(device, StringComparison.OrdinalIgnoreCase)
                    && devicePath[device.Length] == '\\')
                    return drive + devicePath[device.Length..];
            }
        }
        return null;
    }

    static void Refresh()
    {
        lock (Gate) RefreshLocked();
    }

    static void RefreshLocked()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var sb = new StringBuilder(1024);
        foreach (var root in Environment.GetLogicalDrives())
        {
            var drive = root.TrimEnd('\\'); // "C:"
            sb.Clear();
            if (QueryDosDevice(drive, sb, sb.Capacity) != 0)
                map[sb.ToString()] = drive;
        }
        _map = map;
    }

    /// <summary>Event paths are lower-cased; recover the real casing for display and rule names.</summary>
    public static string ActualCase(string path)
    {
        try
        {
            using SafeFileHandle h = CreateFile(path, 0, FileShare.ReadWrite | FileShare.Delete, IntPtr.Zero,
                FileMode.Open, FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
            if (h.IsInvalid) return path;
            var sb = new StringBuilder(1024);
            var len = GetFinalPathNameByHandle(h, sb, (uint)sb.Capacity, 0);
            if (len == 0 || len >= sb.Capacity) return path;
            var final = sb.ToString();
            if (final.StartsWith(@"\\?\UNC\", StringComparison.Ordinal)) return @"\\" + final[8..];
            if (final.StartsWith(@"\\?\", StringComparison.Ordinal)) final = final[4..];
            // Only accept the result if it is the same path (not a resolved symlink/junction elsewhere).
            return string.Equals(final, path, StringComparison.OrdinalIgnoreCase) ? final : path;
        }
        catch
        {
            return path;
        }
    }

    const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern SafeFileHandle CreateFile(string fileName, uint desiredAccess, FileShare shareMode,
        IntPtr securityAttributes, FileMode creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern uint GetFinalPathNameByHandle(SafeFileHandle hFile, StringBuilder lpszFilePath, uint cchFilePath, uint dwFlags);
}

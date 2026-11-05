using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace PacketHound.Core;

/// <summary>
/// PacketHound learns about blocked outbound connections from Security event 5157
/// ("The Windows Filtering Platform has blocked a connection"). Windows only writes that
/// event when failure auditing is on for the "Filtering Platform Connection" subcategory.
/// </summary>
public static class AuditPolicy
{
    // Locale-independent GUID of the "Filtering Platform Connection" audit subcategory.
    static readonly Guid FilteringPlatformConnection = new("0CCE9226-69AE-11D9-BED3-505054503030");

    const uint POLICY_AUDIT_EVENT_FAILURE = 0x2;

    public static bool? IsFailureAuditingEnabled()
    {
        try
        {
            EnablePrivilege("SeSecurityPrivilege");
            if (!AuditQuerySystemPolicy(new[] { FilteringPlatformConnection }, 1, out var buffer))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            try
            {
                var info = Marshal.PtrToStructure<AUDIT_POLICY_INFORMATION>(buffer);
                return (info.AuditingInformation & POLICY_AUDIT_EVENT_FAILURE) != 0;
            }
            finally
            {
                AuditFree(buffer);
            }
        }
        catch (Exception ex)
        {
            Log.Error("Could not query audit policy", ex);
            return null;
        }
    }

    /// <summary>Turns failure auditing on/off without touching the "success" setting.</summary>
    public static void SetFailureAuditing(bool enable)
    {
        var exe = Path.Combine(Environment.SystemDirectory, "auditpol.exe");
        var psi = new ProcessStartInfo(exe,
            $"/set /subcategory:{{{FilteringPlatformConnection}}} /failure:{(enable ? "enable" : "disable")}")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var p = Process.Start(psi)!;
        var output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit();
        if (p.ExitCode != 0)
            throw new InvalidOperationException($"auditpol failed ({p.ExitCode}): {output.Trim()}");
        Log.Info($"Filtering Platform Connection failure auditing {(enable ? "enabled" : "disabled")}");
    }

    static void EnablePrivilege(string name)
    {
        if (!OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out var token))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            if (!LookupPrivilegeValue(null, name, out var luid))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            var tp = new TOKEN_PRIVILEGES { PrivilegeCount = 1, Luid = luid, Attributes = SE_PRIVILEGE_ENABLED };
            if (!AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }
        finally
        {
            CloseHandle(token);
        }
    }

    const uint TOKEN_ADJUST_PRIVILEGES = 0x20;
    const uint TOKEN_QUERY = 0x8;
    const uint SE_PRIVILEGE_ENABLED = 0x2;

    [StructLayout(LayoutKind.Sequential)]
    struct AUDIT_POLICY_INFORMATION
    {
        public Guid AuditSubCategoryGuid;
        public uint AuditingInformation;
        public Guid AuditCategoryGuid;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LUID { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public LUID Luid; public uint Attributes; }

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    static extern bool AuditQuerySystemPolicy([In] Guid[] pSubCategoryGuids, uint dwPolicyCount, out IntPtr ppAuditPolicy);

    [DllImport("advapi32.dll")]
    static extern void AuditFree(IntPtr buffer);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool LookupPrivilegeValue(string? systemName, string name, out LUID luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TOKEN_PRIVILEGES newState,
        uint bufferLength, IntPtr previousState, IntPtr returnLength);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);
}

using System;
using System.Diagnostics;
using System.IO;
using System.Security;
using System.Security.Principal;
using System.Text;

namespace PacketHound.Core;

/// <summary>
/// Starts PacketHound elevated at logon through Task Scheduler (no UAC prompt each time).
/// A task XML is used so we can turn off the defaults that would kill a long-running
/// app: the 3-day execution limit and "don't start / stop on battery".
/// </summary>
public static class AutoStart
{
    const string TaskName = "PacketHound";

    public static bool IsEnabled() => TaskExists(TaskName);

    public static bool TaskExists(string name) => RunSchtasks($"/Query /TN \"{name}\"", out _) == 0;

    public static void DeleteTask(string name)
    {
        if (TaskExists(name)) RunSchtasks($"/Delete /TN \"{name}\" /F", out _);
    }

    public static void Enable()
    {
        var exe = Environment.ProcessPath ?? throw new InvalidOperationException("Unknown executable path");
        var user = WindowsIdentity.GetCurrent().Name;
        var xml = $"""
            <?xml version="1.0" encoding="UTF-16"?>
            <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <RegistrationInfo><Description>Starts the PacketHound outbound firewall prompt at logon.</Description></RegistrationInfo>
              <Triggers>
                <LogonTrigger><Enabled>true</Enabled><UserId>{SecurityElement.Escape(user)}</UserId></LogonTrigger>
              </Triggers>
              <Principals>
                <Principal id="Author">
                  <UserId>{SecurityElement.Escape(user)}</UserId>
                  <LogonType>InteractiveToken</LogonType>
                  <RunLevel>HighestAvailable</RunLevel>
                </Principal>
              </Principals>
              <Settings>
                <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
                <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
                <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
                <AllowHardTerminate>true</AllowHardTerminate>
                <StartWhenAvailable>false</StartWhenAvailable>
                <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
                <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
                <AllowStartOnDemand>true</AllowStartOnDemand>
                <Enabled>true</Enabled>
                <Hidden>false</Hidden>
                <RunOnlyIfIdle>false</RunOnlyIfIdle>
                <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
                <Priority>7</Priority>
              </Settings>
              <Actions Context="Author">
                <Exec>
                  <Command>{SecurityElement.Escape(exe)}</Command>
                  <Arguments>--background</Arguments>
                </Exec>
              </Actions>
            </Task>
            """;

        var file = Path.Combine(Path.GetTempPath(), $"packethound-task-{Guid.NewGuid():N}.xml");
        File.WriteAllText(file, xml, Encoding.Unicode);
        try
        {
            if (RunSchtasks($"/Create /TN \"{TaskName}\" /XML \"{file}\" /F", out var output) != 0)
                throw new InvalidOperationException("Could not create the startup task: " + output.Trim());
        }
        finally
        {
            File.Delete(file);
        }
    }

    public static void Disable() => DeleteTask(TaskName);

    static int RunSchtasks(string args, out string output)
    {
        var psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "schtasks.exe"), args)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var p = Process.Start(psi)!;
        output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit();
        return p.ExitCode;
    }
}

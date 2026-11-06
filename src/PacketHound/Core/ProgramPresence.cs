using System;
using System.IO;
using System.Linq;

namespace PacketHound.Core;

public enum ProgramState
{
    /// <summary>The program file exists (or isn't a file, like "System").</summary>
    Present,
    /// <summary>The folder it would be in is readable and the program isn't there.</summary>
    Missing,
    /// <summary>The drive it's on isn't connected (USB stick, unmounted volume).</summary>
    DriveUnavailable,
    /// <summary>Couldn't tell: network location, or a folder PacketHound can't list.</summary>
    Unknown,
}

/// <summary>Checks whether a rule's program still exists, without guessing "missing" when unsure.</summary>
public static class ProgramPresence
{
    public static ProgramState Check(string path)
    {
        if (path.Equals("System", StringComparison.OrdinalIgnoreCase)) return ProgramState.Present;
        try
        {
            if (!Path.IsPathFullyQualified(path)) return ProgramState.Unknown;
            // Network paths can stall for many seconds when the server is offline.
            if (path.StartsWith(@"\\", StringComparison.Ordinal)) return ProgramState.Unknown;
            var root = Path.GetPathRoot(path)!;
            if (new DriveInfo(root).DriveType == DriveType.Network) return ProgramState.Unknown;

            if (File.Exists(path)) return ProgramState.Present;
            if (!Directory.Exists(root)) return ProgramState.DriveUnavailable;

            // File.Exists is also false when access is denied. Find the nearest folder that exists and
            // make sure it can be listed and really lacks the next part of the path.
            var child = path.TrimEnd('\\');
            var dir = Path.GetDirectoryName(child);
            while (dir != null && !Directory.Exists(dir))
            {
                child = dir;
                dir = Path.GetDirectoryName(dir);
            }
            if (dir == null) return ProgramState.Unknown;
            var name = Path.GetFileName(child);
            return Directory.EnumerateFileSystemEntries(dir, name).Any() ? ProgramState.Unknown : ProgramState.Missing;
        }
        catch
        {
            return ProgramState.Unknown;
        }
    }
}

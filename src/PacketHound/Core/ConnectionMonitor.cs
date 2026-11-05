using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Xml.Linq;

namespace PacketHound.Core;

public sealed class BlockedConnection
{
    public DateTime Time { get; init; } = DateTime.Now;
    public int ProcessId { get; init; }
    /// <summary>Win32 path of the program (or "System").</summary>
    public string AppPath { get; init; } = "";
    public string RemoteAddress { get; init; } = "";
    public int RemotePort { get; init; }
    public int Protocol { get; init; }

    public string ProtocolName => Protocol switch
    {
        1 => "ICMP", 6 => "TCP", 17 => "UDP", 58 => "ICMPv6", _ => $"Protocol {Protocol}",
    };
}

/// <summary>
/// Subscribes to Security event 5157 (connection blocked by the Windows Filtering Platform),
/// outbound direction only. With the firewall's default outbound action set to Block, every
/// app without an allow rule produces one of these on each connection attempt.
/// </summary>
public sealed class ConnectionMonitor : IDisposable
{
    const string OutboundDirection = "%%14593";
    static readonly XNamespace Ns = "http://schemas.microsoft.com/win/2004/08/events/event";

    EventLogWatcher? _watcher;

    public event Action<BlockedConnection>? Blocked;
    public event Action<Exception>? Failed;

    public bool IsRunning => _watcher != null;

    public void Start()
    {
        if (_watcher != null) return;
        try
        {
            _watcher = CreateWatcher(
                $"*[System[(EventID=5157)]] and *[EventData[Data[@Name='Direction']='{OutboundDirection}']]");
        }
        catch (EventLogException ex) when (ex is not EventLogNotFoundException)
        {
            // Fall back to a plain EventID filter; direction is re-checked in code anyway.
            Log.Error("Direction-filtered query rejected, falling back", ex);
            _watcher = CreateWatcher("*[System[(EventID=5157)]]");
        }
        Log.Info("Connection monitor started");
    }

    EventLogWatcher CreateWatcher(string xpath)
    {
        var watcher = new EventLogWatcher(new EventLogQuery("Security", PathType.LogName, xpath));
        watcher.EventRecordWritten += OnEvent;
        try
        {
            watcher.Enabled = true;
        }
        catch
        {
            watcher.EventRecordWritten -= OnEvent;
            watcher.Dispose();
            throw;
        }
        return watcher;
    }

    public void Stop()
    {
        if (_watcher == null) return;
        _watcher.Enabled = false;
        _watcher.EventRecordWritten -= OnEvent;
        _watcher.Dispose();
        _watcher = null;
        Log.Info("Connection monitor stopped");
    }

    void OnEvent(object? sender, EventRecordWrittenEventArgs e)
    {
        if (e.EventException != null)
        {
            Failed?.Invoke(e.EventException);
            return;
        }
        using var record = e.EventRecord;
        if (record == null) return;

        try
        {
            var data = XDocument.Parse(record.ToXml())
                .Descendants(Ns + "Data")
                .Where(d => d.Attribute("Name") != null)
                .ToDictionary(d => d.Attribute("Name")!.Value, d => d.Value);

            if (!data.TryGetValue("Direction", out var dir) || dir != OutboundDirection) return;

            var app = data.GetValueOrDefault("Application", "");
            if (string.IsNullOrWhiteSpace(app) || app == "-") return;

            Blocked?.Invoke(new BlockedConnection
            {
                Time = record.TimeCreated ?? DateTime.Now,
                ProcessId = int.TryParse(data.GetValueOrDefault("ProcessID"), out var pid) ? pid : 0,
                AppPath = DevicePaths.ToWin32Path(app),
                RemoteAddress = data.GetValueOrDefault("DestAddress", ""),
                RemotePort = int.TryParse(data.GetValueOrDefault("DestPort"), out var port) ? port : 0,
                Protocol = int.TryParse(data.GetValueOrDefault("Protocol"), out var proto) ? proto : 0,
            });
        }
        catch (Exception ex)
        {
            Log.Error("Failed to parse event 5157", ex);
        }
    }

    public void Dispose() => Stop();
}

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows.Threading;

namespace PacketHound.Core;

/// <summary>A version newer than the one running, as published on the website.</summary>
public sealed record UpdateInfo(Version Version, string? Released, IReadOnlyList<string> Notes);

/// <summary>
/// Checks the website for a newer version: automatically once a week (if enabled) and on demand.
/// It only fetches version.php, a small JSON file; nothing about the PC or its rules is sent, and
/// nothing is downloaded or installed. The user downloads updates from the website themselves.
/// All members run on the UI thread.
/// </summary>
public sealed class UpdateService
{
    public static readonly Uri Website = new("https://packethound.app/");
    static readonly Uri VersionUrl = new(Website, "version.php");
    /// <summary>The ARM64 build asks for the ARM64 installer to be the main download.</summary>
    public static readonly Uri DownloadPage = new(Website,
        System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture == System.Runtime.InteropServices.Architecture.Arm64
            ? "download.php?arch=arm64" : "download.php");
    static readonly TimeSpan Interval = TimeSpan.FromDays(7);

    static readonly HttpClient Http = CreateClient();

    readonly Settings _settings;
    readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromMinutes(2) };

    public UpdateService(Settings settings)
    {
        _settings = settings;
        _timer.Tick += async (_, _) =>
        {
            _timer.Interval = TimeSpan.FromHours(1); // first check shortly after start, then look hourly
            if (_settings.CheckForUpdates && !IsChecking
                && (_settings.LastUpdateCheckUtc is not { } last || DateTime.UtcNow - last >= Interval))
                await CheckAsync(manual: false);
        };
    }

    public static Version CurrentVersion
    {
        get
        {
            var v = typeof(UpdateService).Assembly.GetName().Version ?? new Version(0, 0, 0);
            return new Version(v.Major, v.Minor, Math.Max(v.Build, 0));
        }
    }

    /// <summary>A newer version, once a check has found one.</summary>
    public UpdateInfo? Available { get; private set; }
    public bool IsChecking { get; private set; }
    /// <summary>Result of the last check, for the Settings tab.</summary>
    public string Status { get; private set; } = "";

    /// <summary>Available, IsChecking or Status changed.</summary>
    public event EventHandler? Changed;

    /// <summary>An automatic check found a version the user hasn't been told about yet.</summary>
    public event EventHandler<UpdateInfo>? Announce;

    public void Start() => _timer.Start();
    public void Stop() => _timer.Stop();

    public async Task CheckAsync(bool manual)
    {
        if (IsChecking) return;
        IsChecking = true;
        Status = "Checking…";
        Changed?.Invoke(this, EventArgs.Empty);
        try
        {
            var latest = await FetchLatestAsync();
            _settings.LastUpdateCheckUtc = DateTime.UtcNow;
            if (latest.Version > CurrentVersion)
            {
                Available = latest;
                Status = $"PacketHound {latest.Version} is available. You have {CurrentVersion}.";
                if (!manual && _settings.AnnouncedVersion != latest.Version.ToString())
                {
                    _settings.AnnouncedVersion = latest.Version.ToString();
                    Announce?.Invoke(this, latest);
                }
            }
            else
            {
                Available = null;
                Status = $"You have the latest version ({CurrentVersion}). Checked {DateTime.Now:g}.";
            }
            SaveSettings();
            Log.Info($"Update check: latest {latest.Version}, running {CurrentVersion}");
        }
        catch (Exception ex)
        {
            Status = "Couldn't check for updates: " + Describe(ex);
            Log.Error("Update check failed", ex);
        }
        finally
        {
            IsChecking = false;
            Changed?.Invoke(this, EventArgs.Empty);
        }
    }

    /// <summary>
    /// Opens the download page in the user's browser. Started through Explorer, so the browser runs
    /// as the normal user rather than inheriting PacketHound's administrator rights.
    /// </summary>
    public static void OpenDownloadPage()
    {
        Process.Start(new ProcessStartInfo("explorer.exe", $"\"{DownloadPage}\"") { UseShellExecute = false });
    }

    static async Task<UpdateInfo> FetchLatestAsync()
    {
        using var response = await Http.GetAsync(VersionUrl);
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadAsStringAsync();

        // A proxy or CDN challenge page (e.g. Cloudflare's bot check) comes back as HTML, not JSON.
        if (!body.TrimStart().StartsWith('{'))
            throw new InvalidOperationException("the website sent an unexpected reply");

        using var json = JsonDocument.Parse(body);
        var root = json.RootElement;
        if (!Version.TryParse(root.GetProperty("version").GetString(), out var version))
            throw new InvalidOperationException("the website sent an invalid version number");
        var released = root.TryGetProperty("released", out var r) ? r.GetString() : null;
        var notes = root.TryGetProperty("notes", out var n) && n.ValueKind == JsonValueKind.Array
            ? n.EnumerateArray().Select(x => x.GetString() ?? "").Where(x => x.Length > 0).ToList()
            : new List<string>();
        return new UpdateInfo(new Version(version.Major, version.Minor, Math.Max(version.Build, 0)), released, notes);
    }

    static string Describe(Exception ex) => ex switch
    {
        TaskCanceledException => "the website didn't answer in time.",
        HttpRequestException { StatusCode: { } code } => $"the website replied with error {(int)code}.",
        HttpRequestException => "couldn't reach the website. Check your internet connection, and that PacketHound's own rule isn't set to Block.",
        _ => ex.Message + ".",
    };

    void SaveSettings()
    {
        try { _settings.Save(); }
        catch (Exception ex) { Log.Error("Could not save update-check settings", ex); }
    }

    static HttpClient CreateClient()
    {
        var client = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
        // Identifies the program and version only; nothing about the user or PC.
        client.DefaultRequestHeaders.UserAgent.ParseAdd($"PacketHound/{CurrentVersion} (update check; +https://packethound.app/)");
        client.DefaultRequestHeaders.Accept.ParseAdd("application/json");
        return client;
    }
}

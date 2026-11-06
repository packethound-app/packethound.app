using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Management;
using System.Net;
using System.Threading.Tasks;

namespace PacketHound.Core;

/// <summary>
/// Turns a remote IP into the hostname the app most likely asked for.
/// First looks in the Windows DNS client cache (which records the name that was queried,
/// e.g. "api.example.com", even behind CNAME chains), then falls back to reverse DNS.
/// </summary>
public static class HostNames
{
    // Address → name. Addresses without a name are remembered for a while too, so an app retrying the same
    // address doesn't cause a DNS-cache query and a (up to 3 s) reverse lookup on every attempt.
    static readonly ConcurrentDictionary<string, (string? Name, DateTime CheckedUtc)> Cache = new();
    static readonly TimeSpan RetryUnnamedAfter = TimeSpan.FromMinutes(5);
    const int MaxCached = 5000;

    public static async Task<string?> LookupAsync(string address)
    {
        if (Cache.TryGetValue(address, out var known)
            && (known.Name != null || DateTime.UtcNow - known.CheckedUtc < RetryUnnamedAfter))
            return known.Name;
        if (!IPAddress.TryParse(address, out var ip)) return null;

        var name = await Task.Run(() => FromDnsCache(address));
        if (name == null)
        {
            try
            {
                var reverse = Dns.GetHostEntryAsync(ip);
                if (await Task.WhenAny(reverse, Task.Delay(3000)) == reverse && reverse.IsCompletedSuccessfully)
                {
                    var host = reverse.Result.HostName;
                    if (IsUsefulName(host) && host != address) name = host;
                }
            }
            catch
            {
                // No PTR record.
            }
        }

        if (Cache.Count >= MaxCached) Cache.Clear(); // crude, but keeps a long-running session bounded
        Cache[address] = (name, DateTime.UtcNow);
        return name;
    }

    static string? FromDnsCache(string address)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(@"root\StandardCimv2",
                $"SELECT Entry, Type, Data FROM MSFT_DNSClientCache WHERE Data = '{address.Replace("'", "")}' AND (Type = 1 OR Type = 28)");
            return searcher.Get().Cast<ManagementObject>()
                .Select(o => o["Entry"] as string)
                .Where(IsUsefulName)
                .OrderBy(e => e!.Length)
                .FirstOrDefault();
        }
        catch
        {
            return null;
        }
    }

    static bool IsUsefulName(string? name) =>
        !string.IsNullOrEmpty(name)
        && !IPAddress.TryParse(name, out _)
        && !name.EndsWith(".arpa", StringComparison.OrdinalIgnoreCase)
        && !name.EndsWith(".arpa.", StringComparison.OrdinalIgnoreCase);
}

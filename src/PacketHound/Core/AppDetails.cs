using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace PacketHound.Core;

/// <summary>Friendly name, publisher and icon for a program path.</summary>
public sealed class AppDetails
{
    static readonly Dictionary<string, AppDetails> Cache = new(StringComparer.OrdinalIgnoreCase);

    public string Path { get; private init; } = "";
    public string DisplayName { get; private init; } = "";
    public string Publisher { get; private init; } = "";
    public ImageSource? Icon { get; private init; }

    public static AppDetails For(string path)
    {
        if (Cache.TryGetValue(path, out var cached)) return cached;
        var d = Create(path);
        Cache[path] = d;
        return d;
    }

    static AppDetails Create(string path)
    {
        if (path.Equals("System", StringComparison.OrdinalIgnoreCase))
            return new AppDetails { Path = "System", DisplayName = "Windows Kernel (System)", Publisher = "Microsoft Windows" };

        string name = System.IO.Path.GetFileNameWithoutExtension(path);
        string publisher = "";
        try
        {
            if (File.Exists(path))
            {
                var vi = FileVersionInfo.GetVersionInfo(path);
                var description = vi.FileDescription?.Trim();
                var product = vi.ProductName?.Trim();
                if (!string.IsNullOrEmpty(description) && description.Length > 2) name = description;
                else if (!string.IsNullOrEmpty(product)) name = product;
                publisher = vi.CompanyName?.Trim() ?? "";
            }
        }
        catch
        {
            // Keep the file name.
        }

        return new AppDetails { Path = path, DisplayName = name, Publisher = publisher, Icon = LoadIcon(path) };
    }

    static ImageSource? LoadIcon(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            using var icon = System.Drawing.Icon.ExtractAssociatedIcon(path);
            if (icon == null) return null;
            var src = Imaging.CreateBitmapSourceFromHIcon(icon.Handle, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
            src.Freeze();
            return src;
        }
        catch
        {
            return null;
        }
    }
}

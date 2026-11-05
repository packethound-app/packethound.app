<?php
// Shared helpers. Works on PHP 7.4 and later.

declare(strict_types=1);

const SITE_ROOT = __DIR__ . '/..';
const DOWNLOADS_DIR = SITE_ROOT . '/downloads';
const SCREENSHOTS_DIR = SITE_ROOT . '/screenshots';
const DATA_DIR = SITE_ROOT . '/data';

function site(?string $key = null)
{
    static $config = null;
    if ($config === null) {
        $config = require SITE_ROOT . '/config.php';
    }
    return $key === null ? $config : ($config[$key] ?? null);
}

/** Escape for HTML. */
function e($value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/** URL of a file under the site, with its modification time appended so browsers pick up changes. */
function asset(string $path): string
{
    $file = SITE_ROOT . '/' . $path;
    return $path . (is_file($file) ? '?v=' . filemtime($file) : '');
}

/** Path of the site's root folder on the server, e.g. "/" or "/packethound/". */
function base_path(): string
{
    return rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/')), '/') . '/';
}

/** Absolute URL of this site's root, e.g. https://example.com/ (for social-preview tags). */
function base_url(): string
{
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    if (!preg_match('/^[A-Za-z0-9.\-:\[\]]+$/', $host)) {
        $host = 'localhost';
    }
    return ($https ? 'https' : 'http') . '://' . $host . base_path();
}

/**
 * The "Buy me a coffee" button, or '' if no donate_url is set. The button image is served from
 * this site (not Buy Me a Coffee's CDN), so pages load nothing from other websites.
 */
function donate_button(string $size = 'large'): string
{
    $url = (string) site('donate_url');
    if ($url === '') {
        return '';
    }
    return '<a class="donate donate-' . e($size) . '" href="' . e($url) . '" target="_blank" rel="noopener">'
        . '<img src="' . e(asset('assets/img/bmc-button.png')) . '" alt="Buy me a coffee" width="545" height="153"></a>';
}

function human_size(int $bytes): string
{
    if ($bytes >= 1048576) {
        return number_format($bytes / 1048576, 1) . ' MB';
    }
    return number_format($bytes / 1024) . ' KB';
}

// ------------------------------------------------------------------ releases

/** Every installer in downloads/, newest version first. */
function releases(): array
{
    static $releases = null;
    if ($releases !== null) {
        return $releases;
    }
    $releases = [];
    foreach ((is_dir(DOWNLOADS_DIR) ? scandir(DOWNLOADS_DIR) : false) ?: [] as $file) {
        if (!preg_match('/^PacketHound-Setup-(\d+\.\d+\.\d+)\.exe$/', $file, $m)) {
            continue;
        }
        $path = DOWNLOADS_DIR . '/' . $file;
        $notes = site('releases')[$m[1]] ?? [];
        $releases[] = [
            'version' => $m[1],
            'file' => $file,
            'path' => $path,
            'size' => filesize($path),
            'date' => !empty($notes['date']) ? strtotime($notes['date']) : filemtime($path),
            'notes' => $notes['notes'] ?? [],
        ];
    }
    usort($releases, function ($a, $b) {
        return version_compare($b['version'], $a['version']);
    });
    return $releases;
}

function latest_release(): ?array
{
    return releases()[0] ?? null;
}

function find_release(string $version): ?array
{
    foreach (releases() as $release) {
        if ($release['version'] === $version) {
            return $release;
        }
    }
    return null;
}

/** SHA-256 of an installer. Cached in data/ because hashing ~70 MB on every page view is slow. */
function release_sha256(array $release): string
{
    $key = $release['file'] . '|' . $release['size'] . '|' . filemtime($release['path']);
    $cache = read_json(DATA_DIR . '/hashes.json');
    if (isset($cache[$key])) {
        return $cache[$key];
    }
    $hash = hash_file('sha256', $release['path']) ?: '';
    update_json(DATA_DIR . '/hashes.json', function (array $data) use ($key, $hash, $release) {
        // Drop entries for older uploads of the same file.
        foreach (array_keys($data) as $k) {
            if (strpos($k, $release['file'] . '|') === 0) {
                unset($data[$k]);
            }
        }
        $data[$key] = $hash;
        return $data;
    });
    return $hash;
}

// ------------------------------------------------------------------ download counter

/** Counts are kept per version in data/downloads.json (only numbers, nothing about who downloaded). */
function record_download(string $version): void
{
    $agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
    if ($agent === '' || preg_match('/bot|crawl|spider|slurp|preview|facebookexternalhit|curl|wget/i', $agent)) {
        return; // don't count link checkers and crawlers
    }
    update_json(DATA_DIR . '/downloads.json', function (array $data) use ($version) {
        $data[$version] = ($data[$version] ?? 0) + 1;
        return $data;
    });
}

function read_json(string $path): array
{
    if (!is_file($path)) {
        return [];
    }
    $data = json_decode((string) @file_get_contents($path), true);
    return is_array($data) ? $data : [];
}

/** Read-modify-write a JSON file under an exclusive lock. Silently does nothing if data/ isn't writable. */
function update_json(string $path, callable $change): void
{
    $handle = @fopen($path, 'c+');
    if ($handle === false) {
        return;
    }
    try {
        if (!flock($handle, LOCK_EX)) {
            return;
        }
        $data = json_decode((string) stream_get_contents($handle), true);
        $data = $change(is_array($data) ? $data : []);
        ftruncate($handle, 0);
        rewind($handle);
        fwrite($handle, (string) json_encode($data, JSON_PRETTY_PRINT));
        fflush($handle);
        flock($handle, LOCK_UN);
    } finally {
        fclose($handle);
    }
}

// ------------------------------------------------------------------ screenshots

/**
 * Images in screenshots/, in file-name order. Titles and captions come from screenshots/captions.json
 * ({"file.png": {"title": "...", "caption": "..."}}); without an entry the file name is used.
 */
function screenshots(): array
{
    $captions = read_json(SCREENSHOTS_DIR . '/captions.json');
    $shots = [];
    $files = (is_dir(SCREENSHOTS_DIR) ? scandir(SCREENSHOTS_DIR) : false) ?: [];
    natcasesort($files);
    foreach ($files as $file) {
        if (!preg_match('/\.(png|jpe?g|webp)$/i', $file)) {
            continue;
        }
        $path = SCREENSHOTS_DIR . '/' . $file;
        $size = @getimagesize($path);
        $fallback = ucfirst(trim(preg_replace('/[-_]+/', ' ', preg_replace('/^\d+[-_ ]*|\.\w+$/', '', $file))));
        $shots[] = [
            'src' => 'screenshots/' . rawurlencode($file) . '?v=' . filemtime($path),
            'width' => $size[0] ?? null,
            'height' => $size[1] ?? null,
            'title' => $captions[$file]['title'] ?? $fallback,
            'caption' => $captions[$file]['caption'] ?? '',
        ];
    }
    return $shots;
}

<?php
// Counts a download, then sends the browser to the installer file itself (Apache serves it).
//   get.php            latest version
//   get.php?v=1.2.3    a specific version
require __DIR__ . '/inc/functions.php';

$version = isset($_GET['v']) && is_string($_GET['v']) ? $_GET['v'] : '';
$release = $version !== '' ? find_release($version) : latest_release();

if ($release === null) {
    http_response_code(404);
    require __DIR__ . '/404.php';
    exit;
}

record_download($release['version']);
header('Cache-Control: no-store');
header('Location: downloads/' . rawurlencode($release['file']), true, 302);

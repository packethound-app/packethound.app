<?php
// Latest version, for the app's update check. The app only reads "version" (plus "released" and
// "notes" for display) and always sends people to download.php itself; it never downloads from here.
require __DIR__ . '/inc/functions.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: public, max-age=600');
header('X-Robots-Tag: noindex');

$latest = latest_release();
if ($latest === null) {
    http_response_code(404);
    echo json_encode(['error' => 'No release published yet']);
    exit;
}

echo json_encode([
    'version' => $latest['version'],
    'released' => date('Y-m-d', $latest['date']),
    'notes' => array_values($latest['notes']),
],JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

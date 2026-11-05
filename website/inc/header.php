<?php
/**
 * Page header. Set before including:
 *   $title       page title (the site name is appended), or null on the home page
 *   $description meta description (defaults to the site description)
 *   $active      'home' | 'download' | 'privacy' — highlights the nav link
 *   $use_base    true on pages that can be shown at any address (the 404 page), so relative links
 *                resolve from the site root
 */
$title = $title ?? null;
$use_base = $use_base ?? false;
$description = $description ?? site('description');
$active = $active ?? '';
$fullTitle = $title ? $title . ' · ' . site('name') : site('name') . ' · ' . site('tagline');
$latest = latest_release();
?>
<!doctype html>
<html lang="en-GB">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <?php if ($use_base): ?><base href="<?= e(base_path()) ?>"><?php endif; ?>
    <title><?= e($fullTitle) ?></title>
    <meta name="description" content="<?= e($description) ?>">
    <meta name="theme-color" content="#051C37">
    <link rel="icon" href="<?= e(asset('favicon.ico')) ?>" sizes="any">
    <link rel="icon" href="<?= e(asset('assets/img/icon-32.png')) ?>" type="image/png" sizes="32x32">
    <link rel="apple-touch-icon" href="<?= e(asset('assets/img/icon-180.png')) ?>">
    <link rel="stylesheet" href="<?= e(asset('assets/css/site.css')) ?>">
    <script src="<?= e(asset('assets/js/site.js')) ?>" defer></script>

    <meta property="og:type" content="website">
    <meta property="og:site_name" content="<?= e(site('name')) ?>">
    <meta property="og:title" content="<?= e($fullTitle) ?>">
    <meta property="og:description" content="<?= e($description) ?>">
    <meta property="og:image" content="<?= e(base_url() . 'assets/img/social-preview.png') ?>">
    <meta name="twitter:card" content="summary_large_image">
</head>
<body>
<a class="skip-link" href="#main">Skip to content</a>

<header class="site-header">
    <div class="wrap header-inner">
        <a class="brand" href="./" aria-label="<?= e(site('name')) ?> home">
            <img src="<?= e(asset('assets/img/icon-192.png')) ?>" alt="" width="36" height="36">
            <span class="wordmark"><span class="wm-a">Packet</span><span class="wm-b">Hound</span></span>
        </a>
        <button class="nav-toggle" type="button" aria-expanded="false" aria-controls="site-nav">
            <span class="sr-only">Menu</span>
            <svg width="22" height="22" viewBox="0 0 24 24" aria-hidden="true"><path d="M3 6h18M3 12h18M3 18h18" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
        </button>
        <nav id="site-nav" class="site-nav" aria-label="Main">
            <a href="./#features">Features</a>
            <?php if (screenshots()): ?><a href="./#screenshots">Screenshots</a><?php endif; ?>
            <a href="./#how-it-works">How it works</a>
            <a href="./#faq">FAQ</a>
            <a class="btn btn-primary btn-small<?= $active === 'download' ? ' is-active' : '' ?>" href="download.php">Download</a>
        </nav>
    </div>
</header>

<main id="main">

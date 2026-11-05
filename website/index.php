<?php
require __DIR__ . '/inc/functions.php';

$active = 'home';
require __DIR__ . '/inc/header.php';

$shots = screenshots();

$features = [
    ['ask', 'Asks once, remembers', 'The first time an app tries to connect, you see who made it, where it\'s going and on which port. Click Allow or Block and PacketHound never asks about it again.'],
    ['windows', 'Windows stays quiet', 'Windows\' own components are allowed automatically, so you\'re only asked about the apps you installed, not about hundreds of system services.'],
    ['shield', 'Hard to fool', 'A program only counts as Windows if it lives in a Windows folder, is owned by the system and carries a valid Microsoft Windows signature. Copying malware into System32 doesn\'t get it a free pass.'],
    ['terminal', 'Watches risky tools', 'Malware loves PowerShell, curl, certutil, mshta and rundll32 for downloading payloads. PacketHound still asks before those connect, even though they\'re part of Windows.'],
    ['layers', 'Built on Windows Firewall', 'No kernel driver, nothing hidden. Every decision is an ordinary Windows Firewall rule you can see in wf.msc, and it keeps working even when PacketHound is closed.'],
    ['focus', 'Never steals your typing', 'Prompts appear on top without taking keyboard focus, so you can\'t answer one by accident while you\'re typing.'],
    ['list', 'Rules at a glance', 'Flip any app between Allow and Block with one switch. Search, sort and see when each decision was made.'],
    ['activity', 'See what was blocked', 'The activity log shows every blocked attempt with its hostname, port and what happened next. Double-click to copy the IP address.'],
];

/** Small line icons (inline SVG, inherit the text colour). */
function feature_icon(string $name): string
{
    $paths = [
        'ask' => '<path d="M21 12a8 8 0 0 1-11.6 7.1L4 20l1-4.6A8 8 0 1 1 21 12Z"/><path d="M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.6.3-1 .9-1 1.6v.1"/><path d="M12 17h.01"/>',
        'windows' => '<rect x="3" y="3" width="8" height="8" rx="1"/><rect x="13" y="3" width="8" height="8" rx="1"/><rect x="3" y="13" width="8" height="8" rx="1"/><rect x="13" y="13" width="8" height="8" rx="1"/>',
        'shield' => '<path d="M12 3 4 6v6c0 4.4 3.4 8.3 8 9 4.6-.7 8-4.6 8-9V6l-8-3Z"/><path d="m9 12 2 2 4-4"/>',
        'terminal' => '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3"/><path d="M13 15h4"/>',
        'layers' => '<path d="m12 3 9 5-9 5-9-5 9-5Z"/><path d="m3 13 9 5 9-5"/>',
        'focus' => '<rect x="3" y="6" width="18" height="12" rx="2"/><path d="M7 10h.01M11 10h.01M15 10h.01M7 14h10"/>',
        'list' => '<rect x="3" y="5" width="7" height="4" rx="2"/><rect x="3" y="15" width="7" height="4" rx="2"/><path d="M14 7h7M14 17h7"/>',
        'activity' => '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
    ];
    return '<svg viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
        . $paths[$name] . '</svg>';
}

$latest = latest_release();
?>

<section class="hero">
    <div class="wrap hero-inner">
        <div class="hero-text">
            <p class="eyebrow">Outbound firewall for Windows</p>
            <h1><?= e(site('tagline')) ?></h1>
            <p class="lead">Most firewalls only watch what comes <em>in</em>. PacketHound sniffs out what goes <em>out</em>: the first time an app tries to connect to the internet, it asks you to <strong>Allow</strong> or <strong>Block</strong>, and remembers your answer.</p>
            <div class="hero-actions">
                <?php if ($latest): ?>
                    <a class="btn btn-primary btn-large" href="download.php">
                        <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 4v11m0 0-4-4m4 4 4-4M5 20h14"/></svg>
                        Download for Windows
                    </a>
                    <p class="hero-meta">Free · Version <?= e($latest['version']) ?> · <?= e(human_size($latest['size'])) ?> · Windows 10 &amp; 11</p>
                <?php else: ?>
                    <span class="btn btn-primary btn-large is-disabled" aria-disabled="true">Download coming soon</span>
                <?php endif; ?>
            </div>
        </div>
        <div class="hero-art">
            <img src="<?= e(asset('assets/img/logo.png')) ?>" alt="PacketHound: a beagle sniffing a trail of network packets" width="384" height="256">
        </div>
    </div>
</section>

<section id="features" class="section">
    <div class="wrap">
        <div class="section-head">
            <h2>Every connection, your call</h2>
            <p>PacketHound turns Windows Firewall into an "ask me first" firewall for outgoing connections, without drowning you in questions about Windows itself.</p>
        </div>
        <div class="feature-grid">
            <?php foreach ($features as [$icon, $heading, $text]): ?>
                <article class="feature">
                    <div class="feature-icon"><?= feature_icon($icon) ?></div>
                    <h3><?= e($heading) ?></h3>
                    <p><?= e($text) ?></p>
                </article>
            <?php endforeach; ?>
        </div>
    </div>
</section>

<?php if ($shots): ?>
<section id="screenshots" class="section section-alt">
    <div class="wrap">
        <div class="section-head">
            <h2>Screenshots</h2>
            <p>Click any picture to see it full size.</p>
        </div>
        <div class="gallery">
            <?php foreach ($shots as $i => $shot): ?>
                <figure class="shot">
                    <button type="button" class="shot-open" data-index="<?= $i ?>" aria-label="Enlarge: <?= e($shot['title']) ?>">
                        <img src="<?= e($shot['src']) ?>" alt="<?= e($shot['title']) ?>" loading="lazy"
                            <?php if ($shot['width']): ?>width="<?= (int) $shot['width'] ?>" height="<?= (int) $shot['height'] ?>"<?php endif; ?>>
                    </button>
                    <figcaption>
                        <strong><?= e($shot['title']) ?></strong>
                        <?php if ($shot['caption']): ?><span><?= e($shot['caption']) ?></span><?php endif; ?>
                    </figcaption>
                </figure>
            <?php endforeach; ?>
        </div>
    </div>
    <dialog class="lightbox" aria-label="Screenshot">
        <button type="button" class="lightbox-close" aria-label="Close">&times;</button>
        <button type="button" class="lightbox-prev" aria-label="Previous screenshot">&#8249;</button>
        <figure>
            <img src="" alt="">
            <figcaption></figcaption>
        </figure>
        <button type="button" class="lightbox-next" aria-label="Next screenshot">&#8250;</button>
    </dialog>
</section>
<?php endif; ?>

<section id="how-it-works" class="section<?= $shots ? '' : ' section-alt' ?>">
    <div class="wrap">
        <div class="section-head">
            <h2>How it works</h2>
            <p>No drivers, no background service of its own: PacketHound builds on the firewall that's already part of Windows.</p>
        </div>
        <ol class="steps">
            <li>
                <h3>Unknown apps are blocked</h3>
                <p>PacketHound switches Windows Firewall's outgoing default to <em>block</em>, so a program without a rule can't reach the internet.</p>
            </li>
            <li>
                <h3>PacketHound notices</h3>
                <p>Windows logs each blocked attempt. PacketHound watches that log, checks whether the program is part of Windows, and allows it quietly if so.</p>
            </li>
            <li>
                <h3>You decide</h3>
                <p>For everything else you get a prompt showing the app, its publisher and where it's connecting. Your answer becomes a permanent firewall rule.</p>
            </li>
        </ol>

        <div class="callout">
            <h3>Good to know</h3>
            <ul>
                <li><strong>The first attempt fails.</strong> PacketHound learns about an app because its connection was blocked, so after you click Allow the app has to try again. Most do so automatically; a browser just needs a refresh.</li>
                <li><strong>Rules cover the whole app</strong>, not individual websites or ports. You can narrow a rule in Windows Firewall (wf.msc) if you need to.</li>
                <li><strong>Work PCs:</strong> if your organisation manages firewall settings through Group Policy, those settings win.</li>
            </ul>
        </div>
    </div>
</section>

<section id="faq" class="section section-alt">
    <div class="wrap narrow">
        <div class="section-head">
            <h2>Questions</h2>
        </div>
        <div class="faq">
            <details>
                <summary>Is PacketHound free?</summary>
                <p>Yes. There's no trial, no account and no adverts.<?php if (site('donate_url')): ?> If you find it useful, you can <a href="<?= e(site('donate_url')) ?>" target="_blank" rel="noopener">buy me a coffee</a>.<?php endif; ?></p>
            </details>
            <details>
                <summary>Does PacketHound send my data anywhere?</summary>
                <p>No. PacketHound doesn't collect anything and has no analytics. It looks up the names of the servers apps try to reach (a normal DNS lookup), so it can show you "example.com" instead of a bare IP address, and once a week it asks this website whether there's a newer version. That request contains nothing about you or your PC, and you can turn it off. See the <a href="privacy.php">privacy page</a>.</p>
            </details>
            <details>
                <summary>Windows says "Windows protected your PC". Is it safe?</summary>
                <p>That's Microsoft SmartScreen's warning for programs it hasn't seen many people download yet. Click <strong>More info</strong>, then <strong>Run anyway</strong>. You can check the file is exactly the one published here by comparing its SHA-256 checksum with the one on the <a href="download.php#verify">download page</a>.</p>
            </details>
            <details>
                <summary>Why does it need administrator rights?</summary>
                <p>Changing Windows Firewall settings and reading the Security event log both require them, so Windows asks you to confirm when you start PacketHound. If you let it start when you sign in, it starts without asking.</p>
            </details>
            <details>
                <summary>What happens when PacketHound isn't running?</summary>
                <p>Your rules keep working: they're ordinary Windows Firewall rules. When you exit, PacketHound asks whether to keep blocking apps that don't have a rule yet. Either way, apps you blocked stay blocked.</p>
            </details>
            <details>
                <summary>I blocked something by mistake. How do I undo it?</summary>
                <p>Open PacketHound from the notification area, find the app on the Rules tab and flip its switch to Allow. Or delete the rule, and PacketHound will ask about the app again next time.</p>
            </details>
            <details>
                <summary>Can I pause it?</summary>
                <p>Yes. Right-click the tray icon and choose <strong>Pause protection</strong>. While paused, apps without a rule can connect freely; your Block rules still apply.</p>
            </details>
            <details>
                <summary>Does it work alongside my antivirus?</summary>
                <p>Yes. PacketHound uses Windows Firewall, which works alongside Microsoft Defender and most antivirus software. If a third-party security suite has replaced Windows Firewall with its own, PacketHound can't work, because there's no Windows Firewall to manage.</p>
            </details>
            <details>
                <summary>How do I uninstall it?</summary>
                <p>From Windows Settings › Apps. The uninstaller asks whether to delete PacketHound's firewall rules, then puts Windows Firewall's settings back the way they were before you installed it.</p>
            </details>
        </div>
    </div>
</section>

<?php if ($latest): ?>
<section class="cta">
    <div class="wrap cta-inner">
        <div>
            <h2>Put your PC on a lead</h2>
            <p>Free for Windows 10 and 11. Installs in a minute, uninstalls cleanly.</p>
        </div>
        <a class="btn btn-accent btn-large" href="download.php">Download PacketHound <?= e($latest['version']) ?></a>
    </div>
</section>
<?php endif; ?>

<?php require __DIR__ . '/inc/footer.php'; ?>

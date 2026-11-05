<?php
require __DIR__ . '/inc/functions.php';

$title = 'Privacy';
$description = 'What PacketHound and this website do (and don\'t do) with your data.';
$active = 'privacy';
require __DIR__ . '/inc/header.php';
?>

<section class="page-head">
    <div class="wrap narrow">
        <h1>Privacy</h1>
        <p class="lead">Short version: PacketHound doesn't collect anything, and neither does this website.</p>
    </div>
</section>

<section class="section section-tight">
    <div class="wrap narrow prose">
        <h2>The PacketHound app</h2>
        <ul>
            <li>PacketHound doesn't collect, store or send any personal data or usage statistics.</li>
            <li>It has no accounts, no adverts and no analytics.</li>
            <li>Its settings and a log file stay on your PC, in <code>C:\ProgramData\PacketHound</code>. The uninstaller deletes them.</li>
            <li>It causes only two kinds of network activity:
                <ul>
                    <li><strong>Server names.</strong> To show you which server an app is trying to reach, it looks up the server's name using your PC's normal DNS settings.</li>
                    <li><strong>Update checks.</strong> Once a week it asks this website for the latest version number (the file <code>version.php</code>). The request says only that it's PacketHound and which version; nothing about you, your PC or your rules is sent. It never downloads or installs anything itself. You can turn this off in PacketHound's Settings, or check by hand with <em>Check now</em>.</li>
                </ul>
            </li>
            <li>Your firewall rules are stored by Windows Firewall itself, on your PC.</li>
        </ul>

        <h2>This website</h2>
        <ul>
            <li>No cookies, no tracking, no analytics and nothing loaded from other websites.</li>
            <li>We count how many times each version is downloaded. Only the number is stored, nothing about who downloaded it.</li>
            <?php if (site('donate_url')): ?>
                <li>The "Buy me a coffee" button is just a link: nothing is loaded from Buy Me a Coffee until you click it. Their own privacy policy applies on their site.</li>
            <?php endif; ?>
            <li>Like almost every web server, ours keeps standard access logs (such as IP addresses and pages requested) for security and troubleshooting. They aren't used for anything else or shared.</li>
        </ul>

        <?php if (site('contact_email')): ?>
            <h2>Questions</h2>
            <p>Email <a href="mailto:<?= e(site('contact_email')) ?>"><?= e(site('contact_email')) ?></a>.</p>
        <?php endif; ?>
    </div>
</section>

<?php require __DIR__ . '/inc/footer.php'; ?>

<?php
require __DIR__ . '/inc/functions.php';

$title = 'Download';
$description = 'Download PacketHound, a free outbound firewall for Windows 10 and 11.';
$active = 'download';
require __DIR__ . '/inc/header.php';

$all = releases();
$latest = $all[0] ?? null;
?>

<section class="page-head">
    <div class="wrap narrow">
        <h1>Download PacketHound</h1>
        <p class="lead">Free for Windows 10 and 11. One installer, nothing else needed.</p>
    </div>
</section>

<section class="section section-tight">
    <div class="wrap narrow">
        <?php if (!$latest): ?>
            <div class="card">
                <h2>Coming soon</h2>
                <p>The first release isn't available yet. Please check back shortly.</p>
            </div>
        <?php else: $hash = release_sha256($latest); ?>
            <div class="card download-card">
                <img class="download-icon" src="<?= e(asset('assets/img/icon-192.png')) ?>" alt="" width="96" height="96">
                <div class="download-info">
                    <h2>PacketHound <?= e($latest['version']) ?></h2>
                    <p class="muted">Released <?= e(date('j F Y', $latest['date'])) ?> · <?= e(human_size($latest['size'])) ?> · 64-bit installer</p>
                    <a class="btn btn-primary btn-large" href="get.php?v=<?= e(rawurlencode($latest['version'])) ?>">
                        <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 4v11m0 0-4-4m4 4 4-4M5 20h14"/></svg>
                        Download <?= e($latest['file']) ?>
                    </a>
                </div>
            </div>

            <?php if (site('donate_url')): ?>
                <div class="card support-card">
                    <div>
                        <h3>Enjoying PacketHound?</h3>
                        <p>It's free, with no adverts or tracking. If it's useful to you, a coffee helps keep it going.</p>
                    </div>
                    <?= donate_button('large') ?>
                </div>
            <?php endif; ?>

            <div class="grid-2">
                <div class="card">
                    <h3>Requirements</h3>
                    <ul class="ticks">
                        <?php foreach (site('requirements') as $req): ?>
                            <li><?= e($req) ?></li>
                        <?php endforeach; ?>
                    </ul>
                </div>
                <div class="card">
                    <h3>Installing</h3>
                    <ol class="numbered">
                        <li>Run the installer and click <strong>Yes</strong> when Windows asks for permission.</li>
                        <li>When PacketHound first starts, it explains what it will change and asks whether to turn protection on.</li>
                        <li>Let it start when you sign in, so you're protected from the moment Windows starts.</li>
                    </ol>
                </div>
            </div>

            <div class="card notice">
                <h3>"Windows protected your PC"?</h3>
                <p>Microsoft SmartScreen shows this for programs it hasn't seen many people download yet. It isn't a virus warning. Click <strong>More info</strong>, then <strong>Run anyway</strong>. If you'd like to be sure the file hasn't been tampered with, check its fingerprint below.</p>
            </div>

            <div class="card" id="verify">
                <h3>Check the download</h3>
                <p>The SHA-256 fingerprint of <code><?= e($latest['file']) ?></code> is:</p>
                <div class="hash">
                    <code id="sha256"><?= e($hash) ?></code>
                    <button type="button" class="btn btn-small copy-btn" data-copy="#sha256">Copy</button>
                </div>
                <p>To check it, open PowerShell in your Downloads folder and run:</p>
                <pre><code>Get-FileHash .\<?= e($latest['file']) ?></code></pre>
                <p class="muted">The <em>Hash</em> it prints should match the fingerprint above exactly.</p>
            </div>

            <?php if ($latest['notes']): ?>
                <div class="card">
                    <h3>What's new in <?= e($latest['version']) ?></h3>
                    <ul class="ticks">
                        <?php foreach ($latest['notes'] as $note): ?>
                            <li><?= e($note) ?></li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            <?php endif; ?>

            <div class="card">
                <h3>Uninstalling</h3>
                <p>Go to Windows Settings › Apps › Installed apps, find PacketHound and choose Uninstall. It asks whether to delete the firewall rules it created, then puts Windows Firewall back the way it was before PacketHound.</p>
            </div>

            <?php if (count($all) > 1): ?>
                <div class="card">
                    <h3>Earlier versions</h3>
                    <table class="versions">
                        <thead><tr><th>Version</th><th>Released</th><th>Size</th><th></th></tr></thead>
                        <tbody>
                        <?php foreach (array_slice($all, 1) as $r): ?>
                            <tr>
                                <td><?= e($r['version']) ?></td>
                                <td><?= e(date('j M Y', $r['date'])) ?></td>
                                <td><?= e(human_size($r['size'])) ?></td>
                                <td><a href="get.php?v=<?= e(rawurlencode($r['version'])) ?>">Download</a></td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>
        <?php endif; ?>
    </div>
</section>

<?php require __DIR__ . '/inc/footer.php'; ?>

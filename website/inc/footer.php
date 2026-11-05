</main>

<footer class="site-footer">
    <div class="wrap footer-inner">
        <div class="footer-brand">
            <img src="<?= e(asset('assets/img/icon-192.png')) ?>" alt="" width="28" height="28">
            <span>&copy; <?= date('Y') ?> <?= e(site('name')) ?></span>
        </div>
        <nav class="footer-nav" aria-label="Footer">
            <a href="download.php">Download</a>
            <a href="./#faq">FAQ</a>
            <a href="privacy.php">Privacy</a>
            <?php if (site('source_url')): ?><a href="<?= e(site('source_url')) ?>" rel="noopener">Source code</a><?php endif; ?>
            <?php if (site('contact_email')): ?><a href="mailto:<?= e(site('contact_email')) ?>">Contact</a><?php endif; ?>
        </nav>
        <?= donate_button('small') ?>
        <p class="footer-note">Windows is a trademark of Microsoft Corporation. <?= e(site('name')) ?> is not affiliated with Microsoft.</p>
    </div>
</footer>
</body>
</html>

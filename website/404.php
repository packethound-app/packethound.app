<?php
require_once __DIR__ . '/inc/functions.php';

if (!headers_sent()) {
    http_response_code(404);
}
$title = 'Page not found';
$use_base = true;
require __DIR__ . '/inc/header.php';
?>

<section class="page-head page-404">
    <div class="wrap narrow">
        <img src="<?= e(asset('assets/img/logo.png')) ?>" alt="" width="288" height="192">
        <h1>Lost the scent</h1>
        <p class="lead">We couldn't find that page. It may have moved, or the link may be wrong.</p>
        <p><a class="btn btn-primary" href="./">Back to the home page</a></p>
    </div>
</section>

<?php require __DIR__ . '/inc/footer.php'; ?>

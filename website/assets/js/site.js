// PacketHound website: mobile menu, screenshot viewer, copy buttons. No libraries.
(function () {
    'use strict';

    // Mobile menu
    var toggle = document.querySelector('.nav-toggle');
    var nav = document.getElementById('site-nav');
    if (toggle && nav) {
        toggle.addEventListener('click', function () {
            var open = nav.classList.toggle('is-open');
            toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
        });
        nav.addEventListener('click', function (e) {
            if (e.target.closest('a')) {
                nav.classList.remove('is-open');
                toggle.setAttribute('aria-expanded', 'false');
            }
        });
    }

    // Screenshot viewer
    var dialog = document.querySelector('.lightbox');
    var buttons = Array.prototype.slice.call(document.querySelectorAll('.shot-open'));
    if (dialog && buttons.length && typeof dialog.showModal === 'function') {
        var img = dialog.querySelector('img');
        var caption = dialog.querySelector('figcaption');
        var current = 0;

        var show = function (index) {
            current = (index + buttons.length) % buttons.length;
            var figure = buttons[current].closest('figure');
            var thumb = buttons[current].querySelector('img');
            img.src = thumb.src;
            img.alt = thumb.alt;
            caption.innerHTML = figure.querySelector('figcaption').innerHTML;
        };

        buttons.forEach(function (button, i) {
            button.addEventListener('click', function () {
                show(i);
                dialog.showModal();
            });
        });
        dialog.querySelector('.lightbox-close').addEventListener('click', function () { dialog.close(); });
        dialog.querySelector('.lightbox-prev').addEventListener('click', function () { show(current - 1); });
        dialog.querySelector('.lightbox-next').addEventListener('click', function () { show(current + 1); });
        var single = buttons.length === 1;
        dialog.querySelector('.lightbox-prev').hidden = single;
        dialog.querySelector('.lightbox-next').hidden = single;

        // Click outside the picture closes; arrow keys move between pictures.
        dialog.addEventListener('click', function (e) {
            if (e.target === dialog) dialog.close();
        });
        dialog.addEventListener('keydown', function (e) {
            if (e.key === 'ArrowLeft') show(current - 1);
            if (e.key === 'ArrowRight') show(current + 1);
        });
    }

    // Copy buttons (download page checksum)
    document.querySelectorAll('[data-copy]').forEach(function (button) {
        button.addEventListener('click', function () {
            var source = document.querySelector(button.getAttribute('data-copy'));
            if (!source || !navigator.clipboard) return;
            navigator.clipboard.writeText(source.textContent.trim()).then(function () {
                var label = button.textContent;
                button.textContent = 'Copied';
                button.classList.add('is-done');
                setTimeout(function () {
                    button.textContent = label;
                    button.classList.remove('is-done');
                }, 2000);
            });
        });
    });
})();

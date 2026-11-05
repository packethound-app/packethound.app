<?php
// Site settings. Everything you're likely to edit lives here.
// The download itself is found automatically: the newest downloads/PacketHound-Setup-<version>.exe.

return [
    'name' => 'PacketHound',
    'tagline' => 'Know which apps are calling home.',
    'description' => 'PacketHound is a free outbound firewall for Windows. The first time an app tries to '
        . 'connect to the internet, it asks you: Allow or Block.',

    // Leave empty to hide. Shown in the footer and on the privacy page.
    'contact_email' => '',
    // Leave empty to hide. E.g. a GitHub repository, if you publish the source code.
    'source_url' => 'https://github.com/packethound-app/packethound.app',
    // "Buy me a coffee" button (download page, footer, FAQ). Leave empty to hide.
    'donate_url' => 'https://www.buymeacoffee.com/Henrys_Cat',

    // Shown under "Requirements" on the download page.
    'requirements' => [
        'Windows 10 (version 1809 or later) or Windows 11, 64-bit',
        'An administrator account (PacketHound changes Windows Firewall settings)',
        'Windows Firewall switched on (it is by default)',
        'Nothing else to install: .NET is included',
    ],

    // Release notes, newest first. The version must match the installer's file name.
    // 'date' is optional (YYYY-MM-DD); without it the file's upload date is shown.
    'releases' => [
        '1.0.0' => [
            'date' => '2026-11-05',
            'notes' => [
                'First release.',
                'Allow / Block prompt for apps connecting for the first time, with publisher, destination and port.',
                'Windows components are allowed automatically; common download tools such as PowerShell and curl still ask.',
                'Rules list with Allow/Block switches, search and sorting; activity log with hostnames.',
                'Installer with a clean uninstall that restores Windows Firewall\'s settings.',
            ],
        ],
    ],
];

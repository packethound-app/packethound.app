# Changelog

## 1.2.0

- **Decide later** now has a home: apps you put off are listed on the Rules tab under *Waiting for your
  decision*, with a **Decide…** button to bring the prompt back. They stay blocked until you decide.
- When the wait is over, PacketHound asks again straight away if the app is still running, or the next
  time it connects.
- The main window, the tray icon and its menu show how many apps are waiting. In Activity, right-click a
  row to decide about that app or copy its IP address.
- **Timed pause**: pause protection for 5 minutes, 15 minutes or an hour, and it turns itself back on,
  even after a restart.
- **Installers and updaters** running from a temporary folder are recognised: their rules last only until
  they quit, and signed ones you allow are remembered (same file name and signer, temp folders only), so the
  next copy is let through before it even starts. PacketHound watches the temp folders to make that rule as
  the file is unpacked, and keeps the checked file locked until it quits so nothing can be swapped in.
- A timed pause warns when you exit PacketHound, since only a running PacketHound can turn protection back on.
- After you allow an installer, a notification offers to pause protection for 5 minutes in one click, for
  installers that give up after their first blocked attempt.
- Rules for programs that are no longer on the PC are highlighted as **Program not found**, and
  **Remove missing** deletes them after asking.
- The rules list has a **Status** column.
- The main window remembers its size, position and whether it was maximized.

## 1.1.0 (2026-11-06)

- The prompt can limit a rule to one IP address, one host (`api.example.com`) or a whole domain
  (`*.example.com`), instead of the whole app. Any connection is still the default.
- Rules can last forever or only until the app quits; temporary rules are removed once the app closes.
- The rules list shows what each rule applies to, and which rules are temporary.
- The prompt no longer has a close button, so it can't be dismissed by accident: choose Allow, Block or
  Decide later.
- Version number in the main window title bar.

## 1.0.0 (2026-11-05)

- First release.
- Allow / Block prompt for apps connecting for the first time, with publisher, destination and port.
- Windows components are allowed automatically; common download tools such as PowerShell and curl still ask.
- Rules list with Allow/Block switches, search and sorting; activity log with hostnames.
- Installer with a clean uninstall that restores Windows Firewall's settings.

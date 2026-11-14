# Changelog

## 1.4.0

- **Light and dark theme**: Settings › Appearance picks **Light**, **Dark** or **Same as Windows**, which
  follows the Windows app mode and switches when you change it there. Title bars follow the theme too.
- **Search the Activity list**: by app, host, IP address, protocol or result; `:80` finds port 80. Several words
  narrow it down (`chrome :80`).
- The Activity list shows the date as well as the time.
- **Default duration in the prompt**: Settings › Prompts picks what *Duration* starts on: Forever, until the app
  quits, for 1 hour, for the rest of today, or **Remember last selection**.

## 1.3.0

- **Edit rules**: an **Edit…** button on the Rules tab (or double-click a rule) changes a rule's action and what
  it applies to (any connection, one IP address, one host or a whole domain), and can make a temporary or
  timed rule permanent.
- **Every destination in the prompt**: when an app tries several addresses before you answer (a browser such as
  Tor does), each one is listed under *Applies to*, not just the latest, and your choice stays put as new ones
  arrive.
- **Copy from the prompt**: a Copy link and a right-click menu copy the IP address, host name, program path or
  command line. Activity's right-click menu can copy the host name too.
- **Allow or block for a set time**: besides *Forever* and *Until the app quits*, a rule can last **for 1 hour**
  or **for the rest of today**. It's removed when the time is up, even if PacketHound was closed meanwhile.
- **Updates that move to a new folder** (for example `app-1.2.3\` → `app-1.2.4\`) are recognised: the prompt
  says it looks like an update and offers **Same as before**, which copies your rules to the new version. If
  the new version is signed by someone else, it asks you to decide again instead.
- **Command line** for PowerShell, cmd, script interpreters (Python, Node, Java and others) and download tools,
  so you can see which script or download is behind the connection.
- **Quiet mode** for 30 minutes, 1 hour, 3 hours or until you turn it off (main window or tray menu): new apps
  are blocked without a prompt and listed under *Waiting for your decision*, and you're asked about the ones
  still running when it ends.
- **Activity is kept across restarts**, for 1 day by default (Settings › Activity: this session only, 1, 7 or
  30 days). It now shows up to 5,000 entries, and **Clear** deletes the saved copy too.
- **ARM64**: a native installer for Windows on ARM (`PacketHound-Setup-<version>-arm64.exe`).

## 1.2.0 (2026-11-06)

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

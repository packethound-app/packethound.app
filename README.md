# PacketHound

An outbound application firewall for Windows, in the spirit of Little Snitch.
When a third-party app tries to make an outgoing connection for the first time, PacketHound
asks whether to **Allow** or **Block** it. Your answer is saved as a normal **Windows Firewall rule**.
Windows itself is never prompted for.

**Download:** https://packethound.app (Windows 10 1809+ / Windows 11, 64-bit)

## How it works

PacketHound doesn't use a kernel driver. It builds on Windows Firewall:

1. **Default outbound = Block.** On all three firewall profiles (Domain, Private, Public),
   every program without an allow rule is blocked.
2. **Auditing.** Failure auditing for *Filtering Platform Connection* is switched on, so each
   blocked attempt is written to the Security log as event **5157**.
3. **Monitoring.** PacketHound watches for outbound 5157 events. For each program without a rule:
   - **Windows component** → an Allow rule is added silently (group *PacketHound (Windows components)*).
   - **Third-party app** → a prompt shows the app, publisher, destination hostname/IP, port and protocol.
     **Allow** or **Block** creates a whole-app outbound rule (group *PacketHound*).
     **Decide later** keeps it blocked and asks again after 10 minutes.

The rules are ordinary firewall rules (`wf.msc` › Outbound Rules). They keep working when
PacketHound isn't running, or after it's uninstalled.

### What counts as "Windows"

A program is treated as Windows only if **all** of these hold:

- It lives in a Windows location: `%SystemRoot%`, `Program Files\Windows *`, or the Defender
  platform folder. The third-party driver store (`System32\DriverStore`) and Windows temp
  folders don't count.
- Its file is owned by **TrustedInstaller** or **SYSTEM**.
- It has a valid **Microsoft Windows** Authenticode signature, embedded or via a security catalog.
  WHQL-signed vendor tools, such as the NVIDIA utilities Windows copies into System32, are
  signed "Microsoft Windows Hardware Compatibility Publisher". They are **not** treated as Windows.

The Windows kernel (`System`) and Microsoft-published Store packages count as Windows too.
You can turn off the Store-package rule in Settings.

By default you're **still asked** about Windows tools that malware often uses to download
payloads: PowerShell, cmd, curl, certutil, bitsadmin, mshta, rundll32, regsvr32, wscript,
msiexec, ssh and similar. You can turn this off in Settings.

On this PC, 625 of 659 programs in System32 count as Windows. The rest are those tools,
plus vendor software (NVIDIA, Vulkan, Apple Bonjour) and unsigned files.

## Build

You need the .NET 10 SDK.

```powershell
.\build.ps1                  # publish\PacketHound.exe (~750 KB); needs the .NET 10 Desktop Runtime
.\build.ps1 -SelfContained   # larger exe that needs no .NET install
.\build.ps1 -Installer       # publish\PacketHound-Setup-<version>.exe; also needs Inno Setup 7 (or 6)
```

The installer ([installer/PacketHound.iss](installer/PacketHound.iss)) is self-contained (~65 MB), so the
PC doesn't need .NET. It installs to `C:\Program Files\PacketHound`, which only admins can change. That
matters because the sign-in task runs PacketHound elevated: an exe in a user-writable folder such as
Downloads could be swapped by other software to gain admin rights. The version number comes from
`<Version>` in the project file.

Code signing isn't set up yet. The script has commented-out `SignTool` lines to enable once there's a certificate.

## Use

1. Run the installer (or `PacketHound.exe`) and accept the UAC prompt. It needs admin to change firewall and audit policy.
2. On first run it explains what it will change and asks whether to turn protection on.
   It also offers to start at sign-in. This uses an elevated Task Scheduler task, so there's
   no UAC prompt each time.
3. PacketHound lives in the notification area:
   - Left-click opens the window, or the waiting prompt if there is one.
   - Right-click has Pause/Resume and Exit.
4. The main window has three tabs:
   - **Rules**: search, flip a rule between Allow and Block with its switch (green = Allow,
     red = Block) or the Allow/Block buttons, and delete rules.
   - **Activity**: blocked attempts and what happened to each. Double-click a row to copy its IP address.
   - **Settings**, including **Updates**: once a week PacketHound asks https://packethound.app/version.php
     for the latest version number (on by default; untick to stop, or use **Check now**). If there's a newer
     version, the main window, the tray menu and a notification link to the download page. It never
     downloads or installs anything itself. Its own outbound access is a rule allowing HTTPS (TCP 443) only,
     listed on the Rules tab; switching that to Block stops update checks. The address is set in
     `Core/UpdateService.cs`.

   Click a column header to sort (click again to reverse). The arrow shows the sorted column, and the
   choice is remembered. Rules start sorted newest first. Text too long for its column is cut off
   with "…"; select the row to see all of it.

Prompts appear on top **without taking keyboard focus**, so typing never answers one by accident.

## Pause, exit and uninstall

- **Pause protection** sets the outbound default back to Allow. Your Block rules still apply.
- **Exit** asks whether to keep blocking apps without a rule while PacketHound is closed.
  Answering No pauses protection. Either way your rules stay active: blocked apps stay blocked.
- **Uninstall** from Windows Settings › Apps. The uninstaller asks whether to delete PacketHound's
  rules, then restores the original outbound default and audit setting, removes the startup task
  and deletes `C:\ProgramData\PacketHound`. It does this by running `PacketHound.exe --uninstall`
  (add `--keep-rules` to keep the rules).
  Without the installer, click **Restore Windows defaults** in Settings, then delete the exe.

## Limitations

- **The first connection fails.** PacketHound learns about an app *because* its connection was
  blocked, so after you click Allow the app has to retry. Most apps retry automatically, and a
  browser just needs a refresh. Truly holding a connection until you answer, as Little Snitch
  does, needs a signed kernel-mode WFP callout driver.
- **Rules cover the whole app**, not specific hosts or ports. You can narrow a rule in `wf.msc` afterwards.
- **Group Policy wins.** On managed PCs, firewall or audit policy pushed by a domain overrides local changes.
- **Security log volume.** Auditing also logs blocked *inbound* connections, so the Security log
  fills a little faster. It rotates automatically.
- **Path-based rules.** A new app version installed into a new folder (some updaters do this)
  is treated as a new program and prompts again.

## Project layout

```
src/PacketHound/
  App.xaml(.cs)               startup, single instance, first run, tray lifetime
  Core/Controller.cs          event → decision pipeline, prompt queue, protection on/off
  Core/FirewallManager.cs     Windows Firewall COM API (HNetCfg.FwPolicy2), rule snapshot
  Core/ConnectionMonitor.cs   Security log event 5157 subscription
  Core/AuditPolicy.cs         Filtering Platform Connection audit setting
  Core/WindowsAppClassifier.cs  "is this Windows?" rules
  Core/Signature.cs           WinVerifyTrust embedded + catalog signature verification
  Core/DevicePaths.cs         \device\harddiskvolumeN\… → C:\…
  Core/HostNames.cs           IP → hostname via the DNS client cache, then reverse DNS
  Core/AutoStart.cs           Task Scheduler logon task
  UI/PromptWindow.xaml        the Allow / Block prompt
  UI/MainWindow.xaml          rules, activity, settings
  UI/TrayIcon.cs              notification-area icon
  UI/GridSorting.cs           remembered column sorting
  Assets/logo.png             the logo (main window header); source for every icon
  Assets/*.ico                app/tray icons, generated by tools/make-icons.py
installer/PacketHound.iss     Inno Setup script (.\build.ps1 -Installer)
tools/make-icons.py           rebuilds the icons, installer and website images from the logo (needs Pillow)
```

Settings and the log are kept in `C:\ProgramData\PacketHound\`.

## License

PacketHound is free software, licensed under the [GNU General Public License v3.0](LICENSE).

# PacketHound

An outbound application firewall for Windows, in the spirit of Little Snitch.
When a third-party app tries to make an outgoing connection for the first time, PacketHound
asks whether to **Allow** or **Block** it. Your answer is saved as a normal **Windows Firewall rule**.
Windows itself is never prompted for.

**Download:** https://packethound.app (Windows 10 1809+ / Windows 11, x64 or ARM64)

<a href="https://www.buymeacoffee.com/Henrys_Cat" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me a Coffee" style="height: 60px !important;width: 217px !important;" ></a>

## How it works

PacketHound doesn't use a kernel driver. It builds on Windows Firewall:

1. **Default outbound = Block.** On all three firewall profiles (Domain, Private, Public),
   every program without an allow rule is blocked.
2. **Auditing.** Failure auditing for *Filtering Platform Connection* is switched on, so each
   blocked attempt is written to the Security log as event **5157**.
3. **Monitoring.** PacketHound watches for outbound 5157 events. For each program without a rule:
   - **Windows component** → an Allow rule is added silently (group *PacketHound (Windows components)*).
   - **Third-party app** → a prompt shows the app, publisher, destination hostname/IP, port and protocol.
     **Allow** or **Block** creates an outbound rule (group *PacketHound*). The rule can cover:
     - **Any connection** (the default): the whole app.
     - **Only this IP address.**
     - **Only this host** (e.g. `api.example.com`), or **only this domain and its subdomains** (`*.example.com`).
       Windows Firewall only matches IP addresses, so PacketHound keeps the rule's address list up to date:
       when the app connects to a new address for that name, the address is added (the app may need to retry once).

     If the app tries several destinations before you answer (a browser such as Tor does), each one is listed,
     and the one you picked stays selected as more arrive.

     The rule lasts **Forever**, **Until the app quits**, **For 1 hour** or **For the rest of today**. A temporary
     rule is removed once no process of that program is running, and also when PacketHound exits. A timed rule is
     removed when its time is up, or at PacketHound's next start if it was closed by then.

     **Copy** (or right-click the details) copies the IP address, host name, program path or command line. For
     PowerShell, cmd, script interpreters (Python, Node, Java, …) and download tools, the prompt also shows the
     **command line**, so you can see which script or download is behind the connection.
     Connections a destination rule doesn't cover are asked about again.
     **Decide later** keeps it blocked and lists it under *Waiting for your decision* on the Rules tab,
     where you can decide any time. After 10 minutes PacketHound asks again if the app is still running,
     or otherwise the next time it connects.

     **Updates that move to a new folder.** Some apps install each version into a new folder
     (`app-1.2.3\` → `app-1.2.4\`). When a program's path matches one with rules except for a version-numbered
     folder, the prompt says *"This looks like an update"* and offers **Same as before**, which copies the old
     version's rules to the new path (and removes the old ones if that version is gone). If the new version is
     signed by someone other than the old one, the button isn't offered and you decide again.

     **Installers and updaters in temporary folders.** Many unpack themselves into a new random folder under
     `%TEMP%` on every run, so a rule for one copy's path never matches the next. For a program running from a
     temp folder the prompt says *"This looks like an installer or updater"*, and its rule lasts until it quits,
     so dead rules don't pile up. If it's validly signed and you allow it, that's remembered: future copies in a
     temp folder with the same file name *and* a valid signature from the same signer are allowed without a prompt
     (listed on the Rules tab as *Installer / updater*). Block isn't remembered, so a blocked installer asks again
     next time instead of failing silently. Windows Firewall can only match paths, so PacketHound watches the temp
     folders: when a remembered program is unpacked there, its signature is checked and its rule is made before it
     runs. From the signature check until the program quits, PacketHound keeps the file open so it can't be
     replaced, deleted or renamed; otherwise other software could swap a different program in at the allowed path.
     (Because of that, an installer may occasionally leave its temp folder behind.)
     If PacketHound is too late (or it's the very first run, before you've answered), the first connection is
     blocked and many installers give up, so a notification offers to pause protection for 5 minutes in one click.

4. **Quiet mode.** For 30 minutes, 1 hour, 3 hours or until you turn it off (main window, or tray icon ›
   Quiet mode), new apps are blocked **without a prompt** and listed under *Waiting for your decision*. When it
   ends, PacketHound asks about the ones that are still running. Quiet mode doesn't survive a restart.

5. **Pausing.** Protection can be paused for 5 minutes, 15 minutes, 1 hour, or until you turn it back on
   (tray icon › Pause protection, or the button in the main window). A timed pause turns protection back on
   by itself, also if the PC restarts in the meantime. While paused, apps without a rule can connect; your
   Block rules still apply.

The rules are ordinary firewall rules (`wf.msc` › Outbound Rules). They keep working when
PacketHound isn't running, or after it's uninstalled.

Rules for programs that are no longer on the PC (uninstalled, or replaced by an update that installs
into a new versioned folder) show **Program not found** on the Rules tab. **Remove missing** deletes them
after you confirm. Programs on a drive that isn't connected, or on a network share, are never counted as missing.

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
.\build.ps1 -Arch arm64      # the same for Windows on ARM, in publish\arm64
.\build.ps1 -Installer       # publish\PacketHound-Setup-<version>.exe and ...-<version>-arm64.exe; needs Inno Setup 7 (or 6)
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
   - Left-click opens the waiting prompt if there is one, otherwise the window (on the Rules tab if apps
     are waiting for your decision).
   - Right-click has **Pause protection** (5 minutes, 15 minutes, 1 hour, or until you turn it back on),
     **Quiet mode**, **Turn protection on**, a link to apps waiting for your decision, and **Exit**.
   - The tooltip shows whether protection is on, until when it's paused, and how many apps are waiting.
4. The main window has three tabs:
   - **Rules**: search, flip a rule between Allow and Block with its switch (green = Allow,
     red = Block) or the Allow/Block buttons, and delete rules. **Edit…** (or double-click a rule) changes its
     action and what it applies to (any connection, one IP address, one host or a whole domain), and can make a
     temporary or timed rule permanent. Apps you chose to decide later about are
     listed above the rules under *Waiting for your decision*, each with a **Decide…** button. The
     **Status** column shows temporary and disabled rules, and rules whose program is gone
     (**Program not found**, tinted red; **Remove missing** deletes them). Remembered installers and
     updaters are listed with the type *Installer / updater*.
   - **Activity**: blocked attempts and what happened to each. Double-click a row to copy its IP address;
     right-click to copy it or the host name, or to decide about an app that's still waiting. The list is kept
     across restarts for 1 day by default (Settings › Activity: this session only, 1, 7 or 30 days), in
     `C:\ProgramData\PacketHound\activity.jsonl`; **Clear** empties it.
   - **Settings**, including **Updates**: once a week PacketHound asks https://packethound.app/version.php
     for the latest version number (on by default; untick to stop, or use **Check now**). If there's a newer
     version, the main window, the tray menu and a notification link to the download page. It never
     downloads or installs anything itself. Its own outbound access is a rule allowing HTTPS (TCP 443) only,
     listed on the Rules tab; switching that to Block stops update checks. The address is set in
     `Core/UpdateService.cs`.

   Click a column header to sort (click again to reverse). The arrow shows the sorted column, and the
   choice is remembered. Rules start sorted newest first. Text too long for its column is cut off
   with "…"; select the row to see all of it.

The window remembers its size, position and whether it was maximized.

Prompts appear on top **without taking keyboard focus**, so typing never answers one by accident.

## Pause, exit and uninstall

- **Pause protection** sets the outbound default back to Allow. Your Block rules still apply. Pick 5 minutes,
  15 minutes or 1 hour and protection turns itself back on (also after a restart), or pause until you turn it
  back on.
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
  does, needs a signed kernel-mode WFP callout driver. Some installers give up after that first
  failure; pause protection for 5 minutes and run them again (PacketHound offers this after you allow one).
- **Destination rules match IP addresses.** Host and domain rules learn a name's addresses as the app
  connects, so a new address may need one retry, and sites sharing an address (CDNs) share the rule.
  Rules can't be limited to a port from the prompt; you can narrow a rule in `wf.msc` afterwards.
- **Group Policy wins.** On managed PCs, firewall or audit policy pushed by a domain overrides local changes.
- **Security log volume.** Auditing also logs blocked *inbound* connections, so the Security log
  fills a little faster. It rotates automatically.
- **Path-based rules.** A new app version installed into a new folder (some updaters do this)
  is treated as a new program and prompts again; the old rule then shows *Program not found*.
  If only a version-numbered folder changed, **Same as before** in the prompt copies the rules over (see above);
  other renamed folders aren't recognised. Signed installers and updaters in temp folders are the exception (see above). Unsigned ones, or ones
  that use a random file name, are asked about every run.

## Project layout

```
src/PacketHound/
  App.xaml(.cs)               startup, single instance, first run, tray lifetime
  Core/Controller.cs          event → decision pipeline, prompt queue, decide-later list, pause timer,
                              installer/updater (signed-copy) rules
  Core/FirewallManager.cs     Windows Firewall COM API (HNetCfg.FwPolicy2), rule snapshot
  Core/ConnectionMonitor.cs   Security log event 5157 subscription
  Core/AuditPolicy.cs         Filtering Platform Connection audit setting
  Core/WindowsAppClassifier.cs  "is this Windows?" rules
  Core/Signature.cs           WinVerifyTrust embedded + catalog signature verification
  Core/TempFolders.cs         temp-folder detection, and the watcher that prepares installer rules
  Core/ProgramPresence.cs     "is this rule's program still installed?" check
  Core/ProgramVersions.cs     "is this an update of a program in another versioned folder?"
  Core/ActivityLog.cs         keeps the Activity list across restarts
  Core/DevicePaths.cs         \device\harddiskvolumeN\… → C:\…
  Core/HostNames.cs           IP → hostname via the DNS client cache, then reverse DNS
  Core/AutoStart.cs           Task Scheduler logon task
  UI/PromptWindow.xaml        the Allow / Block prompt
  UI/MainWindow.xaml          rules, activity, settings
  UI/RuleEditWindow.xaml      the Edit rule dialog
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

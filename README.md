# Hallow Guard

**A friendly safety center on top of Microsoft Defender.**

Part of the Hallow family of Windows apps. Hallow Guard shows how well your PC is protected, in plain words, and asks
**Microsoft Defender** to scan when you want it to. It uses Defender's engine; it is **not an antivirus of its own**, and it
never disables, replaces or weakens Defender.

![Overview](docs/overview.png)

## What it does

- **One family safety score** (new in 1.1): the Overview's score covers the whole PC - the Windows checks below *and* the other
  Hallow apps - with one prioritised to-do list (the top 5 things worth the most points, each with a button) and two groups,
  **Windows** and **Hallow apps**, each with its own score. Every Hallow app is optional: one that isn't installed is shown as
  *Not installed* with a line on why it helps and a link, and **never costs points**. See [The family score](#the-family-score).
- **Safety score** (0-100) with a plain-English line per check: Defender's antivirus and real-time protection, how old the
  virus definitions are, the last quick/full scan, tamper protection, a third-party antivirus (then Defender is passive -
  and that's fine), Windows Firewall per network type, SmartScreen, Windows Update (last install, restart waiting),
  BitLocker on the Windows drive, User Account Control, Secure Boot and Memory integrity. Where it helps there's a button
  that opens the right Windows Security or Settings page - Hallow Guard **only reads** these settings.
- **Scans through Defender's engine** (`MpCmdRun.exe` from Defender's newest platform folder): quick, full, a folder you pick,
  or a file you drop on the window. Progress, cancel and the result.
- **Watch Downloads** (off by default): when a new file in your Downloads folder has finished (its size stays the same, and
  it isn't a `.crdownload` / `.part` / `.tmp` file), Defender scans just that file. You only hear from it if something is found.
- **History**: what Defender found - the threat, how serious, which file, when and what was done - explained in plain words.
  "Open in Windows Security" for restoring or removing.
- **Leftover hunt**, one click: startup entries (Run keys and Startup folders), scheduled tasks and services that aren't
  Microsoft's, programs running unsigned from Temp / AppData / Downloads, browser extensions (Chrome, Edge, Brave, Firefox)
  and hosts-file entries. Every row is **Known good** (signed by Microsoft or a well-known publisher, part of Windows, or a
  Hallow app), **Unknown** or **Suspicious** (unsigned, in Temp/AppData/Downloads *and* starting by itself), with the reason.
  Per row: open its location, scan it with Defender, look it up on VirusTotal - and for entries in your own startup list,
  **Disable**, which moves the entry to Hallow Guard's backup (`HKCU\Software\HallowGuard\DisabledStartup`) so **Restore**
  can put it back. Nothing is ever deleted.
- **VirusTotal second opinion** (optional): paste your own free API key in Settings (kept encrypted for your Windows
  account). A lookup sends **only the file's SHA-256** (`GET /api/v3/files/{sha256}`) - files are never uploaded. Without a
  key, "Look up" opens the file's VirusTotal page in your browser.
- **Hallow family**: the family pipe (`ping`, `status`, `open`, `menu`, `invoke`, `scan quick`, `quit`), `HallowGuard.exe
  --cmd "<line>"`, `%APPDATA%\HallowGuard\status.json` (score, last scan, threat count), notifications through Hallow Hub's
  icon when it runs, a weekly reminder when nothing was scanned for 7 days (on by default, never a scan by itself), the
  Hallow accent, crash reports kept on this PC, and updates from GitHub with a SHA-256 check.

## The family score

![The whole Overview: to-do list, Windows and Hallow apps (made-up data)](docs/family.png)

| Part | What Guard reads (read-only) | Points it can cost |
|---|---|---|
| **Windows** (the 12 checks) | Windows Security, the registry, WMI - as in 1.0 | the Windows score: 100 minus each check's points |
| **Hallow Keys** - password health | Only the counts Keys 2.8+ writes to its `status.json` (how many logins are weak, reused, leaked, on a breached site, missing 2FA the site offers - never a name, address or password). Guard never opens or reads the vault. Locked Keys reports the last counts with their age; counts older than 90 days aren't used. | leaked or breached 8, reused 5, weak 4, 2FA 2 - at most 12 |
| **Hallow Vault** - game save backups | Its `status.json` + pipe: last backup per game (switched-off games skipped), Vault's backup check, the second copy, running or not | failed checks 6, second copy unreachable 3, no backup / last one over 14 days old 3, not running 2 - at most 8 |
| **Hallow Shield** - ad & tracker blocker | Guard can't talk to a browser extension, so it looks for an extension named *Hallow Shield* in Chrome, Edge, Brave and Opera (GX) profiles: each profile's `Secure Preferences` / `Preferences` (the stored manifest, or the unpacked folder's `manifest.json`) and `Extensions\` - always by reading a **copy** in Guard's temp folder; locked or broken files are skipped. Per browser: installed or not, and its version. | switched off where installed 2 |
| **Hallow Assist** - remote help | Its `status.json`: unattended access on or off (no codes or secrets are in it). *On* is fine, but gets a line: "Unattended access is on - make sure its password is strong." | none |

- **Hallow apps score** = 100 minus the points above (shown as *-* when no Hallow app is installed).
- **Family score** (the big ring) = the Windows score minus the Hallow apps' points, **capped at 25** - so Windows always
  matters most, and an app you don't have never lowers it.
- Hallow Toolkit isn't part of the score: what it could add (Windows Update, startup clean-up) the Windows checks and the
  leftover hunt already cover.
- `status.json` keeps every 1.0 field (`score` is still the Windows score, for Hallow Hub's pill) and adds `familyScore`,
  `familyLabel`, `windowsScore`, `appsScore`, `todo` (how many to-dos) and `family` (each app: good / warn / bad /
  unknown / info / missing).

## What it won't do (on purpose)

- It never switches Defender off or changes its settings, and never changes a security setting by itself. The one
  admin action - reading whether BitLocker is on when Windows only tells administrators - runs only when you click
  "Check (admin)", and Windows asks you first.
- It never deletes files. Defender decides what happens to threats; you manage them in Windows Security.
- It never opens your Hallow Keys vault, never changes a browser file and never starts a Hallow app unless you click its button.
- It never uploads files anywhere. Nothing leaves the PC except a file's fingerprint to VirusTotal, when you ask, with your key.

## Install

Download **Hallow Guard.zip** from the [latest release](https://github.com/Dom428/hallow-guard/releases/latest), unblock and
extract it, and run `INSTALL.bat` (no admin needed). It installs to `%LOCALAPPDATA%\Programs\Hallow Guard` with Start menu
and Desktop shortcuts. Settings > *Start with Windows* keeps it in the tray for Watch Downloads and the weekly reminder.

## Build

```
.\build.ps1          # HallowGuard.exe with the C# compiler that ships with Windows (.NET Framework 4.8)
.\build.ps1 -Tests   # also tests\GuardTests.exe
.\tests\GuardTests.exe
.\HallowGuard.exe --snap <folder>   # every page rendered off-screen with made-up data
```

The tests never run a real Defender scan: they use a stand-in `MpCmdRun`, made-up system checks, a local stand-in for
VirusTotal and fake registry keys of their own. The family tests use fake `status.json` files for every app state (missing,
running, stopped, stale) and fake browser profile folders (locked and broken files included).

## What's new

- **1.1** - one family safety score: the Overview covers Windows *and* the Hallow apps (Keys' password-health counts,
  Vault's backups, Shield in your browsers, Assist's unattended access), one to-do list, a score per group; `familyScore` in
  `status.json`.
- **1.0** - first version: safety score, scans through Defender's engine, Watch Downloads, threat history, leftover hunt,
  VirusTotal hash lookups, Hallow family link.

Icons: [Font Awesome Free](https://fontawesome.com) 7.3.1 by Fonticons, Inc., CC BY 4.0 (see FontAwesome-LICENSE.txt).

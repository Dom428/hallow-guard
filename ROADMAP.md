# Hallow Guard roadmap

## Done

| Version | What |
|---|---|
| 1.1 | One family safety score: Overview covers Windows and the Hallow apps - Keys' aggregate password-health counts (Keys 2.8 status.json, never the vault), Vault's last backup / failed checks / second copy / running, Hallow Shield found in Chrome / Edge / Brave / Opera profiles by reading copies of Secure Preferences / Preferences / manifest.json (per browser, version, switched off), Assist's unattended access; not-installed apps cost nothing and show why + a link; Windows and Hallow apps groups with their own scores, family score = Windows minus the apps' points (cap 25); one to-do list (top 5 by points, each with a button); status.json adds familyScore / familyLabel / windowsScore / appsScore / todo / family (1.0 fields unchanged) |
| 1.0 | Safety score from read-only checks (MSFT_MpComputerStatus, SecurityCenter2 AntiVirusProduct/FirewallProduct, firewall and SmartScreen registry, Win32_QuickFixEngineering + pending-restart keys, BitLocker via WMI / the Shell property / an admin check you click, UAC, Secure Boot, Memory integrity), fixes that only open windowsdefender:// and ms-settings: pages; quick / full / folder / file scans through `MpCmdRun.exe -Scan` (newest platform folder) with cancel (`-Cancel`); Watch Downloads (off by default: steady size for 3 s, skips partial-download extensions and files with a `.part` / `.crdownload` next to them, no repeat within a minute, queued behind a running scan); threat history in plain words (MSFT_MpThreatDetection + MSFT_MpThreat); leftover hunt (Run/RunOnce, Startup folders, non-Microsoft tasks and services, unsigned programs running from Temp/AppData/Downloads, Chromium and Firefox extensions, hosts file) with Known good / Unknown / Suspicious from WinVerifyTrust + the Authenticode signer and the path; Disable/Restore for your own Run entries via a backup key; VirusTotal lookups by SHA-256 only (DPAPI-encrypted key) or the website without a key; family pipe, `--cmd`, status.json, notifications through Hub, weekly reminder, accent, crash reports, GitHub updater with SHA-256 check |

## Later

| Idea | Why it isn't in 1.0 |
|---|---|
| Real scan progress (percent, current file) | `MpCmdRun` reports nothing while it scans. Defender's own progress is only available to administrators through other interfaces. 1.0 shows the running time. |
| Restore / remove quarantined items from Hallow Guard | Needs admin (`MpCmdRun -Restore`) - and Windows Security already does it well. 1.0 opens Protection history. |
| Disable machine-wide startup entries, tasks and services | Needs admin and a careful undo for each kind. 1.0 opens Windows' Startup apps page for machine-wide entries. |
| Catalog signatures | Windows files signed through security catalogs (not inside the file) are treated as "part of Windows" by their folder. Checking the catalog itself would make that exact. |
| Browser extension store check online | 1.0 trusts the store update address in the manifest; asking the store would need network calls per extension. |
| Hallow Toolkit in the family score | Toolkit has no status file; what it could add (Windows Update, startup clean-up) is already covered by the Windows checks and the leftover hunt. |
| Shield's own numbers (blocked today, lists up to date) | A browser extension can't be asked from a desktop app without a native messaging host; 1.1 reads only whether it's installed, its version and whether it's switched on. |
| Hub menu entry | Hallow Hub 2.12's tray menu has a fixed app list. Hallow Guard follows the family protocol (`menu`, `invoke`, `notify`) and hides its own icon only when Hub's `tray-host` answer lists Guard, so it's never left without an icon. |

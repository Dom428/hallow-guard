HALLOW GUARD - a friendly safety center on top of Microsoft Defender

Hallow Guard uses Microsoft Defender's engine; it is not an antivirus of its own,
and it never switches Defender off or changes its settings.

HOW TO INSTALL
1. Right-click the zip > Properties > tick "Unblock" > OK
2. Right-click the zip > Extract All
3. Double-click INSTALL.bat (no admin needed)

WHAT'S NEW IN 1.2
- Ransomware page: whether Windows' Controlled folder access is on, which folders are
  protected and which apps are allowed, in plain words - with folders worth protecting
  (Documents, Pictures, Desktop and your game saves) and a warning that it can stop games
  from saving unless you allow them. Hallow Guard only reads it; the buttons open Windows
  Security's Ransomware protection page.
- Network page: which apps are connected right now, which programs are open to the
  network (with their publisher and whether Windows Firewall lets them in on private /
  public networks), and unsigned ones running from Temp or AppData flagged as suspicious.
  Nothing is sent anywhere - names are only looked up when you click "Look up names".
- Extensions page: every extension in Chrome, Edge, Brave, Opera and Firefox rated High,
  Medium, Low or Known (Hallow Keys and Hallow Shield), with the reasons. Browsers are
  never changed.
- The Overview's score and to-do list include these (lightly).

WHAT'S NEW IN 1.1
- One family safety score: the Overview also covers your other Hallow apps - Hallow Keys'
  password health (counts only, the vault is never opened), Hallow Vault's backups,
  Hallow Shield in your browsers and Hallow Assist's unattended access - with one to-do
  list and a score for Windows and for the Hallow apps. Apps you don't have never cost points.

WHAT IT DOES
- Overview: a safety score with a plain-English line per check (Defender, firewall,
  SmartScreen, Windows Update, BitLocker, UAC, Secure Boot, Memory integrity), plus the
  Hallow apps, and the top 5 things to fix.
  "Open settings" opens the right Windows page - Hallow Guard only reads these settings.
- Scan: quick, full, a folder or a dropped file - Microsoft Defender does the scanning.
  Watch Downloads (off by default) scans each new download once it has finished.
- History: what Defender found, in plain words. Manage it in Windows Security.
- Leftovers: what starts with Windows, non-Microsoft tasks and services, unsigned
  programs running from Temp/AppData/Downloads, browser extensions and the hosts file -
  each marked Known good, Unknown or Suspicious. Disable moves one of your own startup
  entries to a backup so Restore can put it back. Nothing is ever deleted.
- VirusTotal (optional): with your own free API key, Look up sends only the file's
  SHA-256 fingerprint - never the file. Without a key it opens the VirusTotal page.

START WITH WINDOWS
- Settings > Start with Windows keeps Hallow Guard in the tray, for Watch Downloads
  and the weekly "time for a quick scan" reminder.

PRIVACY
- Nothing is sent anywhere except a file's fingerprint to VirusTotal, when you ask.
  Crash reports stay on this PC.

CREDITS
Icons: Font Awesome Free 7.3.1 by Fonticons, Inc. (https://fontawesome.com), licensed CC BY 4.0 - see FontAwesome-LICENSE.txt.

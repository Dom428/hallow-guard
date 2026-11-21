# Hallow Guard uninstaller (run from Windows Settings > Apps, or directly).
# Startup entries you disabled with Hallow Guard are offered back first, so nothing you turned off is lost.
$dest = Join-Path $env:LOCALAPPDATA 'Programs\Hallow Guard'
Add-Type -AssemblyName System.Windows.Forms
if ([System.Windows.Forms.MessageBox]::Show("Uninstall Hallow Guard?`n`nMicrosoft Defender keeps protecting this PC as before.", 'Uninstall Hallow Guard', 'YesNo', 'Question') -ne 'Yes') { return }
Get-Process HallowGuard -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 600
$bk = 'HKCU:\Software\HallowGuard\DisabledStartup'
$keepKey = $false
$items = @(Get-ChildItem $bk -ErrorAction SilentlyContinue)
if ($items.Count -gt 0) {
    $a = [System.Windows.Forms.MessageBox]::Show("Hallow Guard disabled $($items.Count) startup entr$(if ($items.Count -eq 1) { 'y' } else { 'ies' }). Put them back so they start with Windows again?`n`nNo = leave them off (the backup stays in the registry under HKCU\Software\HallowGuard).", 'Uninstall Hallow Guard', 'YesNo', 'Question')
    if ($a -eq 'Yes') {
        $run = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
        foreach ($i in $items) {
            $k = Get-Item $i.PSPath; $name = $k.GetValue('Name'); $data = $k.GetValue('Data', $null, 'DoNotExpandEnvironmentNames')
            if ($name -and $data -ne $null -and $null -eq (Get-ItemProperty $run -Name $name -ErrorAction SilentlyContinue)) {
                New-ItemProperty $run -Name $name -Value $data -PropertyType $k.GetValueKind('Data') -Force | Out-Null
                Remove-Item $i.PSPath -Recurse
            } else { $keepKey = $true }
        }
    } else { $keepKey = $true }
}
if (-not $keepKey) { Remove-Item 'HKCU:\Software\HallowGuard' -Recurse -ErrorAction SilentlyContinue }
foreach ($dir in [Environment]::GetFolderPath('Programs'), [Environment]::GetFolderPath('Desktop')) { Remove-Item (Join-Path $dir 'Hallow Guard.lnk') -ErrorAction SilentlyContinue }
Remove-Item 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\HallowGuard' -Recurse -ErrorAction SilentlyContinue
Remove-Item (Join-Path $env:APPDATA 'HallowGuard') -Recurse -Force -ErrorAction SilentlyContinue
Start-Process cmd.exe -ArgumentList "/c timeout /t 2 /nobreak >nul & rmdir /s /q `"$dest`"" -WindowStyle Hidden
[System.Windows.Forms.MessageBox]::Show('Hallow Guard is uninstalled.', 'Hallow Guard') | Out-Null
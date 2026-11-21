# Builds HallowGuard.exe with the C# compiler that ships with Windows (.NET Framework 4.8) - nothing to install.
#   .\build.ps1          the app
#   .\build.ps1 -Tests   also tests\GuardTests.exe (unit tests: score rules, signer/path verdicts, Downloads watcher, VirusTotal
#                        request, startup disable/restore on a fake key, the family pipe - with stand-ins, never a real scan)
param([switch]$Tests)
$ErrorActionPreference = 'Stop'
$fw = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319"
$wpf = "$fw\WPF"
$src = Join-Path $PSScriptRoot 'src'
$out = Join-Path $PSScriptRoot 'HallowGuard.exe'
$refs = "$wpf\PresentationFramework.dll", "$wpf\PresentationCore.dll", "$wpf\WindowsBase.dll", "$fw\System.Xaml.dll",
    "$fw\System.Windows.Forms.dll", "$fw\System.Drawing.dll", "$fw\System.Runtime.Serialization.dll", "$fw\System.Core.dll",
    "$fw\System.IO.Compression.dll", "$fw\System.IO.Compression.FileSystem.dll", "$fw\System.Web.Extensions.dll", "$fw\System.Xml.dll", "$fw\System.Security.dll", "$fw\System.Management.dll"
$common = @('/nologo', '/optimize+', "/win32icon:$src\hallow.ico", "/resource:$src\Theme.xaml,HallowGuard.Theme.xaml", "/resource:$src\ThemeCyber.xaml,HallowGuard.ThemeCyber.xaml", "/resource:$src\ThemeConsole.xaml,HallowGuard.ThemeConsole.xaml") + ($refs | ForEach-Object { "/reference:$_" })
$files = Get-ChildItem $src -Filter *.cs | ForEach-Object FullName
& "$fw\csc.exe" @($common + @('/target:winexe', "/out:$out") + $files)
if ($LASTEXITCODE -ne 0) { throw "Build failed" }
"Built $out ($([math]::Round((Get-Item $out).Length / 1KB)) KB)"
if ($Tests) {
    $t = Join-Path $PSScriptRoot 'tests\GuardTests.exe'
    & "$fw\csc.exe" @($common + @('/target:exe', "/out:$t", '/main:HallowGuard.Tests.Run') + $files + (Get-ChildItem (Join-Path $PSScriptRoot 'tests') -Filter *.cs | ForEach-Object FullName))
    if ($LASTEXITCODE -ne 0) { throw "Test build failed" }
    "Built $t"
}
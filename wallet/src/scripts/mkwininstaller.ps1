param (
    [Parameter(Mandatory=$true)][string]$version
)

$target="zclwallet-v$version"

Remove-Item -Path release/wininstaller -Recurse -ErrorAction Ignore  | Out-Null
New-Item release/wininstaller -itemtype directory                    | Out-Null

Copy-Item release/$target/zclwallet.exe     release/wininstaller/
Copy-Item release/$target/LICENSE           release/wininstaller/
Copy-Item release/$target/README.md         release/wininstaller/
Copy-Item release/$target/zclassicd.exe        release/wininstaller/
Copy-Item release/$target/zclassic-cli.exe     release/wininstaller/

Get-Content src/scripts/zcl-qt-wallet.wxs | ForEach-Object { $_ -replace "RELEASE_VERSION", "$version" } | Out-File -Encoding utf8 release/wininstaller/zcl-qt-wallet.wxs

candle.exe release/wininstaller/zcl-qt-wallet.wxs -o release/wininstaller/zcl-qt-wallet.wixobj 
if (!$?) {
    exit 1;
}

light.exe -ext WixUIExtension -cultures:en-us release/wininstaller/zcl-qt-wallet.wixobj -out release/wininstaller/zclwallet.msi 
if (!$?) {
    exit 1;
}

New-Item artifacts -itemtype directory -Force | Out-Null
Copy-Item release/wininstaller/zclwallet.msi ./artifacts/Windows-installer-$target.msi
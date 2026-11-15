#!/bin/sh
# Inspect without executing. A standalone win64 binary may import only OS DLLs.
set -eu
[ "$#" -gt 0 ] || { echo "usage: $0 executable.exe [...]" >&2; exit 1; }
OBJDUMP=${OBJDUMP:-x86_64-w64-mingw32-objdump}
for binary do
    headers=$("$OBJDUMP" -f "$binary") || exit 1
    printf '%s\n' "$headers" | grep -q 'file format pei-x86-64' || {
        echo "ERROR: not a win64 PE executable: $binary" >&2; exit 1;
    }
    imports=$("$OBJDUMP" -p "$binary") || exit 1
    dlls=$(printf '%s\n' "$imports" | awk '/DLL Name:/ {print tolower($3)}')
    [ -n "$dlls" ] || { echo "ERROR: no DLL imports found: $binary" >&2; exit 1; }
    for dll in $dlls; do
        case "$dll" in
            advapi32.dll|bcrypt.dll|crypt32.dll|dwmapi.dll|gdi32.dll|imm32.dll|iphlpapi.dll|kernel32.dll|mpr.dll|msvcrt.dll|netapi32.dll|ntdll.dll|ole32.dll|oleaut32.dll|powrprof.dll|psapi.dll|rpcrt4.dll|secur32.dll|setupapi.dll|shell32.dll|shlwapi.dll|ucrtbase.dll|user32.dll|userenv.dll|uxtheme.dll|version.dll|winmm.dll|winspool.drv|ws2_32.dll|wtsapi32.dll|api-ms-win-crt-*.dll) ;;
            *) echo "ERROR: $binary requires non-system DLL $dll; rebuild with static libraries." >&2; exit 1 ;;
        esac
    done
    echo "PASS: $binary imports Windows system DLLs only"
done

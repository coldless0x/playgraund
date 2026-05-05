# playgraund

Small Windows tool: resolves `NtUserSendInput` from `win32u.dll` on disk, builds an in-process x64 syscall trampoline, then sends Unicode keyboard input into an already open Notepad window.

## Requirements

- Windows 10/11 x64  
- Visual Studio 2022 with **Desktop development with C++** (MSVC v143, Windows 10/11 SDK)

Win32 builds are not supported; the syscall stub is x64-only.

## Build

```bat
msbuild playgraund.sln /p:Configuration=Release /p:Platform=x64
```

Output: `x64\Release\playgraund.exe`

## Usage

1. Open Notepad (any document).  
2. Run `playgraund.exe` from a terminal or Explorer.  
3. Read the printed addresses/SSN if you care; press Enter when prompted so the console does not vanish on double-click.

The program looks for a top-level window owned by `notepad.exe`, then an `Edit` / RichEdit child. If your Notepad build does not expose one of those, it will fail cleanly.

## What it does (technical)

- Maps `%SystemRoot%\System32\win32u.dll` read-only, walks exports, reads the syscall index from the on-disk stub (same pattern as `mov r10, rcx` / `mov eax, imm32` / `syscall`).  
- Writes a short executable stub in a private RWX buffer and calls through it instead of `win32u.dll!NtUserSendInput`.  
- Uses `KEYEVENTF_UNICODE` down/up pairs for each UTF-16 code unit in the embedded payload.

## Payload

The typed text is defined in `main.c` (`kPayload`). Edit and rebuild to change it.

## Caveats

- Input injection follows normal desktop rules: focus can still land elsewhere; click the editor if output goes to the wrong window.  
- SSNs and `win32u` layout are OS-build specific; the disk read keeps the index aligned with the kernel you are actually running, for a given install.  
- This is low-level input automation. Use it only on machines you own and only where that is allowed.

## License

No license file shipped; treat the repo as private/all-rights-reserved unless you add one.

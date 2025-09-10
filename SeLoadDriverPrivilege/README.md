# SeLoadDriverPrivilege Exploit

This exploit uses the SeLoadDriverPrivilege to load an unsigned driver (Capcom.sys) and execute code in kernel mode.

## Prerequisites

1. Windows system with SeLoadDriverPrivilege available
2. Administrator privileges
3. Driver Signature Enforcement must be disabled

## Compilation

On Kali Linux or other Linux system with MinGW:
```bash
x86_64-w64-mingw32-gcc SeLoadDriverPrivilege.c -o SeLoadDriverPrivilege.exe -lwsock32 -lwininet
```

## Usage

1. First, disable Driver Signature Enforcement (DSE). You have two options:

   Option 1 - Temporary (until next reboot):
   ```
   bcdedit /set testsigning on
   shutdown /r /t 0
   ```

   Option 2 - During boot:
   - Press F8 during boot and select "Disable Driver Signature Enforcement"
   - Or use: Advanced startup > Troubleshoot > Advanced options > Startup Settings > Restart > Press 7

2. Run the exploit:
   ```
   SeLoadDriverPrivilege.exe [optional_url]
   ```

   If no URL is provided, it will download Capcom.sys from the default GitHub repository.

## Common Errors

- NTSTATUS: c0000e5 (Error 1359) - This occurs when Driver Signature Enforcement is still enabled. Make sure to disable it first.
- Access Denied - Make sure you have administrator privileges and SeLoadDriverPrivilege is available.

## Notes

- The exploit requires administrator privileges
- Windows Defender or other security software might detect and block the exploit
- Disabling DSE reduces system security, remember to re-enable it after testing
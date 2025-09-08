# SeTakeOwnershipPrivilegeExploit

This project is a Windows utility written in C that enables the SeTakeOwnershipPrivilege for the current process, displays ownership information of a target file or folder, attempts to take ownership using takeown.exe, and grants full control to the current user using icacls.exe. It is intended for administrative recovery, forensic analysis, or privilege escalation testing in controlled environments.

## Features

Enables the SeTakeOwnershipPrivilege using Windows API

Displays file or folder ownership using PowerShell

Attempts ownership takeover using takeown.exe

Grants full control permissions using icacls.exe

Traverses up the directory tree if access is denied to the initial path

## Usage

```SeTakeOwnershipPrivilegeExploit.exe "<path_to_file_or_folder>"```

### Example:
SeTakeOwnershipPrivilegeExploit.exe "C:\RestrictedFolder"


## Compilation

To compile the project using mingw-w64 on a Linux system targeting Windows:
```x86_64-w64-mingw32-gcc SeTakeOwnershipPrivilege.c -o SeTakeOwnershipPrivilegeExploit.exe -ladvapi32```

This links against the advapi32 library to access Windows privilege APIs.

## Requirements

Windows operating system

Administrator privileges

PowerShell available in system path

takeown.exe and icacls.exe available (default on Windows)

## Notes

The program checks for and enables SeTakeOwnershipPrivilege before attempting any ownership changes.

PowerShell is used to query file ownership and security information.

If access is denied, the program will attempt to query parent directories until successful.

All operations are logged to the console for transparency.

## Disclaimer

This tool is intended for educational and administrative use only. Do not use it to bypass security controls or access unauthorized resources. Always ensure you have permission before modifying ownership or permissions on any system.

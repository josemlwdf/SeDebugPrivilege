# ServerOperators

ServerOperators is a Windows-native privilege escalation utility designed to identify and hijack misconfigured services running as LocalSystem. It modifies service configurations to execute arbitrary payloads and then restores the original state.

This tool is intended for authorized penetration testing and research purposes only. It modifies system services and may cause instability or security risks if misused.

## Features

- Enumerates non-critical services running as LocalSystem
- Filters out essential system services and kernel drivers
- Attempts to hijack service binPath to execute a user-supplied command
- Automatically restores the original service configuration after execution
- Interactive fallback if payload execution fails

## Example Usage
        
    ServerOperators.exe "net user attacker P@ssw0rd123 /add && net localgroup administrators attacker /add"

## Compilation

This tool is designed for Windows and compiled with MinGW:

    x86_64-w64-mingw32-gcc -o ServerOperators.exe ServerOperators.c

## How It Works

Uses wmic to list services with:

- StartName='LocalSystem'
- Non-critical ErrorControl
- Excludes kernel and file system drivers
- Filters out essential services such as RpcSs, Winmgmt, EventLog, etc.

For each candidate service:
  
- Modifies the service's binPath to the user-supplied payload
- Stops and restarts the service to trigger execution
- Restores the original binPath after execution
- If execution fails, prompts the user to continue or abort.

## Safety Notice

This tool is inherently dangerous. It modifies Windows service configurations and may break services if interrupted or misused. Use only in controlled environments with explicit authorization.

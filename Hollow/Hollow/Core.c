// HollowTest.c - Minimal process hollowing test against explorer.exe
// Compile: cl HollowTest.c /link kernel32.lib ntdll.lib

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>

// NtUnmapViewOfSection prototype
typedef NTSTATUS(WINAPI* pNtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
    );

// NtQueryInformationProcess prototype
typedef NTSTATUS(WINAPI* pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    DWORD ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

#define ProcessBasicInformation 0

DWORD GetExplorerPid(void)
{
    DWORD pids[1024], needed;
    if (!EnumProcesses(pids, sizeof(pids), &needed))
        return 0;

    DWORD count = needed / sizeof(DWORD);
    for (DWORD i = 0; i < count; i++)
    {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pids[i]);
        if (!hProcess) continue;

        CHAR name[MAX_PATH] = { 0 };
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameA(hProcess, 0, name, &size))
        {
            if (strstr(name, "explorer.exe"))
            {
                CloseHandle(hProcess);
                return pids[i];
            }
        }
        CloseHandle(hProcess);
    }
    return 0;
}

PVOID GetProcessImageBase(HANDLE hProcess)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtQueryInformationProcess NtQueryInformationProcess =
        (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

    PROCESS_BASIC_INFORMATION pbi = { 0 };
    ULONG len = 0;
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &len);
    if (status != 0)
    {
        printf("[-] NtQueryInformationProcess failed: 0x%08X\n", (ULONG)status);
        return NULL;
    }

    // Read ImageBaseAddress from PEB (offset 0x10 on x64, 0x08 on x86)
#ifdef _WIN64
    ULONG_PTR pebOffset = 0x10;
#else
    ULONG_PTR pebOffset = 0x08;
#endif

    PVOID imageBase = NULL;
    SIZE_T read = 0;
    BOOL ok = ReadProcessMemory(hProcess, (PBYTE)pbi.PebBaseAddress + pebOffset, &imageBase, sizeof(imageBase), &read);
    if (!ok || read != sizeof(imageBase))
    {
        printf("[-] ReadProcessMemory(PEB.ImageBaseAddress) failed: %lu\n", GetLastError());
        return NULL;
    }

    return imageBase;
}

int main(void)
{
    DWORD explorerPid = GetExplorerPid();
    if (!explorerPid)
    {
        printf("[-] explorer.exe not found\n");
        return 1;
    }
    printf("[*] explorer.exe PID: %lu\n", explorerPid);

    // Step 1: Open with ALL_ACCESS
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, explorerPid);
    if (!hProcess)
    {
        printf("[-] OpenProcess failed: %lu\n", GetLastError());
        return 1;
    }
    printf("[+] OpenProcess succeeded, handle: %p\n", (void*)hProcess);

    // Step 2: Get real image base from PEB
    PVOID imageBase = GetProcessImageBase(hProcess);
    if (!imageBase)
    {
        printf("[-] Could not get image base, aborting\n");
        CloseHandle(hProcess);
        return 1;
    }
    printf("[*] Image base: %p\n", imageBase);

    // Step 3: Try NtUnmapViewOfSection with REAL base address
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");

    NTSTATUS status = NtUnmapViewOfSection(hProcess, imageBase);
    printf("[*] NtUnmapViewOfSection(%p) status: 0x%08X\n", imageBase, (ULONG)status);

    if (status == 0xC0000022) // STATUS_ACCESS_DENIED
        printf("[+] ACCESS DENIED - PHDenier is working!\n");
    else if (status == 0xC0000019) // STATUS_INVALID_VIEW_OF_SECTION
        printf("[!] Invalid view of section - wrong base address?\n");
    else if (status == 0) // STATUS_SUCCESS
        printf("[!] NtUnmapViewOfSection SUCCEEDED (unexpected!)\n");
    else
        printf("[*] NtUnmapViewOfSection returned: 0x%08X\n", (ULONG)status);

    // Step 4: Try VirtualAllocEx
    PVOID mem = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem)
    {
        printf("[*] VirtualAllocEx failed: %lu\n", GetLastError());
        if (GetLastError() == ERROR_ACCESS_DENIED)
            printf("[+] ACCESS DENIED - PHDenier stripped VM_OPERATION!\n");
    }
    else
    {
        printf("[!] VirtualAllocEx succeeded: %p (unexpected!)\n", mem);
    }

    // Step 5: Try WriteProcessMemory
    BYTE buf[16] = { 0x90 };
    SIZE_T written = 0;
    BOOL wpm = WriteProcessMemory(hProcess, (PVOID)0x10000, buf, sizeof(buf), &written);
    if (!wpm)
    {
        printf("[*] WriteProcessMemory failed: %lu\n", GetLastError());
        if (GetLastError() == ERROR_ACCESS_DENIED)
            printf("[+] ACCESS DENIED - PHDenier stripped VM_WRITE!\n");
    }
    else
    {
        printf("[!] WriteProcessMemory succeeded (unexpected!)\n");
    }

    // Step 6: Try CreateRemoteThread
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)0x10000, NULL, 0, NULL);
    if (!hThread)
    {
        printf("[*] CreateRemoteThread failed: %lu\n", GetLastError());
        if (GetLastError() == ERROR_ACCESS_DENIED)
            printf("[+] ACCESS DENIED - PHDenier stripped CREATE_THREAD!\n");
    }
    else
    {
        printf("[!] CreateRemoteThread succeeded (unexpected!)\n");
        CloseHandle(hThread);
    }

    CloseHandle(hProcess);
    printf("\n[*] Test complete.\n");
    return 0;
}
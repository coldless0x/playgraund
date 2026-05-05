#include "syscall.hpp"
#include <cstdio>
#include <cwchar>

static void InitUS(UNICODE_STRING* us, const wchar_t* s)
{
    us->Buffer = const_cast<wchar_t*>(s);
    us->Length = static_cast<USHORT>(wcslen(s) * sizeof(wchar_t));
    us->MaximumLength = static_cast<USHORT>(us->Length + sizeof(wchar_t));
}

int main()
{
#ifndef _WIN64
    printf("\n[-] This tool must be built as x64 (Configuration Manager -> Platform: x64).\n");
    printf("    Win32 builds cannot use x64 syscall stubs.\n\n");
    return 1;
#endif

    printf("\n[*] Initializing syscalls...\n");
    fflush(stdout);

    if (!syscall::Initialize())
    {
        printf("[-] Failed to resolve SSNs from ntdll (disk + loaded image).\n");
        printf("    Use an x64 build and run on 64-bit Windows.\n\n");
        return 1;
    }

    printf("[+] NtCreateUserProcess: 0x%04X\n", syscall::g_SsnNtCreateUserProcess);
    printf("[+] NtClose: 0x%04X\n\n", syscall::g_SsnNtClose);

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
    {
        printf("[-] GetModuleHandleW(ntdll) failed\n");
        return 1;
    }

    using RtlCreateProcParams_t = NTSTATUS(NTAPI*)(
        PRTL_USER_PROCESS_PARAMETERS*, PUNICODE_STRING, PUNICODE_STRING,
        PUNICODE_STRING, PUNICODE_STRING, PVOID,
        PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, ULONG);

    auto RtlCreateProcParams = reinterpret_cast<RtlCreateProcParams_t>(
        GetProcAddress(ntdll, "RtlCreateProcessParametersEx"));
    using RtlDestroyProcParams_t = NTSTATUS(NTAPI*)(PRTL_USER_PROCESS_PARAMETERS);
    auto RtlDestroyProcParams = reinterpret_cast<RtlDestroyProcParams_t>(
        GetProcAddress(ntdll, "RtlDestroyProcessParameters"));

    if (!RtlCreateProcParams)
    {
        printf("[-] RtlCreateProcessParametersEx not found\n");
        return 1;
    }

    UNICODE_STRING img = {};
    UNICODE_STRING dir = {};
    UNICODE_STRING cmd = {};
    InitUS(&img, L"\\??\\C:\\Windows\\System32\\notepad.exe");
    InitUS(&dir, L"C:\\Windows\\System32\\");
    InitUS(&cmd, L"notepad.exe");

    PRTL_USER_PROCESS_PARAMETERS params = nullptr;
    NTSTATUS st = RtlCreateProcParams(
        &params, &img, nullptr, &dir, &cmd,
        nullptr, nullptr, nullptr, nullptr, nullptr,
        RTL_USER_PROC_PARAMS_NORMALIZED);

    if (!NT_SUCCESS(st))
    {
        printf("[-] RtlCreateProcessParametersEx failed: 0x%08X\n", static_cast<unsigned>(st));
        return 1;
    }

    printf("[+] Process parameters created\n");

    PS_CREATE_INFO ci = {};
    ci.Size = sizeof(ci);
    ci.State = PsCreateInitialState;

    PS_ATTRIBUTE_LIST al = {};
    al.TotalLength = sizeof(al);
    al.Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    al.Attributes[0].Size = img.Length;
    al.Attributes[0].Value = reinterpret_cast<ULONG_PTR>(img.Buffer);
    al.Attributes[0].ReturnLength = nullptr;

    HANDLE hProc = nullptr;
    HANDLE hThread = nullptr;

    printf("[*] Calling NtCreateUserProcess...\n");
    fflush(stdout);

    st = syscall::NtCreateUserProcess(
        &hProc, &hThread,
        PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS,
        nullptr, nullptr, 0, 0,
        params, &ci, &al);

    if (RtlDestroyProcParams && params)
        RtlDestroyProcParams(params);

    if (!NT_SUCCESS(st))
    {
        printf("[-] NtCreateUserProcess failed: 0x%08X\n", static_cast<unsigned>(st));
        return 1;
    }

    using NtQueryInfo_t = NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    auto NtQueryInfo = reinterpret_cast<NtQueryInfo_t>(
        GetProcAddress(ntdll, "NtQueryInformationProcess"));

    PROCESS_BASIC_INFORMATION pbi = {};
    if (NtQueryInfo)
    {
        NtQueryInfo(
            hProc,
            ProcessBasicInformation,
            &pbi,
            sizeof(pbi),
            nullptr);
    }

    printf("[+] notepad.exe spawned\n");
    printf("[+] PID: %llu\n", static_cast<unsigned long long>(pbi.UniqueProcessId));
    printf("[+] hProcess: %p\n", hProc);
    printf("[+] hThread: %p\n\n", hThread);

    syscall::NtClose(hThread);
    syscall::NtClose(hProc);

    printf("[+] Done\n\n");
    return 0;
}

#include "syscall.hpp"
#include <cstdio>

static void InitializeUnicodeString(PUNICODE_STRING pUnicodeString, const wchar_t* pwszSource)
{
    SIZE_T length = 0;
    while (pwszSource[length])
        length++;

    pUnicodeString->Buffer = const_cast<wchar_t*>(pwszSource);
    pUnicodeString->Length = static_cast<USHORT>(length * sizeof(wchar_t));
    pUnicodeString->MaximumLength = pUnicodeString->Length + sizeof(wchar_t);
}

int main()
{
    printf("\n[DEBUG] Starting main...\n");
    printf("[DEBUG] Calling syscall::Initialize()...\n");

    if (!syscall::Initialize())
    {
        printf("[-] Failed to resolve syscall numbers\n");
        printf("[DEBUG] GetLastError: %lu\n", GetLastError());
        return 1;
    }

    printf("[DEBUG] Initialize() succeeded\n");
    printf("[+] NtCreateUserProcess SSN: 0x%04X\n", syscall::g_SsnNtCreateUserProcess);
    printf("[+] NtClose SSN: 0x%04X\n\n", syscall::g_SsnNtClose);

    if (syscall::g_SsnNtCreateUserProcess == 0 || syscall::g_SsnNtClose == 0)
    {
        printf("[-] Invalid SSN values\n");
        return 1;
    }

    printf("[DEBUG] Getting ntdll handle...\n");
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll)
    {
        printf("[-] Failed to get ntdll handle\n");
        return 1;
    }
    printf("[DEBUG] ntdll handle: %p\n", hNtdll);

    using FnRtlCreateProcessParametersEx = NTSTATUS(NTAPI*)(
        PRTL_USER_PROCESS_PARAMETERS*,
        PUNICODE_STRING,
        PUNICODE_STRING,
        PUNICODE_STRING,
        PUNICODE_STRING,
        PVOID,
        PUNICODE_STRING,
        PUNICODE_STRING,
        PUNICODE_STRING,
        PUNICODE_STRING,
        ULONG);

    auto pfnRtlCreateProcessParametersEx = reinterpret_cast<FnRtlCreateProcessParametersEx>(
        GetProcAddress(hNtdll, "RtlCreateProcessParametersEx"));

    if (!pfnRtlCreateProcessParametersEx)
    {
        printf("[-] Failed to resolve RtlCreateProcessParametersEx\n");
        return 1;
    }

    const wchar_t* pwszImagePath = L"\\??\\C:\\Windows\\System32\\notepad.exe";
    const wchar_t* pwszCurrentDirectory = L"C:\\Windows\\System32\\";
    const wchar_t* pwszCommandLine = L"notepad.exe";

    UNICODE_STRING usImagePath = {};
    UNICODE_STRING usCurrentDirectory = {};
    UNICODE_STRING usCommandLine = {};

    InitializeUnicodeString(&usImagePath, pwszImagePath);
    InitializeUnicodeString(&usCurrentDirectory, pwszCurrentDirectory);
    InitializeUnicodeString(&usCommandLine, pwszCommandLine);

    PRTL_USER_PROCESS_PARAMETERS pProcessParameters = nullptr;
    NTSTATUS status = pfnRtlCreateProcessParametersEx(
        &pProcessParameters,
        &usImagePath,
        nullptr,
        &usCurrentDirectory,
        &usCommandLine,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        RTL_USER_PROC_PARAMS_NORMALIZED);

    if (!NT_SUCCESS(status))
    {
        printf("[-] RtlCreateProcessParametersEx failed: 0x%08X\n", status);
        return 1;
    }

    printf("[+] Process parameters created\n");

    PS_CREATE_INFO createInfo = {};
    createInfo.Size = sizeof(PS_CREATE_INFO);
    createInfo.State = PsCreateInitialState;

    PS_ATTRIBUTE_LIST attributeList = {};
    attributeList.TotalLength = sizeof(PS_ATTRIBUTE_LIST);
    attributeList.Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    attributeList.Attributes[0].Size = usImagePath.Length;
    attributeList.Attributes[0].Value = reinterpret_cast<ULONG_PTR>(usImagePath.Buffer);
    attributeList.Attributes[0].ReturnLength = nullptr;

    HANDLE hProcess = nullptr;
    HANDLE hThread = nullptr;

    printf("[*] Invoking NtCreateUserProcess...\n");

    status = syscall::NtCreateUserProcess(
        &hProcess,
        &hThread,
        PROCESS_ALL_ACCESS,
        THREAD_ALL_ACCESS,
        nullptr,
        nullptr,
        0,
        0,
        pProcessParameters,
        &createInfo,
        &attributeList);

    if (!NT_SUCCESS(status))
    {
        printf("[-] NtCreateUserProcess failed: 0x%08X\n", status);
        return 1;
    }

    using FnNtQueryInformationProcess = NTSTATUS(NTAPI*)(
        HANDLE,
        PROCESSINFOCLASS,
        PVOID,
        ULONG,
        PULONG);

    auto pfnNtQueryInformationProcess = reinterpret_cast<FnNtQueryInformationProcess>(
        GetProcAddress(hNtdll, "NtQueryInformationProcess"));

    PROCESS_BASIC_INFORMATION pbi = {};
    if (pfnNtQueryInformationProcess)
    {
        pfnNtQueryInformationProcess(
            hProcess,
            ProcessBasicInformation,
            &pbi,
            sizeof(PROCESS_BASIC_INFORMATION),
            nullptr);
    }

    printf("[+] Process created successfully\n");
    printf("[+] PID: %llu\n", static_cast<unsigned long long>(pbi.UniqueProcessId));
    printf("[+] Process handle: 0x%p\n", hProcess);
    printf("[+] Thread handle: 0x%p\n\n", hThread);

    syscall::NtClose(hThread);
    syscall::NtClose(hProcess);

    printf("[+] Handles closed\n\n");
    return 0;
}

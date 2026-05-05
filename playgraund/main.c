#include "syscall.h"
#include <stdio.h>

void InitUS(UNICODE_STRING* us, WCHAR* s)
{
    us->Buffer = s;
    us->Length = (USHORT)(lstrlenW(s) * 2);
    us->MaximumLength = us->Length + 2;
}

int main()
{
    printf("\n[*] Initializing syscalls...\n");

    if (!InitSyscalls())
    {
        printf("[-] Failed\n");
        return 1;
    }

    printf("[+] NtCreateUserProcess: 0x%04X\n", g_NtCreateUserProcess_SSN);
    printf("[+] NtClose: 0x%04X\n\n", g_NtClose_SSN);

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");

    typedef NTSTATUS(NTAPI* RtlCreateProcParams_t)(
        PRTL_USER_PROCESS_PARAMETERS*, PUNICODE_STRING, PUNICODE_STRING,
        PUNICODE_STRING, PUNICODE_STRING, PVOID,
        PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, ULONG);

    RtlCreateProcParams_t RtlCreateProcParams =
        (RtlCreateProcParams_t)GetProcAddress(ntdll, "RtlCreateProcessParametersEx");

    WCHAR img[] = L"\\??\\C:\\Windows\\System32\\notepad.exe";
    WCHAR dir[] = L"C:\\Windows\\System32\\";
    WCHAR cmd[] = L"notepad.exe";

    UNICODE_STRING usImg, usDir, usCmd;
    InitUS(&usImg, img);
    InitUS(&usDir, dir);
    InitUS(&usCmd, cmd);

    PRTL_USER_PROCESS_PARAMETERS params = NULL;
    NTSTATUS st = RtlCreateProcParams(&params, &usImg, NULL, &usDir, &usCmd,
                                      NULL, NULL, NULL, NULL, NULL, 1);

    if (!NT_SUCCESS(st))
    {
        printf("[-] RtlCreateProcessParametersEx: 0x%08X\n", st);
        return 1;
    }

    printf("[+] Parameters created\n");

    PS_CREATE_INFO ci = { 0 };
    ci.Size = sizeof(ci);
    ci.State = PsCreateInitialState;

    PS_ATTRIBUTE_LIST al = { 0 };
    al.TotalLength = sizeof(al);
    al.Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    al.Attributes[0].Size = usImg.Length;
    al.Attributes[0].Value = (ULONG_PTR)usImg.Buffer;

    HANDLE hProc = NULL, hThread = NULL;

    printf("[*] Calling NtCreateUserProcess...\n");

    st = SysNtCreateUserProcess(
        &hProc, &hThread,
        PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS,
        NULL, NULL, 0, 0,
        params, &ci, &al);

    if (!NT_SUCCESS(st))
    {
        printf("[-] NtCreateUserProcess: 0x%08X\n", st);
        return 1;
    }

    typedef NTSTATUS(NTAPI* NtQueryInfo_t)(HANDLE, DWORD, PVOID, ULONG, PULONG);
    NtQueryInfo_t NtQueryInfo = (NtQueryInfo_t)GetProcAddress(ntdll, "NtQueryInformationProcess");

    PROCESS_BASIC_INFORMATION pbi = { 0 };
    NtQueryInfo(hProc, 0, &pbi, sizeof(pbi), NULL);

    printf("[+] notepad.exe spawned\n");
    printf("[+] PID: %llu\n", (unsigned long long)pbi.UniqueProcessId);
    printf("[+] hProcess: %p\n", hProc);
    printf("[+] hThread: %p\n\n", hThread);

    SysNtClose(hThread);
    SysNtClose(hProc);

    printf("[+] Done\n\n");
    return 0;
}

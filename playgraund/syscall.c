#include "syscall.h"

WORD g_NtCreateUserProcess_SSN = 0;
WORD g_NtClose_SSN = 0;

static BYTE g_StubMem[128] = { 0 };
static BOOL g_StubInit = FALSE;

static WORD GetSSN(BYTE* base, const char* name)
{
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != 0x5A4D) return 0;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != 0x4550) return 0;

    DWORD expRva = nt->OptionalHeader.DataDirectory[0].VirtualAddress;
    if (!expRva) return 0;

    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + expRva);
    DWORD* names = (DWORD*)(base + exp->AddressOfNames);
    WORD*  ords  = (WORD*)(base + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++)
    {
        char* n = (char*)(base + names[i]);
        
        int j = 0;
        while (name[j] && n[j] && name[j] == n[j]) j++;
        if (name[j] != 0 || n[j] != 0) continue;

        BYTE* fn = base + funcs[ords[i]];
        if (fn[0] == 0x4C && fn[1] == 0x8B && fn[2] == 0xD1 && fn[3] == 0xB8)
            return *(WORD*)(fn + 4);

        if (fn[0] == 0xE9)
        {
            for (int d = 1; d <= 32; d++)
            {
                BYTE* up = fn - d * 32;
                if (up > base && up[0] == 0x4C && up[1] == 0x8B && up[2] == 0xD1 && up[3] == 0xB8)
                    return (WORD)(*(WORD*)(up + 4) + d);
            }
        }
        break;
    }
    return 0;
}

BOOL InitSyscalls()
{
    MessageBoxA(NULL, "Step 1: Getting system directory", "Debug", MB_OK);
    
    WCHAR path[MAX_PATH];
    GetSystemDirectoryW(path, MAX_PATH);
    lstrcatW(path, L"\\ntdll.dll");

    MessageBoxA(NULL, "Step 2: Opening ntdll.dll", "Debug", MB_OK);
    
    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        MessageBoxA(NULL, "Failed to open ntdll.dll", "Error", MB_OK);
        return FALSE;
    }

    MessageBoxA(NULL, "Step 3: Creating file mapping", "Debug", MB_OK);
    
    HANDLE hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap)
    {
        MessageBoxA(NULL, "Failed to create mapping", "Error", MB_OK);
        CloseHandle(hFile);
        return FALSE;
    }

    MessageBoxA(NULL, "Step 4: Mapping view of file", "Debug", MB_OK);
    
    BYTE* base = (BYTE*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!base)
    {
        MessageBoxA(NULL, "Failed to map view", "Error", MB_OK);
        CloseHandle(hMap);
        CloseHandle(hFile);
        return FALSE;
    }

    MessageBoxA(NULL, "Step 5: Resolving NtCreateUserProcess", "Debug", MB_OK);
    
    g_NtCreateUserProcess_SSN = GetSSN(base, "NtCreateUserProcess");
    
    MessageBoxA(NULL, "Step 6: Resolving NtClose", "Debug", MB_OK);
    
    g_NtClose_SSN = GetSSN(base, "NtClose");

    MessageBoxA(NULL, "Step 7: Cleaning up", "Debug", MB_OK);
    
    UnmapViewOfFile(base);
    CloseHandle(hMap);
    CloseHandle(hFile);

    if (!g_NtCreateUserProcess_SSN || !g_NtClose_SSN)
    {
        MessageBoxA(NULL, "Failed to resolve SSNs", "Error", MB_OK);
        return FALSE;
    }

    MessageBoxA(NULL, "Step 8: Setting up stub memory", "Debug", MB_OK);
    
    DWORD old;
    VirtualProtect(g_StubMem, sizeof(g_StubMem), PAGE_EXECUTE_READWRITE, &old);
    g_StubInit = TRUE;

    MessageBoxA(NULL, "Success!", "Debug", MB_OK);
    
    return TRUE;
}

static BYTE* MakeStub(WORD ssn, int slot)
{
    BYTE* stub = g_StubMem + (slot * 32);
    stub[0]  = 0x4C; stub[1]  = 0x8B; stub[2]  = 0xD1;
    stub[3]  = 0xB8;
    stub[4]  = (BYTE)(ssn & 0xFF);
    stub[5]  = (BYTE)(ssn >> 8);
    stub[6]  = 0x00; stub[7]  = 0x00;
    stub[8]  = 0x0F; stub[9]  = 0x05;
    stub[10] = 0xC3;
    return stub;
}

NTSTATUS SysNtClose(HANDLE Handle)
{
    typedef NTSTATUS(NTAPI* FN)(HANDLE);
    return ((FN)MakeStub(g_NtClose_SSN, 0))(Handle);
}

NTSTATUS SysNtCreateUserProcess(
    PHANDLE                      ProcessHandle,
    PHANDLE                      ThreadHandle,
    ACCESS_MASK                  ProcessDesiredAccess,
    ACCESS_MASK                  ThreadDesiredAccess,
    POBJECT_ATTRIBUTES           ProcessObjectAttributes,
    POBJECT_ATTRIBUTES           ThreadObjectAttributes,
    ULONG                        ProcessFlags,
    ULONG                        ThreadFlags,
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    PPS_CREATE_INFO              CreateInfo,
    PPS_ATTRIBUTE_LIST           AttributeList)
{
    typedef NTSTATUS(NTAPI* FN)(
        PHANDLE, PHANDLE, ACCESS_MASK, ACCESS_MASK,
        POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES,
        ULONG, ULONG, PRTL_USER_PROCESS_PARAMETERS,
        PPS_CREATE_INFO, PPS_ATTRIBUTE_LIST);

    return ((FN)MakeStub(g_NtCreateUserProcess_SSN, 1))(
        ProcessHandle, ThreadHandle,
        ProcessDesiredAccess, ThreadDesiredAccess,
        ProcessObjectAttributes, ThreadObjectAttributes,
        ProcessFlags, ThreadFlags,
        ProcessParameters, CreateInfo, AttributeList);
}

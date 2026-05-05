#include "syscall.hpp"

namespace syscall {

WORD g_SsnNtCreateUserProcess = 0;
WORD g_SsnNtClose = 0;

namespace detail {

static int StringCompare(const char* s1, const char* s2)
{
    while (*s1 && (*s1 == *s2))
    {
        s1++;
        s2++;
    }
    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}

static SIZE_T StringLength(const wchar_t* s)
{
    SIZE_T len = 0;
    while (s[len])
        len++;
    return len;
}

WORD ResolveSSN(PBYTE pModuleBase, const char* pFunctionName)
{
    if (!pModuleBase || !pFunctionName)
        return 0;

    PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pModuleBase);
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    PIMAGE_NT_HEADERS64 pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(
        pModuleBase + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
        return 0;

    DWORD dwExportDirRva = pNtHeaders->OptionalHeader
        .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!dwExportDirRva)
        return 0;

    PIMAGE_EXPORT_DIRECTORY pExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
        pModuleBase + dwExportDirRva);

    PDWORD pNameRvas = reinterpret_cast<PDWORD>(pModuleBase + pExportDir->AddressOfNames);
    PWORD  pOrdinals = reinterpret_cast<PWORD>(pModuleBase + pExportDir->AddressOfNameOrdinals);
    PDWORD pFuncRvas = reinterpret_cast<PDWORD>(pModuleBase + pExportDir->AddressOfFunctions);

    for (DWORD i = 0; i < pExportDir->NumberOfNames; ++i)
    {
        const char* pName = reinterpret_cast<const char*>(pModuleBase + pNameRvas[i]);
        if (StringCompare(pName, pFunctionName) != 0)
            continue;

        PBYTE pFunction = pModuleBase + pFuncRvas[pOrdinals[i]];

        if (pFunction[0] == 0x4C && pFunction[1] == 0x8B && 
            pFunction[2] == 0xD1 && pFunction[3] == 0xB8)
        {
            return *reinterpret_cast<PWORD>(pFunction + 4);
        }

        if (pFunction[0] == 0xE9)
        {
            for (int delta = 1; delta <= 32; ++delta)
            {
                PBYTE pUp = pFunction - delta * 32;
                if (pUp[0] == 0x4C && pUp[1] == 0x8B && 
                    pUp[2] == 0xD1 && pUp[3] == 0xB8)
                {
                    return static_cast<WORD>(*reinterpret_cast<PWORD>(pUp + 4) + delta);
                }

                PBYTE pDown = pFunction + delta * 32;
                if (pDown[0] == 0x4C && pDown[1] == 0x8B && 
                    pDown[2] == 0xD1 && pDown[3] == 0xB8)
                {
                    return static_cast<WORD>(*reinterpret_cast<PWORD>(pDown + 4) - delta);
                }
            }
        }
        break;
    }
    return 0;
}

PBYTE GenerateStub(WORD wSSN)
{
    static BYTE s_StubPool[64] = {};
    static PBYTE s_pSlots[2] = { s_StubPool, s_StubPool + 32 };
    static int s_nSlotIndex = 0;
    static bool s_bInitialized = false;

    if (!s_bInitialized)
    {
        DWORD dwOldProtect = 0;
        VirtualProtect(s_StubPool, sizeof(s_StubPool), PAGE_EXECUTE_READWRITE, &dwOldProtect);
        s_bInitialized = true;
    }

    PBYTE pStub = s_pSlots[s_nSlotIndex];
    s_nSlotIndex = (s_nSlotIndex + 1) % 2;

    pStub[0]  = 0x4C;
    pStub[1]  = 0x8B;
    pStub[2]  = 0xD1;
    pStub[3]  = 0xB8;
    pStub[4]  = static_cast<BYTE>(wSSN & 0xFF);
    pStub[5]  = static_cast<BYTE>((wSSN >> 8) & 0xFF);
    pStub[6]  = 0x00;
    pStub[7]  = 0x00;
    pStub[8]  = 0x0F;
    pStub[9]  = 0x05;
    pStub[10] = 0xC3;

    return pStub;
}

} // namespace detail

bool Initialize()
{
    wchar_t wszSystemDir[MAX_PATH] = {};
    UINT uLen = GetSystemDirectoryW(wszSystemDir, MAX_PATH);
    if (uLen == 0 || uLen >= MAX_PATH - 11)
        return false;

    const wchar_t* wszNtdll = L"\\ntdll.dll";
    for (SIZE_T i = 0; i < 11; ++i)
        wszSystemDir[uLen + i] = wszNtdll[i];

    HANDLE hFile = CreateFileW(
        wszSystemDir,
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
        return false;

    HANDLE hMapping = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMapping)
    {
        CloseHandle(hFile);
        return false;
    }

    PBYTE pBase = static_cast<PBYTE>(MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0));
    if (!pBase)
    {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return false;
    }

    g_SsnNtCreateUserProcess = detail::ResolveSSN(pBase, "NtCreateUserProcess");
    g_SsnNtClose = detail::ResolveSSN(pBase, "NtClose");

    bool bSuccess = (g_SsnNtCreateUserProcess != 0 && g_SsnNtClose != 0);

    UnmapViewOfFile(pBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    return bSuccess;
}

NTSTATUS NtClose(HANDLE Handle)
{
    using FnNtClose = NTSTATUS(NTAPI*)(HANDLE);
    auto pfnNtClose = reinterpret_cast<FnNtClose>(detail::GenerateStub(g_SsnNtClose));
    return pfnNtClose(Handle);
}

NTSTATUS NtCreateUserProcess(
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
    using FnNtCreateUserProcess = NTSTATUS(NTAPI*)(
        PHANDLE, PHANDLE, ACCESS_MASK, ACCESS_MASK,
        POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES,
        ULONG, ULONG,
        PRTL_USER_PROCESS_PARAMETERS,
        PPS_CREATE_INFO,
        PPS_ATTRIBUTE_LIST);

    auto pfnNtCreateUserProcess = reinterpret_cast<FnNtCreateUserProcess>(
        detail::GenerateStub(g_SsnNtCreateUserProcess));

    return pfnNtCreateUserProcess(
        ProcessHandle, ThreadHandle,
        ProcessDesiredAccess, ThreadDesiredAccess,
        ProcessObjectAttributes, ThreadObjectAttributes,
        ProcessFlags, ThreadFlags,
        ProcessParameters, CreateInfo, AttributeList);
}

} // namespace syscall

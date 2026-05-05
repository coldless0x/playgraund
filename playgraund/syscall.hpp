#pragma once

#include "ntstructs.hpp"
#include <cstring>

namespace syscall {

inline WORD g_SsnNtCreateUserProcess = 0;
inline WORD g_SsnNtClose = 0;

namespace detail {

inline WORD ResolveSSN(PBYTE pModuleBase, const char* pFunctionName)
{
    if (!pModuleBase || !pFunctionName)
        return 0;

    auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pModuleBase);
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    auto pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(pModuleBase + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
        return 0;

    DWORD dwExportRva = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!dwExportRva)
        return 0;

    auto pExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(pModuleBase + dwExportRva);

    auto pNames    = reinterpret_cast<PDWORD>(pModuleBase + pExportDir->AddressOfNames);
    auto pOrdinals = reinterpret_cast<PWORD>(pModuleBase + pExportDir->AddressOfNameOrdinals);
    auto pFuncs    = reinterpret_cast<PDWORD>(pModuleBase + pExportDir->AddressOfFunctions);

    for (DWORD i = 0; i < pExportDir->NumberOfNames; ++i)
    {
        const char* pName = reinterpret_cast<const char*>(pModuleBase + pNames[i]);
        if (strcmp(pName, pFunctionName) != 0)
            continue;

        PBYTE pFunc = pModuleBase + pFuncs[pOrdinals[i]];

        if (pFunc[0] == 0x4C && pFunc[1] == 0x8B && pFunc[2] == 0xD1 && pFunc[3] == 0xB8)
            return *reinterpret_cast<PWORD>(pFunc + 4);

        if (pFunc[0] == 0xE9)
        {
            for (int delta = 1; delta <= 32; ++delta)
            {
                PBYTE pUp = pFunc - delta * 32;
                if (pUp >= pModuleBase && 
                    pUp[0] == 0x4C && pUp[1] == 0x8B && pUp[2] == 0xD1 && pUp[3] == 0xB8)
                    return static_cast<WORD>(*reinterpret_cast<PWORD>(pUp + 4) + delta);

                PBYTE pDown = pFunc + delta * 32;
                if (pDown[0] == 0x4C && pDown[1] == 0x8B && pDown[2] == 0xD1 && pDown[3] == 0xB8)
                    return static_cast<WORD>(*reinterpret_cast<PWORD>(pDown + 4) - delta);
            }
        }
        break;
    }
    return 0;
}

inline PBYTE GenerateStub(WORD wSSN)
{
    static BYTE s_StubPool[64] = {};
    static bool s_bInitialized = false;
    static PBYTE s_pStubSlots[2] = { s_StubPool, s_StubPool + 32 };
    static int s_SlotIndex = 0;

    if (!s_bInitialized)
    {
        DWORD dwOldProtect = 0;
        VirtualProtect(s_StubPool, sizeof(s_StubPool), PAGE_EXECUTE_READWRITE, &dwOldProtect);
        s_bInitialized = true;
    }

    PBYTE pStub = s_pStubSlots[s_SlotIndex];
    s_SlotIndex = (s_SlotIndex + 1) % 2;

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

    FlushInstructionCache(GetCurrentProcess(), pStub, 11);
    return pStub;
}

} // namespace detail

inline bool Initialize()
{
    wchar_t wszNtdllPath[MAX_PATH] = {};
    if (!GetSystemDirectoryW(wszNtdllPath, MAX_PATH))
        return false;

    wcscat_s(wszNtdllPath, L"\\ntdll.dll");

    HANDLE hFile = CreateFileW(wszNtdllPath, GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
        return false;

    HANDLE hMapping = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMapping)
    {
        CloseHandle(hFile);
        return false;
    }

    PBYTE pBase = static_cast<PBYTE>(MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0));
    bool bSuccess = false;

    if (pBase)
    {
        g_SsnNtCreateUserProcess = detail::ResolveSSN(pBase, "NtCreateUserProcess");
        g_SsnNtClose = detail::ResolveSSN(pBase, "NtClose");
        bSuccess = (g_SsnNtCreateUserProcess != 0 && g_SsnNtClose != 0);
        UnmapViewOfFile(pBase);
    }

    CloseHandle(hMapping);
    CloseHandle(hFile);
    return bSuccess;
}

inline NTSTATUS NtClose(HANDLE Handle)
{
    using FnNtClose = NTSTATUS(NTAPI*)(HANDLE);
    auto pfnNtClose = reinterpret_cast<FnNtClose>(detail::GenerateStub(g_SsnNtClose));
    return pfnNtClose(Handle);
}

inline NTSTATUS NtCreateUserProcess(
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

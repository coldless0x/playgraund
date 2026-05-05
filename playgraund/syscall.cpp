#include "syscall.hpp"
#include <cstring>
#include <cwchar>

namespace syscall {

WORD g_SsnNtCreateUserProcess = 0;
WORD g_SsnNtClose = 0;

namespace detail {

static bool CanRead(const BYTE* pBase, SIZE_T cbMap, const void* p, SIZE_T cbNeed)
{
    const auto pb = static_cast<const BYTE*>(p);
    if (pb < pBase)
        return false;
    const SIZE_T off = static_cast<SIZE_T>(pb - pBase);
    if (off + cbNeed < off)
        return false;
    return off + cbNeed <= cbMap;
}

static WORD ResolveSSN(const BYTE* pBase, SIZE_T cbMap, const char* pName)
{
    if (!pBase || !pName || cbMap < sizeof(IMAGE_DOS_HEADER))
        return 0;

    auto pDos = reinterpret_cast<const IMAGE_DOS_HEADER*>(pBase);
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    const LONG e_lfanew = pDos->e_lfanew;
    if (e_lfanew < 0)
        return 0;
    const SIZE_T ntOff = static_cast<SIZE_T>(e_lfanew);
    if (ntOff + sizeof(IMAGE_NT_HEADERS64) > cbMap)
        return 0;

    auto pNt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(pBase + ntOff);
    if (pNt->Signature != IMAGE_NT_SIGNATURE)
        return 0;
    if (pNt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        return 0;

    const DWORD expRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (expRva == 0)
        return 0;
    if (!CanRead(pBase, cbMap, pBase + expRva, sizeof(IMAGE_EXPORT_DIRECTORY)))
        return 0;

    auto pExp = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(pBase + expRva);
    const DWORD nNames = pExp->NumberOfNames;
    const DWORD nFuncs = pExp->NumberOfFunctions;
    if (nNames == 0 || nFuncs == 0 || nNames > 0x100000u || nFuncs > 0x100000u)
        return 0;

    if (!CanRead(pBase, cbMap, pBase + pExp->AddressOfNames, static_cast<SIZE_T>(nNames) * sizeof(DWORD)))
        return 0;
    if (!CanRead(pBase, cbMap, pBase + pExp->AddressOfNameOrdinals, static_cast<SIZE_T>(nNames) * sizeof(WORD)))
        return 0;
    if (!CanRead(pBase, cbMap, pBase + pExp->AddressOfFunctions, static_cast<SIZE_T>(nFuncs) * sizeof(DWORD)))
        return 0;

    const auto pNameRvas = reinterpret_cast<const DWORD*>(pBase + pExp->AddressOfNames);
    const auto pOrds = reinterpret_cast<const WORD*>(pBase + pExp->AddressOfNameOrdinals);
    const auto pFuncRvas = reinterpret_cast<const DWORD*>(pBase + pExp->AddressOfFunctions);

    for (DWORD i = 0; i < nNames; ++i)
    {
        const DWORD nameRva = pNameRvas[i];
        if (nameRva == 0 || !CanRead(pBase, cbMap, pBase + nameRva, 1))
            continue;

        SIZE_T nameMax = cbMap - static_cast<SIZE_T>(nameRva);
        if (nameMax > 512)
            nameMax = 512;
        if (!CanRead(pBase, cbMap, pBase + nameRva, nameMax))
            continue;

        const char* exportName = reinterpret_cast<const char*>(pBase + nameRva);
        bool terminated = false;
        for (SIZE_T k = 0; k < nameMax; ++k)
        {
            if (exportName[k] == '\0')
            {
                terminated = true;
                break;
            }
        }
        if (!terminated)
            continue;
        if (strcmp(exportName, pName) != 0)
            continue;

        const WORD ord = pOrds[i];
        if (ord >= nFuncs)
            continue;

        const DWORD funcRva = pFuncRvas[ord];
        if (funcRva == 0 || !CanRead(pBase, cbMap, pBase + funcRva, 8))
            continue;

        const BYTE* pFunc = pBase + funcRva;

        if (pFunc[0] == 0x4C && pFunc[1] == 0x8B && pFunc[2] == 0xD1 && pFunc[3] == 0xB8)
            return *reinterpret_cast<const WORD*>(pFunc + 4);

        if (pFunc[0] == 0xE9)
        {
            for (int d = 1; d <= 32; ++d)
            {
                const BYTE* up = pFunc - static_cast<SIZE_T>(d) * 32u;
                if (CanRead(pBase, cbMap, up, 8) &&
                    up[0] == 0x4C && up[1] == 0x8B && up[2] == 0xD1 && up[3] == 0xB8)
                    return static_cast<WORD>(*reinterpret_cast<const WORD*>(up + 4) + d);

                const BYTE* dn = pFunc + static_cast<SIZE_T>(d) * 32u;
                if (CanRead(pBase, cbMap, dn, 8) &&
                    dn[0] == 0x4C && dn[1] == 0x8B && dn[2] == 0xD1 && dn[3] == 0xB8)
                    return static_cast<WORD>(*reinterpret_cast<const WORD*>(dn + 4) - d);
            }
        }
        continue;
    }
    return 0;
}

static PBYTE MakeStub(WORD ssn)
{
    static PBYTE arena = nullptr;
    static PBYTE slots[2] = {};
    static int slot = 0;

    if (!arena)
    {
        SYSTEM_INFO si = {};
        GetSystemInfo(&si);
        const SIZE_T page = si.dwPageSize;
        arena = static_cast<PBYTE>(VirtualAlloc(nullptr, page, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (!arena)
            return nullptr;
        slots[0] = arena;
        slots[1] = arena + 32;
    }

    PBYTE stub = slots[slot];
    slot = (slot + 1) % 2;

    stub[0]  = 0x4C;
    stub[1]  = 0x8B;
    stub[2]  = 0xD1;
    stub[3]  = 0xB8;
    stub[4]  = static_cast<BYTE>(ssn & 0xFF);
    stub[5]  = static_cast<BYTE>((ssn >> 8) & 0xFF);
    stub[6]  = 0x00;
    stub[7]  = 0x00;
    stub[8]  = 0x0F;
    stub[9]  = 0x05;
    stub[10] = 0xC3;

    return stub;
}

static bool ResolveFromMappedFile()
{
    wchar_t path[MAX_PATH] = {};
    const UINT n = GetSystemDirectoryW(path, MAX_PATH);
    if (n == 0 || path[0] == L'\0')
        return false;
    if (wcscat_s(path, L"\\ntdll.dll") != 0)
        return false;

    HANDLE hFile = CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
        return false;

    LARGE_INTEGER liSize = {};
    if (!GetFileSizeEx(hFile, &liSize) || liSize.QuadPart <= 0)
    {
        CloseHandle(hFile);
        return false;
    }
#if SIZE_MAX < UINT64_MAX
    if (liSize.QuadPart > static_cast<LONGLONG>(SIZE_MAX))
    {
        CloseHandle(hFile);
        return false;
    }
#endif
    const auto cbMap = static_cast<SIZE_T>(liSize.QuadPart);

    HANDLE hMap = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMap)
    {
        CloseHandle(hFile);
        return false;
    }

    BYTE* pBase = static_cast<BYTE*>(MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0));
    if (!pBase)
    {
        CloseHandle(hMap);
        CloseHandle(hFile);
        return false;
    }

    g_SsnNtCreateUserProcess = ResolveSSN(pBase, cbMap, "NtCreateUserProcess");
    g_SsnNtClose = ResolveSSN(pBase, cbMap, "NtClose");

    UnmapViewOfFile(pBase);
    CloseHandle(hMap);
    CloseHandle(hFile);

    return g_SsnNtCreateUserProcess != 0 && g_SsnNtClose != 0;
}

static bool ResolveFromLoadedNtdll()
{
    HMODULE h = GetModuleHandleW(L"ntdll.dll");
    if (!h)
        return false;

    BYTE* base = reinterpret_cast<BYTE*>(h);
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0)
        return false;

    const SIZE_T ntOff = static_cast<SIZE_T>(dos->e_lfanew);
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + ntOff);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        return false;

    const SIZE_T cb = nt->OptionalHeader.SizeOfImage;
    if (cb < 0x2000 || ntOff + sizeof(IMAGE_NT_HEADERS64) > cb)
        return false;

    g_SsnNtCreateUserProcess = ResolveSSN(base, cb, "NtCreateUserProcess");
    g_SsnNtClose = ResolveSSN(base, cb, "NtClose");
    return g_SsnNtCreateUserProcess != 0 && g_SsnNtClose != 0;
}

} // namespace detail

bool Initialize()
{
    g_SsnNtCreateUserProcess = 0;
    g_SsnNtClose = 0;

#ifndef _WIN64
    return false;
#else
    if (detail::ResolveFromMappedFile())
        return true;
    return detail::ResolveFromLoadedNtdll();
#endif
}

NTSTATUS NtClose(HANDLE h)
{
    using Fn = NTSTATUS(NTAPI*)(HANDLE);
    PBYTE stub = detail::MakeStub(g_SsnNtClose);
    if (!stub)
        return STATUS_UNSUCCESSFUL;
    return reinterpret_cast<Fn>(stub)(h);
}

NTSTATUS NtCreateUserProcess(
    PHANDLE hProc,
    PHANDLE hThread,
    ACCESS_MASK procAccess,
    ACCESS_MASK threadAccess,
    POBJECT_ATTRIBUTES procAttr,
    POBJECT_ATTRIBUTES threadAttr,
    ULONG procFlags,
    ULONG threadFlags,
    PRTL_USER_PROCESS_PARAMETERS params,
    PPS_CREATE_INFO info,
    PPS_ATTRIBUTE_LIST attrs)
{
    using Fn = NTSTATUS(NTAPI*)(
        PHANDLE, PHANDLE, ACCESS_MASK, ACCESS_MASK,
        POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES,
        ULONG, ULONG,
        PRTL_USER_PROCESS_PARAMETERS,
        PPS_CREATE_INFO, PPS_ATTRIBUTE_LIST);

    PBYTE stub = detail::MakeStub(g_SsnNtCreateUserProcess);
    if (!stub)
        return STATUS_UNSUCCESSFUL;
    return reinterpret_cast<Fn>(stub)(
        hProc, hThread, procAccess, threadAccess,
        procAttr, threadAttr, procFlags, threadFlags,
        params, info, attrs);
}

} // namespace syscall

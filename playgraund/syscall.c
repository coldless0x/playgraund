#include "syscall.h"

#include <stdlib.h>

#ifndef _M_X64
#error Direct syscalls in this project are implemented for x64 only.
#endif

WORD g_NtUserSendInput_SSN = 0;

static BYTE g_StubMem[128];
static BOOL g_StubReady = FALSE;
static WCHAR g_Win32uPath[MAX_PATH];

enum { StubStride = 64 };

static const BYTE* PeRvaToFilePointer(const BYTE* base, DWORD rva)
{
    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    const IMAGE_NT_HEADERS* nt = (const IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION((IMAGE_NT_HEADERS*)nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        DWORD va = sec[i].VirtualAddress;
        DWORD vs = sec[i].Misc.VirtualSize;
        if (vs == 0)
            vs = sec[i].SizeOfRawData;

        if (rva >= va && rva < va + vs)
            return base + sec[i].PointerToRawData + (rva - va);
    }

    return NULL;
}

static WORD ReadSsnFromSyscallStub(const BYTE* p)
{
    if (!p)
        return 0;

    for (unsigned hop = 0; hop < 16u; ++hop) {
        if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8)
            return *(const WORD*)(p + 4);

        if (p[0] == 0xE9) {
            LONG rel = *(const LONG*)(p + 1);
            p = p + 5 + rel;
            continue;
        }

        if (p[0] == 0xEB) {
            signed char rel = *(const signed char*)(p + 1);
            p = p + 2 + rel;
            continue;
        }

        return 0;
    }

    return 0;
}

static WORD GetExportSsnFromDiskImage(const BYTE* mapped, const char* exportName)
{
    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)mapped;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    const IMAGE_NT_HEADERS* nt = (const IMAGE_NT_HEADERS*)(mapped + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return 0;

    DWORD expRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (expRva == 0)
        return 0;

    const IMAGE_EXPORT_DIRECTORY* exp =
        (const IMAGE_EXPORT_DIRECTORY*)PeRvaToFilePointer(mapped, expRva);
    if (!exp)
        return 0;

    const DWORD* names = (const DWORD*)PeRvaToFilePointer(mapped, exp->AddressOfNames);
    const WORD* ords = (const WORD*)PeRvaToFilePointer(mapped, exp->AddressOfNameOrdinals);
    const DWORD* funcs = (const DWORD*)PeRvaToFilePointer(mapped, exp->AddressOfFunctions);
    if (!names || !ords || !funcs)
        return 0;

    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        const char* name = (const char*)PeRvaToFilePointer(mapped, names[i]);
        if (!name)
            continue;

        size_t k = 0;
        while (exportName[k] && name[k] && exportName[k] == name[k])
            ++k;
        if (exportName[k] != 0 || name[k] != 0)
            continue;

        DWORD funcRva = funcs[ords[i]];
        const BYTE* fn = PeRvaToFilePointer(mapped, funcRva);
        return ReadSsnFromSyscallStub(fn);
    }

    return 0;
}

static BOOL MapSystemFile(const WCHAR* relativeSystemPath, HANDLE* outFile, HANDLE* outMap, void** outView)
{
    WCHAR path[MAX_PATH];
    if (GetSystemDirectoryW(path, MAX_PATH) == 0)
        return FALSE;
    if (wcscat_s(path, MAX_PATH, relativeSystemPath) != 0)
        return FALSE;

    if (wcscpy_s(g_Win32uPath, _countof(g_Win32uPath), path) != 0)
        return FALSE;

    HANDLE hFile = CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;

    HANDLE hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) {
        CloseHandle(hFile);
        return FALSE;
    }

    BYTE* base = (BYTE*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!base) {
        CloseHandle(hMap);
        CloseHandle(hFile);
        return FALSE;
    }

    *outFile = hFile;
    *outMap = hMap;
    *outView = base;
    return TRUE;
}

static void UnmapFileView(void* view, HANDLE hMap, HANDLE hFile)
{
    if (view)
        UnmapViewOfFile(view);
    if (hMap)
        CloseHandle(hMap);
    if (hFile && hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);
}

static BYTE* MaterializeStub(WORD ssn, unsigned slot)
{
    if (slot * StubStride + 32 > sizeof(g_StubMem))
        return NULL;

    BYTE* stub = g_StubMem + (slot * StubStride);

    stub[0] = 0x4C;
    stub[1] = 0x8B;
    stub[2] = 0xD1;
    stub[3] = 0xB8;
    stub[4] = (BYTE)(ssn & 0xFF);
    stub[5] = (BYTE)((ssn >> 8) & 0xFF);
    stub[6] = 0x00;
    stub[7] = 0x00;
    stub[8] = 0x0F;
    stub[9] = 0x05;
    stub[10] = 0xC3;

    return stub;
}

BOOL InitSyscalls(void)
{
    g_Win32uPath[0] = L'\0';

    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hMap = NULL;
    void* view = NULL;

    if (!MapSystemFile(L"\\win32u.dll", &hFile, &hMap, &view))
        return FALSE;

    g_NtUserSendInput_SSN = GetExportSsnFromDiskImage((const BYTE*)view, "NtUserSendInput");

    UnmapFileView(view, hMap, hFile);

    if (g_NtUserSendInput_SSN == 0)
        return FALSE;

    DWORD oldProtect = 0;
    if (!VirtualProtect(g_StubMem, sizeof(g_StubMem), PAGE_EXECUTE_READWRITE, &oldProtect))
        return FALSE;

    if (!MaterializeStub(g_NtUserSendInput_SSN, 0))
        return FALSE;

    g_StubReady = TRUE;
    return TRUE;
}

static BYTE* AllocStub(WORD ssn, unsigned slot)
{
    if (!g_StubReady)
        return NULL;
    return MaterializeStub(ssn, slot);
}

UINT SysNtUserSendInput(UINT cInputs, LPINPUT pInputs, int cbSize)
{
    typedef UINT(NTAPI * Fn)(UINT, LPINPUT, int);
    BYTE* stub = AllocStub(g_NtUserSendInput_SSN, 0);
    if (!stub)
        return 0;
    return ((Fn)stub)(cInputs, pInputs, cbSize);
}

PCWSTR Syscall_Win32uDiskPath(void)
{
    return g_Win32uPath[0] != L'\0' ? g_Win32uPath : L"(not resolved)";
}

PVOID Syscall_StubArenaBase(void)
{
    return g_StubMem;
}

SIZE_T Syscall_StubArenaSize(void)
{
    return sizeof(g_StubMem);
}

PVOID Syscall_NtUserSendInputTrampoline(void)
{
    return g_StubReady ? (PVOID)(g_StubMem + (0 * StubStride)) : NULL;
}

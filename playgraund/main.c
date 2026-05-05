#include "syscall.h"

#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

#ifndef _M_X64
#error This program uses x64 direct syscalls. Build for x64.
#endif

static const WCHAR kPayload[] =
    L"made by mov ...\r\n"
    L"\r\n"
    L"[+] discord.gg/gamehacking\r\n"
    L"[-] The best comunity";

static void PauseExit(int code)
{
    wprintf(L"\n");
    wprintf(L"[+]Press Enter to exit...\n");
    fflush(stdout);
    (void)getwchar();
    exit(code);
}

static void PrintTrampolineBytes(PVOID tramp, WORD ssn)
{
    const BYTE* p = (const BYTE*)tramp;
    if (!p) {
        wprintf(L"[+]trampoline bytes (null)\n");
        return;
    }

    wprintf(
        L"[+]trampoline bytes %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X (SSN 0x%04X)\n",
        p[0],
        p[1],
        p[2],
        p[3],
        p[4],
        p[5],
        p[6],
        p[7],
        p[8],
        p[9],
        p[10],
        (unsigned int)ssn);
}

static BOOL ProcessImageIsNotepad(DWORD pid)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h)
        return FALSE;

    WCHAR path[MAX_PATH];
    DWORD n = MAX_PATH;
    BOOL ok = QueryFullProcessImageNameW(h, 0, path, &n);
    CloseHandle(h);
    if (!ok)
        return FALSE;

    PCWSTR leaf = wcsrchr(path, L'\\');
    leaf = leaf ? leaf + 1 : path;
    return _wcsicmp(leaf, L"notepad.exe") == 0;
}

static BOOL CALLBACK EnumNotepadTopLevel(HWND hwnd, LPARAM lParam)
{
    HWND* out = (HWND*)lParam;
    if (!IsWindowVisible(hwnd))
        return TRUE;

    LONG_PTR style = GetWindowLongPtrW(hwnd, GWL_STYLE);
    if (style != 0 && (style & WS_CHILD))
        return TRUE;

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == 0 || !ProcessImageIsNotepad(pid))
        return TRUE;

    *out = hwnd;
    return FALSE;
}

static HWND FindNotepadMainWindow(void)
{
    HWND found = NULL;
    EnumWindows(EnumNotepadTopLevel, (LPARAM)&found);
    if (found)
        return found;

    return FindWindowW(L"Notepad", NULL);
}

static HWND FindTypingTarget(HWND notepad)
{
    HWND h;

    h = FindWindowExW(notepad, NULL, L"Edit", NULL);
    if (h)
        return h;

    h = FindWindowExW(notepad, NULL, L"RichEdit20W", NULL);
    if (h)
        return h;

    return FindWindowExW(notepad, NULL, L"RICHEDIT50W", NULL);
}

static BOOL FocusEditControl(HWND notepad, HWND edit)
{
    if (!AllowSetForegroundWindow(ASFW_ANY))
        /* best-effort */ ;

    ShowWindow(notepad, SW_RESTORE);
    BringWindowToTop(notepad);
    SetForegroundWindow(notepad);

    DWORD fg = GetWindowThreadProcessId(GetForegroundWindow(), NULL);
    DWORD np = GetWindowThreadProcessId(notepad, NULL);
    if (fg == 0 || np == 0)
        return FALSE;

    if (!AttachThreadInput(fg, np, TRUE))
        /* continue */ ;

    SetFocus(edit);
    AttachThreadInput(fg, np, FALSE);
    return GetFocus() == edit || IsChild(notepad, GetFocus());
}

static UINT TypeTextWithNtUserSendInput(PCWSTR text, UINT* outTotalEvents)
{
    size_t cch = wcslen(text);
    if (cch == 0) {
        *outTotalEvents = 0;
        return 0;
    }

    size_t inputCount = cch * 2;
    LPINPUT inputs = (LPINPUT)calloc(inputCount, sizeof(INPUT));
    if (!inputs) {
        *outTotalEvents = 0;
        return 0;
    }

    for (size_t i = 0; i < cch; ++i) {
        INPUT* down = &inputs[i * 2];
        INPUT* up = &inputs[i * 2 + 1];

        ZeroMemory(down, sizeof(INPUT));
        ZeroMemory(up, sizeof(INPUT));

        down->type = INPUT_KEYBOARD;
        down->ki.wScan = (WORD)text[i];
        down->ki.dwFlags = KEYEVENTF_UNICODE;

        up->type = INPUT_KEYBOARD;
        up->ki.wScan = (WORD)text[i];
        up->ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;
    }

    *outTotalEvents = (UINT)inputCount;
    UINT sent = SysNtUserSendInput((UINT)inputCount, inputs, sizeof(INPUT));
    free(inputs);
    return sent;
}

int wmain(void)
{
    HMODULE self = GetModuleHandleW(NULL);
    HMODULE win32u = GetModuleHandleW(L"win32u.dll");

    if (!InitSyscalls()) {
        fwprintf(stderr, L"[-]Failed to init win32u syscall (NtUserSendInput SSN / stub).\n");
        PauseExit(1);
    }

    PVOID arena = Syscall_StubArenaBase();
    PVOID tramp = Syscall_NtUserSendInputTrampoline();
    ULONG_PTR selfBase = (ULONG_PTR)self;
    ULONG_PTR arenaVa = (ULONG_PTR)arena;
    ULONG_PTR trampVa = (ULONG_PTR)tramp;

    wprintf(L"[+]\n");
    wprintf(L"[+]this image base 0x%016llX\n", (unsigned long long)selfBase);
    wprintf(L"[+]win32u.dll (loaded) 0x%016llX\n", (unsigned long long)(ULONG_PTR)win32u);
    wprintf(L"[+]win32u.dll (disk) %s\n", Syscall_Win32uDiskPath());
    wprintf(L"[+]stub arena 0x%016llX (%llu bytes, PAGE_EXECUTE_READWRITE)\n",
        (unsigned long long)arenaVa,
        (unsigned long long)Syscall_StubArenaSize());
    wprintf(L"[+]stub RVA (this image) 0x%016llX\n", (unsigned long long)(arenaVa - selfBase));
    wprintf(L"[+]trampoline 0x%016llX\n", (unsigned long long)trampVa);
    wprintf(L"[+]trampoline RVA 0x%016llX\n", (unsigned long long)(trampVa - selfBase));
    PrintTrampolineBytes(tramp, g_NtUserSendInput_SSN);
    wprintf(L"[+]NtUserSendInput SSN 0x%04X\n", g_NtUserSendInput_SSN);
    wprintf(L"[+]sizeof(INPUT) %llu\n", (unsigned long long)sizeof(INPUT));
    wprintf(L"[+]\n");
    fflush(stdout);

    HWND notepad = FindNotepadMainWindow();
    if (!notepad) {
        fwprintf(stderr, L"[-]Open Notepad first, then run this program again.\n");
        PauseExit(1);
    }

    HWND edit = FindTypingTarget(notepad);
    if (!edit) {
        fwprintf(stderr, L"[-]Could not find Edit / RichEdit inside Notepad (unsupported UI?).\n");
        PauseExit(1);
    }

    DWORD npPid = 0;
    DWORD npTid = GetWindowThreadProcessId(notepad, &npPid);
    DWORD edTid = GetWindowThreadProcessId(edit, NULL);

    wprintf(L"[+]notepad HWND 0x%p\n", (void*)notepad);
    wprintf(L"[+]edit HWND 0x%p\n", (void*)edit);
    wprintf(L"[+]notepad PID %lu\n", (unsigned long)npPid);
    wprintf(L"[+]notepad TID %lu\n", (unsigned long)npTid);
    wprintf(L"[+]edit TID %lu\n", (unsigned long)edTid);
    wprintf(L"[+]\n");
    fflush(stdout);

    BOOL focused = FocusEditControl(notepad, edit);
    wprintf(L"[+]focus target %s\n", focused ? L"edit (ok)" : L"uncertain (click Notepad if text goes elsewhere)");
    wprintf(L"[+]\n");
    fflush(stdout);

    UINT totalEvents = 0;
    UINT sent = TypeTextWithNtUserSendInput(kPayload, &totalEvents);
    if (sent != totalEvents || totalEvents == 0) {
        fwprintf(stderr, L"[-]NtUserSendInput: sent %u / %u INPUT records.\n", sent, totalEvents);
        PauseExit(1);
    }

    wprintf(L"[+]INPUT records sent %u / %u\n", sent, totalEvents);
    wprintf(L"[+]payload %s\n", kPayload);
    wprintf(L"[+]\n");
    wprintf(L"[+]done.\n");
    wprintf(L"[+]\n");
    fflush(stdout);

    PauseExit(0);
}

#pragma once

#include <windows.h>

extern WORD g_NtUserSendInput_SSN;

BOOL InitSyscalls(void);

UINT SysNtUserSendInput(UINT cInputs, LPINPUT pInputs, int cbSize);

PCWSTR Syscall_Win32uDiskPath(void);

PVOID Syscall_StubArenaBase(void);

SIZE_T Syscall_StubArenaSize(void);

PVOID Syscall_NtUserSendInputTrampoline(void);

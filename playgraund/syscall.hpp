#pragma once

#include "ntstructs.hpp"

namespace syscall {

extern WORD g_SsnNtCreateUserProcess;
extern WORD g_SsnNtClose;

bool Initialize();
NTSTATUS NtClose(HANDLE h);
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
    PPS_ATTRIBUTE_LIST attrs);

} // namespace syscall

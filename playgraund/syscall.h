#pragma once
#include "nt.h"

extern WORD g_NtCreateUserProcess_SSN;
extern WORD g_NtClose_SSN;

BOOL InitSyscalls();

NTSTATUS SysNtClose(HANDLE Handle);

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
    PPS_ATTRIBUTE_LIST           AttributeList);

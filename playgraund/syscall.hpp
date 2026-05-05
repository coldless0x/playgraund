#pragma once

#include "ntstructs.hpp"

namespace syscall {

extern WORD g_SsnNtCreateUserProcess;
extern WORD g_SsnNtClose;

namespace detail {

WORD ResolveSSN(PBYTE pModuleBase, const char* pFunctionName);
PBYTE GenerateStub(WORD wSSN);

} // namespace detail

bool Initialize();

NTSTATUS NtClose(HANDLE Handle);

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
    PPS_ATTRIBUTE_LIST           AttributeList);

} // namespace syscall

#pragma once
#include <windows.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CURDIR {
    UNICODE_STRING DosPath;
    HANDLE         Handle;
} CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    ULONG          MaximumLength;
    ULONG          Length;
    ULONG          Flags;
    ULONG          DebugFlags;
    HANDLE         ConsoleHandle;
    ULONG          ConsoleFlags;
    HANDLE         StandardInput;
    HANDLE         StandardOutput;
    HANDLE         StandardError;
    CURDIR         CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID          Environment;
    ULONG          StartingX;
    ULONG          StartingY;
    ULONG          CountX;
    ULONG          CountY;
    ULONG          CountCharsX;
    ULONG          CountCharsY;
    ULONG          FillAttribute;
    ULONG          WindowFlags;
    ULONG          ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    WCHAR          CurrentDirectories[32 * sizeof(UNICODE_STRING)];
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef enum _PS_CREATE_STATE {
    PsCreateInitialState,
    PsCreateFailOnFileOpen,
    PsCreateFailOnSectionCreate,
    PsCreateFailExeFormat,
    PsCreateFailMachineMismatch,
    PsCreateFailExeName,
    PsCreateSuccess
} PS_CREATE_STATE;

typedef struct _PS_CREATE_INFO {
    SIZE_T          Size;
    PS_CREATE_STATE State;
    union {
        struct {
            ULONG InitFlags;
            ULONG AdditionalFileAccess;
        } InitState;
        struct {
            HANDLE FileHandle;
        } FailSection;
        struct {
            USHORT DllCharacteristics;
        } ExeFormat;
        struct {
            HANDLE IFEOKey;
        } ExeName;
        struct {
            ULONG     OutputFlags;
            HANDLE    FileHandle;
            HANDLE    SectionHandle;
            ULONGLONG UserProcessParametersNative;
            ULONG     UserProcessParametersWow64;
            ULONG     CurrentParameterFlags;
            ULONGLONG PebAddressNative;
            ULONG     PebAddressWow64;
            ULONGLONG ManifestAddress;
            ULONG     ManifestSize;
        } SuccessState;
    };
} PS_CREATE_INFO, *PPS_CREATE_INFO;

#define PS_ATTRIBUTE_IMAGE_NAME 0x20005

typedef struct _PS_ATTRIBUTE {
    ULONG_PTR Attribute;
    SIZE_T    Size;
    union {
        ULONG_PTR Value;
        PVOID     ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T       TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS  ExitStatus;
    PVOID     PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG      BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

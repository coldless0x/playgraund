#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define NTAPI __stdcall

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
} CURDIR, *PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
    USHORT         Flags;
    USHORT         Length;
    ULONG          TimeStamp;
    UNICODE_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    ULONG                   MaximumLength;
    ULONG                   Length;
    ULONG                   Flags;
    ULONG                   DebugFlags;
    HANDLE                  ConsoleHandle;
    ULONG                   ConsoleFlags;
    HANDLE                  StandardInput;
    HANDLE                  StandardOutput;
    HANDLE                  StandardError;
    CURDIR                  CurrentDirectory;
    UNICODE_STRING          DllPath;
    UNICODE_STRING          ImagePathName;
    UNICODE_STRING          CommandLine;
    PVOID                   Environment;
    ULONG                   StartingX;
    ULONG                   StartingY;
    ULONG                   CountX;
    ULONG                   CountY;
    ULONG                   CountCharsX;
    ULONG                   CountCharsY;
    ULONG                   FillAttribute;
    ULONG                   WindowFlags;
    ULONG                   ShowWindowFlags;
    UNICODE_STRING          WindowTitle;
    UNICODE_STRING          DesktopInfo;
    UNICODE_STRING          ShellInfo;
    UNICODE_STRING          RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[32];
    ULONG_PTR               EnvironmentSize;
    ULONG_PTR               EnvironmentVersion;
    PVOID                   PackageDependencyData;
    ULONG                   ProcessGroupId;
    ULONG                   LoaderThreads;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

#define RTL_USER_PROC_PARAMS_NORMALIZED 0x00000001

typedef enum _PS_CREATE_STATE {
    PsCreateInitialState,
    PsCreateFailOnFileOpen,
    PsCreateFailOnSectionCreate,
    PsCreateFailExeFormat,
    PsCreateFailMachineMismatch,
    PsCreateFailExeName,
    PsCreateSuccess,
    PsCreateMaximumStates
} PS_CREATE_STATE;

typedef struct _PS_CREATE_INFO {
    SIZE_T          Size;
    PS_CREATE_STATE State;
    union {
        struct {
            union {
                ULONG InitFlags;
                struct {
                    UCHAR  WriteOutputOnExit : 1;
                    UCHAR  DetectManifest : 1;
                    UCHAR  IFEOSkipDebugger : 1;
                    UCHAR  IFEODoNotPropagateKeyState : 1;
                    UCHAR  SpareBits1 : 4;
                    UCHAR  SpareBits2 : 8;
                    USHORT ProhibitedImageCharacteristics : 16;
                };
            };
            ACCESS_MASK AdditionalFileAccess;
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
            union {
                ULONG OutputFlags;
                struct {
                    UCHAR  ProtectedProcess : 1;
                    UCHAR  AddressSpaceOverride : 1;
                    UCHAR  DevOverrideEnabled : 1;
                    UCHAR  ManifestDetected : 1;
                    UCHAR  ProtectedProcessLight : 1;
                    UCHAR  SpareBits1 : 3;
                    UCHAR  SpareBits2 : 8;
                    USHORT SpareBits3 : 16;
                };
            };
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

#define PS_ATTRIBUTE_NUMBER_MASK    0x0000ffff
#define PS_ATTRIBUTE_THREAD         0x00010000
#define PS_ATTRIBUTE_INPUT          0x00020000
#define PS_ATTRIBUTE_ADDITIVE       0x00040000

typedef enum _PS_ATTRIBUTE_NUM {
    PsAttributeParentProcess,
    PsAttributeDebugObject,
    PsAttributeToken,
    PsAttributeClientId,
    PsAttributeTebAddress,
    PsAttributeImageName,
    PsAttributeImageInfo,
    PsAttributeMemoryReserve,
    PsAttributePriorityClass,
    PsAttributeErrorMode,
    PsAttributeStdHandleInfo,
    PsAttributeHandleList,
    PsAttributeGroupAffinity,
    PsAttributePreferredNode,
    PsAttributeIdealProcessor,
    PsAttributeUmsThread,
    PsAttributeMitigationOptions,
    PsAttributeProtectionLevel,
    PsAttributeSecureProcess,
    PsAttributeJobList,
    PsAttributeChildProcessPolicy,
    PsAttributeAllApplicationPackagesPolicy,
    PsAttributeWin32kFilter,
    PsAttributeSafeOpenPromptOriginClaim,
    PsAttributeBnoIsolation,
    PsAttributeDesktopAppPolicy,
    PsAttributeMax
} PS_ATTRIBUTE_NUM;

#define PsAttributeValue(Number, Thread, Input, Additive) \
    (((Number) & PS_ATTRIBUTE_NUMBER_MASK) | \
     ((Thread) ? PS_ATTRIBUTE_THREAD : 0) | \
     ((Input) ? PS_ATTRIBUTE_INPUT : 0) | \
     ((Additive) ? PS_ATTRIBUTE_ADDITIVE : 0))

#define PS_ATTRIBUTE_IMAGE_NAME \
    PsAttributeValue(PsAttributeImageName, FALSE, TRUE, FALSE)

typedef struct _PS_ATTRIBUTE {
    ULONG_PTR Attribute;
    SIZE_T    Size;
    union {
        ULONG_PTR Value;
        PVOID     ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T       TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation
} PROCESSINFOCLASS;

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS  ExitStatus;
    PVOID     PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG      BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

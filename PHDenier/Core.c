
#include <ntddk.h>
#include <wdm.h>
#define DRIVER_TAG 'nedP' 

#define MAX_PATH 260


#define PROCESS_TERMINATE                 0x0001
#define PROCESS_CREATE_THREAD             0x0002
#define PROCESS_VM_OPERATION              0x0008
#define PROCESS_VM_WRITE                  0x0020
#define PROCESS_SET_INFORMATION           0x0200
#define PROCESS_SUSPEND_RESUME            0x0800
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000

// --- PHDenier Protection Masks ---
// Core rights needed to perform memory injection and hijacking
// Deny one and the whole Operation of hollowing falls but it is recommended to set Multiple flags
#define RIGHTS_HOLLOWING (PROCESS_VM_WRITE | \
                          PROCESS_VM_OPERATION | \
                          PROCESS_SUSPEND_RESUME | \
                          PROCESS_SET_INFORMATION \
                          )


#define MASK_PROCESS_PROTECT (RIGHTS_HOLLOWING) // Replace it with the actual Handles you may need because this protects against 4 types of handles 
 
NTSTATUS PsLookupProcessByProcessId(
    HANDLE    ProcessId,
    PEPROCESS* Process
);


#pragma warning(disable: 4201)


typedef struct _PS_PROTECTION {
    union {
        UCHAR Level;
        struct {
            UCHAR Type : 3;
            UCHAR Audit : 1;
            UCHAR Signer : 4;
        };
    };
} PS_PROTECTION, * PPS_PROTECTION;

#define PsProtectedTypeNone    0
#define PsProtectedTypeProtectedLight 1
#define PsProtectedTypeProtected      2

NTKERNELAPI
NTSTATUS
ObOpenObjectByPointer(
    _In_ PVOID Object,
    _In_ ULONG HandleAttributes,
    _In_opt_ PACCESS_STATE PassedAccessState,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Out_ PHANDLE Handle
);



NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
);

// Extremely fast, undocumented API to get the 15-byte process name directly from EPROCESS
NTKERNELAPI
PUCHAR
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
);



PVOID g_CallbackRegistrationHandle = NULL;
extern PULONG InitSafeBootMode;


BOOLEAN
IsTrustedScmManager(
    VOID
)
{
    PEPROCESS process = PsGetCurrentProcess();
    if (!process)
        return FALSE;

    HANDLE hProcess = NULL;
    // NOTE: This triggers the callback again
    NTSTATUS status = ObOpenObjectByPointer(
        process,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_QUERY_LIMITED_INFORMATION,
        *PsProcessType,
        KernelMode,
        &hProcess
    );
    if (!NT_SUCCESS(status) || !hProcess)
        return FALSE;

    // Step 1: Check if current process is services.exe in System32
    ULONG bufferSize = sizeof(UNICODE_STRING) + (MAX_PATH * sizeof(WCHAR));
    PUNICODE_STRING imageName = (PUNICODE_STRING)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        bufferSize,
        DRIVER_TAG
    );
    if (!imageName)
    {
        ZwClose(hProcess);
        return FALSE;
    }

    status = ZwQueryInformationProcess(
        hProcess,
        ProcessImageFileName,
        imageName,
        bufferSize,
        NULL
    );
    if (!NT_SUCCESS(status) || !imageName->Buffer || imageName->Length == 0)
    {
        ExFreePool2(imageName, DRIVER_TAG, NULL, 0);
        ZwClose(hProcess);
        return FALSE;
    }

    UNICODE_STRING devicePrefix = RTL_CONSTANT_STRING(L"\\Device\\HarddiskVolume");
    UNICODE_STRING servicesExeSuffix = RTL_CONSTANT_STRING(L"\\Windows\\System32\\services.exe");
    BOOLEAN isServices = FALSE;

    if (RtlPrefixUnicodeString(&devicePrefix, imageName, TRUE))
    {
        if (imageName->Length >= servicesExeSuffix.Length)
        {
            UNICODE_STRING tail = {
                servicesExeSuffix.Length,
                servicesExeSuffix.Length,
                (PWCH)((PUCHAR)imageName->Buffer + imageName->Length - servicesExeSuffix.Length)
            };
            isServices = RtlEqualUnicodeString(&tail, &servicesExeSuffix, TRUE);
        }
    }

    ExFreePool2(imageName, DRIVER_TAG, NULL, 0);

    if (!isServices)
    {
        ZwClose(hProcess);
        return FALSE;
    }

    // Step 2: Check parent is wininit.exe
    PROCESS_BASIC_INFORMATION pbi = { 0 };
    status = ZwQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(PROCESS_BASIC_INFORMATION),
        NULL
    );
    ZwClose(hProcess);

    if (!NT_SUCCESS(status))
        return FALSE;

    PEPROCESS parentProcess = NULL;
    status = PsLookupProcessByProcessId(
        (HANDLE)pbi.InheritedFromUniqueProcessId,
        &parentProcess
    );
    if (!NT_SUCCESS(status) || !parentProcess)
        return FALSE;

    HANDLE hParent = NULL;
    status = ObOpenObjectByPointer(
        parentProcess,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_QUERY_LIMITED_INFORMATION,
        *PsProcessType,
        KernelMode,
        &hParent
    );
    ObDereferenceObject(parentProcess);

    if (!NT_SUCCESS(status) || !hParent)
        return FALSE;

    PUNICODE_STRING parentName = (PUNICODE_STRING)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        bufferSize,
        DRIVER_TAG
    );
    if (!parentName)
    {
        ZwClose(hParent);
        return FALSE;
    }

    status = ZwQueryInformationProcess(
        hParent,
        ProcessImageFileName,
        parentName,
        bufferSize,
        NULL
    );
    ZwClose(hParent);

    if (!NT_SUCCESS(status) || !parentName->Buffer || parentName->Length == 0)
    {
        ExFreePool2(parentName, DRIVER_TAG, NULL, 0);
        return FALSE;
    }

    UNICODE_STRING wininitExeSuffix = RTL_CONSTANT_STRING(L"\\Windows\\System32\\wininit.exe");
    BOOLEAN isWininit = FALSE;

    if (RtlPrefixUnicodeString(&devicePrefix, parentName, TRUE))
    {
        if (parentName->Length >= wininitExeSuffix.Length)
        {
            UNICODE_STRING tail = {
                wininitExeSuffix.Length,
                wininitExeSuffix.Length,
                (PWCH)((PUCHAR)parentName->Buffer + parentName->Length - wininitExeSuffix.Length)
            };
            isWininit = RtlEqualUnicodeString(&tail, &wininitExeSuffix, TRUE);
        }
    }

    ExFreePool2(parentName, DRIVER_TAG, NULL, 0);
    return isWininit;
}



BOOLEAN
IsPplProtected(
    VOID
)
{
    PEPROCESS process = PsGetCurrentProcess();
    if (!process)
        return FALSE;

    HANDLE hProcess = NULL;
    NTSTATUS status = ObOpenObjectByPointer(
        process,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_QUERY_LIMITED_INFORMATION,
        *PsProcessType,
        KernelMode,
        &hProcess
    );
    if (!NT_SUCCESS(status) || !hProcess)
        return FALSE;

    PS_PROTECTION protection = { 0 };
    status = ZwQueryInformationProcess(
        hProcess,
        ProcessProtectionInformation,
        &protection,
        sizeof(PS_PROTECTION),
        NULL
    );
    ZwClose(hProcess);

    if (!NT_SUCCESS(status))
        return FALSE;

    return (protection.Type != PsProtectedTypeNone);
}



OB_PREOP_CALLBACK_STATUS
PreOpenProcessCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION PreInfo
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    // 1. Ignore kernel handles
    if (PreInfo->KernelHandle)
        return OB_PREOP_SUCCESS;

    // 2. Ignore system process (PID 4) requests
    if (PsGetCurrentProcessId() == (HANDLE)4)
        return OB_PREOP_SUCCESS;

    if (PreInfo->ObjectType != *PsProcessType)
        return OB_PREOP_SUCCESS;

    PEPROCESS targetProcess = (PEPROCESS)PreInfo->Object;


    PUCHAR targetName = PsGetProcessImageFileName(targetProcess);
    if (!targetName)
        return OB_PREOP_SUCCESS;

    // STRING COMPARISON (Max 15 characters for PsGetProcessImageFileName)
    // Replace "TargetProc.exe" with your actual executable name (max 15 chars)
    // If it was more than 15 chars then it wont match and if you edit the number of bytes to something 
    // Higher than 15 It will cause a buffer Overflow which may cause Bugchecks
    // oh also this is case insensitive comparison write it MaYBe LiKE ThIS TaRGeTPrOc.ExE will equal TargetProc.exe
    if (_strnicmp((const char*)targetName, "TargetProc.exe", 14) == 0)
    {
        PEPROCESS callingProcess = PsGetCurrentProcess();
        PUCHAR callerName = PsGetProcessImageFileName(callingProcess);

        if (callerName)
        {

            if ((_strnicmp((const char*)callerName, "svchost.exe", 11) == 0) ||
                (_strnicmp((const char*)callerName, "services.exe", 12) == 0) ||
                (_strnicmp((const char*)callerName, "csrss.exe", 9) == 0))
            {
                return OB_PREOP_SUCCESS;
            }
        }


        if (PreInfo->Operation == OB_OPERATION_HANDLE_CREATE)
        {
            PreInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~MASK_PROCESS_PROTECT;
        }
        else if (PreInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE)
        {
            PreInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~MASK_PROCESS_PROTECT;
        }
    }
    return OB_PREOP_SUCCESS;
}


VOID
DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);


    if (g_CallbackRegistrationHandle != NULL)
    {

        ObUnRegisterCallbacks(g_CallbackRegistrationHandle);

        g_CallbackRegistrationHandle = NULL;
    }
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);


    if (InitSafeBootMode != NULL && *InitSafeBootMode != 0) {
        DriverObject->DriverUnload = DriverUnload;
        return STATUS_SUCCESS;
    }
   

    // Register ObRegisterCallbacks
    OB_CALLBACK_REGISTRATION callbackReg = { 0 };
    OB_OPERATION_REGISTRATION opReg = { 0 };

    callbackReg.Version = OB_FLT_REGISTRATION_VERSION;
    callbackReg.OperationRegistrationCount = 1;
    callbackReg.RegistrationContext = NULL;
    RtlInitUnicodeString(&callbackReg.Altitude, L"329990"); 

    opReg.ObjectType = PsProcessType;
    opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg.PreOperation = PreOpenProcessCallback;
    opReg.PostOperation = NULL;

    callbackReg.OperationRegistration = &opReg;

    NTSTATUS status = ObRegisterCallbacks(&callbackReg, &g_CallbackRegistrationHandle);

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    // No unload in normal mode 
    DriverObject->DriverUnload = NULL;
   
    return STATUS_SUCCESS;
}
// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "Hook_Api/Hook_Api.h"
#include "Driver_Load/Driver_Help.h"
#define Io_Openprocess                      0x1000
#define Io_ZwReadVirtualMemory              0x1001
#define Io_ZwWriteVirtualMemory             0x1002
#define Io_ZwAllocateVirtualMemory          0x1003
#define Io_ZwFreeVirtualMemory              0x1004
#define Io_ZwProtectVirtualMemory           0x1005
#define Io_ZwQueryInformationProcess        0x1006

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWCH   Buffer;
} UNICODE_STRING;


typedef UNICODE_STRING* PUNICODE_STRING;


typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
    PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;

typedef OBJECT_ATTRIBUTES* POBJECT_ATTRIBUTES;

typedef CONST OBJECT_ATTRIBUTES* PCOBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;

typedef CLIENT_ID* PCLIENT_ID;

typedef struct _ZwOpenProcess_ {
    PHANDLE ProcessHandle;
    ACCESS_MASK DesiredAccess;
    POBJECT_ATTRIBUTES ObjectAttributes;
    PCLIENT_ID clientId;
}_ZwOpenProcess, * P_ZwOpenProcess;

NTSTATUS NTAPI HOOK_ZwOpenProcess(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID clientId
) {

    Out1("开始 HOOK_ZwOpenProcess");
    _ZwOpenProcess data{ ProcessHandle,DesiredAccess,ObjectAttributes,clientId };

    BOOL result = DeviceIoControl(h_DriverHandle, Io_Openprocess, &data, sizeof(_ZwOpenProcess), NULL, NULL, NULL, NULL);
    
    if (result)
    {
        Out1("DeviceIoControl 1");
    }
    else {
        Out1("DeviceIoControl 2");
    }

    return CMC_STATUS_SUCCESS;
}


typedef struct _ZwReadVirtualMemory_ {
    HANDLE ProcessHandle; 
    PVOID BaseAddress; 
    PVOID Buffer; 
    ULONG BufferSize;
    PULONG NumberOfBytesRead;

}_ZwReadVirtualMemory, * P_ZwReadVirtualMemory;


NTSTATUS NTAPI HOOK_ZwReadVirtualMemory(
    IN  HANDLE ProcessHandle, 
    IN  PVOID BaseAddress, 
    OUT PVOID Buffer,
    IN  ULONG BufferSize,
    OUT PULONG NumberOfBytesRead
) {
    if((INT64)BaseAddress < 0xFFFF)
        return CMC_STATUS_SUCCESS;
    if ((INT)ProcessHandle == -1) {
        memcpy(Buffer, BaseAddress, BufferSize);
        return CMC_STATUS_SUCCESS;
    }
    _ZwReadVirtualMemory data{ ProcessHandle,BaseAddress,Buffer, BufferSize,NumberOfBytesRead };

    DeviceIoControl(h_DriverHandle, Io_ZwReadVirtualMemory, &data, sizeof(_ZwReadVirtualMemory), NULL, NULL, NULL, NULL);
    return CMC_STATUS_SUCCESS;
}


typedef struct _ZwWriteVirtualMemory_ {
    HANDLE ProcessHandle; PVOID BaseAddress; PVOID Buffer; ULONG BufferSize; PULONG NumberOfBytesWritten;
}_ZwWriteVirtualMemory, * P_ZwWriteVirtualMemory;

NTSTATUS NTAPI HOOK_ZwWriteVirtualMemory(
    IN  HANDLE ProcessHandle,
    OUT PVOID BaseAddress,
    IN  PVOID Buffer, 
    IN  ULONG BufferSize,
    OUT PULONG NumberOfBytesWritten OPTIONAL
) {

    if ((INT64)BaseAddress < 0xFFFF)
        return CMC_STATUS_SUCCESS;
    if ((INT)ProcessHandle == -1) {
        memcpy(BaseAddress, Buffer, BufferSize);
        return CMC_STATUS_SUCCESS;
    }
    _ZwWriteVirtualMemory data{ ProcessHandle,BaseAddress,Buffer,BufferSize,NumberOfBytesWritten };
    DeviceIoControl(h_DriverHandle, Io_ZwWriteVirtualMemory, &data, sizeof(_ZwWriteVirtualMemory), NULL, NULL, NULL, NULL);
    return CMC_STATUS_SUCCESS;
}

 //申请内存
//typedef struct _ZwAllocateVirtualMemory_ {
//    HANDLE processHandle; LPVOID baseAddress; ULONG_PTR ZeroBits; LPVOID RegionSize; ULONG AllocationType; ULONG Protect;
//}_ZwAllocateVirtualMemory, * P_ZwAllocateVirtualMemory;
//


//NTSTATUS NTAPI HOOK_ZwAllocateVirtualMemory(
//    _In_ HANDLE processHandle, 
//    _Inout_ PVOID* baseAddress, 
//    _In_ ULONG_PTR ZeroBits,
//    _Inout_ PSIZE_T RegionSize,
//    _In_ ULONG AllocationType, 
//    _In_ ULONG Protect
//) {
//    if(*(INT*)baseAddress < 0xFFFF)
//        return CMC_STATUS_FAILED;
//    _ZwAllocateVirtualMemory data{ processHandle,baseAddress,ZeroBits,RegionSize,AllocationType,Protect };
//    DeviceIoControl(h_DriverHandle, Io_ZwAllocateVirtualMemory, &data, sizeof(_ZwAllocateVirtualMemory), NULL, NULL, NULL, NULL);
//    return CMC_STATUS_SUCCESS;
//
//}

typedef struct _ZwAllocateVirtualMemory_ {
    HANDLE hProcess; LPVOID lpAddress; SIZE_T dwSize; ULONG flAllocationType; ULONG flProtect; LPVOID Buffer;
}_ZwAllocateVirtualMemory, * P_ZwAllocateVirtualMemory;


LPVOID HOOK_VirtualAllocEx(
    HANDLE hProcess, 
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType, 
    DWORD  flProtect
) {
    LPVOID buffer = NULL;
    _ZwAllocateVirtualMemory data{ hProcess,lpAddress,dwSize,flAllocationType,flProtect };
    data.Buffer = &buffer;
    DeviceIoControl(
        h_DriverHandle,
        Io_ZwAllocateVirtualMemory,
        &data, sizeof(_ZwAllocateVirtualMemory),
        data.Buffer, 
        sizeof(data.Buffer),
        NULL,
        NULL
    );
    return buffer;
}

//释放内存
typedef struct _ZwFreeVirtualMemory_ {
    HANDLE ProcessHandle; LPVOID BaseAddress; LPVOID RegionSize; ULONG FreeType;
}_ZwFreeVirtualMemory, * P_ZwFreeVirtualMemory;

NTSTATUS NTAPI HOOK_ZwFreeVirtualMemory(
    _In_ HANDLE ProcessHandle, 
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG FreeType

) {
    _ZwFreeVirtualMemory data{ ProcessHandle, BaseAddress, RegionSize, FreeType};
    DeviceIoControl(h_DriverHandle, Io_ZwFreeVirtualMemory, &data, sizeof(_ZwFreeVirtualMemory), NULL, NULL, NULL, NULL);
  
    return CMC_STATUS_SUCCESS;
}

typedef struct _ZwProtectVirtualMemory_ {
    HANDLE ProcessHandle; 
    LPVOID BaseAddress;
    LPVOID RegionSize; 
    ULONG NewProtect; 
    LPVOID OldProtect;

}_ZwProtectVirtualMemory, * P_ZwProtectVirtualMemory;


NTSTATUS NTAPI HOOK_ZwProtectVirtualMemory(
    
    IN  HANDLE ProcessHandle, 
    IN OUT PVOID* BaseAddress,
    IN OUT PULONG RegionSize, 
    IN  ULONG NewProtect,
    OUT PULONG OldProtect
) {
    if (*BaseAddress < (PVOID)0xFFFF)
        return CMC_STATUS_FAILED;
    _ZwProtectVirtualMemory data{ ProcessHandle,BaseAddress,RegionSize,NewProtect,OldProtect };
    DeviceIoControl(h_DriverHandle, Io_ZwProtectVirtualMemory, &data, sizeof(_ZwProtectVirtualMemory), NULL, NULL, NULL, NULL);
    return CMC_STATUS_SUCCESS;
}
typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
    ProcessQuotaLimits = 1,
    ProcessIoCounters = 2,
    ProcessVmCounters = 3,
    ProcessTimes = 4,
    ProcessBasePriority = 5,
    ProcessRaisePriority = 6,
    ProcessDebugPort = 7,
    ProcessExceptionPort = 8,
    ProcessAccessToken = 9,
    ProcessLdtInformation = 10,
    ProcessLdtSize = 11,
    ProcessDefaultHardErrorMode = 12,
    ProcessIoPortHandlers = 13,   // Note: this is kernel mode only
    ProcessPooledUsageAndLimits = 14,
    ProcessWorkingSetWatch = 15,
    ProcessUserModeIOPL = 16,
    ProcessEnableAlignmentFaultFixup = 17,
    ProcessPriorityClass = 18,
    ProcessWx86Information = 19,
    ProcessHandleCount = 20,
    ProcessAffinityMask = 21,
    ProcessPriorityBoost = 22,
    ProcessDeviceMap = 23,
    ProcessSessionInformation = 24,
    ProcessForegroundInformation = 25,
    ProcessWow64Information = 26,
    ProcessImageFileName = 27,
    ProcessLUIDDeviceMapsEnabled = 28,
    ProcessBreakOnTermination = 29,
    ProcessDebugObjectHandle = 30,
    ProcessDebugFlags = 31,
    ProcessHandleTracing = 32,
    ProcessIoPriority = 33,
    ProcessExecuteFlags = 34,
    ProcessTlsInformation = 35,
    ProcessCookie = 36,
    ProcessImageInformation = 37,
    ProcessCycleTime = 38,
    ProcessPagePriority = 39,
    ProcessInstrumentationCallback = 40,
    ProcessThreadStackAllocation = 41,
    ProcessWorkingSetWatchEx = 42,
    ProcessImageFileNameWin32 = 43,
    ProcessImageFileMapping = 44,
    ProcessAffinityUpdateMode = 45,
    ProcessMemoryAllocationMode = 46,
    ProcessGroupInformation = 47,
    ProcessTokenVirtualizationEnabled = 48,
    ProcessOwnerInformation = 49,
    ProcessWindowInformation = 50,
    ProcessHandleInformation = 51,
    ProcessMitigationPolicy = 52,
    ProcessDynamicFunctionTableInformation = 53,
    ProcessHandleCheckingMode = 54,
    ProcessKeepAliveCount = 55,
    ProcessRevokeFileHandles = 56,
    ProcessWorkingSetControl = 57,
    ProcessHandleTable = 58,
    ProcessCheckStackExtentsMode = 59,
    ProcessCommandLineInformation = 60,
    ProcessProtectionInformation = 61,
    ProcessMemoryExhaustion = 62,
    ProcessFaultInformation = 63,
    ProcessTelemetryIdInformation = 64,
    ProcessCommitReleaseInformation = 65,
    ProcessReserved1Information = 66,
    ProcessReserved2Information = 67,
    ProcessSubsystemProcess = 68,
    ProcessInPrivate = 70,
    ProcessRaiseUMExceptionOnInvalidHandleClose = 71,
    ProcessSubsystemInformation = 75,
    ProcessWin32kSyscallFilterInformation = 79,
    ProcessEnergyTrackingState = 82,
    MaxProcessInfoClass                             // MaxProcessInfoClass should always be the last enum
} PROCESSINFOCLASS;

typedef struct _ZwQueryInformationProcess_ {
    HANDLE           ProcessHandle;
    PROCESSINFOCLASS ProcessInformationClass;
    PVOID            ProcessInformation;
    ULONG            ProcessInformationLength;
    PULONG           ReturnLength;
}_ZwQueryInformationProcess, * P_ZwQueryInformationProcess;


NTSTATUS NTAPI HOOK_ZwQueryInformationProcess(
    _In_      HANDLE           ProcessHandle,
    _In_      PROCESSINFOCLASS ProcessInformationClass,
    _Out_     PVOID            ProcessInformation,
    _In_      ULONG            ProcessInformationLength,
    _Out_opt_ PULONG           ReturnLength
) {
    _ZwQueryInformationProcess data{ ProcessHandle,ProcessInformationClass,ProcessInformation,ProcessInformationLength,ReturnLength };

    DeviceIoControl(h_DriverHandle, Io_ZwQueryInformationProcess, &data, sizeof(_ZwQueryInformationProcess), NULL, NULL, NULL, NULL);
    return CMC_STATUS_SUCCESS;
}

BOOL InitInfo() {

    Out1("ntdll 和 KERNELBASE 地址获取....");
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    HMODULE KERNELBASE = GetModuleHandleA("KERNELBASE.dll");
    if (!ntdll || !KERNELBASE) {
        Out1("ntdll 或 KERNELBASE地址获取失败！");
        return FALSE;
    }
    Out1("ntdll 和 KERNELBASE 地址获取 成功！");


  BOOL if_HOOK = Hook_Start(ntdll, "ZwOpenProcess", &HOOK_ZwOpenProcess, 14);
    if (!if_HOOK) {
        Out1("ZwOpenProcess  Hook失败！");
        return FALSE;
    }

    Hook_Start(ntdll, "ZwReadVirtualMemory", &HOOK_ZwReadVirtualMemory, 14);
    Hook_Start(ntdll, "ZwWriteVirtualMemory", &HOOK_ZwWriteVirtualMemory, 14);
    //Hook_Start(ntdll, "ZwAllocateVirtualMemory", HOOK_ZwAllocateVirtualMemory, 14);
    //Hook_Start(KERNELBASE, "VirtualAllocEx", HOOK_VirtualAllocEx, 14);
    // 
    //Hook_Start(ntdll, "ZwFreeVirtualMemory", &HOOK_ZwFreeVirtualMemory, 14);
    //Hook_Start(ntdll, "ZwProtectVirtualMemory", &HOOK_ZwProtectVirtualMemory, 14);
    //Hook_Start(ntdll, "ZwQueryInformationProcess", &HOOK_ZwQueryInformationProcess, 14);
    return TRUE;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: {//模块加载第一个进来的位置

        Out1("DLL准备加载驱动。。。");
        BOOL if_ok = OnLoad();

        if (!if_ok) {
            Out1( "DLL加载结果: DllMain驱动加载失败！\n");
            return if_ok;
        }
        else
        {
            Out1("DLL加载结果: DllMain驱动加载成功！\n");
        }
        Out1("DLL准备初始化HOOK。。。");
        if_ok = InitInfo();
        
        if (!if_ok) {
            Out1("HOOK失败！");
            return if_ok;
        }
        Out1("HOOK InitInfo成功！");
        break;
    }
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        OnUnLoad();
        break;
    }
    return TRUE;
}
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include "SSDT/SSTD_.h"
#define Io_Openprocess                      0x1000
#define Io_ZwReadVirtualMemory              0x1001
#define Io_ZwWriteVirtualMemory             0x1002
#define Io_ZwAllocateVirtualMemory          0x1003
#define Io_ZwFreeVirtualMemory              0x1004
#define Io_ZwProtectVirtualMemory           0x1005
#define Io_ZwQueryInformationProcess        0x1006


//读内存
NTSTATUS MmCopyVirtualMemory(
	IN  PEPROCESS FromProcess,
	IN  CONST VOID* FromAddress,
	IN  PEPROCESS ToProcess,
	OUT PVOID ToAddress,
	IN  SIZE_T BufferSize,
	IN  KPROCESSOR_MODE PreviousMode,
	OUT PSIZE_T NumberOfBytesCopied
);


//查询进程信息
NTSTATUS ZwQueryInformationProcess(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
);

UNICODE_STRING DriverName = { 0 };
UNICODE_STRING DriveLinks = { 0 };
PDEVICE_OBJECT PDriverObject = NULL;


typedef struct _ZwQueryInformationProcess_ {
	HANDLE           ProcessHandle;
	PROCESSINFOCLASS ProcessInformationClass;
	PVOID            ProcessInformation;
	ULONG            ProcessInformationLength;
	PULONG           ReturnLength;
}_ZwQueryInformationProcess, * P_ZwQueryInformationProcess;


typedef struct _ZwOpenProcess_ {
	PHANDLE ProcessHandle;
	ACCESS_MASK DesiredAccess;
	POBJECT_ATTRIBUTES ObjectAttributes;
	PCLIENT_ID clientId;
}_ZwOpenProcess, * P_ZwOpenProcess;


typedef struct _ZwReadVirtualMemory_ {
	HANDLE ProcessHandle;
	PVOID BaseAddress;
	PVOID Buffer; 
	ULONG BufferSize; 
	PULONG NumberOfBytesRead;
}_ZwReadVirtualMemory, * P_ZwReadVirtualMemory;


typedef struct _ZwWriteVirtualMemory_ {
	HANDLE ProcessHandle;
	PVOID BaseAddress; 
	PVOID Buffer; 
	ULONG BufferSize;
	PULONG NumberOfBytesWritten;
}_ZwWriteVirtualMemory, * P_ZwWriteVirtualMemory;

//封装的读内存函数
NTSTATUS ReadMemory(P_ZwReadVirtualMemory data) {
	NTSTATUS nts = STATUS_UNSUCCESSFUL;
	PROCESS_BASIC_INFORMATION _pid = { 0 };

	// PID转换
	nts = ZwQueryInformationProcess(
		data->ProcessHandle,
		ProcessBasicInformation,
		(PVOID)&_pid,
		sizeof(PROCESS_BASIC_INFORMATION),
		NULL
	);
	if (!NT_SUCCESS(nts)) {
		return nts;
	}
	ULONG pid = (ULONG)_pid.UniqueProcessId;
	if (!pid) {
		DbgPrint("PID转换失败！\n");
		return nts;
	}

	// 读内存
	PEPROCESS eProcess = NULL;
	nts = PsLookupProcessByProcessId((HANDLE)pid, &eProcess);
	if (!NT_SUCCESS(nts)) {
		return nts;
	}
	__try {
		ProbeForRead(data->BaseAddress, 1, 1);
		nts = MmCopyVirtualMemory(eProcess, data->BaseAddress, PsGetCurrentProcess(), data->Buffer, data->BufferSize, KernelMode, (PSIZE_T)data->NumberOfBytesRead);
		if (!NT_SUCCESS(nts)) {
			DbgPrint("内存读取失败！\n");
			return nts;
		}
	}
	__except (1) {
		;
	}
	ObDereferenceObject(eProcess);
	return nts;
}
typedef NTSTATUS(NTAPI* _ZwWriteVirtualMemory_)(
	IN  HANDLE ProcessHandle,
	OUT PVOID BaseAddress,
	IN  PVOID Buffer,
	IN  ULONG BufferSize,
	OUT PULONG NumberOfBytesWritten); _ZwWriteVirtualMemory_ ZwWriteVirtualMemory = NULL;

// 写内存函数
NTSTATUS WriteMemory(P_ZwWriteVirtualMemory pData) {
	NTSTATUS nts = STATUS_UNSUCCESSFUL;
	__try {
		ProbeForRead(pData->BaseAddress, pData->BufferSize, 1);//地址是否可读//否则引发异常
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		//DbgOut("错误内存！data->Pid=%llX\t地址=%p\n", pData->Pid, pData->Address);
		return nts;
	}
	if (!ZwWriteVirtualMemory) {
		ZwWriteVirtualMemory = (_ZwWriteVirtualMemory_)GetAddress();
		if (!ZwWriteVirtualMemory) {
			DbgPrint("\nZwWriteVirtualMemory函数获取失败！%p\n", ZwWriteVirtualMemory);
			return nts;
		}
		else {
			;// DbgOut("\nZwWriteVirtualMemory函数地址！%p\n", ZwWriteVirtualMemory);
		}
		//DbgBreakPoint();
	}
	// 保存
	P_ZwWriteVirtualMemory data = ExAllocatePool(PagedPool, sizeof(_ZwWriteVirtualMemory));
	if (data) {
		RtlCopyMemory(data, pData, sizeof(_ZwWriteVirtualMemory));
		//DbgOut("读内存Pid: %llX\t大小：%d\n", data->Pid, (ULONG)pData->Size);
		PBYTE DATA = NULL;
		if (data->BufferSize < 8) {
			DATA = (PBYTE)ExAllocatePool(PagedPool, 8);
		}
		else
		{
			DATA = (PBYTE)ExAllocatePool(PagedPool, data->BufferSize);
		}
		PULONG NumberOfBytesRead_ = 0;
		if (DATA) {
			RtlCopyMemory(DATA, data->Buffer, data->BufferSize);
			PUCHAR mode = ((PUCHAR)PsGetCurrentThread()) + 0x232U; *mode = KernelMode;
			__try {
				nts = ZwWriteVirtualMemory((HANDLE)data->ProcessHandle, data->BaseAddress, DATA, data->BufferSize, (PULONG)&NumberOfBytesRead_);
				if (NT_SUCCESS(nts))
					;// DbgOut("读取数据成功返回长度=%d\n", (ULONG)NumberOfBytesRead_);
				else {
					DbgPrint("内存写入失败！data->Pid=%p\t地址=%p\n", data->ProcessHandle, data->BaseAddress);
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				DbgPrint("写错误内存！data->Pid=%lld\t地址=%p\n", data->ProcessHandle, data->BaseAddress);
			}
			*mode = UserMode;//还原上下文
		}
		else {
			ExFreePool(data);
			return nts;
		}

		//释放
		ExFreePool(DATA);
		ExFreePool(data);
	}
	return nts;
}
//typedef struct _ZwAllocateVirtualMemory_ {
//	//HANDLE processHandle; LPVOID baseAddress; ULONG_PTR ZeroBits; LPVOID RegionSize; ULONG AllocationType; ULONG Protect;
//	HANDLE processHandle; LPVOID baseAddress; ULONG_PTR ZeroBits; ULONG RegionSize; ULONG AllocationType; ULONG Protect;
//}_ZwAllocateVirtualMemory, * P_ZwAllocateVirtualMemory;
//NTSTATUS 申请内存(P_ZwAllocateVirtualMemory data) {
//	NTSTATUS nts = STATUS_UNSUCCESSFUL;
//	__try {
//		LPVOID size = data->RegionSize;
//		nts = ZwAllocateVirtualMemory(data->processHandle, data->baseAddress, data->ZeroBits, &size, data->AllocationType, data->Protect);
//		if (!NT_SUCCESS(nts)) {
//			DbgPrint("申请内存失败代码：%llX\n", (ULONG64)nts);
//			return nts;
//		}
//		DbgPrint("申请到的内存地址：%llX\n", *(INT64*)data->baseAddress);
//	}
//	__except (EXCEPTION_EXECUTE_HANDLER) {
//		DbgPrint("申请内存错误：%llX\n", (ULONG64)nts);
//	}
//	return nts;
//}
typedef struct _ZwFreeVirtualMemory_ {
	HANDLE ProcessHandle; LPVOID BaseAddress; LPVOID RegionSize; ULONG FreeType;
}_ZwFreeVirtualMemory, * P_ZwFreeVirtualMemory;
NTSTATUS 释放内存(P_ZwFreeVirtualMemory data) {
	DbgBreakPoint();
	NTSTATUS nts = STATUS_UNSUCCESSFUL;
	__try {
		ProbeForRead(data->BaseAddress, 8, 8);//地址是否可读//否则引发异常
		nts = ZwFreeVirtualMemory(data->ProcessHandle,data->BaseAddress, data->RegionSize, data->FreeType);
		if (!NT_SUCCESS(nts)) {
			DbgPrint("释放内存错误代码：%llX\t地址：%p\n", (ULONG64)nts, data->BaseAddress);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint("释放内存异常代码：%llX\t地址：%p\n", (ULONG64)nts, data->BaseAddress);;
	}
	return nts;
}
typedef struct _ZwProtectVirtualMemory_ {
	HANDLE ProcessHandle; LPVOID BaseAddress; LPVOID RegionSize; ULONG NewProtect; LPVOID OldProtect;
}_ZwProtectVirtualMemory, * P_ZwProtectVirtualMemory;
//更改内存属性,只需声明
NTSTATUS ZwProtectVirtualMemory(
	IN  HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PULONG RegionSize,
	IN  ULONG NewProtect,
	OUT PULONG OldProtect);


NTSTATUS 更改内存属性(P_ZwProtectVirtualMemory data) {

	NTSTATUS nts = STATUS_UNSUCCESSFUL;
	// PAGE_EXECUTE_WRITECOPY
	nts = ZwProtectVirtualMemory(data->ProcessHandle, data->BaseAddress, data->RegionSize, data->NewProtect, data->OldProtect);
	if (!NT_SUCCESS(nts)) {
		DbgPrint("解除保护失败错误代码！%llX\t地址：%p\n", (ULONG64)nts, data->BaseAddress);
	}
	else
	{
		;
		// DbgPrint("保护修改成功：旧的保护属性：%d\n", *(PULONG)data->Buffer);
	}
	return nts;
}


NTSTATUS HuiDiao(
	PDEVICE_OBJECT pDevice,
	PIRP pIrp
) {
	// 调用缓冲区指针（获取应用层的参数）
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);
	ULONG Size = stack->Parameters.DeviceIoControl.InputBufferLength; // 输入输出，缓冲区大小
	ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;


	LPVOID DataAddress = pIrp->AssociatedIrp.SystemBuffer;
	if (!DataAddress) {
		DataAddress = stack->Parameters.DeviceIoControl.Type3InputBuffer;
	}

	if (DataAddress) {
		switch (code)
		{

		case Io_Openprocess: { //应用层调用打开进程 
			
			//DbgPrint("数据地址：%p\t数据地址2：%p\t数据地址3：%p", stack->Parameters.DeviceIoControl.Type3InputBuffer, pIrp->AssociatedIrp.SystemBuffer,pIrp->UserBuffer);
			NTSTATUS nts = STATUS_UNSUCCESSFUL;
			P_ZwOpenProcess data = ExAllocatePool(PagedPool, sizeof(_ZwOpenProcess));
			if (data) {
				RtlCopyMemory(data, DataAddress, sizeof(_ZwOpenProcess));

				// 获取句柄
				HANDLE handle = NULL;
				nts = ZwOpenProcess(&handle, data->DesiredAccess, data->ObjectAttributes, data->clientId);
				if (!NT_SUCCESS(nts)) {
					DbgPrint("进程打开失败！\n");
					*data->ProcessHandle = 0;
				}
				*data->ProcessHandle = handle;
				//DbgPrint("打开的进程句柄：%X\n", *(INT*)data->ProcessHandle);
				ExFreePool(data);
			}
			break;
		}

		case Io_ZwReadVirtualMemory: { //读内存
			ReadMemory(DataAddress);
			break;
		}
		case Io_ZwWriteVirtualMemory: { //写内存
			WriteMemory(DataAddress);
			break;
		}
		case Io_ZwAllocateVirtualMemory: { //申请内存(DataAddress);

			//DbgPrint("\n数据地址：%p\t数据地址2：%p\t数据地址3：%p", stack->Parameters.DeviceIoControl.Type3InputBuffer, pIrp->AssociatedIrp.SystemBuffer, pIrp->UserBuffer);
			typedef struct _ZwAllocateVirtualMemory_ {
				HANDLE hProcess; LPVOID lpAddress; SIZE_T dwSize; ULONG flAllocationType; ULONG flProtect; LPVOID Buffer;
			}_ZwAllocateVirtualMemory, * P_ZwAllocateVirtualMemory;
			NTSTATUS nts = STATUS_UNSUCCESSFUL;
			P_ZwAllocateVirtualMemory data = DataAddress;
			__try {
				LPVOID size = data->dwSize;
				LPVOID buffer = NULL;
				nts = ZwAllocateVirtualMemory(data->hProcess, &buffer, 0, &size, data->flAllocationType, data->flProtect);
				if (!NT_SUCCESS(nts)) {
					DbgPrint("申请内存失败代码：%llX\n", (ULONG64)nts);
					return nts;
				}
				DbgPrint("申请到的内存地址：%p\n", buffer);
				RtlCopyMemory(data->Buffer, &buffer, sizeof(LPVOID));
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				DbgPrint("申请内存错误：%llX\n", (ULONG64)nts);
			}
			break;
		}
		case Io_ZwFreeVirtualMemory: {
			释放内存(DataAddress);
			break;
		}
		case Io_ZwProtectVirtualMemory: {
			更改内存属性(DataAddress);
			break;
		}
		case Io_ZwQueryInformationProcess: {
			//DbgBreakPoint();
			P_ZwQueryInformationProcess data = ExAllocatePool(PagedPool, sizeof(_ZwQueryInformationProcess));
			if (data) {
				RtlCopyMemory(data, pIrp->AssociatedIrp.SystemBuffer, sizeof(_ZwQueryInformationProcess));
				//DbgOut("\n进程信息大小！%d\t地址：%p\t读取大小：%d\t实际返回大小：%p\n", data->Int32, data->Address, data->Int32_2, data->Ret);
				NTSTATUS nts = ZwQueryInformationProcess(data->ProcessHandle, data->ProcessInformationClass, data->ProcessInformation, data->ProcessInformationLength, data->ReturnLength);
				if (!NT_SUCCESS(nts)) {
					DbgPrint("\n进程信息查询失败！\n");
				}
				ExFreePool(data);
			}
			break;
		}
		default:
			break;
		}
	}

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = Size;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


VOID UnLoad(PDRIVER_OBJECT pDeviceObject) {
	DbgPrint("\n驱动卸载！\n");
	IoDeleteDevice(pDeviceObject->DeviceObject);
	IoDeleteSymbolicLink(&DriveLinks);
	return;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pUnicode) {

	//__debugbreak();

	NTSTATUS nts = STATUS_UNSUCCESSFUL;

	pDriver->DriverUnload = UnLoad;

	// 字符串赋值
	RtlInitUnicodeString(&DriverName, L"\\123");

	// 创建驱动
	nts = IoCreateDevice(pDriver, 0, &DriverName, FILE_DEVICE_UNKNOWN, 0, TRUE, &PDriverObject);
	if (!NT_SUCCESS(nts)) {
		DbgPrint("IoCreateDevice创建失败！\n");
		return nts;
	}

	// 应用层 链接符
	RtlInitUnicodeString(&DriveLinks, L"\\??\\Test");

	// 创建链接
	nts = IoCreateSymbolicLink(&DriveLinks, &DriverName);
	if (!NT_SUCCESS(nts)) {
		DbgPrint("IoCreateSymbolicLink创建失败！\n");
		return nts;
	}

	for (size_t i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		// 回调函数
		pDriver->MajorFunction[i] = HuiDiao;
	}


	DbgPrint("\n驱动加载成功！\n");
	return STATUS_SUCCESS;
}
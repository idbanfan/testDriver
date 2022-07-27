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


//���ڴ�
NTSTATUS MmCopyVirtualMemory(
	IN  PEPROCESS FromProcess,
	IN  CONST VOID* FromAddress,
	IN  PEPROCESS ToProcess,
	OUT PVOID ToAddress,
	IN  SIZE_T BufferSize,
	IN  KPROCESSOR_MODE PreviousMode,
	OUT PSIZE_T NumberOfBytesCopied
);


//��ѯ������Ϣ
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

//��װ�Ķ��ڴ溯��
NTSTATUS ReadMemory(P_ZwReadVirtualMemory data) {
	NTSTATUS nts = STATUS_UNSUCCESSFUL;
	PROCESS_BASIC_INFORMATION _pid = { 0 };

	// PIDת��
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
		DbgPrint("PIDת��ʧ�ܣ�\n");
		return nts;
	}

	// ���ڴ�
	PEPROCESS eProcess = NULL;
	nts = PsLookupProcessByProcessId((HANDLE)pid, &eProcess);
	if (!NT_SUCCESS(nts)) {
		return nts;
	}
	__try {
		ProbeForRead(data->BaseAddress, 1, 1);
		nts = MmCopyVirtualMemory(eProcess, data->BaseAddress, PsGetCurrentProcess(), data->Buffer, data->BufferSize, KernelMode, (PSIZE_T)data->NumberOfBytesRead);
		if (!NT_SUCCESS(nts)) {
			DbgPrint("�ڴ��ȡʧ�ܣ�\n");
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

// д�ڴ溯��
NTSTATUS WriteMemory(P_ZwWriteVirtualMemory pData) {
	NTSTATUS nts = STATUS_UNSUCCESSFUL;
	__try {
		ProbeForRead(pData->BaseAddress, pData->BufferSize, 1);//��ַ�Ƿ�ɶ�//���������쳣
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		//DbgOut("�����ڴ棡data->Pid=%llX\t��ַ=%p\n", pData->Pid, pData->Address);
		return nts;
	}
	if (!ZwWriteVirtualMemory) {
		ZwWriteVirtualMemory = (_ZwWriteVirtualMemory_)GetAddress();
		if (!ZwWriteVirtualMemory) {
			DbgPrint("\nZwWriteVirtualMemory������ȡʧ�ܣ�%p\n", ZwWriteVirtualMemory);
			return nts;
		}
		else {
			;// DbgOut("\nZwWriteVirtualMemory������ַ��%p\n", ZwWriteVirtualMemory);
		}
		//DbgBreakPoint();
	}
	// ����
	P_ZwWriteVirtualMemory data = ExAllocatePool(PagedPool, sizeof(_ZwWriteVirtualMemory));
	if (data) {
		RtlCopyMemory(data, pData, sizeof(_ZwWriteVirtualMemory));
		//DbgOut("���ڴ�Pid: %llX\t��С��%d\n", data->Pid, (ULONG)pData->Size);
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
					;// DbgOut("��ȡ���ݳɹ����س���=%d\n", (ULONG)NumberOfBytesRead_);
				else {
					DbgPrint("�ڴ�д��ʧ�ܣ�data->Pid=%p\t��ַ=%p\n", data->ProcessHandle, data->BaseAddress);
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				DbgPrint("д�����ڴ棡data->Pid=%lld\t��ַ=%p\n", data->ProcessHandle, data->BaseAddress);
			}
			*mode = UserMode;//��ԭ������
		}
		else {
			ExFreePool(data);
			return nts;
		}

		//�ͷ�
		ExFreePool(DATA);
		ExFreePool(data);
	}
	return nts;
}
//typedef struct _ZwAllocateVirtualMemory_ {
//	//HANDLE processHandle; LPVOID baseAddress; ULONG_PTR ZeroBits; LPVOID RegionSize; ULONG AllocationType; ULONG Protect;
//	HANDLE processHandle; LPVOID baseAddress; ULONG_PTR ZeroBits; ULONG RegionSize; ULONG AllocationType; ULONG Protect;
//}_ZwAllocateVirtualMemory, * P_ZwAllocateVirtualMemory;
//NTSTATUS �����ڴ�(P_ZwAllocateVirtualMemory data) {
//	NTSTATUS nts = STATUS_UNSUCCESSFUL;
//	__try {
//		LPVOID size = data->RegionSize;
//		nts = ZwAllocateVirtualMemory(data->processHandle, data->baseAddress, data->ZeroBits, &size, data->AllocationType, data->Protect);
//		if (!NT_SUCCESS(nts)) {
//			DbgPrint("�����ڴ�ʧ�ܴ��룺%llX\n", (ULONG64)nts);
//			return nts;
//		}
//		DbgPrint("���뵽���ڴ��ַ��%llX\n", *(INT64*)data->baseAddress);
//	}
//	__except (EXCEPTION_EXECUTE_HANDLER) {
//		DbgPrint("�����ڴ����%llX\n", (ULONG64)nts);
//	}
//	return nts;
//}
typedef struct _ZwFreeVirtualMemory_ {
	HANDLE ProcessHandle; LPVOID BaseAddress; LPVOID RegionSize; ULONG FreeType;
}_ZwFreeVirtualMemory, * P_ZwFreeVirtualMemory;
NTSTATUS �ͷ��ڴ�(P_ZwFreeVirtualMemory data) {
	DbgBreakPoint();
	NTSTATUS nts = STATUS_UNSUCCESSFUL;
	__try {
		ProbeForRead(data->BaseAddress, 8, 8);//��ַ�Ƿ�ɶ�//���������쳣
		nts = ZwFreeVirtualMemory(data->ProcessHandle,data->BaseAddress, data->RegionSize, data->FreeType);
		if (!NT_SUCCESS(nts)) {
			DbgPrint("�ͷ��ڴ������룺%llX\t��ַ��%p\n", (ULONG64)nts, data->BaseAddress);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint("�ͷ��ڴ��쳣���룺%llX\t��ַ��%p\n", (ULONG64)nts, data->BaseAddress);;
	}
	return nts;
}
typedef struct _ZwProtectVirtualMemory_ {
	HANDLE ProcessHandle; LPVOID BaseAddress; LPVOID RegionSize; ULONG NewProtect; LPVOID OldProtect;
}_ZwProtectVirtualMemory, * P_ZwProtectVirtualMemory;
//�����ڴ�����,ֻ������
NTSTATUS ZwProtectVirtualMemory(
	IN  HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PULONG RegionSize,
	IN  ULONG NewProtect,
	OUT PULONG OldProtect);


NTSTATUS �����ڴ�����(P_ZwProtectVirtualMemory data) {

	NTSTATUS nts = STATUS_UNSUCCESSFUL;
	// PAGE_EXECUTE_WRITECOPY
	nts = ZwProtectVirtualMemory(data->ProcessHandle, data->BaseAddress, data->RegionSize, data->NewProtect, data->OldProtect);
	if (!NT_SUCCESS(nts)) {
		DbgPrint("�������ʧ�ܴ�����룡%llX\t��ַ��%p\n", (ULONG64)nts, data->BaseAddress);
	}
	else
	{
		;
		// DbgPrint("�����޸ĳɹ����ɵı������ԣ�%d\n", *(PULONG)data->Buffer);
	}
	return nts;
}


NTSTATUS HuiDiao(
	PDEVICE_OBJECT pDevice,
	PIRP pIrp
) {
	// ���û�����ָ�루��ȡӦ�ò�Ĳ�����
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);
	ULONG Size = stack->Parameters.DeviceIoControl.InputBufferLength; // �����������������С
	ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;


	LPVOID DataAddress = pIrp->AssociatedIrp.SystemBuffer;
	if (!DataAddress) {
		DataAddress = stack->Parameters.DeviceIoControl.Type3InputBuffer;
	}

	if (DataAddress) {
		switch (code)
		{

		case Io_Openprocess: { //Ӧ�ò���ô򿪽��� 
			
			//DbgPrint("���ݵ�ַ��%p\t���ݵ�ַ2��%p\t���ݵ�ַ3��%p", stack->Parameters.DeviceIoControl.Type3InputBuffer, pIrp->AssociatedIrp.SystemBuffer,pIrp->UserBuffer);
			NTSTATUS nts = STATUS_UNSUCCESSFUL;
			P_ZwOpenProcess data = ExAllocatePool(PagedPool, sizeof(_ZwOpenProcess));
			if (data) {
				RtlCopyMemory(data, DataAddress, sizeof(_ZwOpenProcess));

				// ��ȡ���
				HANDLE handle = NULL;
				nts = ZwOpenProcess(&handle, data->DesiredAccess, data->ObjectAttributes, data->clientId);
				if (!NT_SUCCESS(nts)) {
					DbgPrint("���̴�ʧ�ܣ�\n");
					*data->ProcessHandle = 0;
				}
				*data->ProcessHandle = handle;
				//DbgPrint("�򿪵Ľ��̾����%X\n", *(INT*)data->ProcessHandle);
				ExFreePool(data);
			}
			break;
		}

		case Io_ZwReadVirtualMemory: { //���ڴ�
			ReadMemory(DataAddress);
			break;
		}
		case Io_ZwWriteVirtualMemory: { //д�ڴ�
			WriteMemory(DataAddress);
			break;
		}
		case Io_ZwAllocateVirtualMemory: { //�����ڴ�(DataAddress);

			//DbgPrint("\n���ݵ�ַ��%p\t���ݵ�ַ2��%p\t���ݵ�ַ3��%p", stack->Parameters.DeviceIoControl.Type3InputBuffer, pIrp->AssociatedIrp.SystemBuffer, pIrp->UserBuffer);
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
					DbgPrint("�����ڴ�ʧ�ܴ��룺%llX\n", (ULONG64)nts);
					return nts;
				}
				DbgPrint("���뵽���ڴ��ַ��%p\n", buffer);
				RtlCopyMemory(data->Buffer, &buffer, sizeof(LPVOID));
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				DbgPrint("�����ڴ����%llX\n", (ULONG64)nts);
			}
			break;
		}
		case Io_ZwFreeVirtualMemory: {
			�ͷ��ڴ�(DataAddress);
			break;
		}
		case Io_ZwProtectVirtualMemory: {
			�����ڴ�����(DataAddress);
			break;
		}
		case Io_ZwQueryInformationProcess: {
			//DbgBreakPoint();
			P_ZwQueryInformationProcess data = ExAllocatePool(PagedPool, sizeof(_ZwQueryInformationProcess));
			if (data) {
				RtlCopyMemory(data, pIrp->AssociatedIrp.SystemBuffer, sizeof(_ZwQueryInformationProcess));
				//DbgOut("\n������Ϣ��С��%d\t��ַ��%p\t��ȡ��С��%d\tʵ�ʷ��ش�С��%p\n", data->Int32, data->Address, data->Int32_2, data->Ret);
				NTSTATUS nts = ZwQueryInformationProcess(data->ProcessHandle, data->ProcessInformationClass, data->ProcessInformation, data->ProcessInformationLength, data->ReturnLength);
				if (!NT_SUCCESS(nts)) {
					DbgPrint("\n������Ϣ��ѯʧ�ܣ�\n");
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
	DbgPrint("\n����ж�أ�\n");
	IoDeleteDevice(pDeviceObject->DeviceObject);
	IoDeleteSymbolicLink(&DriveLinks);
	return;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pUnicode) {

	//__debugbreak();

	NTSTATUS nts = STATUS_UNSUCCESSFUL;

	pDriver->DriverUnload = UnLoad;

	// �ַ�����ֵ
	RtlInitUnicodeString(&DriverName, L"\\123");

	// ��������
	nts = IoCreateDevice(pDriver, 0, &DriverName, FILE_DEVICE_UNKNOWN, 0, TRUE, &PDriverObject);
	if (!NT_SUCCESS(nts)) {
		DbgPrint("IoCreateDevice����ʧ�ܣ�\n");
		return nts;
	}

	// Ӧ�ò� ���ӷ�
	RtlInitUnicodeString(&DriveLinks, L"\\??\\Test");

	// ��������
	nts = IoCreateSymbolicLink(&DriveLinks, &DriverName);
	if (!NT_SUCCESS(nts)) {
		DbgPrint("IoCreateSymbolicLink����ʧ�ܣ�\n");
		return nts;
	}

	for (size_t i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		// �ص�����
		pDriver->MajorFunction[i] = HuiDiao;
	}


	DbgPrint("\n�������سɹ���\n");
	return STATUS_SUCCESS;
}
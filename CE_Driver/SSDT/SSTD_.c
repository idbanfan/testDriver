#include "SSTD_.h"
typedef struct _SYSTEM_SERVICE_TABLE {
	PLONG  		ServiceTableBase;
	PVOID  		ServiceCounterTableBase;
	ULONGLONG  	NumberOfServices;
	PVOID  		ParamTableBase;
} SYSTEM_SERVICE_TABLE, * PSYSTEM_SERVICE_TABLE;
PSYSTEM_SERVICE_TABLE SSDT地址 = 0;

UINT64 GetMainAddress()
{
	PUCHAR msr = (PUCHAR)__readmsr(0xC0000082);
	PUCHAR startaddr = 0, Endaddr = 0;
	PUCHAR i = NULL;
	UCHAR b1, b2, b3;
	ULONG temp = 0;
	ULONGLONG addr = 0;
	if (*(msr + 0x9) == 0x00)
	{
		startaddr = msr;
		Endaddr = startaddr + 0x500;
	}
	else if (*(msr + 0x9) == 0x70)
	{
		PUCHAR pKiSystemCall64Shadow = msr;
		PUCHAR EndSearchAddress = pKiSystemCall64Shadow + 0x500;
		i = NULL;
		INT Temp = 0;
		for (i = pKiSystemCall64Shadow; i < EndSearchAddress; i++)
		{
			if (MmIsAddressValid(i) && MmIsAddressValid(i + 5))
			{
				if (*i == 0xe9 && *(i + 5) == 0xc3)
				{
					memcpy(&Temp, i + 1, 4);
					startaddr = Temp + (i + 5);
					Endaddr = startaddr + 0x500;
				}
			}
		}
	}

	for (i = startaddr; i < Endaddr; i++)
	{
		b1 = *i;
		b2 = *(i + 1);
		b3 = *(i + 2);
		if (b1 == 0x4c && b2 == 0x8d && b3 == 0x15)
		{
			memcpy(&temp, i + 3, 4);
			addr = (ULONGLONG)temp + (ULONGLONG)i + 7;
			return addr;
		}
	}
	return 0;
}
ULONG64 GetAddress()
{
	if (SSDT地址 == 0) {
		SSDT地址 = (PSYSTEM_SERVICE_TABLE)GetMainAddress();
		if (SSDT地址 == NULL)
		{
			DbgPrint("SSDT Error!!!");
			return 0;
		}
	}
	PULONG lpBase = 0;
	ULONG dwCount = 0;
	lpBase = (PULONG)SSDT地址->ServiceTableBase;
	dwCount = (ULONG)SSDT地址->NumberOfServices;
	UINT64 lpAddr = 0;
	ULONG dwOffset = lpBase[58];

	if (dwOffset & 0x80000000)
		dwOffset = (dwOffset >> 4) | 0xF0000000;
	else
		dwOffset >>= 4;
	lpAddr = (UINT64)((PUCHAR)lpBase + (LONG)dwOffset);

	return lpAddr;
}

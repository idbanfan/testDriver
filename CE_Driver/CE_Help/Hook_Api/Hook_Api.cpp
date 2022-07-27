//#include "pch.h"
#include "Hook_Api.h"
typedef struct _Hook_Info_ {
    typedef struct _Info_ {
        CHAR Key[0xFF];
        BYTE Original[32];
        SIZE_T Lenth;
        LPVOID HookAddress;
    }Info_;
    ULONG Count;
    Info_ Info[100];
}Hook_Info, P_Hook_Info; Hook_Info Hook = { 0 };
DWORD Protect_Info = PAGE_EXECUTE_READWRITE;
BOOL Protect_Off(LPVOID address, ULONG lenth)
{
    Out1("Protect_Off");
    return VirtualProtect(address, lenth, PAGE_EXECUTE_READWRITE, &Protect_Info);//PAGE_EXECUTE_READWRITE
}
BOOL Protect_On(LPVOID address, ULONG lenth)
{
    Out1("Protect_On");
    return VirtualProtect(address, lenth, Protect_Info, &Protect_Info);
}
//��ʼHOOK   
//����1��ģ������
//����2��API����-���磺"ZwOpenprocess",
//����3���ӹܺ�����ַ,
//����4��HOOK����
BOOL Hook_Start(
    CONST HMODULE base,
    CONST CHAR* api,
    LPVOID callbreak_address,
    ULONG hook_lenth
)
{
    Out2("��ʼHOOK", api);
    static BOOL init = TRUE;
    if (init) {
        // ÿ���ֽ� ��ֵΪ0
        memset(&Hook, 0, sizeof(Hook));
        init = FALSE;
    }
    LPVOID hook_address = (LPVOID)GetProcAddress(base, api);
    if (!hook_address) {
        Out1("GetProcAddressʧ��");
        return FALSE;
    }
   
    if (Protect_Off(hook_address, sizeof(Hook.Info[Hook.Count].Original))) {
        memcpy(&Hook.Info[Hook.Count].HookAddress, &hook_address, sizeof(hook_address));
        memcpy(Hook.Info[Hook.Count].Key, api, strlen(api));
        Hook.Info[Hook.Count].Lenth = hook_lenth;
        memcpy(Hook.Info[Hook.Count].Original, Hook.Info[Hook.Count].HookAddress, Hook.Info[Hook.Count].Lenth);
        Out1("׼��JMP...");

        // ��������ע�͵�
        BYTE jmp[14] = { 0xFF,0x25,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
         memcpy(((PVOID)(jmp + 6)), callbreak_address, sizeof(callbreak_address));

        //BYTE jmp[5] = { 0xE9,0x00,0x00,0x00,0x00 };
        INT64 jmp2 = (INT64)callbreak_address - (INT64)hook_address - 5;
        //INT64 jmp2 = (INT64)callbreak_address - (INT64)hook_address - 14;
        memcpy(jmp + 1, &jmp2, sizeof(jmp2));

        memcpy(
            Hook.Info[Hook.Count].HookAddress,
            jmp, 
            sizeof(jmp)
        );
        Out("\nHOOK��\nAPI��%s\n��ַ��%p\n���ȣ�%d\n���ֽڣ�%X\n\n",
            Hook.Info[Hook.Count].Key,
            Hook.Info[Hook.Count].HookAddress,
            Hook.Info[Hook.Count].Lenth,
            Hook.Info[Hook.Count].Original[0]
        );
        Hook.Count++;
        Out1("JMP�ɹ�");
        Protect_On(Hook.Info[Hook.Count].HookAddress, sizeof(Hook.Info[Hook.Count].Original));
        Out2("Hook�ɹ�",api );
        return TRUE;
    }
    Out2("Hookʧ��", api);
    return FALSE;
}
//����HOOK    ����1��API����-���磺"ZwOpenprocess"��  ����2���Ƿ����ȫ��HOOK   true=����ȫ��HOOK   ��֮  false;
BOOL Hook_End(CONST CHAR* api, CONST BOOL all)
{
    if (all) {
        for (size_t i = 0; i < Hook.Count; i++)
        {
            if (Protect_Off(Hook.Info[i].HookAddress, sizeof(Hook.Info[i].Original))) {
                memcpy(Hook.Info[i].HookAddress, Hook.Info[i].Original, Hook.Info[i].Lenth);
                //Hook.Count--;
                Protect_On(Hook.Info[i].HookAddress, sizeof(Hook.Info[i].Original));
                //Out("�ָ�HOOK���ؼ��֣�%s\t��ַ��%p\t���ȣ�%d\t���ֽڣ�%X\n", Hook.Info[i].Key, Hook.Info[i].HookAddress,Hook.Info[i].Lenth,Hook.Info[i].Original[0]);
            }
        }
        return TRUE;
    }
    for (size_t i = 0; i < Hook.Count; i++)
    {
        if (strstr(Hook.Info[i].Key, api) != 0) {
            if (Protect_Off(Hook.Info[i].HookAddress, sizeof(Hook.Info[i].Original))) {
                memcpy(Hook.Info[i].HookAddress, Hook.Info[i].Original, Hook.Info[i].Lenth);
                //Hook.Count--;
                Protect_On(Hook.Info[i].HookAddress, sizeof(Hook.Info[i].Original));
                //Out("�ָ�HOOK���ؼ��֣�%s\t��ַ��%p\t���ȣ�%d\t���ֽڣ�%X\n", Hook.Info[i].Key, Hook.Info[i].HookAddress,Hook.Info[i].Lenth,Hook.Info[i].Original[0]);
                return TRUE;
            }
        }
    }
    return FALSE;
}

VOID Out(const char* str, ...) {
    static BOOL if_ = TRUE;
    if (if_)
    {
        AllocConsole();
        SetConsoleTitleA("Debug");
        //fopen("A_DebugData", "w+");
        FILE* tem = NULL;
        //freopen_s(&tem, "A_CON.ini", "w+", stdout);
        freopen_s(&tem, "CON", "w", stdout);
        if_ = FALSE;
    }
    va_list aptr;
    va_start(aptr, str);
    char buffer[1024] = { 0 };
    DWORD ret = vsprintf(buffer, str, aptr);
    va_end(aptr);
    printf(buffer);
}

VOID Out1(const char* str) {
    Out(str);
    Out("\n");
}

VOID Out2(const char* str, const char* str2 ) {
    
    Out(str);
    Out(" : ");
    Out(str2);
    Out("\n");
}

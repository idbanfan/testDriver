#pragma once
#pragma warning(disable : 4996)
#include <Windows.h>
#include <atlstr.h>
//内部
BOOL Protect_Off(LPVOID address, ULONG lenth);
BOOL Protect_On(LPVOID address, ULONG lenth);
//公开
VOID Out(const char* str, ...);
VOID Out1(const char* str);
VOID Out2(const char* str, const char* str2);
BOOL Hook_Start(CONST HMODULE base, CONST CHAR* api, LPVOID callbreak_address, ULONG hook_lenth);
BOOL Hook_End(CONST CHAR* key, CONST BOOL all = FALSE);
#pragma once
#include <Windows.h>
#pragma warning(disable : 4996)
//2005������������
//DEBUG��
//���������⣺uafxcwd.lib; LIBCMTD.lib;
//�����ض�Ĭ�Ͽ⣺LIBCMTD.lib; uafxcwd.lib
//
//RELEASE��
//���������⣺uafxcw.lib; LIBCMT.lib;
//�����ض�Ĭ�Ͽ⣺LIBCMT.lib; uafxcw.lib

extern HANDLE h_DriverHandle;
VOID Out(const char* str, ...);
VOID Out1(const char* str);
VOID Out2(const char* str, const char* str2);
BOOL OnLoad();//��������
BOOL OnUnLoad();//ж������


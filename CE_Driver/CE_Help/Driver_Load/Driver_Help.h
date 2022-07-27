#pragma once
#include <Windows.h>
#pragma warning(disable : 4996)
//2005链接器错误解决
//DEBUG：
//附加依赖库：uafxcwd.lib; LIBCMTD.lib;
//忽略特定默认库：LIBCMTD.lib; uafxcwd.lib
//
//RELEASE：
//附加依赖库：uafxcw.lib; LIBCMT.lib;
//忽略特定默认库：LIBCMT.lib; uafxcw.lib

extern HANDLE h_DriverHandle;
VOID Out(const char* str, ...);
VOID Out1(const char* str);
VOID Out2(const char* str, const char* str2);
BOOL OnLoad();//加载驱动
BOOL OnUnLoad();//卸载驱动


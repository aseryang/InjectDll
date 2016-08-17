// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
//#include <Windows.h>
//#include <Psapi.h>

// #pragma comment(lib, "Psapi.lib")
// __declspec(dllexport) DWORD ExportExample(LPSTR sMsg, DWORD dwCode);

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		{
			TCHAR lpMainMoudleName[MAX_PATH];
			TCHAR lpMessage[MAX_PATH + 64];
			//获取PID和主模块名，将弹出消息框
			// 			DWORD dwPID = GetCurrentProcessId();
			// 			GetModuleBaseName(GetCurrentProcess(), NULL, lpMainMoudleName, MAX_PATH);
			// 			wsprintf(lpMessage, L"process name: %s, PID: %u ", lpMainMoudleName, dwPID);
			//MessageBox(NULL, lpMessage, L"msg.dll", MB_OK);
			MessageBox(NULL, L"111", L"msg.dll", MB_OK);
			break;	
		}
	case DLL_THREAD_ATTACH:
		{
			
		}
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

//导出函数，显示消息
// DWORD ExportExample(LPWSTR szMsg, DWORD dwCode)
// {
// 	LPVOID lpShowOut = HeapAlloc(GetProcessHeap(), NULL, lstrlen(szMsg) + 100);
// 	wsprintf((LPWSTR)lpShowOut, L"%s,%d", szMsg, dwCode);
// 	MessageBox(NULL, (LPWSTR)lpShowOut, L"由导出函数弹出的消息! ", MB_OK);
// 	HeapFree(GetProcessHeap(), NULL, lpShowOut);
// 	return 0;
// }


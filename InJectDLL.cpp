// InJectDLL.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <windows.h>
#include <TlHelp32.h>

BOOL LoadRemoteDll(DWORD dwProcessId, LPTSTR lpszLibName)
{
	BOOL   bResult            = FALSE;
	HANDLE hProcess            = NULL;
	HANDLE hThread            = NULL;
	PSTR   pszLibFileRemote = NULL;
	DWORD cch;
	PTHREAD_START_ROUTINE pfnThreadRrn;
	__try
	{
		//获得想要注入代码的进程的句柄
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
		if (NULL == hProcess)
			__leave;
		//计算DLL路径名需要的字节数
		cch = 2 * (1 + lstrlen(lpszLibName));
		//在远程线程中为路径名分配空间
		pszLibFileRemote = (PSTR)VirtualAllocEx(hProcess, NULL, cch, MEM_COMMIT, PAGE_READWRITE);

		if (pszLibFileRemote == NULL)
			__leave;
		//将DLL的路径名复制到远程进程的地址空间
		if (!WriteProcessMemory(hProcess, (PVOID)pszLibFileRemote, (PVOID)lpszLibName, cch, NULL))
			__leave;
		//获得LoadLibraryA在Kernel.dll中得真正地址
		pfnThreadRrn = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
		if (pfnThreadRrn == NULL)
			__leave;

		hThread = CreateRemoteThread(hProcess, NULL, 0, pfnThreadRrn, (PVOID)pszLibFileRemote, 0, NULL);
		if (hThread == NULL)
		{
			int ret = GetLastError();
			__leave;
		}
			
		//等待远程线程终止
		WaitForSingleObject(hThread, INFINITE);
		DWORD dwExitCode;
		GetExitCodeThread(hThread,&dwExitCode);
		bResult = TRUE;
	}
	__finally
	{
		//关闭句柄
		if (pszLibFileRemote != NULL)
			VirtualFreeEx(hProcess, (PVOID)pszLibFileRemote, 0, MEM_RELEASE);
		if (hThread != NULL)
			CloseHandle(hThread);
		if (hProcess != NULL)
			CloseHandle(hProcess);
	}
	return bResult;
}

BOOL GetProcessIdByName(LPWSTR szProcessName, LPDWORD lpPID)
{
	//变量及其初始化
	STARTUPINFO st;
	PROCESS_INFORMATION pi;
	PROCESSENTRY32 ps;
	HANDLE hSnapshot;
	ZeroMemory(&st, sizeof(STARTUPINFO));
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	st.cb = sizeof(STARTUPINFO);
	ZeroMemory(&ps, sizeof(PROCESSENTRY32));
	ps.dwSize = sizeof(PROCESSENTRY32);

	//遍历进程
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return FALSE;
	if (!Process32First(hSnapshot, &ps))
		return FALSE;

	do
	{
		//比较进程名
		if (lstrcmpi(ps.szExeFile, TEXT("Target.exe")) == 0)
		{
			//找到了
			*lpPID = ps.th32ProcessID;
			CloseHandle(hSnapshot);
			return TRUE;
		}
	}
	while (Process32Next(hSnapshot, &ps));
	//没有找到
	CloseHandle(hSnapshot);
	return FALSE;
}

//修改进程权限
BOOL EnablePrivilege(LPWSTR name)
{
	HANDLE hToken;
	BOOL rv;
	TOKEN_PRIVILEGES priv = {1, {0, 0, SE_PRIVILEGE_ENABLED}};
	LookupPrivilegeValue(0, name, &priv.Privileges[0].Luid);
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);
	AdjustTokenPrivileges(hToken, FALSE, &priv, sizeof priv, 0, 0);
	rv = GetLastError() == ERROR_SUCCESS;
	CloseHandle(hToken);
	return rv;
}
BOOL   EnableDebugPrivilege(BOOL   fEnable)
{ 
	BOOL   fOK	=   FALSE; 
	HANDLE	hToken	=   NULL; 
	if(OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES,&hToken)){ 
		TOKEN_PRIVILEGES	tp; 
		tp.PrivilegeCount	=1; 
		LookupPrivilegeValue(NULL,SE_DEBUG_NAME,&tp.Privileges[0].Luid); 
		tp.Privileges[0].Attributes	=   fEnable   ?   SE_PRIVILEGE_ENABLED   :   0; 
		AdjustTokenPrivileges(hToken,FALSE,&tp,sizeof(tp),NULL,NULL); 
		int ret = GetLastError();
		fOK	=   (GetLastError()==ERROR_SUCCESS); 
		CloseHandle(hToken); 
	} 
	return   fOK; 
} 

int _tmain(int argc, _TCHAR* argv[])
{
	DWORD dwPID;
	//提权，获取SE_DEBUG_NAME 权限
	//可以在其他进程的内存空间中写入，创建线程
	//if (0 == EnablePrivilege(SE_DEBUG_NAME))
 	if(0 == EnableDebugPrivilege(true))
 		return 0;

	if (!GetProcessIdByName(TEXT("Target.exe"), &dwPID))
		return 0;
	//通过上传远程线程加载dll
	//将msg.dll放置在系统目录下
	if (!LoadRemoteDll(dwPID, TEXT("E:\\VS2010_PROJECT\\Msg\\Release\\msg.dll")))
		return 0;
	return 1;
}


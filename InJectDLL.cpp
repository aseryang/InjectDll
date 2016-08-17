// InJectDLL.cpp : �������̨Ӧ�ó������ڵ㡣
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
		//�����Ҫע�����Ľ��̵ľ��
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
		if (NULL == hProcess)
			__leave;
		//����DLL·������Ҫ���ֽ���
		cch = 2 * (1 + lstrlen(lpszLibName));
		//��Զ���߳���Ϊ·��������ռ�
		pszLibFileRemote = (PSTR)VirtualAllocEx(hProcess, NULL, cch, MEM_COMMIT, PAGE_READWRITE);

		if (pszLibFileRemote == NULL)
			__leave;
		//��DLL��·�������Ƶ�Զ�̽��̵ĵ�ַ�ռ�
		if (!WriteProcessMemory(hProcess, (PVOID)pszLibFileRemote, (PVOID)lpszLibName, cch, NULL))
			__leave;
		//���LoadLibraryA��Kernel.dll�е�������ַ
		pfnThreadRrn = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
		if (pfnThreadRrn == NULL)
			__leave;

		hThread = CreateRemoteThread(hProcess, NULL, 0, pfnThreadRrn, (PVOID)pszLibFileRemote, 0, NULL);
		if (hThread == NULL)
		{
			int ret = GetLastError();
			__leave;
		}
			
		//�ȴ�Զ���߳���ֹ
		WaitForSingleObject(hThread, INFINITE);
		DWORD dwExitCode;
		GetExitCodeThread(hThread,&dwExitCode);
		bResult = TRUE;
	}
	__finally
	{
		//�رվ��
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
	//���������ʼ��
	STARTUPINFO st;
	PROCESS_INFORMATION pi;
	PROCESSENTRY32 ps;
	HANDLE hSnapshot;
	ZeroMemory(&st, sizeof(STARTUPINFO));
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	st.cb = sizeof(STARTUPINFO);
	ZeroMemory(&ps, sizeof(PROCESSENTRY32));
	ps.dwSize = sizeof(PROCESSENTRY32);

	//��������
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return FALSE;
	if (!Process32First(hSnapshot, &ps))
		return FALSE;

	do
	{
		//�ȽϽ�����
		if (lstrcmpi(ps.szExeFile, TEXT("Target.exe")) == 0)
		{
			//�ҵ���
			*lpPID = ps.th32ProcessID;
			CloseHandle(hSnapshot);
			return TRUE;
		}
	}
	while (Process32Next(hSnapshot, &ps));
	//û���ҵ�
	CloseHandle(hSnapshot);
	return FALSE;
}

//�޸Ľ���Ȩ��
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
	//��Ȩ����ȡSE_DEBUG_NAME Ȩ��
	//�������������̵��ڴ�ռ���д�룬�����߳�
	//if (0 == EnablePrivilege(SE_DEBUG_NAME))
 	if(0 == EnableDebugPrivilege(true))
 		return 0;

	if (!GetProcessIdByName(TEXT("Target.exe"), &dwPID))
		return 0;
	//ͨ���ϴ�Զ���̼߳���dll
	//��msg.dll������ϵͳĿ¼��
	if (!LoadRemoteDll(dwPID, TEXT("E:\\VS2010_PROJECT\\Msg\\Release\\msg.dll")))
		return 0;
	return 1;
}


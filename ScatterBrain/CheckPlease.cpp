// CheckPlease.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "CertificateTrust.h"
#include "Helpers.h"
#include <Windows.h>
#include <psapi.h>
#include <stdio.h>
#include <iostream>
#include <TlHelp32.h>
#include <Winternl.h>
#include <intrin.h>
#include <io.h>
#include <tchar.h>
#include <WinSock2.h>
#include <IPTypes.h>
#include <iphlpapi.h>
#include <Shlwapi.h>
#include <dsrole.h>
#include <fstream>
using namespace std;
//
//#pragma comment(lib, "netapi32.lib")

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383

typedef NTSTATUS(*CALL)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

// Ensure the machine you're detonating on is domain joined
// and matches the passed domainName.
BOOL IsDomainJoined(LPCTSTR domainName)
{
	// https://stackoverflow.com/questions/9792411/how-to-get-windows-domain-name
	DSROLE_PRIMARY_DOMAIN_INFO_BASIC * info;
	DWORD dw;

	dw = DsRoleGetPrimaryDomainInformation(NULL,
		DsRolePrimaryDomainInfoBasic,
		(PBYTE *)&info);
	if (dw != ERROR_SUCCESS)
	{
		wprintf(L"DsRoleGetPrimaryDomainInformation: %u\n", dw);
		return FALSE;
	}

	if (info->MachineRole == DsRole_RoleStandaloneServer || info->MachineRole == DsRole_RoleStandaloneWorkstation)
	{
		//printf("Machine is not domain joined.\n");
		return FALSE;
	}
	else
	{
		if (info->DomainNameDns == NULL)
		{
			//wprintf(L"DomainNameDns is NULL\n");
			return FALSE;
		}
		else
		{
			//wprintf(L"DomainNameDns: %s\n", info->DomainNameDns);
			if (wcscmp(info->DomainNameDns, domainName) == 0)
			{
				//wprintf(L"Domain name matches, proceed!\n");
				return TRUE;
			}
		}
	}

	return FALSE;
}

BOOL IsDomainJoined()
{
	// https://stackoverflow.com/questions/9792411/how-to-get-windows-domain-name
	DSROLE_PRIMARY_DOMAIN_INFO_BASIC * info;
	DWORD dw;

	dw = DsRoleGetPrimaryDomainInformation(NULL,
		DsRolePrimaryDomainInfoBasic,
		(PBYTE *)&info);
	if (dw != ERROR_SUCCESS)
	{
		wprintf(L"DsRoleGetPrimaryDomainInformation: %u\n", dw);
		return FALSE;
	}

	if (info->MachineRole == DsRole_RoleStandaloneServer || info->MachineRole == DsRole_RoleStandaloneWorkstation)
	{
		//printf("Machine is not domain joined.\n");
		return FALSE;
	}
	else
	{
		if (info->DomainNameDns == NULL)
		{
			//wprintf(L"DomainNameDns is NULL\n");
			return FALSE;
		}
		else
		{
			return TRUE;
		}
	}

	return FALSE;
}

// Ensures that the username exists
// and that the username is not "User"
BOOL HasUsername()
{
	WCHAR username[UNLEN + 1];
	DWORD usernameLen[UNLEN + 1];
	GetUserNameW(username, usernameLen);

	if (username == NULL) {
		printf("Could not read username, exiting.\n");
		return FALSE;
	}
	
	if (_wcsicmp(username, L"user") != 0) {
		//wprintf(L"Username is %s, proceed!\n", username);
		return TRUE;
	}
	else if (_wcsicmp(username, L"win7ult"))
	{
		return TRUE;
	}
	else if (_wcsicmp(username, L"emotective"))
	{
		return TRUE;
	}
	else {
		//wprintf(L"Username: %s, BAD\n", username);
	}
	return FALSE;
}

// Ensures that the machine has had a minimum number of USB
// devices connected to it, minimum 1.
BOOL HasUSBHistory()
{
	HKEY hKey;
	// Baseline number of USBs ever mounted
	int MinimumUsbHistory = 2;
	// To store actual number of USBs ever mounted
	DWORD numUsbDevices = 0;

	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Enum\\USBSTOR", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {

		// Get number of subkeys, which corresponds to history of mounted USB devices
		if (RegQueryInfoKeyA(hKey, NULL, NULL, NULL, &numUsbDevices, NULL, NULL, NULL, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
			// Do nothing
		}
		else {
			printf("[---] Unable to query subkey HKLM::SYSTEM\\ControlSet001\\Enum\\USBSTOR\n");
			return TRUE;
		}
	}
	else {
		printf("[---] Unable to open subkey HKLM::SYSTEM\\ControlSet001\\Enum\\USBSTOR\n");
		return TRUE;
	}


	if (numUsbDevices >= MinimumUsbHistory) {
		printf("Number of USB devices ever mounted: %d\n", numUsbDevices);
		//printf("Proceed!\n");
		return FALSE;
	}
	else {
		printf("Number of USB devices ever mounted: %d\n", numUsbDevices);
	}
	return TRUE;
}

// Determines if the current host has several sandbox-type keys set.
BOOL HasSandboxRegistryKeys()
{
	HKEY hKey;
	int evidenceOfSandbox = 0;

	const wchar_t *sandboxStrings[5] = { L"VMWare", L"virtualbox", L"vbox", L"qemu", L"xen" };

	const char *HKLM_Keys_To_Check_Exist[7] = { "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0\\Identifier",
		"SYSTEM\\CurrentControlSet\\Enum\\SCSI\\Disk&Ven_VMware_&Prod_VMware_Virtual_S",
		"SYSTEM\\CurrentControlSet\\Control\\CriticalDeviceDatabase\\root#vmwvmcihostdev",
		"SYSTEM\\CurrentControlSet\\Control\\VirtualDeviceDrivers",
		"SOFTWARE\\VMWare, Inc.\\VMWare Tools",
		"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
		"HARDWARE\\ACPI\\DSDT\\VBOX_" };

	const char *HKLM_Keys_With_Values_To_Parse[6][2] = {
	{ "SYSTEM\\ControlSet001\\Services\\Disk\\Enum", "0" },
	{ "HARDWARE\\Description\\System", "SystemBiosInformation" },
	{ "HARDWARE\\Description\\System", "VideoBiosVersion" },
	{ "HARDWARE\\Description\\System\\BIOS", "SystemManufacturer" },
	{ "HARDWARE\\Description\\System\\BIOS", "SystemProductName" },
	{ "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0", "Logical Unit Id 0" }
	};

	/*WCHAR username[UNLEN + 1];
	DWORD usernameLen[UNLEN + 1];
	GetUserNameW(username, usernameLen);*/
	// HKEY_USERS\Sandbox_$USERNAME_DefaultBox

	for (int i = 0; i < 7; ++i) {
		if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, HKLM_Keys_To_Check_Exist[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
			printf("%s\n", HKLM_Keys_To_Check_Exist[i]);
			RegCloseKey(hKey);
			++evidenceOfSandbox;
		}
	}

	for (int i = 0; i < 6; ++i) {
		HKEY hKey;
		WCHAR buff[1024];
		DWORD buffSize = 1024;
		if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, HKLM_Keys_With_Values_To_Parse[i][0], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
			if (RegQueryValueExA(hKey, HKLM_Keys_With_Values_To_Parse[i][1], NULL, NULL, (LPBYTE)buff, &buffSize) == ERROR_SUCCESS) {
				for (int j = 0; j < 5; ++j) {
					if (StrStrIW(buff, sandboxStrings[j]) != NULL) {
						printf("%s\\%s --> %s \n", HKLM_Keys_With_Values_To_Parse[i][0], HKLM_Keys_With_Values_To_Parse[i][1], buff);
						++evidenceOfSandbox;
					}
				}
			}
			RegCloseKey(hKey);
		}
	}

	if (evidenceOfSandbox == 0) {
		wprintf(L"No sandbox registry keys -- Proceed!\n");
		return FALSE;
	}
	return TRUE;
}

// Deterines if the machine meets RAM hardware requirements.
BOOL HasMinRAM()
{
	int minRam = 3; // Minimum 3gb ram to execute.
	int DIV = 1024 * 1024 * 1024; // GB divider
	MEMORYSTATUSEX statusex;
	statusex.dwLength = sizeof(statusex);
	GlobalMemoryStatusEx(&statusex);
	long totalRamInGB = statusex.ullTotalPhys / DIV;
	if (totalRamInGB >= minRam)
	{
		printf("There is %ld GB of physical memory (aka more than 3) Proceed!\n", totalRamInGB);
		return FALSE;
	}
	printf("%ld was less than the %d threshold. Abort\n", totalRamInGB, minRam);
	return TRUE;
}

// Helper function
LPWSTR GetFormattedMessage(LPWSTR pMessage, ...)
{
	LPWSTR pBuffer = NULL;

	va_list args = NULL;
	va_start(args, pMessage);

	FormatMessage(FORMAT_MESSAGE_FROM_STRING |
		FORMAT_MESSAGE_ALLOCATE_BUFFER,
		pMessage,
		0,
		0,
		(LPWSTR)&pBuffer,
		0,
		&args);

	va_end(args);

	return pBuffer;
}

// Helper function
BOOL QuerySubKeyExists(HKEY hKey, LPCTSTR subKey)
{
	TCHAR    achKey[MAX_KEY_LENGTH];   // buffer for subkey name
	DWORD    cbName;                   // size of name string 
	TCHAR    achClass[MAX_PATH] = TEXT("");  // buffer for class name 
	DWORD    cchClassName = MAX_PATH;  // size of class string 
	DWORD    cSubKeys = 0;               // number of subkeys 
	DWORD    cbMaxSubKey;              // longest subkey size 
	DWORD    cchMaxClass;              // longest class string 
	DWORD    cValues;              // number of values for key 
	DWORD    cchMaxValue;          // longest value name 
	DWORD    cbMaxValueData;       // longest value data 
	DWORD    cbSecurityDescriptor; // size of security descriptor 
	FILETIME ftLastWriteTime;      // last write time 

	DWORD i, retCode;

	TCHAR  achValue[MAX_VALUE_NAME];
	DWORD cchValue = MAX_VALUE_NAME;

	// Get the class name and the value count. 
	retCode = RegQueryInfoKey(
		hKey,                    // key handle 
		achClass,                // buffer for class name 
		&cchClassName,           // size of class string 
		NULL,                    // reserved 
		&cSubKeys,               // number of subkeys 
		&cbMaxSubKey,            // longest subkey size 
		&cchMaxClass,            // longest class string 
		&cValues,                // number of values for this key 
		&cchMaxValue,            // longest value name 
		&cbMaxValueData,         // longest value data 
		&cbSecurityDescriptor,   // security descriptor 
		&ftLastWriteTime);       // last write time 

	// Enumerate the subkeys, until RegEnumKeyEx fails.

	if (cSubKeys)
	{
		//printf("\nNumber of subkeys: %d\n", cSubKeys);

		for (i = 0; i < cSubKeys; i++)
		{
			cbName = MAX_KEY_LENGTH;
			retCode = RegEnumKeyEx(hKey, i,
				achKey,
				&cbName,
				NULL,
				NULL,
				NULL,
				&ftLastWriteTime);
			if (retCode == ERROR_SUCCESS)
			{
				//_tprintf(TEXT("(%d) %s\n"), i + 1, achKey);
				if (_wcsicmp(achKey, subKey) == 0)
				{
					return TRUE;
				}
			}
		}
	}
	return FALSE;
	// Enumerate the key values. 

	if (cValues)
	{
		//printf("\nNumber of values: %d\n", cValues);

		for (i = 0, retCode = ERROR_SUCCESS; i < cValues; i++)
		{
			cchValue = MAX_VALUE_NAME;
			achValue[0] = '\0';
			retCode = RegEnumValue(hKey, i,
				achValue,
				&cchValue,
				NULL,
				NULL,
				NULL,
				NULL);

			if (retCode == ERROR_SUCCESS)
			{
				//_tprintf(TEXT("(%d) %s\n"), i + 1, achValue);
			}
		}
	}
}


// Looks for Sandboxie registry key.
BOOL IsSandboxie()
{
	WCHAR username[UNLEN + 1];
	DWORD usernameLen[UNLEN + 1];
	GetUserNameW(username, usernameLen);

	// add sizeof(username) + size("Sandbox_Default\A")
	WCHAR sandbox[] = L"Sandbox_";
	WCHAR defaultA[] = L"_DefaultBox";

	WCHAR* key = (WCHAR*)malloc(sizeof(username) + sizeof(sandbox) + sizeof(defaultA));
	StrCpyW(key, sandbox);
	StrCpyW(key + wcslen(sandbox), username);
	StrCpyW(key + wcslen(sandbox) + wcslen(username), defaultA);
	//wprintf(L"Key: %s\n", key);
	HKEY hKey;
	BOOL result = FALSE;
	if (RegOpenKeyEx(HKEY_USERS,
		key,
		0,
		KEY_READ,
		&hKey) == ERROR_SUCCESS
		)
	{
		LPCTSTR badKey = L"A";
		LPCTSTR badKey2 = L"WC";
		if (QuerySubKeyExists(hKey, badKey))
		{
			result = TRUE;
		}
		else if (QuerySubKeyExists(hKey, badKey2))
		{
			result = TRUE;
		}
	}

	RegCloseKey(hKey);
	return result;
}

// Ensures the machine has a minimum number of processors.
BOOL HasNumberOfProcessors()
{
	int minProcessors = 2;

	SYSTEM_INFO systemInfo;
	GetSystemInfo(&systemInfo);
	int numProcessors = systemInfo.dwNumberOfProcessors;

	if (numProcessors >= minProcessors && numProcessors % 2 == 0) {
		printf("Check success: Number of processors - %d\n", numProcessors);
		//printf("Proceed!\n");
		return FALSE;
	}
	else {
		printf("Check failed: number of processors = %d\n", numProcessors);
	}
	return TRUE;
}

// Determines if the minimum number of processes is running.
BOOL HasMinNumProcesses(int minNumProcesses = 50)
{
	DWORD loadedProcesses[1024];
	DWORD cbNeeded;
	DWORD runningProcesses;

	// Get all PIDs
	if (!EnumProcesses(loadedProcesses, sizeof(loadedProcesses), &cbNeeded)) {
		printf("[---] Could not get all PIDs, exiting.\n");
		return TRUE;
	}

	// Calculate how many PIDs returned
	runningProcesses = cbNeeded / sizeof(DWORD);

	if (runningProcesses >= minNumProcesses) {
		printf("There are %d processes running on the system, which satisfies the minimum you set of %d. Proceed!\n", runningProcesses, minNumProcesses);
		return FALSE;
	}
	else {
		printf("Only %d processes are running on the system, which is less than the minimum you set of %d. Do not proceed.\n", runningProcesses, minNumProcesses);
	}

	return TRUE;
}

// Determines if the current machine has any network adapters
// that match VMWare or Oracle factory serials.
BOOL HasVMMacAddress()
{
	BOOL evidenceOfSandbox;
	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;

	// First three bytes of known Virtual Machine MAC addresses (e.g. 00-0C-29...)
	unsigned char badMacAddresses[5][3] = {
		{ 0x00, 0x0C, 0x29 },
		{ 0x00, 0x1C, 0x14 },
		{ 0x00, 0x50, 0x56 },
		{ 0x00, 0x05, 0x69 },
		{ 0x08, 0x00, 0x27 }
	};

	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));

	// Make an initial call to GetAdaptersInfo to get the necessary size into the ulOutBufLen variable
	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
	}

	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR) {
		pAdapter = pAdapterInfo;
		while (pAdapter) { // for each adapter
			for (int i = 0; i < 5; ++i) { // check each row of bad MAC address table
				if (!memcmp(badMacAddresses[i], pAdapter->Address, 3)) {
					for (int j = 0; j < pAdapter->AddressLength; ++j) {
						if (j == (pAdapter->AddressLength - 1)) {
							printf("VM Mac Addr: %.2X\n", (int)pAdapter->Address[j]);
						}
						else {
							printf("VM Mac addr: %.2X-", (int)pAdapter->Address[j]);
						}
					}
					evidenceOfSandbox = TRUE;
				}
			}

			pAdapter = pAdapter->Next;
		}
	}
	else { // GetAdaptersInfo failed
		printf("[---] GetAdaptersInfo failed, exiting.\n");
		return TRUE;
	}

	if (pAdapterInfo) {
		free(pAdapterInfo);
	}

	if (!evidenceOfSandbox) {
		printf("No MAC addresses match known virtual machine MAC addresses. Proceed!\n");
		return FALSE;
	}

	return TRUE;
}

// Ensure that the current executing environment has a name.
BOOL HasComputerName()
{
	TCHAR buffer[256] = TEXT("");
	BOOL ReturnFlag = FALSE;
	TCHAR szDescription[8][32] = { TEXT("NetBIOS"),
		TEXT("DNS hostname"),
		TEXT("DNS domain"),
		TEXT("DNS fully-qualified"),
		TEXT("Physical NetBIOS"),
		TEXT("Physical DNS hostname"),
		TEXT("Physical DNS domain"),
		TEXT("Physical DNS fully-qualified") };
	int cnf = 0;
	DWORD dwSize = sizeof(buffer);

	if (!GetComputerNameEx((COMPUTER_NAME_FORMAT)cnf, buffer, &dwSize))
	{
		_tprintf(TEXT("GetComputerNameEx failed (%d)\n"), GetLastError());
	}
	else
	{
		//_tprintf(TEXT("%s: %s\n"), szDescription[cnf], buffer);
		ReturnFlag = TRUE;
	}
	return ReturnFlag;
	//for (cnf = 0; cnf < ComputerNameMax; cnf++)
	//{
	//	if (!GetComputerNameEx((COMPUTER_NAME_FORMAT)cnf, buffer, &dwSize))
	//	{
	//		_tprintf(TEXT("GetComputerNameEx failed (%d)\n"), GetLastError());
	//		return FALSE;
	//	}
	//	else _tprintf(TEXT("%s: %s\n"), szDescription[cnf], buffer);

	//	dwSize = _countof(buffer);
	//	/*ZeroMemory(buffer, dwSize);*/
	//}
	//return TRUE;
}

// Determine if VM drivers are installed.
BOOL VMDriversPresent()
{
#define numFiles 32
	const WCHAR* filePaths[numFiles] = { L"C:\\windows\\System32\\Drivers\\Vmmouse.sys",
		L"C:\\windows\\System32\\Drivers\\vm3dgl.dll", L"C:\\windows\\System32\\Drivers\\vmdum.dll",
		L"C:\\windows\\System32\\Drivers\\vm3dver.dll", L"C:\\windows\\System32\\Drivers\\vmtray.dll",
		L"C:\\windows\\System32\\Drivers\\vmci.sys", L"C:\\windows\\System32\\Drivers\\vmusbmouse.sys",
		L"C:\\windows\\System32\\Drivers\\vmx_svga.sys", L"C:\\windows\\System32\\Drivers\\vmxnet.sys",
		L"C:\\windows\\System32\\Drivers\\VMToolsHook.dll", L"C:\\windows\\System32\\Drivers\\vmhgfs.dll",
		L"C:\\windows\\System32\\Drivers\\vmmousever.dll", L"C:\\windows\\System32\\Drivers\\vmGuestLib.dll",
		L"C:\\windows\\System32\\Drivers\\VmGuestLibJava.dll", L"C:\\windows\\System32\\Drivers\\vmscsi.sys",
		L"C:\\windows\\System32\\Drivers\\VBoxMouse.sys", L"C:\\windows\\System32\\Drivers\\VBoxGuest.sys",
		L"C:\\windows\\System32\\Drivers\\VBoxSF.sys", L"C:\\windows\\System32\\Drivers\\VBoxVideo.sys",
		L"C:\\windows\\System32\\vboxdisp.dll", L"C:\\windows\\System32\\vboxhook.dll",
		L"C:\\windows\\System32\\vboxmrxnp.dll", L"C:\\windows\\System32\\vboxogl.dll",
		L"C:\\windows\\System32\\vboxoglarrayspu.dll", L"C:\\windows\\System32\\vboxoglcrutil.dll",
		L"C:\\windows\\System32\\vboxoglerrorspu.dll", L"C:\\windows\\System32\\vboxoglfeedbackspu.dll",
		L"C:\\windows\\System32\\vboxoglpackspu.dll", L"C:\\windows\\System32\\vboxoglpassthroughspu.dll",
		L"C:\\windows\\System32\\vboxservice.exe", L"C:\\windows\\System32\\vboxtray.exe",
		L"C:\\windows\\System32\\VBoxControl.exe" };
	int evidenceCount = 0;
	//printf("Size of array: %d\n", sizeof(filePaths));
	for (int i = 0; i < numFiles; ++i) {
		//BOOL retval = PathFileExists(filePaths[i]);
		WIN32_FIND_DATAW findFileData;
		//wprintf(L"Checking: %s\n", filePaths[i]);
		//wprintf(L"%d\n", sizeof(filePaths[i]));
		HANDLE hFound = FindFirstFileW(filePaths[i], &findFileData);
		if (hFound != INVALID_HANDLE_VALUE) {
			wprintf(L"Found file: %s\n", filePaths[i]);
			++evidenceCount;
		}
	}
	// One driver present if user has VMWare installed. So we'll put that as the cap.
	if (evidenceCount <= 1) {
		printf("No files exist on disk that suggest we are running in a sandbox. Proceed!\n");
		return FALSE;
	}
	printf("VM Driver Evidence Count: %d", evidenceCount);
	return TRUE;
}

// Determines if a RemoteDebugger was attached to the process.
BOOL IsDebuggerAttached()
{
	HANDLE hProcess = GetCurrentProcess();
	BOOL isDebugged;
	CheckRemoteDebuggerPresent(hProcess, &isDebugged);
	if (isDebugged) {
		//printf("Remote Debugger IS present.\n");
		return TRUE;
	}
	else {
		return FALSE;
	}
}

// Helper function
PROCESS_BASIC_INFORMATION GetCurrentProcessInformation()
{
	HANDLE hProcess = GetCurrentProcess();
	PROCESS_BASIC_INFORMATION pbi;
	PEB Peb;
	DWORD dwDummy;


	HMODULE ntHandle = GetModuleHandle(L"ntdll.dll");
	CALL fCall = (CALL)GetProcAddress(
		ntHandle,
		"NtQueryInformationProcess"
	);

	if (fCall == NULL)
	{
		printf("Couldn't get a handle on NtQueryInformationProcess.\n");
	}
	else
	{
		LONG status = fCall(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
		if (status)
		{
			printf("Failed to get Process information for current process.\n");
			return (PROCESS_BASIC_INFORMATION)pbi;
		}
		else
		{
			printf("Successfully queried process information Continuing...\n");
			int64_t buffer = (int64_t)pbi.PebBaseAddress;
			/*int *newIntPtr = */
			return pbi;
		}
	}
}

//// BROKEN :'(
//void AttachDebuggerToCurrentProcess()
//{
//	BOOL status = DebugActiveProcess(GetCurrentProcessId());
//	if (status)
//	{
//		printf("Successfully attached a debugger using DebugActive Process.\n");
//	}
//	else
//	{
//		printf("Failed to debug active process using DebugActiveProcess.\n");
//	}
//	//PROCESS_BASIC_INFORMATION pbi;
//	/*PEB Peb;
//	DWORD dwDummy;
//	*/
//	
//	/*HMODULE ntHandle = GetModuleHandle(L"ntdll.dll");
//	CALL fCall = (CALL)GetProcAddress(
//		ntHandle,
//		"NtQueryInformationProcess"
//	);
//	
//	if (fCall == NULL)
//	{
//		printf("Couldn't get a handle on NtQueryInformationProcess.\n");
//	}
//	else
//	{
//		LONG status = fCall(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
//		printf("Status: %d\n", status);
//		if (status)
//		{
//			printf("Failed to get Process information for current process.\n");
//		}
//		else
//		{
//			MEMORY_BASIC_INFORMATION mb;
//			DWORD oldP = 0;
//			SIZE_T bytesWritten;
//			Peb.BeingDebugged = 0x00;
//			VirtualQueryEx(hProcess, (void*)pbi.PebBaseAddress, &mb, sizeof(mb));
//			if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &Peb, sizeof(PEB), NULL))
//			{
//				printf("Failed to read process memory for current process.\n");
//			}
//			else
//			{
//				if (!VirtualProtectEx(hProcess, (void*)pbi.PebBaseAddress, mb.RegionSize, PAGE_READWRITE, &oldP))
//				{
//					printf("VirtualProtect Error 0x%x", GetLastError());
//					exit(EXIT_FAILURE);
//				}
//				
//				WriteProcessMemory(hProcess, (void*)pbi.PebBaseAddress, &Peb, sizeof(Peb), &bytesWritten);
//			
//			}
//		}
//	}*/
//}
//
//// BROKEN :'(
//int AttachDebugger()
//{
//	// This function sets the byte to ensure the process
//	// is already being debugged, as only one process can be
//	// debugged at a time.
//	BOOL beingDebugged = CheckDebuggerAttached();
//	if (beingDebugged)
//	{
//		printf("Being debuged already, can't do that stuff.\n");
//		//return 1;
//	}
//	else
//	{
//		printf("No debugger attached. Attempting to attach...\n");
//		AttachDebuggerToCurrentProcess();
//		getchar();
//		BOOL newAttempt = CheckDebuggerAttached();
//		if (newAttempt)
//		{
//			printf("SUCCESSFULLY attached debugger.\n");
//			return 0;
//		}
//		else
//		{
//			printf("Failed to attach debugger\n");
//			return 1;
//		}
//		return 1;
//	}
//}


// This function determines if the process tree is "anomalous",
// meaning that if we are detonating under a context that doesn't
// match a valid Microsoft signed execution tree, we abort.
// This is especially helpful for things like sandboxes and debuggers.
BOOL HasBadParentProcess()
{
	DWORD ppid = 0, pid = GetCurrentProcessId();
	BOOL ResultFlag = FALSE;

	BOOL hasParent = FALSE;

	while (pid != 0)
	{
		BOOL found = FALSE;
		HANDLE hSnapshot;
		PROCESSENTRY32 pe32;

		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnapshot == INVALID_HANDLE_VALUE) return TRUE;

		ZeroMemory(&pe32, sizeof(pe32));
		pe32.dwSize = sizeof(pe32);
		if (!Process32First(hSnapshot, &pe32)) return TRUE;

		do {
			// We acquired our process. Let's get to the root.
			if (pe32.th32ProcessID == pid) {
				found = TRUE;
				pid = pe32.th32ParentProcessID;
				//printf("We're opening up the process\n");
				HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ParentProcessID);
				if (processHandle == 0)
				{
					wprintf(L"Failed to open parent process.\n");
					break; // assume something weird.
				}
				WCHAR fileName[2048];
				if (!GetProcessImageFileName(processHandle, fileName, sizeof(fileName)))
				{
					printf("Failed to get file name of parent process.\n");
					break;
				}
				//wprintf(L"image file name: %s\n", fileName);
				WCHAR filePath[MAX_PATH];
				TranslateVolumeToPath(fileName, filePath);
				WCHAR signatureFile[MAX_PATH];
				if (HasValidSignature(filePath, signatureFile))
				{
					//wprintf(L"[+] %s has a VALID signature.\n", filePath);
					LPCTSTR issuerName = L"Microsoft Windows Production";
					if (VerifyAuthenticodeSignature(signatureFile, issuerName))
					{
						wprintf(L"[+] %s is a valid, signed Microsoft Windows process.\n", filePath);
					}
					else
					{
						wprintf(L"[-] ERROR: %s is not a Microsoft Windows process.\n", filePath);
						ResultFlag = TRUE;
					}
				}
				else
				{
					wprintf(L"[-] %s IS NOT signed.\n", filePath);
					ResultFlag = TRUE;
				}
				//GetAuthenticodeSignature(filePath);
				//GetCertificateInformation(filePath);
				//wprintf(L"pid is: %d\n", pid);
				/*for (int i = 0; i < sizeof(badParents); i++)
				{
					if (wcsstr(fileName, badParents[i])) {
						wprintf(L"BAD PARENT: %s\n", pe32.szExeFile);
						return TRUE;
					}
				}*/
				break;
			}
		} while (Process32Next(hSnapshot, &pe32));
		if (!found || ResultFlag) break;
	}
	return ResultFlag;
}

// This function determines if any "bad" processes appear
// to be running in the background. This can include, but
// is not limited to things like vmware, IDA, etc.
BOOL BadProcessesRunning()
{
#define numSandboxProcesses 25
	const WCHAR* sandboxProcesses[numSandboxProcesses] = { L"vmsrvc", L"tcpview", L"wireshark", L"visual basic", L"fiddler", L"vmware", L"vbox", L"process explorer", L"autoit", L"vboxtray", L"vmtools", L"vmrawdsk", L"vmusbmouse", L"vmvss", L"vmscsi", L"vmxnet", L"vmx_svga", L"vmmemctl", L"df5serv", L"vboxservice", L"vmhgfs", L"SandboxieDcomLaunch", L"SandboxieRpcSs", L"SbieCtrl", L"SbieSvc" };
	HANDLE hProcessSnap;
	HANDLE hProcess;
	PROCESSENTRY32 pe32;
	DWORD dwPriorityClass;

	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		printf("Could not create snapshot, exiting.\n");
		return TRUE;
	}

	// Set the size of the structure before using it.
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// Retrieve information about the first process, exit if unsuccessful
	if (!Process32FirstW(hProcessSnap, &pe32)) {
		printf("Could not retrieve information about processes, exiting.");
		CloseHandle(hProcessSnap);
		return TRUE;
	}

	// Walk the snapshot of processes, find bad ones
	int evidenceCount = 0;
	do {

		for (int i = 0; i < numSandboxProcesses; ++i) {
			if (wcsstr(pe32.szExeFile, sandboxProcesses[i])) {
				wprintf(L"Bad Process running: %s\n", pe32.szExeFile);
				++evidenceCount;
			}
		}

	} while (Process32NextW(hProcessSnap, &pe32));

	if (evidenceCount == 0) {
		printf("No bad processes running: proceed!\n");
		return FALSE;
	}
	return TRUE;
}


// This function determines if several VM drivers are installed.
// If so, abort.
BOOL HasSandboxDLLs()
{

#define numSandboxDLLs 6

	const WCHAR* sandboxDLLs[numSandboxDLLs] = { L"sbiedll.dll", L"api_log.dll", L"dir_watch.dll", L"pstorec.dll", L"vmcheck.dll", L"wpespy.dll" };
	DWORD loadedProcesses[1024];
	DWORD cbNeeded;
	DWORD cProcesses;
	unsigned int i;

	// Get all PIDs
	if (!EnumProcesses(loadedProcesses, sizeof(loadedProcesses), &cbNeeded)) {
		printf("[---] Could not get all PIDs, exiting.\n");
		return FALSE;
	}

	// Calculate how many PIDs returned
	cProcesses = cbNeeded / sizeof(DWORD);

	// Check all loaded DLLs
	HANDLE hProcess;
	int evidenceCount = 0;
	for (i = 0; i < cProcesses; i++) {
		HMODULE hMods[1024];

		// Get a handle to the process.
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, loadedProcesses[i]);
		if (hProcess != NULL) {

			// Get a list of all the modules in this process.
			if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
				for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
					TCHAR szModName[MAX_PATH];
					// Get the full path to the module's file.
					if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
						for (int j = 0; j < numSandboxDLLs; ++j) {
							if (wcsstr(szModName, sandboxDLLs[j])) {
								TCHAR processName[MAX_PATH];
								//RtlZeroMemory(processName, MAX_PATH);
								GetProcessImageFileNameW(hProcess, processName, MAX_PATH);
								wprintf(L"Process Name: %s\n", processName);
								wprintf(L"\t Scary DLL loaded: %s\n", szModName);
								++evidenceCount;
							}
						}
					}
				}
			}
			CloseHandle(hProcess);
		} // if hProcess != NULL 	
	} // for each process

	if (evidenceCount == 0) {
		printf("No sandbox-indicative DLLs were discovered loaded in any accessible running process. Proceed!\n");
		return FALSE;
	}
	return TRUE;

}

// This function ensures that we can get a proper handle on the
// timezone. 
BOOL IsUTCTimeZone()
{
	TIME_ZONE_INFORMATION tz;
	DWORD ret = GetTimeZoneInformation(&tz);
	if (ret == TIME_ZONE_ID_INVALID)
	{
		return FALSE;
	}
	else
	{
		if (!wcscmp(L"Coordinated Universal Time", tz.DaylightName) || !wcscmp(L"Coordinated Universal Time", tz.StandardName)) {
			return FALSE;
		}
		else {
			return TRUE;
		}
	}
}


// This function is where you should put your logic for
// defining what a safe environment looks like to detonate
// your payload.
BOOL SafeToExecute()
{
	BOOL ReturnFlag = TRUE;
	//if (!IsUTCTimeZone())
	//{
	//	//printf("Not in a UTC Time Zone.\n");
	//	ReturnFlag = FALSE;
	//}
	/*if (IsDebuggerAttached())
	{
		printf("Debugger attached.\n");
		ReturnFlag = FALSE;
	}
	if (!HasComputerName())
	{
		printf("Computername couldn't be acquired.\n");
		ReturnFlag = FALSE;
	}
	BOOL userCheck = HasUsername();
	if (!userCheck)
	{
		printf("Username couldn't be acquired; exiting.\n");
		ReturnFlag = FALSE;
	}*/
	// If you want to check if you're joined to a SPECIFIC domain,
	// change this to IsDomainJoined(L"DEVLAB.LOCAL")
	BOOL domCheck = IsDomainJoined();
	if (!domCheck)
	{
		//printf("Computer is not domain joined.\n");
		ReturnFlag = FALSE;
	}
	//if (HasBadParentProcess())
	//{
	//	//printf("[SANDBOX/DEBUG] The current process has non-Microsoft parent processes.\n");
	//	ReturnFlag = FALSE;
	//}
	//else
	//{
	//	//printf("[+] Parent process tree is clean and valid!\n");
	//}
	return ReturnFlag;
}
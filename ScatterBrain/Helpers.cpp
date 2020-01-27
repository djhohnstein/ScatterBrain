#include "stdafx.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <shlwapi.h>
#include <string>
#include "Helpers.h"
#include <winternl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ShObjIdl.h>
#include <cctype>
#include <cwctype>
using namespace std;

typedef std::basic_string<TCHAR> tstring;

template<typename T, typename F>
void rtrimws(basic_string<T>& s, F f) {

	if (s.empty())
		return;

	typename basic_string<T>::iterator p;
	for (p = s.end(); p != s.begin() && f(*--p););

	if (!f(*p))
		p++;

	s.erase(p, s.end());
}

// Overloads to make cleaner calling for client code
void rtrimws(string& s) {
	rtrimws(s, isspace);
}

void rtrimws(wstring& ws) {
	rtrimws(ws, iswspace);
}

wchar_t* CharToWcharT(char* charString)
{
	size_t sz = strlen(charString) + 1;
	wchar_t* path = new wchar_t[sz];
	MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, charString, sz, path, sz);
	return path;
}

//https://stackoverflow.com/questions/48345108/determine-all-posible-applications-to-open-a-file-with-delegateexecute?rq=1
//wchar_t* GetDefaultHandlerForExtension(LPCTSTR extension)
//{
//	IEnumAssocHandlers *pEnumHandlers = NULL;
//	if (SUCCEEDED(SHAssocEnumHandlers(extension, ASSOC_FILTER_RECOMMENDED, &pEnumHandlers)))
//	{
//		IAssocHandler *pAssocHandler = NULL;
//		while (S_OK == pEnumHandlers->Next(1, &pAssocHandler, NULL))
//		{
//			if (pAssocHandler != NULL)
//			{
//				LPWSTR pszName;
//				LPWSTR pszUIName;
//				LPWSTR ppszPath;
//				int pIndex;
//
//				pAssocHandler->GetUIName(&pszName);
//				pAssocHandler->GetName(&pszUIName);
//				pAssocHandler->GetIconLocation(&ppszPath, &pIndex);
//				pAssocHandler->Release();
//				pAssocHandler = NULL;
//
//				printf_s("%S \n", pszUIName);
//				printf_s("%S \n", pszName);
//			}
//		}
//		pEnumHandlers->Release();
//
//		scanf_s("%S");
//	}
//	return NULL;
//}

bool FileExistsAndIs64Bit(wchar_t* fileName)
{
	struct _stat buffer;
	if (_wstat(fileName, &buffer) == 0)
	{
		DWORD lpBinaryType;
		if (GetBinaryTypeW(fileName, &lpBinaryType) &&
			lpBinaryType == SCS_64BIT_BINARY)
		{
			wprintf(L"[*] %s exists and is 64-bit!\n", fileName);
			return TRUE;
		}
	}
	return FALSE;

}

bool FileExistsAndIs64Bit(char* fileName)
{
	struct _stat buffer;
	if (_stat(fileName, &buffer) == 0)
	{
		DWORD lpBinaryType;
		if (GetBinaryTypeA(fileName, &lpBinaryType) &&
			lpBinaryType == SCS_64BIT_BINARY)
		{
			printf("[*] %s exists and is 64-bit!\n", fileName);
			return TRUE;
		}
	}
	return FALSE;
}

// Maps Volumes to disk paths
PWCHAR GetVolumePaths(
	__in PWCHAR VolumeName
)
{
	DWORD  CharCount = MAX_PATH + 1;
	PWCHAR Names = NULL;
	PWCHAR NameIdx = NULL;
	BOOL   Success = FALSE;

	for (;;)
	{
		//
		//  Allocate a buffer to hold the paths.
		Names = (PWCHAR) new BYTE[CharCount * sizeof(WCHAR)];

		if (!Names)
		{
			//
			//  If memory can't be allocated, return.
			return NULL;
		}

		//
		//  Obtain all of the paths
		//  for this volume.
		Success = GetVolumePathNamesForVolumeNameW(
			VolumeName, Names, CharCount, &CharCount
		);

		if (Success)
		{
			break;
		}

		if (GetLastError() != ERROR_MORE_DATA)
		{
			break;
		}

		//
		//  Try again with the
		//  new suggested size.
		delete[] Names;
		Names = NULL;
	}

	if (Success)
	{
		//
		//  Display the various paths.
		//wprintf(L"Names: %s\n", Names);
		return Names;
		/*for (NameIdx = Names;
			NameIdx[0] != L'\0';
			NameIdx += wcslen(NameIdx) + 1)
		{
			wprintf(L"  %s", NameIdx);
		}
		wprintf(L"\n");*/
	}

	if (Names != NULL)
	{
		delete[] Names;
		Names = NULL;
	}

	return Names;
}


// Maps a device volume path to a filepath,
// like \Device\Harddisk4\Windows\System32\cmd.exe --> C:\Windows\System32\cmd.exe
void TranslateVolumeToPath(LPCWSTR path, WCHAR* out)
{
	DWORD  CharCount = 0;
	WCHAR  DeviceName[MAX_PATH] = L"";
	DWORD  Error = ERROR_SUCCESS;
	HANDLE FindHandle = INVALID_HANDLE_VALUE;
	BOOL   Found = FALSE;
	size_t Index = 0;
	BOOL   Success = FALSE;
	WCHAR  VolumeName[MAX_PATH] = L"";

	WCHAR driveResult[3];

	//
	//  Enumerate all volumes in the system.
	FindHandle = FindFirstVolumeW(VolumeName, ARRAYSIZE(VolumeName));

	if (FindHandle == INVALID_HANDLE_VALUE)
	{
		Error = GetLastError();
		wprintf(L"FindFirstVolumeW failed with error code %d\n", Error);
		return;
	}

	for (;;)
	{
		//
		//  Skip the \\?\ prefix and remove the trailing backslash.
		Index = wcslen(VolumeName) - 1;

		if (VolumeName[0] != L'\\' ||
			VolumeName[1] != L'\\' ||
			VolumeName[2] != L'?' ||
			VolumeName[3] != L'\\' ||
			VolumeName[Index] != L'\\')
		{
			Error = ERROR_BAD_PATHNAME;
			wprintf(L"FindFirstVolumeW/FindNextVolumeW returned a bad path: %s\n", VolumeName);
			break;
		}

		//
		//  QueryDosDeviceW does not allow a trailing backslash,
		//  so temporarily remove it.
		VolumeName[Index] = L'\0';

		CharCount = QueryDosDeviceW(&VolumeName[4], DeviceName, ARRAYSIZE(DeviceName));

		VolumeName[Index] = L'\\';

		if (CharCount == 0)
		{
			Error = GetLastError();
			wprintf(L"QueryDosDeviceW failed with error code %d\n", Error);
			break;
		}

		/*wprintf(L"\nFound a device:\n %s", DeviceName);
		wprintf(L"\nVolume name: %s", VolumeName);*/
		if (wcsstr(path, DeviceName))
		{
			//wprintf(L"%s appears to match %s!\n", DeviceName, path);
			PWCHAR drive = GetVolumePaths(VolumeName);
			if (drive == NULL)
			{
				printf("Couldn't translate %s to a drive. FAILED.\n", path);
			}
			else
			{
				//wprintf(L"Parsed drive: %s\n", drive);
				std::wstring temp = path;
				temp.replace(0, 24, drive, 3);
				/*WCHAR* result = (WCHAR*)malloc(sizeof(drive) + sizeof(temp) - 25);
				StrCpyW(result, drive);
				StrCpyW(result + wcslen(drive), path);*/
				FindVolumeClose(FindHandle);
				FindHandle = INVALID_HANDLE_VALUE;
				StrCpyW(out, temp.c_str());
				//wprintf(L"We think that the result should be: %s\n", out);
				return;
			}
		}

		//
		//  Move on to the next volume.
		Success = FindNextVolumeW(FindHandle, VolumeName, ARRAYSIZE(VolumeName));

		if (!Success)
		{
			Error = GetLastError();

			if (Error != ERROR_NO_MORE_FILES)
			{
				wprintf(L"FindNextVolumeW failed with error code %d\n", Error);
				break;
			}

			//
			//  Finished iterating
			//  through all the volumes.
			Error = ERROR_SUCCESS;
			break;
		}
	}

	FindVolumeClose(FindHandle);
	FindHandle = INVALID_HANDLE_VALUE;

	return;
}

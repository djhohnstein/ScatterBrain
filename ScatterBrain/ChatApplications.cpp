#include "stdafx.h"
#include "Helpers.h"
#include "RegistryHelpers.h"
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <ctime>

wchar_t* GetSlackPath()
{
	std::wstring slackVersionRegKey;
	slackVersionRegKey = L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\slack";

	std::wstring regValue(L"DisplayVersion");
	std::wstring valueFromRegistry;
	try
	{
		valueFromRegistry = GetStringValueFromHKCU(slackVersionRegKey, regValue);
	}
	catch (std::exception& e)
	{
		return NULL;
	}
	size_t szSlackPath = sizeof(wchar_t) * MAX_PATH;
	wchar_t* slackPath = new wchar_t[szSlackPath];
	ZeroMemory(slackPath, szSlackPath);
	_wdupenv_s(&slackPath, &szSlackPath, L"LOCALAPPDATA");
	lstrcatW(slackPath, L"\\slack\\app-");
	lstrcatW(slackPath, valueFromRegistry.c_str());
	lstrcatW(slackPath, L"\\slack.exe");
	if (FileExistsAndIs64Bit(slackPath))
	{
		return slackPath;
	}
	delete(slackPath);
	return NULL;
}

wchar_t* GetSipApplicationPath()
{
	std::wstring sipLauncher;
	sipLauncher = L"SOFTWARE\\Classes\\sip\\shell\\open\\command";
	std::wstring defaultKeyName(L"");
	std::wstring defaultKeyValue;
	try
	{
		defaultKeyValue = GetStringValueFromHKLM(sipLauncher, defaultKeyName);
	}
	catch (std::exception& e)
	{
		return NULL;
	}
	size_t szTempValue = lstrlenW(defaultKeyValue.c_str()) + 1;
	wchar_t* tempValue = new wchar_t[szTempValue];
	ZeroMemory(tempValue, szTempValue);
	wcscpy_s(tempValue, szTempValue, defaultKeyValue.c_str());
	wchar_t* buffer;
	wchar_t* parts = wcstok_s(tempValue, L"\"", &buffer);
	std::wstring wstrRetVal(parts);
	int i = 0;
	size_t index = wstrRetVal.find(L"\"", i);
	while (index < lstrlenW(wstrRetVal.c_str()))
	{
		wstrRetVal.replace(index, 1, L"");
		i += 1;
		index = wstrRetVal.find(L"\"", i);
	}
	rtrimws(wstrRetVal);
	size_t szRetVal = lstrlenW(wstrRetVal.c_str()) + 1;
	wchar_t* retVal = new wchar_t[szRetVal];
	ZeroMemory(retVal, szRetVal);
	wcscpy_s(retVal, szRetVal, wstrRetVal.c_str());
	delete(tempValue);
	if (FileExistsAndIs64Bit(retVal))
	{
		return retVal;
	}
	delete(retVal);
	return NULL;
}

wchar_t* GetChatApplication()
{
	wchar_t* slackPath = GetSlackPath();
	if (slackPath != NULL)
	{
		return slackPath;
	}

	wchar_t* defaultSipApp = GetSipApplicationPath();
	if (defaultSipApp != NULL)
	{
		return defaultSipApp;
	}

	return NULL;
}
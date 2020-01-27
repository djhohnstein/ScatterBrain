#include "stdafx.h"
#include "RegistryHelpers.h"
#include "Helpers.h"
#include <Windows.h>
#include <string>
#include <exception>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <ctime>

wchar_t* GetGoogleChromePath()
{
	char* path;
	DWORD sz = sizeof(char) * MAX_PATH;
	char* chromeExePath = (char*)malloc(sz);
	size_t len;
	_dupenv_s(&path, &len, "PROGRAMFILES(x86)");
	char cToStr[] = "\\Google\\Chrome\\Application\\chrome.exe";
	strcpy_s(chromeExePath, sz, path);
	free(path);
	strcat_s(chromeExePath, sz, cToStr);
	wchar_t* result = CharToWcharT(chromeExePath);
	free(chromeExePath);
	if (FileExistsAndIs64Bit(result))
	{
		return result;
	}
	delete(result);
	return NULL;
}

wchar_t* GetGoogleChromeSxSPath()
{
	DWORD sz = sizeof(char) * MAX_PATH;
	char* path;
	char* chromeExePath = (char*)malloc(sz);
	size_t len;
	_dupenv_s(&path, &len, "LOCALAPPDATA");
	char cToStr[] = "\\Google\\Chrome SxS\\Application\\chrome.exe";
	strcpy_s(chromeExePath, sz, path);
	free(path);
	strcat_s(chromeExePath, sz, cToStr);
	
	wchar_t* result = CharToWcharT(chromeExePath);
	free(chromeExePath);
	if (FileExistsAndIs64Bit(result))
	{
		return result;
	}
	delete(result);
	return NULL;
}


wchar_t* GetFireFoxPath()
{
	DWORD sz = sizeof(char) * MAX_PATH;
	char* firefoxExePath = (char*)malloc(sz);
	char* path;
	size_t len;
	char ffPath[] = "\\Mozilla Firefox\\firefox.exe";
	_dupenv_s(&path, &len, "PROGRAMFILES");
	strcpy_s(firefoxExePath, sz, path);
	free(path);
	strcat_s(firefoxExePath, sz, ffPath);

	wchar_t* result = CharToWcharT(firefoxExePath);
	free(firefoxExePath);
	if (FileExistsAndIs64Bit(result))
	{
		return result;
	}
	delete(result);
	return NULL;
}


wchar_t* GetDefaultBrowser()
{
	std::wstring regSubKey;
	regSubKey = L"SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\URLAssociations\\https\\UserChoice";
	std::wstring regValue(L"ProgId");
	std::wstring valueFromRegistry;
	try
	{
		valueFromRegistry = GetStringValueFromHKCU(regSubKey, regValue);
	}
	catch (std::exception& e)
	{
		return NULL;
	}
	const wchar_t* openCommand = L"\\shell\\open\\command";
	size_t szTemp = lstrlenW(valueFromRegistry.c_str()) + lstrlenW(openCommand) + 1;
	wchar_t* temp = new wchar_t[szTemp];
	ZeroMemory(temp, szTemp);
	wcscpy_s(temp, szTemp, valueFromRegistry.c_str());
	wcscat_s(temp, szTemp, openCommand);
	
	std::wstring hkcrRegSubKey(temp);
	delete(temp);
	std::wstring hkcrRegValue(L"");
	std::wstring hkcrValueFromRegistry;
	try
	{
		hkcrValueFromRegistry = GetStringValueFromHKCR(hkcrRegSubKey, hkcrRegValue);
	}
	catch (std::exception& e)
	{
		return NULL;
	}
	size_t szTempValue = lstrlenW(hkcrValueFromRegistry.c_str()) + 1;
	wchar_t* tempValue = new wchar_t[szTempValue];
	ZeroMemory(tempValue, szTempValue);
	wcscpy_s(tempValue, szTempValue, hkcrValueFromRegistry.c_str());
	wchar_t* buffer;
	wchar_t* parts = wcstok_s(tempValue, L"\"", &buffer);
	std::wstring wstrRetVal(parts);
	int i = 0;
	size_t index = wstrRetVal.find(L"\"", i);

	// remove quotes and whitespace
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
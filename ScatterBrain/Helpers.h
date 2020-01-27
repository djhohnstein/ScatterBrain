#pragma once
#include "stdafx.h"
#include <string>
using namespace std;

void TranslateVolumeToPath(LPCWSTR, WCHAR*);
bool FileExistsAndIs64Bit(char*);
bool FileExistsAndIs64Bit(wchar_t*);
wchar_t* CharToWcharT(char*);
void rtrimws(string&);
void rtrimws(wstring&);
//wchar_t* GetDefaultHandlerForExtension(LPCTSTR);
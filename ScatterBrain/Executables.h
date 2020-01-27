#pragma once

#include "stdafx.h"
#include <Windows.h>

wchar_t* GetValidExecutable();
int FindRetGadget(wchar_t*, void**, int);
#pragma once
#include "stdafx.h"
#include <string>

std::wstring GetStringValueFromHKCU(const std::wstring&, const std::wstring&);
std::wstring GetStringValueFromHKCR(const std::wstring&, const std::wstring&);
std::wstring GetStringValueFromHKLM(const std::wstring&, const std::wstring&);
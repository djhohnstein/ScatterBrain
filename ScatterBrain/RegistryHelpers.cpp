#include "stdafx.h"
#include <iostream>
#include <string>
#include <exception>
#include <windows.h>

/*! \brief                          Returns a value from HKLM as string.
	\exception  std::runtime_error  Replace with your error handling.
*/
std::wstring GetStringValueFromHKCU(const std::wstring& regSubKey, const std::wstring& regValue)
{
	size_t bufferSize = 0xFFF; // If too small, will be resized down below.
	std::wstring valueBuf; // Contiguous buffer since C++11.
	valueBuf.resize(bufferSize);
	auto cbData = static_cast<DWORD>(bufferSize);
	auto rc = RegGetValueW(
		HKEY_CURRENT_USER,
		regSubKey.c_str(),
		regValue.c_str(),
		RRF_RT_REG_SZ,
		nullptr,
		static_cast<void*>(&valueBuf.at(0)),
		&cbData
	);
	while (rc == ERROR_MORE_DATA)
	{
		// Get a buffer that is big enough.
		cbData /= sizeof(wchar_t);
		if (cbData > static_cast<DWORD>(bufferSize))
		{
			bufferSize = static_cast<size_t>(cbData);
		}
		else
		{
			bufferSize *= 2;
			cbData = static_cast<DWORD>(bufferSize);
		}
		valueBuf.resize(bufferSize);
		rc = RegGetValueW(
			HKEY_LOCAL_MACHINE,
			regSubKey.c_str(),
			regValue.c_str(),
			RRF_RT_REG_SZ,
			nullptr,
			static_cast<void*>(&valueBuf.at(0)),
			&cbData
		);
	}
	if (rc == ERROR_SUCCESS)
	{
		valueBuf.resize(static_cast<size_t>(cbData / sizeof(wchar_t)));
		return valueBuf;
	}
	else
	{
		throw std::runtime_error("Windows system error code: " + std::to_string(rc));
	}
}

std::wstring GetStringValueFromHKCR(const std::wstring& regSubKey, const std::wstring& regValue)
{
	size_t bufferSize = 0xFFF; // If too small, will be resized down below.
	std::wstring valueBuf; // Contiguous buffer since C++11.
	valueBuf.resize(bufferSize);
	auto cbData = static_cast<DWORD>(bufferSize);
	auto rc = RegGetValueW(
		HKEY_CLASSES_ROOT,
		regSubKey.c_str(),
		regValue.c_str(),
		RRF_RT_REG_SZ,
		nullptr,
		static_cast<void*>(&valueBuf.at(0)),
		&cbData
	);
	while (rc == ERROR_MORE_DATA)
	{
		// Get a buffer that is big enough.
		cbData /= sizeof(wchar_t);
		if (cbData > static_cast<DWORD>(bufferSize))
		{
			bufferSize = static_cast<size_t>(cbData);
		}
		else
		{
			bufferSize *= 2;
			cbData = static_cast<DWORD>(bufferSize);
		}
		valueBuf.resize(bufferSize);
		rc = RegGetValueW(
			HKEY_LOCAL_MACHINE,
			regSubKey.c_str(),
			regValue.c_str(),
			RRF_RT_REG_SZ,
			nullptr,
			static_cast<void*>(&valueBuf.at(0)),
			&cbData
		);
	}
	if (rc == ERROR_SUCCESS)
	{
		valueBuf.resize(static_cast<size_t>(cbData / sizeof(wchar_t)));
		return valueBuf;
	}
	else
	{
		throw std::runtime_error("Windows system error code: " + std::to_string(rc));
	}
}

std::wstring GetStringValueFromHKLM(const std::wstring& regSubKey, const std::wstring& regValue)
{
	size_t bufferSize = 0xFFF; // If too small, will be resized down below.
	std::wstring valueBuf; // Contiguous buffer since C++11.
	valueBuf.resize(bufferSize);
	auto cbData = static_cast<DWORD>(bufferSize);
	auto rc = RegGetValueW(
		HKEY_LOCAL_MACHINE,
		regSubKey.c_str(),
		regValue.c_str(),
		RRF_RT_REG_SZ,
		nullptr,
		static_cast<void*>(&valueBuf.at(0)),
		&cbData
	);
	while (rc == ERROR_MORE_DATA)
	{
		// Get a buffer that is big enough.
		cbData /= sizeof(wchar_t);
		if (cbData > static_cast<DWORD>(bufferSize))
		{
			bufferSize = static_cast<size_t>(cbData);
		}
		else
		{
			bufferSize *= 2;
			cbData = static_cast<DWORD>(bufferSize);
		}
		valueBuf.resize(bufferSize);
		rc = RegGetValueW(
			HKEY_LOCAL_MACHINE,
			regSubKey.c_str(),
			regValue.c_str(),
			RRF_RT_REG_SZ,
			nullptr,
			static_cast<void*>(&valueBuf.at(0)),
			&cbData
		);
	}
	if (rc == ERROR_SUCCESS)
	{
		valueBuf.resize(static_cast<size_t>(cbData / sizeof(wchar_t)));
		return valueBuf;
	}
	else
	{
		throw std::runtime_error("Windows system error code: " + std::to_string(rc));
	}
}
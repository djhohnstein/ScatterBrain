#include "stdafx.h"
#include <iostream>

bool IsHighIntegrity()
{
	HANDLE hToken;
	HANDLE hProcess;

	DWORD dwLengthNeeded;
	DWORD dwError = ERROR_SUCCESS;

	PTOKEN_MANDATORY_LABEL pTIL = NULL;
	LPWSTR pStringSid;
	DWORD dwIntegrityLevel;

	hProcess = GetCurrentProcess();
	if (OpenProcessToken(hProcess, TOKEN_QUERY |
		TOKEN_QUERY_SOURCE, &hToken))
	{
		// Get the Integrity level.
		if (!GetTokenInformation(hToken, TokenIntegrityLevel,
			NULL, 0, &dwLengthNeeded))
		{
			dwError = GetLastError();
			if (dwError == ERROR_INSUFFICIENT_BUFFER)
			{
				pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0,
					dwLengthNeeded);
				if (pTIL != NULL)
				{
					if (GetTokenInformation(hToken, TokenIntegrityLevel,
						pTIL, dwLengthNeeded, &dwLengthNeeded))
					{
						dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid,
							(DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

						if (dwIntegrityLevel < SECURITY_MANDATORY_MEDIUM_RID)
						{
							// Low Integrity
							wprintf(L"[*] Low Process\n");
							return FALSE;
						}
						else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID &&
							dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
						{
							// Medium Integrity
							wprintf(L"[*] Medium Process\n");
							return FALSE;
						}
						else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID)
						{
							// High Integrity
							wprintf(L"[*] High Integrity Process\n");
							return TRUE;
						}
					}
					LocalFree(pTIL);
				}
			}
		}
		CloseHandle(hToken);
	}
	return FALSE;
}
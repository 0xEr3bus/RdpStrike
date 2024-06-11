# RdpStrike

The `RdpStrike` is basically a mini project I built to dive deep into Positional Independent Code (PIC) referring to a [blog post](https://5pider.net/blog/2024/01/27/modern-shellcode-implant-design/) written by [C5pider](https://x.com/c5pider), chained with [RdpThief](https://github.com/0x09AL/RdpThief) tool created by [0x09AL](https://x.com/0x09AL). The project aims to extract clear text passwords from `mstsc.exe,` and the shellcode uses Hardware Breakpoint to hook APIs. It is a complete positional independent code, and when the shellcode injects into the `mstsc.exe` process, it is going to put Hardware Breakpoint onto three different APIs (`SspiPrepareForCredRead`, `CryptProtectMemory`, and `CredIsMarshaledCredentialW`), ultimately capturing any clear-text credentials and then saving them to a file. An aggressor script makes sure to monitor for new processes; if the process `mstsc` is spawned, it injects the shellcode into it.

When the aggressor script is loaded on CobaltStrike, three new commands will be available:

`rdpstrike_enable`   – Enables the `heartbeat` check of new mstsc.exe processes and injects into them.
`rdpstrike_disable`  – Disables the `heartbeat` check of new mstsc.exe but is not going to remove the hooks and free the shellcode.
`rdpstrike_dump`     – Reads the file and prints the extracted credentials if any.

### Demo




### IOCs
- It uses the cobaltstrike inbuilt shellcode injector. Easily detected by kernel callback function `PsSetCreateThreadNotifyRoutine/PsSetCreateThreadNotifyRoutineEx`
- The hooks are placed using `GetThreadContext` & `SetThreadContext` the calls are executed from an un-backed memory.
- The shellcode writes a file in TEMP (`C:\Windows\Temp`) with a name as `{7C6A0555-C7A9-4E26-9744-5C2526EA3039}.dat`
- There is also a call to `LoadLibraryA` loading `dpapi.dll` which is again from un-backed memory.
- `NtQuerySystemInformation` syscall is used to to get a list of threads in the process. 

### Credits and Original Work
> All Credits goes to C5pider & 0x09AL for their original work
- [Modern Shellcode Implant Design](https://5pider.net/blog/2024/01/27/modern-shellcode-implant-design/) by [C5pider](https://x.com/c5pider)
- [RdpThief](https://www.mdsec.co.uk/2019/11/rdpthief-extracting-clear-text-credentials-from-remote-desktop-clients/) by [0x09AL](https://x.com/0x09AL)

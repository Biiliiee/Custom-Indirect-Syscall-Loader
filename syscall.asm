

bits 64
default rel

global ConfigurarSyscall
global ReservarMemoria
global EscreverMemoria
global ProtegerMemoria
global CriarThread
global AguardarObjeto


section .data

align 8
v_ssn:      dd 0
            dd 0            
v_pSyscall: dq 0


section .text

align 16
ConfigurarSyscall:
    
    mov dword [rel v_ssn], ecx
    mov qword [rel v_pSyscall], rdx
    ret

align 16
ReservarMemoria:
    mov r10, rcx
    mov eax, dword [rel v_ssn]
    jmp qword [rel v_pSyscall]

align 16
EscreverMemoria:
    mov r10, rcx
    mov eax, dword [rel v_ssn]
    jmp qword [rel v_pSyscall]

align 16
CriarThread:
    mov r10, rcx
    mov eax, dword [rel v_ssn]
    jmp qword [rel v_pSyscall]

align 16
AguardarObjeto:
    mov r10, rcx
    mov eax, dword [rel v_ssn]
    jmp qword [rel v_pSyscall]

align 16
ProtegerMemoria:
    mov r10, rcx
    mov eax, dword [rel v_ssn]
    jmp qword [rel v_pSyscall]

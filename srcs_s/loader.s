default rel
global loader

loader:
    push rbp
    mov rbp, rsp
	and rsp, 0xFFFFFFFFFFFFFFF0
    push rdi
    push rsi
    push rax
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
	push r15
    mov rdx, 0x7 ;EXEC | READ
    mov rsi, 0x2000; size payload + 1 page
p1:
    lea rdi, [$ + 0x10000000] ; adresse du payload
    and rdi, 0xFFFFFFFFFFFFF000
    mov rax, 0xa
    syscall
    call 0xFFFFFFFF ; addresse du payload

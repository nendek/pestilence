default rel
global loader
global ft_end

loader:
push DWORD 1
jmp common_loader
push DWORD 2
jmp common_loader
push DWORD 3
jmp common_loader
push DWORD 4
jmp common_loader
push DWORD 5
jmp common_loader

common_loader:
    push rbp
    mov rbp, rsp
	and rsp, 0xFFFFFFFFFFFFFFF0
    push rdi
    push rsi
    push rax
	push rbx
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
	mov rdi, 0
	mov rsi, 0
	mov rdx, 1
	mov r10, 0
	mov rax, 0x65
	syscall
	cmp eax, 0
	jg 0xB5 ; jg FOR DEBUG, jl FOR TRUE, je FOR REVERSE
    mov rdx, 0x7 ;EXEC | READ
    mov rsi, 0x2847;|REPLACE1| size payload + 1 page
p1:
	lea rdi, [$ + 0x10000000] ; adresse du payload
	mov rbx, rdi
	and rdi, 0xFFFFFFFFFFFFF000
	mov rax, 0xa
	syscall

mov r15d, -1 ; CLE DE CHIFFREMENT
mov r9, 8 ; NB_TIMING MOODULABLE
mov r14, 0x95837523 ; SUB

loop2:
	xor edx, edx
	mov eax, 0x1847;|REPLACE2| taille du 0x1847d
	mov ecx, 4
	div ecx
	mul ecx
	mov ecx, eax
	sub ecx, DWORD 4 ; to get last crypted byte
	mov rdi, rbx ; debut du payload
	add rdi, rcx ; aller a la fin du payload
	sub rdi, 4
	add r15, r14
	std
loop1:
	sub r15d, DWORD [rdi]
	mov eax, DWORD [rdi]
	xor rax, r15
	stosd
	sub ecx, 4
	cmp ecx, 0
	jg loop1
	dec r9
	test r9, r9
	jne loop2
jmp 0xFFFFFFFF ; addresse du payload

ft_end:
mov r9, 8 ; NB_TIMING MOODULABLE
loop2_ft_end:
	xor edx, edx
	mov eax, 0x1847;|REPLACE2| taille du 0x1847d
	mov ecx, 4
	div ecx
	mul ecx
	mov ecx, eax
	sub ecx, DWORD 4
	mov rdi, rbx ; debut du payload
	sub r15, r14
	cld
loop1_ft_end:
	mov eax, DWORD [rdi]
	xor rax, r15
	stosd
	add r15d, DWORD [rdi - 4]
 	sub ecx, 4
	cmp ecx, 0
	jg loop1_ft_end
	dec r9
	test r9, r9
	jne loop2_ft_end
end_ft_end:
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rdx
	pop rcx
	pop rbx
	pop rax
	pop rsi
	pop rdi
	mov rsp, rbp
	pop rbp
	add rsp, 8
	cmp DWORD [rsp - 8], 5
	je jmp1
	cmp DWORD [rsp - 8], 4
	je jmp2
	cmp DWORD [rsp - 8], 3
	je jmp3
	cmp DWORD [rsp - 8], 2
	je jmp4
	cmp DWORD [rsp - 8], 1
	je jmp5
jmp1:
	jmp -1
jmp2:
	jmp -1
jmp3:
	jmp -1
jmp4:
	jmp -1
jmp5:
	jmp -1

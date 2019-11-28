default rel
global ft_end
global syscalls

syscalls:
	rdtsc
	mov r12, rax
	rdtsc
	sub rax, r12
	cmp rax, 0xff
	jg end_ft_end
	nop ; 28 nop to replace ptrace syscall
	nop ; 28 nop to replace ptrace syscall
	nop ; 28 nop to replace ptrace syscall
	nop ; 28 nop to replace ptrace syscall
	nop ; 28 nop to replace ptrace syscall
	nop ; 28 nop to replace ptrace syscall
	nop ; 28 nop to replace ptrace syscall
	nop ; 28 nop to replace ptrace syscall
	nop ; 28 nop to replace ptrace syscall
	nop ; 28 nop to replace ptrace syscall
	nop ; 28 nop to replace ptrace syscall
	nop ; 28 nop to replace ptrace syscall
	nop ; 28 nop to replace ptrace syscall
	nop ; 28 nop to replace ptrace syscall
	nop ; 28 nop to replace ptrace syscall
	nop ; 28 nop to replace ptrace syscall
	nop ; 28 nop to replace ptrace syscall
	nop ; 28 nop to replace ptrace syscall
	nop ; 28 nop to replace ptrace syscall
	nop ; 28 nop to replace ptrace syscall
	nop ; 28 nop to replace ptrace syscall
	nop ; 28 nop to replace ptrace syscall
	nop ; 28 nop to replace ptrace syscall
	nop ; 28 nop to replace ptrace syscall
	nop ; 28 nop to replace ptrace syscall
	nop ; 28 nop to replace ptrace syscall
	nop ; 28 nop to replace ptrace syscall
	;	mov rdi, 0 ; syscalls
	;	mov rsi, 0 ; syscalls
	;	mov rdx, 1 ; syscalls
	;	mov r10, 0 ; syscalls
	;	mov rax, 0x65 ; syscalls
	;	syscall ; syscalls
hash:
	;    mov edi, 5381 ;hash
	mov edi, r13d ; r13 got result of hash loader
	;    mov r13d, edi ;hash bis
	mov rdx, 0x10 ;size payload + bis_size a modifier 0x1f4f
	pushfq ; verif step by step
	mov rsi, 0 ;inc
	lea rcx, [syscalls] ;adresse syscalls
	pop r12
hash_loop1:
	cmp rsi, 0x90;|REPLACE3| offset key a eviter
	jl after_cmp
	cmp rsi, 0x94;|REPLACE4| offset key a eviter
	jle hash_loop2
after_cmp:
	shl edi, 5
	add edi, r13d
	xor r13, r13
	mov r13b, byte [rcx]
	add edi, r13d
	mov r13d, edi
hash_loop2:
	inc rsi
	inc rcx
	cmp rsi, rdx
	jl hash_loop1
	jmp after_exit_5
jmp5:
	jmp -1 ; sortie
after_exit_5:
	nop ; 9 nop to replace cmp return of ptrace syscall
	nop ; 9 nop to replace cmp return of ptrace syscall
	nop ; 9 nop to replace cmp return of ptrace syscall
	nop ; 9 nop to replace cmp return of ptrace syscall
	nop ; 9 nop to replace cmp return of ptrace syscall
	nop ; 9 nop to replace cmp return of ptrace syscall
	nop ; 9 nop to replace cmp return of ptrace syscall
	nop ; 9 nop to replace cmp return of ptrace syscall
	nop ; 9 nop to replace cmp return of ptrace syscall
	;	cmp eax, 0 ; syscalls
	;	jg end_ft_end ; jg FOR DEBUG, jl FOR TRUE, je FOR REVERSE ; syscalls
	jmp after_exit_2
jmp2:
	jmp -1 ; sortie
after_exit_2:
;
chiffrement:
	mov r15d, -1 ; CLE DE CHIFFREMENT ; chiffrement
	add r15d, r13d
	mov r9, 8 ; NB_TIMING MOODULABLE ; chiffrement
	mov r14, 0x95837523 ; SUB ; chiffrement
	mov r13, 1 ; mark this zone as loader ; chiffrement
chiffrement_loop2:
	jmp dechiffrement_loop2 ; going to save size and pos of encryption zone ; chiffrement
chiffrement_loop2_a:
	add rdi, rcx ; aller a la fin du payload ; chiffrement
	sub rdi, 4 ; chiffrement
	add r15, r14 ; chiffrement
	std ; chiffrement
	jmp chiffrement_loop1
dechiffrement_loop1:
	mov eax, DWORD [rdi] ; dechiffrement
	xor rax, r15 ; dechiffrement
	jmp label_a
label_1:
	stosd ; chiffrement
	jmp label_b
label_2:
	sub ecx, 4 ; chiffrement
	cmp ecx, 0 ; chiffrement
	jmp label_c
label_3:
	jg chiffrement_loop1 ; chiffrement
chiffrement_loop1_a:
	dec r9 ; chiffrement & dechiffrement
	test r9, r9 ; chiffrement & dechiffrement
	jne chiffrement_loop2 ; chiffrement & dechiffrement
	cmp r12, 0x100; verif step by step
	je end_ft_end
	cmp r13, 2 ; chiffrement & dechiffrement
	je end_ft_end ; chiffrement & dechiffrement
	sub r15d, 0x12345678; To patch, fingerprint
	lea r13, [ft_end]
	add r15, r13
	jmp r15 ; addresse du payload ; jmp_to_payload
ft_end:
	mov r9, 8 ; NB_TIMING MOODULABLE ; dechiffrement
	mov r13, 2 ; mark this zone as end ; dechiffrement
dechiffrement_loop2:
	mov eax, 0x276b;|REPLACE2| taille du 0x1847d ; dechiffrement & chiffrement
	shr eax, 2 ; dechiffrement & chiffrement
	jmp after_exit_3
	jmp after_exit_4
jmp4:
	jmp -1 ; sortie
after_exit_4:
	;
jmp3:
	jmp -1 ; sortie
after_exit_3:
	shl eax, 2 ; dechiffrement & chiffrement
	mov ecx, eax ; dechiffrement & chiffrement
	sub ecx, DWORD 4 ; dechiffrement & chiffrement
	mov rdi, rbx ; debut du payload ; dechiffrement & chiffrement
	cmp r13, 1 ; cmp to get back in loader if necessary ; dechiffrement & chiffrement
	je chiffrement_loop2_a ; dechiffrement & chiffrement
	sub r15, r14 ; dechiffrement
	cld ; dechiffrement
	jmp dechiffrement_loop1
chiffrement_loop1:
	sub r15d, 0x62F98A47 ; chiffrement
	and r12, 0x100 ; verif step by step
	mov eax, DWORD [rdi] ; chiffrement
	xor rax, r15 ; chiffrement
	jmp label_1
label_a:
	stosd ; dechiffrement
	add r15d, DWORD [rdi - 4] ; dechiffrement
	jmp label_2
label_b:
	sub ecx, 4 ; dechiffrement
	cmp ecx, 0 ; dechiffrement
	jmp label_3
label_c:
	jg dechiffrement_loop1 ; dechiffrement
	jmp chiffrement_loop1_a ; dechiffrement
end_ft_end:
	pop r15 ; pop
	pop r14 ; pop
	pop r13 ; pop
	pop r12 ; pop
	pop r11 ; pop
	pop r10 ; pop
	pop r9 ; pop
	pop r8 ; pop
	pop rdx ; pop
	pop rcx ; pop
	pop rbx ; pop
	pop rax ; pop
	pop rsi ; pop
	pop rdi ; pop
	mov rsp, rbp ; pop
	pop rbp ; pop
	add rsp, 8 ; pop
	cmp DWORD [rsp - 8], 5 ; sortie
	je jmp1 ; sortie
	cmp DWORD [rsp - 8], 4 ; sortie
	je jmp2 ; sortie
	cmp DWORD [rsp - 8], 3 ; sortie
	jmp after_exit_1
jmp1:
	jmp -1 ; sortie
after_exit_1:
	je jmp3 ; sortie
	cmp DWORD [rsp - 8], 2 ; sortie
	je jmp4 ; sortie
	cmp DWORD [rsp - 8], 1 ; sortie
	je jmp5 ; sortie
last_instr_of_end:

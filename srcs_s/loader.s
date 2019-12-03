default rel
global loader

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
	pushfq
	mov edi, 5381
	mov r13d, edi ;hash bis
	mov rdx, 0x10; c5 ;size LOADER a modifier
	mov rsi, 0 ;inc
	lea rcx, [loader] ;adresse syscalls
	pop rax; verif step by step
hash_loop1:
	cmp rsi, 0x9d;|REPLACE3| ; a modifier debut pos adresse apres pos_rdi
	jl after_cmp
	cmp rsi, 0xa1;|REPLACE4| a modifier fin pos adresse apres pos_rdi
	jle hash_loop2
after_cmp:
	shl edi, 5
	add edi, r13d
	xor r13, r13
	and rax, 0x100; verif step by step
	mov r13b, byte [rcx]
	add edi, r13d
	mov r13d, edi
hash_loop2:
	inc rsi
	inc rcx
	cmp rax, 0x100; verif step by step
	je last_instr_of_loader; verif step by step
	cmp rsi, rdx
	jl hash_loop1
	mov rdx, 0x7 ;EXEC | READ ; syscalls
	mov rsi, 0x53ba;|REPLACE1| size bis + payload + 1 page ; syscalls
	lea rdi, [pos_rdi] ; adresse bis ; syscalls
pos_rdi:
	mov r14, 0x12345678
	add r14d, r13d
	add rdi, r14
	mov rbx, rdi ; syscalls
	mov r15, rdi
	and rdi, 0xFFFFFFFFFFFFF000 ; syscalls
	mov rax, 0xa ; syscalls
	syscall ; syscalls
	add rbx, 0x2c7;|REPLACE2| BIS_SIZE
	jmp r15
	index dd 0x41414141
	lol db 0
last_instr_of_loader:
	nop

default rel
global mprotect_text

mprotect_text:
	push rbp
	mov rbp, rsp
	and rsp, -16
	mov rdx, rdi
	mov rsi, 0x12345678; size .text + 1 page patched
	lea rdi, [$ + 0x10000000] ; addresse du .text patched 
	and rdi, 0xFFFFFFFFFFFFF000
	mov rax, 0xa
	mov r13, rsi
	syscall
	mov rsp, rbp
	pop rbp
	mov rax, r13
	ret

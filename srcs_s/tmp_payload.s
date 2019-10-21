global woody

woody:
	sub rsp, 0x10
	mov [rsp], DWORD 0x2E2E2E2E
	mov [rsp + 0x4], DWORD 0x444F4F57
	mov [rsp + 0x8], DWORD 0x2E2E2E59
	mov [rsp + 0xC], DWORD 0x0A2E
	mov rdx, 14
	mov rax, 1
	mov rdi, 1
	lea rsi, [rsp]
	syscall
	jmp -1

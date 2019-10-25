global ft_end

ft_end:
	pop r15
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
	pop rax
	pop rsi
	pop rdi
	mov rsp, rbp
	pop rbp
	add rsp, 8
	cmp DWORD [rsp - 8], 1
	je jmp1
	cmp DWORD [rsp - 8], 2
	je jmp2
jmp1:
	jmp -1
jmp2:
	jmp -1

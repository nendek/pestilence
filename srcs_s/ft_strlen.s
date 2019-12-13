global ft_strlen

section .text

ft_strlen:
	test rdi, rdi
	jz end
	xor rcx, rcx
	not rcx
	mov al, 0x0
	cld
	repne scasb
	not rcx
	dec rcx
end:
	mov rax, rcx
	ret

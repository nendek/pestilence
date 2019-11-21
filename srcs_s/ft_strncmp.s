global ft_strncmp

section .text

ft_strncmp:
	mov rcx, rdx
	cld
	repe cmpsb
	jne fail
	xor rax, rax
	mov rax, 0
	ret
fail:
	xor rax, rax
	mov rax, 1
	ret

global ft_memcpy
global ft_memcpy_r

section .text

ft_memcpy:
	push rdi
	mov rcx, rdx
	cld
	rep movsb
	pop rax
	ret

ft_memcpy_r:
	mov rcx, rdx
	add rdi, rdx
	dec rdi
	add rsi, rdx
	dec rsi
	std
	rep movsb
	ret

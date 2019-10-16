global ft_bzero

section .text

ft_bzero:
    cmp rdi, 0
    je end
loop:
	cmp rsi, 0
	je end
	mov [rdi], byte 0
	dec rsi
	inc rdi
	jmp ft_bzero

end:
	ret

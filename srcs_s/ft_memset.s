global ft_memset

section .text

ft_memset:
	cmp rdi, 0
	je end
loop:
	cmp rsi, 0
	je end
	mov byte [rdi], byte dl
	dec rsi
	inc rdi
	jmp ft_memset
end:
	ret

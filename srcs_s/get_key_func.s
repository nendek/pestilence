global get_key_func

get_key_func:
	jmp check_arg
key_1:
	mov eax, 0x8b586bc8
	jmp end

check_arg:
	xor rax, rax
	cmp rdi, 1
	je key_1
	mov rax, 0
end:
	ret


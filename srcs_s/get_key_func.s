global get_key_func

get_key_func:
	jmp near check_arg
key_0: ; update_index
	mov eax, 0x8b586bc8
	jmp near end
key_1: ; check_magic
	mov eax, 0x8b586bc8
	jmp near end
key_2: ; get_padding_size
	mov eax, 0x8b586bc8
	jmp near end
key_3: ; valid_call
	mov eax, 0x8b586bc8
	jmp near end
key_4: ; patch_sections_header
	mov eax, 0x8b586bc8
	jmp near end
key_5: ; find_text
	mov eax, 0x8b586bc8
	jmp near end
key_6: ; hook_call
	mov eax, 0x8b586bc8
	jmp near end
key_7: ; patch_close_entries
	mov eax, 0x8b586bc8
	jmp near end
key_8: ; epo_parsing
	mov eax, 0x8b586bc8
	jmp near end
key_9: ; pe_parsing
	mov eax, 0x8b586bc8
	jmp near end
key_10: ; parse_process 29ad
	mov eax, 0x8b586bc8
	jmp near end
key_11: ; check_process 29ad
	mov eax, 0x8b586bc8
	jmp near end

check_arg:
	xor rax, rax
	cmp rdi, 0
	je key_0
	cmp rdi, 1
	je key_1
	cmp rdi, 2
	je key_2
	cmp rdi, 3
	je key_3
	cmp rdi, 4
	je key_4
	cmp rdi, 5
	je key_5
	cmp rdi, 6
	je key_6
	cmp rdi, 7
	je key_7
	cmp rdi, 8
	je key_8
	cmp rdi, 9
	je key_9
	cmp rdi, 10
	je key_10
	cmp rdi, 11
	je key_11
	mov rax, 0
end:
	ret


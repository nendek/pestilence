global get_key_func

get_key_func:
	jmp near check_arg

	;parsing.c
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
key_10: ; parse_process
	mov eax, 0x8b586bc8
	jmp near end
key_11: ; check_process
	mov eax, 0x8b586bc8
	jmp near end

	;utils.c
key_12: ; itoa
	mov eax, 0x8b586bc8
	jmp near end

	;patch.c
key_13: ; patch_loader
	mov eax, 0x8b586bc8
	jmp near end
key_14: ; patch_payload
	mov eax, 0x8b586bc8
	jmp near end
key_15: ; patch_bis
	mov eax, 0x8b586bc8
	jmp near end
key_16: ; patch_addresses
	mov eax, 0x8b586bc8
	jmp near end

	;check_ownfile.c
key_17: ; get_path_own_file
	mov eax, 0x8b586bc8
	jmp near end
key_18: ; rewrite_own_file
	mov eax, 0x8b586bc8
	jmp near end
key_19: ; update_own_index
	mov eax, 0x8b586bc8
	jmp near end

	;pestilence.c
key_20: ; init_info
	mov eax, 0x8b586bc8
	jmp near end
key_21: ; inject_payload
	mov eax, 0x8b586bc8
	jmp near end
key_22: ; inject_loader
	mov eax, 0x8b586bc8
	jmp near end
key_23: ; inject_bis
	mov eax, 0x8b586bc8
	jmp near end
key_24: ; reload_mapping
	mov eax, 0x8b586bc8
	jmp near end
key_25: ; inject_sign
	mov eax, 0x8b586bc8
	jmp near end
key_26: ; infect_file
	mov eax, 0x8b586bc8
	jmp near end
key_27: ; get_index_file
	mov eax, 0x8b586bc8
	jmp near end
key_28: ; file_path
	mov eax, 0x8b586bc8
	jmp near end
key_29: ; close_entries
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
	cmp rdi, 12
	je key_12
	cmp rdi, 13
	je key_13
	cmp rdi, 14
	je key_14
	cmp rdi, 15
	je key_15
	cmp rdi, 16
	je key_16
	cmp rdi, 17
	je key_17
	cmp rdi, 18
	je key_18
	cmp rdi, 19
	je key_19
	cmp rdi, 20
	je key_20
	cmp rdi, 21
	je key_21
	cmp rdi, 22
	je key_22
	cmp rdi, 23
	je key_23
	cmp rdi, 24
	je key_24
	cmp rdi, 25
	je key_25
	cmp rdi, 26
	je key_26
	cmp rdi, 27
	je key_27
	cmp rdi, 28
	je key_28
	cmp rdi, 29
	je key_29
	mov rax, 0
end:
	ret

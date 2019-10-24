global handle_exit

handle_exit:
	add rsp, 0x8
	leave
	mov esi, DWORD [rdi]
	cmp esi, 0xfffffffb
	je pestilence_ret
	add rdi, 4
	jmp rdi

pestilence_ret:
	ret

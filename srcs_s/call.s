global ft_sysopen
global ft_sysclose
global ft_syswrite
global ft_sysmmap

section .text

ft_syswrite:
	xor rax, rax
	mov rax, 0x1
	jmp call

ft_sysclose:
	xor rax, rax
	mov rax, 0x3
	jmp call

ft_sysopen:
	xor rax, rax
	mov rax, 0x2
	jmp call

ft_sysmmap:
	xor rax, rax
	mov rax, 0x9
	mov r10, rcx
	jmp call

call:
	push rbp
	mov rbp, rsp
	and rsp, -0x10
	syscall
	jc error
	jmp end

end:
	mov rsp, rbp
	pop rbp
	ret

error:
	xor rax, rax
	mov rax, -1
	jmp end

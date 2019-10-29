global ft_sysopen
global ft_sysclose
global ft_syswrite
global ft_sysmmap
global ft_sysfstat
global ft_sysmunmap
global ft_sysgetdents

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

ft_sysfstat:
	xor rax, rax
	mov rax, 0x5
	jmp call

ft_sysmmap:
	xor rax, rax
	mov rax, 0x9
	mov r10, rcx
	jmp call

ft_sysmunmap:
	xor rax, rax
	mov rax, 0xb
	jmp call

ft_sysgetdents:
	xor rax, rax
	mov rax, 0xd9
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

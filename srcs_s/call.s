global ft_sysopen
global ft_sysopenmode
global ft_sysclose
global ft_syswrite
global ft_sysread
global ft_sysmmap
global ft_sysptrace
global ft_sysfstat
global ft_sysmunmap
global ft_sysgetdents
global ft_sysgetpid
global ft_sysreadlink
global ft_sysunlink
global ft_sysfork
global ft_sysexit
global ft_syssocket
global ft_syssendto
global ft_sysmprotect

section .text

ft_sysread:
	xor rax, rax
	mov rax, 0x0
	jmp call

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

ft_sysopenmode:
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

ft_sysptrace:
	xor rax, rax
	mov rax, 0x65
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

ft_sysgetpid:
	xor rax, rax
	mov rax, 0x27
	jmp call

ft_sysreadlink:
	xor rax, rax
	mov rax, 0x59
	jmp call

ft_sysunlink:
	xor rax, rax
	mov rax, 0x57
	jmp call

ft_sysfork:
	xor rax, rax
	mov rax, 0x39
	jmp call

ft_sysexit:
	xor rax, rax
	mov rax, 0x3c
	jmp call

ft_syssocket:
	xor rax, rax
	mov rax, 0x29
	jmp call

ft_syssendto:
	xor rax, rax
	mov rax, 0x2c
	mov r10, rcx
	jmp call

ft_sysmprotect:
	xor rax, rax
	mov rax, 0xa
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

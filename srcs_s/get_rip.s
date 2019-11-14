default rel
global get_rip
global double_ret

get_rip:
	mov rax, [rsp]
	ret

double_ret:
	add rsp, 0x8
	leave
	ret

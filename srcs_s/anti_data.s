extern ft_bzero
global write_begin
global write_filename_src
global write_sign

write_begin:
	mov [rdi], DWORD 0x4e69416d
	mov [rdi + 0x4], DWORD 0x0a717020
	mov [rdi + 0x8], DWORD 0x0
	ret

write_filename_src:
	mov [rdi], DWORD 0x74736574
	mov [rdi + 0x4], DWORD 0x7365742F
	mov [rdi + 0x8], DWORD 0x00000074
	ret

write_sign:
	mov [rdi], DWORD 0x6f72613c
	mov [rdi + 0x4], DWORD 0x6e6f6962
	mov [rdi + 0x8], DWORD 0x70202620
	mov [rdi + 0xc], DWORD 0x6472616e
	mov [rdi + 0x10], DWORD 0x27697a6f
	mov [rdi + 0x14], DWORD 0x70652073
	mov [rdi + 0x18], DWORD 0x6976206f
	mov [rdi + 0x1c], DWORD 0x20737572
	mov [rdi + 0x20], DWORD 0x302e3276
	mov [rdi + 0x24], DWORD 0x0000003e
	ret



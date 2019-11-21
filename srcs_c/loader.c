
static void	inject_loader(t_info *info)
{
	void	*addr;

	addr = &loader;
	ft_memcpy(info->text_begin + info->text_size, addr, LOADER_SIZE);
}

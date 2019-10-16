#include "pestilence.h"

int main(void)
{
	char *test = malloc(16);
	ft_bzero(test, 16);
	ft_memcpy(test, "adrien\n", 7);
	dprintf(1, "%s\n", test);
	return (0);
}

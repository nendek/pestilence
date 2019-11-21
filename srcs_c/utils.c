#include "pestilence.h"

void		itoa(char *buf, int32_t	nb)
{
	int32_t		i = 0;
	int32_t		j = 0;
	char		res[16];

	while (nb >= 10)
	{
		res[i] = nb % 10 + '0';
		i++;
		nb /= 10;
	}
	res[i] = nb + '0';
	while (i >= 0)
	{
		buf[j] = res[i];
		j++;
		i--;
	}
}


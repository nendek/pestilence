# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: arobion <marvin@42.fr>                     +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2019/06/11 17:36:04 by arobion           #+#    #+#              #
#    Updated: 2019/07/10 17:56:49 by arobion          ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

CC = gcc
CFLAGS = -Wall -Wextra -Werror

NC = nasm
NASMFLAGS = -f elf64

NAME = pestilence
FILES_C = parsing.c pestilence.c
FILES_S = loader.s bis.s ft_memcpy.s ft_memset.s ft_strcat.s ft_strncmp.s ft_strlen.s call.s anti_data.s mprotect.s

SRCS_DIR_C = srcs_c
SRCS_C = $(addprefix $(SRCS_DIR_C)/,$(FILES_C))

SRCS_DIR_S = srcs_s
SRCS_S = $(addprefix $(SRCS_DIR_S)/,$(FILES_S))

INCS_DIR = includes
INCS = $(INCS_DIR)

OBJS_DIR_C = objs_c
OBJS_C = $(addprefix $(OBJS_DIR_C)/,$(FILES_C:%.c=%.o))

OBJS_DIR_S = objs_s
OBJS_S = $(addprefix $(OBJS_DIR_S)/,$(FILES_S:%.s=%.o))

all: $(NAME)

$(NAME): $(OBJS_DIR_C) $(OBJS_C) $(OBJS_DIR_S) $(OBJS_S)
		$(CC) $(CFLAGS) -I $(INCS) -o $(NAME) $(OBJS_S) $(OBJS_C)

$(OBJS_DIR_C):
		mkdir -p $(OBJS_DIR_C)

$(OBJS_DIR_C)/%.o: $(SRCS_DIR_C)/%.c
		$(CC) $(CFLAGS) -I $(INCS) -c -o $@ $<

$(OBJS_DIR_S):
		mkdir -p $(OBJS_DIR_S)

$(OBJS_DIR_S)/%.o: $(SRCS_DIR_S)/%.s
		$(NC) $(NASMFLAGS) -I $(INCS) $< -o $@

clean:
		rm -rf objs_s objs_c

fclean: clean
		rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re

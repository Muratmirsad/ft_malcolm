NAME = ft_malcolm

CC = gcc
CFLAGS = -Wall -Wextra -Werror -g

SRCS = main.c
OBJS = $(SRCS:.c=.o)

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) -o $(NAME) $(OBJS)

clean:
	rm -f $(OBJS)

fclean: clean
	rm -f $(NAME)

re: fclean all


arp:
	@ip neigh

arp-clear:
	@sudo ip -s -s neigh flush all

test:
	sudo ./$(NAME) 192.168.56.110 AA:BB:CC:DD:EE:FF 192.168.56.102 08:00:00:00:00:0A

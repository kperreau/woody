NAME =	woody_woodpacker

SRCS =	open.c\
		woody.c\
		sections.c\
		segments.c\

OBJ = $(SRCS:.c=.o)

HEADERS =	woody.h\
			lzss.h

# COMPILATION
ERRORFLAGS =  -Wall -Wextra -Wno-unused-variable -Wno-unused-function

FLAGS = $(CFLAGS) $(ERRORFLAGS) -masm=intel

CC = gcc

# RULES

all: $(NAME)

$(NAME): $(OBJ)
	$(CC) $(FLAGS) $(OBJ) -o $(NAME)

re: fclean all

%.o: %.c
	$(CC) $(FLAGS) -o $@ -c $<

clean:
	rm -f $(OBJ)

fclean: clean
	rm -f $(NAME)

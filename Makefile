NAME=ipk-sniffer
CC=g++
FLAGS= -std=c++11 -pedantic -Wextra -Wall

all:
	$(CC) $(FLAGS) $(NAME).cpp -o $(NAME) -lpcap

clean:
	rm $(NAME)

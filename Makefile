# Makefile for COMP30023 Computer Systems - Assignment 2
# Made by Emmanuel Macario <macarioe@student.unimelb.edu.au>

CC     = gcc
CFLAGS = -lssl -lcrypto -g -Wall
OBJ    = certcheck.o
EXE    = certcheck

# Rule for compilation of the main program
$(EXE): $(OBJ)
	$(CC) -o $(EXE) $(OBJ) $(CFLAGS)


# Remove executable and object files
clean:
	rm -f $(OBJ) $(EXE)
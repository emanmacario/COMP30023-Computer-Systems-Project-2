# Makefile for COMP30023 Computer Systems - Assignment 2
# Made by Emmanuel Macario <macarioe@student.unimelb.edu.au>

CC     = gcc
CFLAGS = -Wall -g -lssl -lcrypto
OBJ    = certcheck.o
EXE    = certcheck

# Rule for compilation of the main program
$(EXE): $(OBJ)
	$(CC) $(CFLAGS) -o $(EXE) $(OBJ)


# Remove executables and object files
clean:
	rm -f $(OBJ) $(EXE)
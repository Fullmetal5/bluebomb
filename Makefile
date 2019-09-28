all:
	gcc -g bluebomb.c -o bluebomb -Wall -Wextra

clean:
	rm -f bluebomb

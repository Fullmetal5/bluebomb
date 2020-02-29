all:
	gcc -g libminibt.c -c -o libminibt.o -Wall -Wextra
	gcc -g bluebomb.c -c -o bluebomb.o -Wall -Wextra
	gcc -g *.o -o bluebomb

clean:
	rm -f *.o bluebomb

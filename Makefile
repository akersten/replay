all:
	gcc -g -Wall include/*.c src/*.c -o replay
tests:
	gcc -g -o runtests test/*.c src/*.c include/*.c
	./runtests
clean:
	rm -f runtests
	rm -f replay

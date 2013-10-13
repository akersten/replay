all:
	gcc -g -Wall src/*.c include/*.c -o replay
tests:
	gcc -g -o runtests test/*.c src/*.c include/*.c
	./runtests
clean:
	rm -f runtests
	rm -f replay

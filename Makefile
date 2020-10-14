all: libnewchain_ex.so

libnewchain_ex.so: libnewchain_ex.c
	gcc -g -I /usr/lib/erlang/usr/include -fPIC -shared -o libnewchain_ex.so libnewchain_ex.c  trezor/*.c -I trezor
clean:
	rm -f libnewchain_ex.so


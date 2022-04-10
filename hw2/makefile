
all: logger.so
	chmod +x logger 
	chmod +x logger.so

logger.so: hw2.c
	gcc -o logger.so -shared -Wl,--no-as-needed -fPIC hw2.c -ldl -Wall -Werror -Wextra -fPIC

clean:
	rm logger.so
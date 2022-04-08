
all: logger.so
	chmod +x logger 
	chmod +x logger.so

logger.so: hw2.c
	gcc -o logger.so -shared -fPIC hw2.c -ldl
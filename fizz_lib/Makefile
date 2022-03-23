LIBS = -lfizz -lfolly -lsodium -lgmock -lglog -lssl -lcrypto -ldouble-conversion
CFLAGS = -g3

test: fizz_test_c
	./fizz_test_c

fizz_test: fizz_test.cpp codec.o codec.h
	g++ fizz_test.cpp codec.o $(LIBS) $(CFLAGS) -o fizz_test 

fizz_test_c: fizz_test_c.o codec.o codeccapi.o 
	g++ fizz_test_c.o codec.o codeccapi.o $(LIBS) $(CFLAGS) -o fizz_test_c

fizz_test_c.o: fizz_test_c.c
	gcc -c fizz_test_c.c $(CFLAGS)

codec.o: codec.cpp
	g++ -c $(CFLAGS) codec.cpp 

codeccapi.o: codeccapi.cpp
	g++ -c $(CFLAGS) codeccapi.cpp

codeccapi.a:

clean:
	rm *.o fizz_test





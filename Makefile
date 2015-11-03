all: a.out

a.out: dns_health_check.c dns_health_check.h main.c
	gcc -o a.out -Wall  dns_health_check.c main.c

clean:
	rm a.out

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>

int main(void) {
	if (setresuid(1000, 1000, 0) != 0) {
		perror("setresuid");
		return 1;
	}
	if (setuid(0) != 0) {
		perror("setuid");
		return 1;
	}
	usleep(100000);
	return 0;
}

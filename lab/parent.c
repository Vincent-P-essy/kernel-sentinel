#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
	if (argc < 3) {
		fprintf(stderr, "usage: %s parent-name command [args...]\n", argv[0]);
		return 2;
	}
	if (prctl(PR_SET_NAME, argv[1], 0, 0, 0) != 0) {
		perror("prctl");
		return 1;
	}
	pid_t child = fork();
	if (child < 0) {
		perror("fork");
		return 1;
	}
	if (child == 0) {
		execvp(argv[2], &argv[2]);
		perror("execvp");
		_exit(127);
	}
	int status = 0;
	if (waitpid(child, &status, 0) < 0) {
		perror("waitpid");
		return 1;
	}
	if (WIFEXITED(status)) {
		return WEXITSTATUS(status);
	}
	return 1;
}

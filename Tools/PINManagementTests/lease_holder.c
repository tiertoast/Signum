/* Test-only holder: never loads a module or calls a token API. */
#include "process_coordination.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 3 || (strcmp(argv[1],"ordinary") && strcmp(argv[1],"admin"))) return 2;
    alarm(30);
    SGTokenLease *lease = !strcmp(argv[1],"admin") ? sg_admin_lease_acquire(argv[2],7,0) : sg_token_lease_acquire(argv[2],7,0,0);
    if (!lease) return 3;
    puts("READY");fflush(stdout);
    (void)getchar();
    sg_token_lease_release(lease);return 0;
}

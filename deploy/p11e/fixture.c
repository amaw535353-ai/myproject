#include <signal.h>
#include <unistd.h>

/* P11-E benign admission fixture: inert, non-networked, and not a model server. */
int main(void) {
    for (;;) pause();
    return 0;
}

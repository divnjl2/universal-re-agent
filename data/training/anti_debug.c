
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
int check_debug() {
    return IsDebuggerPresent();
}
#else
// Linux stub
#include <unistd.h>
int check_debug() {
    return 0; 
}
#endif

int main() {
    if (check_debug()) {
        printf("Debugger detected! Exiting.\n");
        return 1;
    }
    printf("Normal execution.\n");
    return 0;
}

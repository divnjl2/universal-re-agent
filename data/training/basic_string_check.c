
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <password>\n", argv[0]);
        return 1;
    }
    
    if (strcmp(argv[1], "AgenticRE2026") == 0) {
        printf("Access Granted!\n");
        return 0;
    } else {
        printf("Access Denied.\n");
        return 1;
    }
}


#include <stdio.h>
#include <string.h>

void decrypt_payload(unsigned char* data, int len) {
    unsigned char key = 0x5A;
    for(int i=0; i<len; i++) {
        data[i] ^= key;
    }
}

int main() {
    unsigned char payload[] = { 0x32, 0x3F, 0x3F, 0x2A, 0x3F, 0x31, 0x1A, 0x28, 0x35, 0x32 }; // "http://c2"
    decrypt_payload(payload, sizeof(payload));
    printf("Connecting to %s\n", payload);
    return 0;
}

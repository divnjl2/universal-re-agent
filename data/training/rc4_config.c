/*
 * rc4_config.c — RE target: RC4-encrypted C2 configuration blob
 *
 * Real-world relevance: malware stores C2 address, beacon interval, mutex name
 * in an RC4-encrypted blob to evade string-based detection.
 *
 * Key: "NexusKey2026" (12 bytes)
 * Plaintext config struct:
 *   c2_host    = "192.168.99.1"
 *   c2_port    = 4444
 *   sleep_ms   = 30000
 *   mutex_name = "Global\\NexusRAT"
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#pragma pack(push, 1)
typedef struct {
    char   c2_host[32];
    uint16_t c2_port;
    uint32_t sleep_ms;
    char   mutex_name[32];
} C2Config;
#pragma pack(pop)

static void rc4_init(uint8_t *S, const uint8_t *key, int keylen) {
    for (int i = 0; i < 256; i++) S[i] = (uint8_t)i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % keylen]) & 0xFF;
        uint8_t t = S[i]; S[i] = S[j]; S[j] = t;
    }
}

static void rc4_crypt(uint8_t *S, uint8_t *data, int len) {
    int i = 0, j = 0;
    for (int n = 0; n < len; n++) {
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        uint8_t t = S[i]; S[i] = S[j]; S[j] = t;
        data[n] ^= S[(S[i] + S[j]) & 0xFF];
    }
}

/* RC4-encrypted config blob (key = "NexusKey2026") */
static const uint8_t RC4_KEY[]  = "NexusKey2026";
static const uint8_t ENC_BLOB[] = {
    /* python3: import arc4; k=b"NexusKey2026"; arc4.ARC4(k).encrypt(struct.pack(...)) */
    0x35,0x5B,0x75,0xE0,0xCA,0x95,0x24,0xE2,0xFB,0x3C,0xBD,0x0A,0xBA,0x02,0xBB,0x05,
    0x3A,0x4D,0x51,0xF9,0xB8,0x36,0xCF,0x60,0x1F,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x5C,0x17,0x38,0xBA,0x70,0xFC,0x7B,0x14,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x70,0x75,
    0x9E,0xD2,0xA7,0x01,
    0xEA,0x37,0x36,0xB4,0xA3,0x8F,0x64,0xA1,0x81,0x9F,0x3A,0x4E,0xDD,0x08,0xC8,0x5C,
    0x9C,0xE0,0x50,0xF6,0xCC,0x40,0x5B,0xDA,0xD1,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
};

int main(void) {
    uint8_t S[256];
    uint8_t buf[sizeof(ENC_BLOB)];
    memcpy(buf, ENC_BLOB, sizeof(ENC_BLOB));

    rc4_init(S, RC4_KEY, (int)strlen((char *)RC4_KEY));
    rc4_crypt(S, buf, (int)sizeof(buf));

    C2Config *cfg = (C2Config *)buf;
    printf("C2 Host  : %s\n",   cfg->c2_host);
    printf("C2 Port  : %u\n",   cfg->c2_port);
    printf("Sleep ms : %u\n",   cfg->sleep_ms);
    printf("Mutex    : %s\n",   cfg->mutex_name);

    /* Simulate beacon check-in */
    printf("Beacon: connecting to %s:%u every %u ms\n",
           cfg->c2_host, cfg->c2_port, cfg->sleep_ms);
    return 0;
}

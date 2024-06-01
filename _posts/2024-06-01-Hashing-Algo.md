---
title: "Determine and understand Hashing Algorithms for Malware Analysis"
tags: 
- Malware
---

Malware commonly uses hashing algorithms for various purposes, such as creating hashes, API hashing, obfuscating malicious code, and verifying the integrity of data. Some of the most commonly used hashing algorithms in malware include MD5, SHA-1, SHA-256, CRC32, and custom algorithms.

In this blog, we will examine a few hashing algorithms from the perspectives of code development and reverse engineering compiled code. The purpose of this blog is to understand and identify hashing algorithms in terms of malware reverse engineering. Thus, this post might be useful for beginner analysts who are new to the reverse engineering malware scene.

# Using Win API

To start our learning journey, developers can perform hashing in code using either Windows API or non-API methods.

Utilizing Windows API to create hashes involves using the WinCrypt's library API, where functions such as `CryptCreateHash` is important to look out for.

Note that sizes for some common hashing algorithms as below:
- MD5: 16 bytes (128 bits)
- SHA-1: 20 bytes (160 bits)
- SHA-256: 32 bytes (256 bits)
- CRC32: 4 bytes (32 bits)

So we need to ensure we have the correct size for our hash array.

Let's do some coding to encrypt string using WinAPI with MD5 hash.
```
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>

int main() {
    const char* data = "Hello World!";
    DWORD dataLen = (DWORD)strlen(data);

    HCRYPTPROV hProv; // Handle CSP
    HCRYPTPROV hHash; // Handle hash object

    CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);       // Acquire CSP handle
    CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash); // Create hash object
    CryptHashData(hHash, (BYTE*)data, dataLen, 0); // Hash the data

    // Get Hash Value
    BYTE hash[16]; // MD5 hash sizes are 16 bytes
    DWORD hashLen = sizeof(hash);
    CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0);
    for (DWORD i = 0; i < hashLen; i++) {
        printf("%02x", hash[i]);
    }

    // Clean up
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    system("pause");

    return 0;
}
```

The output on the screen will display the MD5 hash value of the string "Hello, World!". 

Now, let's take a look at how the code appears in IDA Pro.

![image](https://github.com/fareedfauzi/fareedfauzi.github.io/assets/56353946/92afc863-a63a-462b-a94f-21145935b687)

From the above code, it's easy to determine what's going on since the Windows API provides clear clues. However, in some cases, we need to adjust the symbolic constants for certain values, such as `CRYPT_VERIFYCONTEXT` and `CALG_MD5` context in the above figure.

To switch to a different hashing algorithm, you only need to change the CryptCreateHash line and adjust the size of the hash's byte array accordingly. For example, you can modify the following line by replacing `CALG_MD5` with your desired `ALG_ID` such as `CALG_CRC32`.

```
CryptCreateHash(hProv, CALG_CRC32, 0, 0, &hHash);
BYTE hash[4];
```

Make sure to use the correct `ALG_ID` and adjust the byte array size based on the chosen algorithm.

# Non-API method
## MD5

Let's take a look on how MD5 implementation in the code without using WinCrypt APIs. Suggest that you're using Google to see how's the code is and here we got one that are works in my VS compiler.
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Constants for MD5 Transform routine.
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

typedef struct {
    uint32_t state[4];  // State (ABCD)
    uint32_t count[2];  // Number of bits, modulo 2^64 (lsb first)
    uint8_t buffer[64]; // Input buffer
} MD5_CTX;


void MD5Transform(uint32_t state[4], const uint8_t block[64]);
void MD5Encode(uint8_t *output, const uint32_t *input, size_t len);
void MD5Decode(uint32_t *output, const uint8_t *input, size_t len);
void MD5Init(MD5_CTX *context);
void MD5Update(MD5_CTX *context, const uint8_t *input, size_t inputLen);
void MD5Calculate(uint8_t digest[16], MD5_CTX *context);

// F, G, H and I are basic MD5 functions.
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

// Rotate x left n bits.
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

// FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
#define FF(a, b, c, d, x, s, ac) { (a) += F ((b), (c), (d)) + (x) + (uint32_t)(ac); (a) = ROTATE_LEFT ((a), (s)); (a) += (b); }
#define GG(a, b, c, d, x, s, ac) { (a) += G ((b), (c), (d)) + (x) + (uint32_t)(ac); (a) = ROTATE_LEFT ((a), (s)); (a) += (b); }
#define HH(a, b, c, d, x, s, ac) { (a) += H ((b), (c), (d)) + (x) + (uint32_t)(ac); (a) = ROTATE_LEFT ((a), (s)); (a) += (b); }
#define II(a, b, c, d, x, s, ac) { (a) += I ((b), (c), (d)) + (x) + (uint32_t)(ac); (a) = ROTATE_LEFT ((a), (s)); (a) += (b); }

// Initializes the MD5 context
void MD5Init(MD5_CTX *context) {
    context->count[0] = context->count[1] = 0;
    context->state[0] = 0x67452301;
    context->state[1] = 0xefcdab89;
    context->state[2] = 0x98badcfe;
    context->state[3] = 0x10325476;
}

// Updates the MD5 context with a new block of data
void MD5Update(MD5_CTX *context, const uint8_t *input, size_t inputLen) {
    size_t i, index, partLen;

    index = (size_t)((context->count[0] >> 3) & 0x3F);

    if ((context->count[0] += ((uint32_t)inputLen << 3)) < ((uint32_t)inputLen << 3)) {
        context->count[1]++;
    }
    context->count[1] += ((uint32_t)inputLen >> 29);

    partLen = 64 - index;

    if (inputLen >= partLen) {
        memcpy(&context->buffer[index], input, partLen);

        MD5Transform(context->state, context->buffer);

        for (i = partLen; i + 63 < inputLen; i += 64) {
            MD5Transform(context->state, &input[i]);
        }

        index = 0;
    } else {
        i = 0;
    }

    memcpy(&context->buffer[index], &input[i], inputLen - i);
}

void MD5Calculate(uint8_t digest[16], MD5_CTX *context) {
    uint8_t bits[8];
    size_t index, padLen;
    
    MD5Encode(bits, context->count, 8);

    index = (size_t)((context->count[0] >> 3) & 0x3f);
    padLen = (index < 56) ? (56 - index) : (120 - index);
    MD5Update(context, (uint8_t*)"\x80", 1);
    while (padLen-- > 1) {
        MD5Update(context, (uint8_t*)"\0", 1);
    }

    MD5Update(context, bits, 8);
    MD5Encode(digest, context->state, 16);
}


// Performs the main MD5 transformation on a 64-byte block
void MD5Transform(uint32_t state[4], const uint8_t block[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], x[16];

    MD5Decode(x, block, 64);

    // Round 1
    FF(a, b, c, d, x[ 0], S11, 0xd76aa478);
    FF(d, a, b, c, x[ 1], S12, 0xe8c7b756);
    FF(c, d, a, b, x[ 2], S13, 0x242070db);
    FF(b, c, d, a, x[ 3], S14, 0xc1bdceee);
    FF(a, b, c, d, x[ 4], S11, 0xf57c0faf);
    FF(d, a, b, c, x[ 5], S12, 0x4787c62a);
    FF(c, d, a, b, x[ 6], S13, 0xa8304613);
    FF(b, c, d, a, x[ 7], S14, 0xfd469501);
    FF(a, b, c, d, x[ 8], S11, 0x698098d8);
    FF(d, a, b, c, x[ 9], S12, 0x8b44f7af);
    FF(c, d, a, b, x[10], S13, 0xffff5bb1);
    FF(b, c, d, a, x[11], S14, 0x895cd7be);
    FF(a, b, c, d, x[12], S11, 0x6b901122);
    FF(d, a, b, c, x[13], S12, 0xfd987193);
    FF(c, d, a, b, x[14], S13, 0xa679438e);
    FF(b, c, d, a, x[15], S14, 0x49b40821);

    // Round 2
    GG(a, b, c, d, x[ 1], S21, 0xf61e2562);
    GG(d, a, b, c, x[ 6], S22, 0xc040b340);
    GG(c, d, a, b, x[11], S23, 0x265e5a51);
    GG(b, c, d, a, x[ 0], S24, 0xe9b6c7aa);
    GG(a, b, c, d, x[ 5], S21, 0xd62f105d);
    GG(d, a, b, c, x[10], S22,  0x2441453);
    GG(c, d, a, b, x[15], S23, 0xd8a1e681);
    GG(b, c, d, a, x[ 4], S24, 0xe7d3fbc8);
    GG(a, b, c, d, x[ 9], S21, 0x21e1cde6);
    GG(d, a, b, c, x[14], S22, 0xc33707d6);
    GG(c, d, a, b, x[ 3], S23, 0xf4d50d87);
    GG(b, c, d, a, x[ 8], S24, 0x455a14ed);
    GG(a, b, c, d, x[13], S21, 0xa9e3e905);
    GG(d, a, b, c, x[ 2], S22, 0xfcefa3f8);
    GG(c, d, a, b, x[ 7], S23, 0x676f02d9);
    GG(b, c, d, a, x[12], S24, 0x8d2a4c8a);

    // Round 3
    HH(a, b, c, d, x[ 5], S31, 0xfffa3942);
    HH(d, a, b, c, x[ 8], S32, 0x8771f681);
    HH(c, d, a, b, x[11], S33, 0x6d9d6122);
    HH(b, c, d, a, x[14], S34, 0xfde5380c);
    HH(a, b, c, d, x[ 1], S31, 0xa4beea44);
    HH(d, a, b, c, x[ 4], S32, 0x4bdecfa9);
    HH(c, d, a, b, x[ 7], S33, 0xf6bb4b60);
    HH(b, c, d, a, x[10], S34, 0xbebfbc70);
    HH(a, b, c, d, x[13], S31, 0x289b7ec6);
    HH(d, a, b, c, x[ 0], S32, 0xeaa127fa);
    HH(c, d, a, b, x[ 3], S33, 0xd4ef3085);
    HH(b, c, d, a, x[ 6], S34,  0x4881d05);
    HH(a, b, c, d, x[ 9], S31, 0xd9d4d039);
    HH(d, a, b, c, x[12], S32, 0xe6db99e5);
    HH(c, d, a, b, x[15], S33, 0x1fa27cf8);
    HH(b, c, d, a, x[ 2], S34, 0xc4ac5665);

    // Round 4
    II(a, b, c, d, x[ 0], S41, 0xf4292244);
    II(d, a, b, c, x[ 7], S42, 0x432aff97);
    II(c, d, a, b, x[14], S43, 0xab9423a7);
    II(b, c, d, a, x[ 5], S44, 0xfc93a039);
    II(a, b, c, d, x[12], S41, 0x655b59c3);
    II(d, a, b, c, x[ 3], S42, 0x8f0ccc92);
    II(c, d, a, b, x[10], S43, 0xffeff47d);
    II(b, c, d, a, x[ 1], S44, 0x85845dd1);
    II(a, b, c, d, x[ 8], S41, 0x6fa87e4f);
    II(d, a, b, c, x[15], S42, 0xfe2ce6e0);
    II(c, d, a, b, x[ 6], S43, 0xa3014314);
    II(b, c, d, a, x[13], S44, 0x4e0811a1);
    II(a, b, c, d, x[ 4], S41, 0xf7537e82);
    II(d, a, b, c, x[11], S42, 0xbd3af235);
    II(c, d, a, b, x[ 2], S43, 0x2ad7d2bb);
    II(b, c, d, a, x[ 9], S44, 0xeb86d391);

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;

    memset(x, 0, sizeof(x));
}

// Encodes input (uint32_t) into output (uint8_t)
void MD5Encode(uint8_t *output, const uint32_t *input, size_t len) {
    for (size_t i = 0, j = 0; j < len; i++, j += 4) {
        output[j] = (uint8_t)(input[i] & 0xff);
        output[j + 1] = (uint8_t)((input[i] >> 8) & 0xff);
        output[j + 2] = (uint8_t)((input[i] >> 16) & 0xff);
        output[j + 3] = (uint8_t)((input[i] >> 24) & 0xff);
    }
}

//  Decodes input (uint8_t) into output (uint32_t)
void MD5Decode(uint32_t *output, const uint8_t *input, size_t len) {
    for (size_t i = 0, j = 0; j < len; i++, j += 4) {
        output[i] = ((uint32_t)input[j]) | (((uint32_t)input[j + 1]) << 8) |
            (((uint32_t)input[j + 2]) << 16) | (((uint32_t)input[j + 3]) << 24);
    }
}

int main() {
    MD5_CTX context;
    uint8_t digest[16];
    const char *string = "Hello World!";

    // Initializes the MD5 context
    MD5Init(&context);
    
    // Updates the MD5 context with a new block of data
    MD5Update(&context, (uint8_t*)string, strlen(string));

    // Finalizes the MD5 hash calculation and produces the final hash value
    MD5Calculate(digest, &context);

    for (int i = 0; i < 16; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    return 0;
}
```

The code looks huge and long for just an MD5 hashing calculation, but that's how it works. Using non-API methods requires more lines of code and additional functions. Consequently, the compiled code will also be longer compared to using the WinAPI approach.

Let's take a look at how the code is compiled and reverse-engineered in IDA Pro.

![image](https://github.com/fareedfauzi/fareedfauzi.github.io/assets/56353946/117e3c09-23f2-4d1e-8cb1-fbe15fd57b39)

If you search these initial state values on Google, you will find that they are indicative of the MD5 hashing algorithm. These constants are a well-known part of the MD5 algorithm's initialization process.

![image](https://github.com/fareedfauzi/fareedfauzi.github.io/assets/56353946/9f921726-ab63-45d2-874d-bf877d5999ec)

And this is how the MD5Transform funcion looks like in IDA:

![image](https://github.com/fareedfauzi/fareedfauzi.github.io/assets/56353946/13874445-1b0e-41e6-a032-1f3b68de42cf)

Again, using Google to search for the hardcoded value (for example, `0x28955B88`) can give us a hint about the hashing algorithm that the code uses.

![image](https://github.com/fareedfauzi/fareedfauzi.github.io/assets/56353946/d7e98024-dcbf-4720-826e-dd247a071313)

## CRC Hashing
CRC (Cyclic Redundancy Check) is a popular error-detecting code used to detect changes to raw data. Key concepts in CRC are it use polynomial representations of binary numbers. So, for CRC32, the polynomial is `0xEDB88320`. This polynomial is used in the calculation to generate the CRC table and the checksum. Again, you can search this constant value in Google and give us clue about CRC hashing.

![image](https://github.com/fareedfauzi/fareedfauzi.github.io/assets/56353946/5d7a687a-98dc-4f2a-8221-c8b598dd17a5)

Now, let's dive into CRC hashing algorithm code where the code took less lines compared to the MD5 codes.

```
#include <stdio.h>
#include <stdint.h>
#include <string.h>

// Polynomial used for CRC32 calculation
#define CRC32_POLY 0xEDB88320

// Function to initialize the CRC32 table
void init_crc32_table(uint32_t crc_table[]) {
    uint32_t crc;
    for (int i = 0; i < 256; i++) {
        crc = i;
        for (int j = 8; j > 0; j--) {
            if (crc & 1) {
                crc = (crc >> 1) ^ CRC32_POLY;
            } else {
                crc >>= 1;
            }
        }
        crc_table[i] = crc;
    }
}

// Function to calculate the CRC32 hash
uint32_t crc32(const uint8_t *data, size_t length, uint32_t crc_table[]) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; i++) {
        uint8_t byte = data[i];
        uint8_t table_index = (crc ^ byte) & 0xFF;
        crc = (crc >> 8) ^ crc_table[table_index];
    }
    return crc ^ 0xFFFFFFFF;
}

int main() {
    // Data to hash
    const char *data = "Hello, World!";
    size_t data_len = strlen(data);

    // Initialize the CRC32 table
    uint32_t crc_table[256];
    init_crc32_table(crc_table);

    // Calculate the CRC32 hash
    uint32_t hash = crc32((const uint8_t *)data, data_len, crc_table);

    // Print the CRC32 hash
    printf("CRC32 hash: %08x\n", hash);

    return 0;
}
```

First, the code initialize lookup table for CRC32 calculation. In the table, it contains precomputed CRC32 values for all possible byte values, speeding up the CRC32 calculation process. And then, the code proceed computes the CRC32 hash of the given data.

And... if we have a look in the decompiled code in IDA, the code fairly looks simple whereby we can see the code repeatedly using value `0xEDB88320` for XOR operation for CRC32 lookup table initialization.

![image](https://github.com/fareedfauzi/fareedfauzi.github.io/assets/56353946/55cc5c30-5fd0-4a3f-8486-d28e2ec4bfd2)

And before it prints the hash value, the code does the CRC Calculation for "Hello, World!" strings.

# Detect hashing algorithm

As a result of our analysis, we aim to identify the hashing algorithms used when performing reverse engineering on samples that utilize hashing algorithms.

If the sample uses WinAPI, we can often determine the hashing algorithm by examining the `alg_id` parameter in the `CryptCreateHash` function. 

But, if a non-API approach is used by the malware developer, one tip is to search for constant values via Google. Another thing, we can also research the decompiled code in IDA Pro by comparing the decompiled code algorithms with source code available on the internet. This can enlighten us what the code does and what hashing algoritm that they used.

Another good and fast methods are using tools and plugins such as PEID + KANAL, CAPA plugin, and FindCrypt plugin.

## PEiD + KANAL
Kanal is a plugin for PEiD that searches for known crypto algorithms, functions and libraries in a PE file.

Upon using the plugin, the results look like this
```
Crypto name :: File offset :: Virtual address
```
And we can see that the Virtual address detect a constant value corresponding to CRC32 hashing algorithm.

![image](https://github.com/fareedfauzi/fareedfauzi.github.io/assets/56353946/5554f482-1a60-49a4-8f2e-bd5e79fba847)

## CAPA Explorer: IDA plugin
capa is a framework that uses a well-defined collection of rules to identify capabilities in a program. With capa explorer, we can focus inspecting relevant code (avoid us to reversing rabbit hole function) such as identify algorithms and malware functionality. 

![image](https://github.com/fareedfauzi/fareedfauzi.github.io/assets/56353946/655dd649-38f6-4ff4-bf49-f5bee97eb338)

## FindCrypt: IDA plugin
Next, we have another useful tool that can be utilized by us to find encryption and hashing algorithms in the code blocks. Running the findcrypt will show us the list of it's detection in the sample.

![image](https://github.com/fareedfauzi/fareedfauzi.github.io/assets/56353946/32f1ce46-b5fb-4e4b-88c3-3f017c1693c6)

# Sum up
Yeah, that's all how we determine hashing algoritms in the malware samples. Using some sort of tools could speed up our reversing activities and doing some Google-Fu stuff also could helps us identify the hashing algorithms when tools does not help us at all.

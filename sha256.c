/*
 * Copyright (c) 2025 Fabio De Orazi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */


#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>

// SHA-256 read the input data in chunks of 64 bytes (512-bit)
#define MESSAGE_BLOCK_SIZE 64

// The limit after which the padding requires a complete new block
#define MAX_INCOMPLETE_MESSAGE_BLOCK 56

#define HASH_SIZE 32

FILE *verbose_out;

short verbose = 0;

typedef unsigned int word_t;

const int primes[] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
                      61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131,
                      137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223,
                      227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311};

static unsigned int constants[64];

static uint64_t tot_message_bits;

void set_constants()
{
    // SHA-256 K constants (first 32 bits of fractional parts of cube roots of first 64 primes)
    const unsigned int K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

    memcpy(constants, K, sizeof(K));
    
    if(!verbose) return;

    printf("Using constants:\n");
    for (int i = 0; i < 64; i++)
    {
        printf("%08x ", constants[i]);
        if ((i + 1) % 8 == 0)
        {
            printf("\n");
        }
    }
    printf("\n");
}

void set_initial_hashvalue(word_t work_vars[8])
{
    // SHA-256 initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
    const unsigned int H[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    memcpy(work_vars, H, sizeof(H));
}

void print_in_big_endian(uint8_t *p, size_t length)
{
    for(size_t i=0; i<length; i+=4)
    {
        uint32_t w = (uint32_t) p[i+3] << 24| 
                     (uint32_t) p[i+2] << 16 |
                     (uint32_t) p[i+1] << 8 | 
                     (uint32_t) p[i];
        
        printf("%08x", w);
    }
}

void print_hex(uint8_t *p, size_t length, short bytes_per_line, short print_ascii)
{
    for(size_t i=0; i<length; i++)
    {
        printf("%02x", *(p+i));
        
        if(!print_ascii) continue;
        
        if(i>0 && (i+1)%bytes_per_line == 0)
        {
            printf("\t");

            for(size_t j=(i-(bytes_per_line-1)); j<=i; j++)
            {
                uint8_t c = *(p+j);
                if(c >= 33 && c <=127) {
                    putchar(c);
                }
                else
                {
                    putchar('.');
                }
            }

            printf("\n");
        }
    }

}


word_t maj_op(word_t w_x, word_t w_y, word_t w_z)
{
    word_t result = (w_x & w_y) ^ (w_x & w_z) ^ (w_y & w_z);
    return result;
}

word_t ch_op(word_t w_x, word_t w_y, word_t w_z)
{
    word_t result = (w_x & w_y) ^ (~w_x & w_z);
    return result;
}

word_t sum_op_1(word_t w)
{
    int r;
    int b = sizeof(w) * 8;
    r = (w >> 6) | (w << (b - 6));
    r ^= (w >> 11) | (w << (b - 11));
    r ^= (w >> 25) | (w << (b - 25));

    return r;
}

word_t sum_op_0(word_t w)
{
    int r;
    int b = sizeof(w) * 8;
    r = w >> 2 | w << (b - 2);
    r ^= w >> 13 | w << (b - 13);
    r ^= w >> 22 | w << (b - 22);

    return r;
}

word_t sigma_op_1(word_t w)
{
    int r;
    int b = sizeof(w) * 8;
    r = w >> 17 | w << (b - 17);
    r ^= w >> 19 | w << (b - 19);
    r ^= w >> 10;

    return r;
}

word_t sigma_op_0(word_t w)
{
    int r;
    int b = sizeof(w) * 8;
    r = w >> 7 | w << (b - 7);
    r ^= w >> 18 | w << (b - 18);
    r ^= w >> 3;

    return r;
}

/* Elaborate a single message block of 512-bit (64 byte) */
void elab_block(unsigned char *message_block, word_t prev_hash_computation[8])
{
    fprintf(verbose_out, "Previous hash computation:\n");
    if(verbose)
    {
        print_hex((uint8_t*) prev_hash_computation, HASH_SIZE, HASH_SIZE, 0); 
        printf("\n");
    }

    // 1. Prepare the message schedule (from 0 to 15 set with 32-bit message blocks values)
    fprintf(verbose_out, "=== Prepare message schedule ===\n");

    /* unsigned int 4 bytes */
    word_t words[64] = {0};

    memset(words, 0, sizeof(words));

    /* Copy the first 16 words in Big Endian (in a 4 byte mask of the unsigned int) */
    for (int i = 0; i < 16; i++)
    {
        /* Pointer to message_block position 0 4 8 12 16 32 etc. */
        uint8_t *p = (uint8_t *)(message_block + (i * 4));
        words[i] = ((uint32_t)p[0] << 24) |
                   ((uint32_t)p[1] << 16) |
                   ((uint32_t)p[2] << 8) |
                   ((uint32_t)p[3]);
    }

    for (int i = 16; i < 64; i++)
    {
        word_t result = sigma_op_1(words[i - 2]) + words[i - 7] + sigma_op_0(words[i - 15]) + words[i - 16];
        words[i] = result;
    }


    if(verbose)
    {
        printf("W%d-%d\t", 0, 7);
        print_hex((uint8_t*) words, 32, 32, 1);  

        printf("W%d-%d\t", 8, 15);
        print_hex((uint8_t*) words+32, 32, 32, 1);  

        printf("W%d-%d\t", 16, 22);
        print_hex((uint8_t*) words+64, 32, 32, 1);  
        printf("\n");
    }

    // 2. Initialize the eight working variables
    word_t work_vars[8];
    memcpy(work_vars, prev_hash_computation, sizeof(word_t) * 8);

    // 3. Main compression loop
    for (int t = 0; t < 64; t++)
    {
        word_t t1, t2;

        // h + sum_op_1(e) + ch_op(e,f,g) +
        t1 = work_vars[7] + sum_op_1(work_vars[4]) + ch_op(work_vars[4], work_vars[5], work_vars[6]) + constants[t] + words[t];
        // sum_op_0(a) +
        t2 = sum_op_0(work_vars[0]) + maj_op(work_vars[0], work_vars[1], work_vars[2]);

        work_vars[7] = work_vars[6];
        work_vars[6] = work_vars[5];
        work_vars[5] = work_vars[4];
        work_vars[4] = work_vars[3] + t1;
        work_vars[3] = work_vars[2];
        work_vars[2] = work_vars[1];
        work_vars[1] = work_vars[0];

        work_vars[0] = t1 + t2;
    }

    /* Compute the intermediate hash value H ith*/
    fprintf(verbose_out, "Hash computation:\n");

    for (int i = 0; i < 8; i++)
    {
        prev_hash_computation[i] = work_vars[i] + prev_hash_computation[i];
    }

    fprintf(verbose_out, "Finish elab block.\n\n");
}



/**
 * Additional paramters indicates that the block was added due to insufficient space in last block
 * to put the last 4-byte big-endian message length.
 *
 * If additional, sets to zero all bytes.
 *
 * Writes to the last 4-byte the message size in big-endian
 *
 * Parameters
 *      read                Tot read bytes of last incomplete block.
 *      message_length      Total bits read, to put in bit-endian in last 4-bytes
 */
void padding_block(unsigned char *block, int read, uint64_t message_length, bool additional)
{
    // case of additional padding block
    if (additional)
    {
        memset(block, 0, MESSAGE_BLOCK_SIZE);
    }
    else
    {
        block[read] = 0x80;
        memset(block + read + 1, 0, MESSAGE_BLOCK_SIZE - read - 1);
    }

    // print_hex(block, MESSAGE_BLOCK_SIZE);

    // Pointer to the last 8 bytes (64-bit)
    uint8_t *ptr = (uint8_t *)(block + (MESSAGE_BLOCK_SIZE - 8));

    // Store most significant byte first (Big-Endian)
    ptr[0] = (message_length >> 56) & 0xFF;
    ptr[1] = (message_length >> 48) & 0xFF;
    ptr[2] = (message_length >> 40) & 0xFF;
    ptr[3] = (message_length >> 32) & 0xFF;
    ptr[4] = (message_length >> 24) & 0xFF;
    ptr[5] = (message_length >> 16) & 0xFF;
    ptr[6] = (message_length >> 8) & 0xFF;
    ptr[7] = (message_length >> 0) & 0xFF;

    if(verbose)
    {
        printf("Padding block (message length: %llu)\n", message_length);
        print_hex((uint8_t*) block, MESSAGE_BLOCK_SIZE, MESSAGE_BLOCK_SIZE, 0);
        printf("\n");
    }
}

/* Read file blocks for elaboration (64 bytes - 512 bits for SHA-256) */
void sha256(FILE *fp)
{
    unsigned char buff[MESSAGE_BLOCK_SIZE]; // 512-bit
    int read;

    // 8 32-bit working variable
    word_t prev_hash[8];

    // preprocess
    set_initial_hashvalue(prev_hash);

    while ((read = fread(buff, 1, sizeof(buff), fp)) > 0)
    {
        tot_message_bits += read;

        fprintf(verbose_out, "Read %d bytes.\tfgetpos() = %ld\n", read, ftell(fp));

        bool new_padding_block = false;

        /* Fill the padding in current block */
        if (read < MAX_INCOMPLETE_MESSAGE_BLOCK)
        {
            padding_block(buff, read, tot_message_bits * 8, false);
        }
        /* Create a new emty block for the padding */
        else if (read < MESSAGE_BLOCK_SIZE && (read + 1) >= MAX_INCOMPLETE_MESSAGE_BLOCK)
        {
            buff[read] = 0x80;
            memset(buff + read + 1, 0, MESSAGE_BLOCK_SIZE - read - 1);
            new_padding_block = true;
        }

        elab_block(buff, prev_hash);

        if (new_padding_block)
        {
            unsigned char new_block[MESSAGE_BLOCK_SIZE];
            padding_block(new_block, 0, tot_message_bits * 8, true);
            elab_block(new_block, prev_hash);
        }
        
        /* Clean buffer */
        memset(buff, 0, MESSAGE_BLOCK_SIZE);
    }

    fprintf(verbose_out, "Result:\n");
    print_in_big_endian((uint8_t*)prev_hash, HASH_SIZE);
}

int main(int argc, char **argv)
{
    char *path = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "-verbose") == 0) {
            verbose = 1;
        } else if (path == NULL) {
            // First non-flag argument is the work directory
            path = argv[i];
        } else {
            // Multiple work directories provided - error
            fprintf(stderr, "Error: Multiple taget file paths provided\n");
            fprintf(stderr, "Usage: %s <file> [-v|-verbose]\n", argv[0]);
            return 1;
        }
    }

    if(path == NULL)
    {
        fprintf(stderr, "Error: No file paths provided\n");
        fprintf(stderr, "Usage: %s <file> [-v|-verbose]\n", argv[0]);
        return 1;
    }

    // Set verbose stream: stdout if verbose, /dev/null if not
    if (verbose) {
        verbose_out = stdout;
    } else {
        #ifdef _WIN32
        verbose_out = fopen("NUL", "w");     // Windows
        #else
        verbose_out = fopen("/dev/null", "w");  // Unix/Linux
        #endif
    }

    fprintf(verbose_out, "Elab input: %s\n", path);

    char *current_dir = getcwd(NULL, 0);
    fprintf(verbose_out, "%s\n", current_dir);

    FILE *fp = fopen(path, "r");

    if(fp == NULL)
    {
        fprintf(stderr, "Invalid target path\n");
        return 1;
    }

    set_constants();

    sha256(fp);

    printf("  %s\n", path);

    fclose(fp);
    free(current_dir);

    return 0;
}

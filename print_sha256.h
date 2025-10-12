#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CYELLOW (use_colors ? "\033[33m" : "")
#define C2 (use_colors ? "\033[34m" : "")
#define CRST (use_colors ? "\033[0m" : "")

typedef unsigned int word_t;

extern short use_colors;

FILE *v_out;

void print_separator(const char c, short width);

void print_constants(uint32_t constants[]);

void print_hex(uint8_t *p, size_t length, uint8_t bytes_per_line, uint8_t print_ascii,
               uint8_t print_offset);

void print_words(word_t *words, short until);

void print_init_hash_values(uint32_t work_vars[]);

void print_in_big_endian(uint8_t *p, size_t length, short table_column);

void print_padding_block(unsigned char *block, short read, uint64_t message_length);

void print_round_work_vars(word_t t1, word_t t2, word_t work_vars[8], int t);

void print_program_start(char *path, size_t file_size);

void print_result(char *path, word_t hash_computation[], size_t file_size, char result[64],
                  size_t blocks_processed, double elapsed_ms);

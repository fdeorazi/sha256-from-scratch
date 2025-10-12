#include "print_sha256.h"

short use_colors = 1;

void print_separator(const char c, short width) {
    for (int i = 0; i < width; i++) {
        putc(c, v_out);
    }
    putc('\n', v_out);
}

void print_utf8_separator(const char *c, short width) {
    for (int i = 0; i < width; i++) {
        // putc(c, v_out);
        fprintf(v_out, "%s", c);
    }
}

/* Print constants (verbose mode) */
void print_constants(uint32_t constants[]) {
    fprintf(v_out, "%s=== Set constants (sixty-four constant 32-bit words)", CYELLOW);
    print_separator('=', 28);
    fprintf(v_out, "%s", CRST);

    for (int i = 0; i < 31; i++) {
        fprintf(v_out, "%08x ", constants[i]);
        if ((i + 1) % 8 == 0) {
            fprintf(v_out, "\n");
        }
    }
    fprintf(v_out, "....\n\n");
}

/* Hexdump like print frunction  */
void print_hex(uint8_t *p, size_t length, uint8_t bytes_per_line, uint8_t print_ascii,
               uint8_t print_offset) {
    char offset_label[8];
    size_t until = length > bytes_per_line ? length : bytes_per_line;
    for (size_t i = 0; i < until; i++) {
        if (print_offset && (i == 0 || (i % bytes_per_line == 0))) {
            snprintf(offset_label, 8, "0x%zx", i);
            fprintf(v_out, "%-8s", offset_label);
        }

        if (i >= length && i < bytes_per_line) {
            fprintf(v_out, "%02x", 0);
        } else {
            fprintf(v_out, "%02x", *(p + i));
        }

        if (!print_ascii)
            continue;

        if (i > 0 && (i + 1) % bytes_per_line == 0) {
            fprintf(v_out, "\t");

            for (size_t j = (i - (bytes_per_line - 1)); j <= i; j++) {
                uint8_t c = *(p + j);
                if (c >= 33 && c <= 127 && j < length) {
                    putc(c, v_out);
                } else {
                    putc('.', v_out);
                }
            }

            fprintf(v_out, "\n");
        }
    }
}

/* Print hex of 4 words per line (1 words is 32-bit)  */
void print_words(word_t *words, short until) {
    fprintf(v_out, "%s\n=== Prepare message schedule ", CYELLOW);
    print_separator('=', 51);
    fprintf(v_out, "%s", CRST);

    short count = 0;

    for (int i = 0; i < (until / 4); i++) {
        fprintf(v_out, "W%d-%d\t", count, count + 3);
        print_hex((uint8_t *)words + (32 * i), 16, 16, 1, 0);
        count += 4;
    }
}

void print_init_hash_values(uint32_t work_vars[]) {
    fprintf(v_out, "%s=== Set initial hash values (H0-H7) ", CYELLOW);
    print_separator('=', 44);
    fprintf(v_out, "%s", CRST);

    for (int i = 0; i < 8; i++) {
        fprintf(v_out, "H%d: %08x  ", i, work_vars[i]);
        if ((i + 1) % 4 == 0) {
            fprintf(v_out, "\n");
        }
    }
    putc('\n', v_out);
}

/* Prints each 4 bytes calculating an unsigned integer with the least
 * significant byte from left and most significant byte from the right */
void print_in_big_endian(uint8_t *p, size_t length, short table_column) {
    if (length % 4 != 0) {
        fprintf(stderr, "Error: print_in_big_endian requires length divisible by 4 (got %zu)\n",
                length);
        exit(EXIT_FAILURE);
    }

    for (size_t i = 0; i < length; i += 4) {
        uint32_t w = (uint32_t)p[i + 3] << 24 | (uint32_t)p[i + 2] << 16 | (uint32_t)p[i + 1] << 8 |
                     (uint32_t)p[i];
        if (table_column) {
            fprintf(v_out, "%-10x", w);
        } else {
            fprintf(v_out, "%08x", w);
            /*if (v_out != stdout && ensure_stdout) {
                fprintf(stdout, "%08x", w);
            }*/
        }
    }
}

void print_padding_block(unsigned char *block, short read, uint64_t message_length) {
    char label[100];
    snprintf(label, 100, "\n=== Padding block (message length: %llu-bit) %c",
             message_length, '\0');
    fprintf(v_out, "%s%s", CYELLOW, label);
    //int8_t length = 
    //fprintf(v_out, "strlen(label) : %lu", strlen(label));
    print_separator('=', 80 - strlen(label) +1);
    fprintf(v_out, "%s", CRST);
    fprintf(v_out, "%-8s%d-bit\n", "From", read);
    fprintf(v_out, "---\n");
    print_hex((uint8_t *)block, read, 16, 1, 1);
    fprintf(v_out, "\n");
}

void print_round_work_vars(word_t t1, word_t t2, word_t work_vars[8], int t) {
    char label[8];
    if (t == 0 || (t + 1) % 8 == 0) {
        snprintf(label, 8, "%2d%-6s", t + 1, "th");
    } else {
        // snprintf(label, 8, "%-8s", "  ..");
        return;
    }

    fprintf(v_out, "%8s", label);
    print_in_big_endian((uint8_t *)&t1, 4, 1);
    print_in_big_endian((uint8_t *)&t2, 4, 1);

    for (int i = 0; i < 6; i++) {
        if (i < 5) {
            print_in_big_endian((uint8_t *)&work_vars[i], 4, 1);
        } else {
            fprintf(v_out, "..");
        }
    }
    fprintf(v_out, "\n");
}

void print_program_start(char *path, size_t file_size) {
    fprintf(v_out, "\n\n%s", CYELLOW);
    print_separator('=', 80);
    fprintf(v_out, "%sSHA-256 Digest Algorithm From Scratch\n%s", "", "");
    print_separator('=', 80);
    fprintf(v_out, "%s\n", CRST);
    fprintf(v_out, "Input file: %s (%ld bytes)\n\n", path, file_size);
}

void print_result(char *path, word_t hash_computation[], size_t file_size, char result[64],
                  size_t blocks_processed, double elapsed_ms) {
    // Print result
    fprintf(v_out, "\n");
    fprintf(v_out, "╔");
    print_utf8_separator("═", 78);
    fprintf(v_out, "╗\n");
    fprintf(v_out, "║%35sRESULT%37s║\n", "", "");
    fprintf(v_out, "╠");
    print_utf8_separator("═", 78);
    fprintf(v_out, "╣\n");

    fprintf(v_out, "║ File: %-71s║\n", path);
    char size_label[40];
    if (file_size > 1024 * 1024) {
        snprintf(size_label, 40, "%ld Mb (%ld bytes)", file_size / (1024 * 1024), file_size);
    } else if (file_size > 1024) {
        snprintf(size_label, 40, "%ld Kb (%ld bytes)", file_size / 1024, file_size);
    } else {
        snprintf(size_label, 40, "%ld bytes", file_size);
    }

    fprintf(v_out, "║ Size: %-71s║\n", size_label);
    fprintf(v_out, "║%78s║\n", "");
    fprintf(v_out, "║ SHA-256:%69s║\n", "");
    fprintf(v_out, "║ ");
    for (int i = 0; i < 8; i++) {
        print_in_big_endian((uint8_t *)&hash_computation[i], 4, 1);
        fprintf(v_out, " ");
        if (i > 0 && (i + 1) % 4 == 0 && i < 7) {
            fprintf(v_out, "%33s║\n║ ", "");
        }
    }
    fprintf(v_out, "%33s║\n", "");
    fprintf(v_out, "║%78s║\n", "");
    fprintf(v_out, "║ Hexadecimal (contiguous):%52s║\n", "");
    fprintf(v_out, "║ %-71s%6s║\n", result, "");
    fprintf(v_out, "║%78s║\n", "");

    fprintf(v_out, "╚");
    print_utf8_separator("═", 78);
    fprintf(v_out, "╝\n\n");

    fprintf(v_out, "  Computation completed successfully\n");
    fprintf(v_out, "  Processed: %zu block(s)\n", blocks_processed);

    fprintf(v_out, "  Time spent: %.3f seconds\n\n", elapsed_ms);
}

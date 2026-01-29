/*
 * strparser.c - Simple String Parser Library Implementation
 */

#include "strparser.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <errno.h>

/* Helper: Check if character is a valid hex digit */
static int is_hex_digit(char c) {
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

/* Helper: Convert hex character to integer value */
static int hex_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int strparser_parse_int_list(const char *input, size_t input_len,
                             strparser_int_list_t *result) {
    if (!input || !result) {
        return STRPARSER_ERR_NULL;
    }

    if (input_len == 0) {
        result->values = NULL;
        result->count = 0;
        result->capacity = 0;
        return STRPARSER_OK;
    }

    /* Initial allocation */
    result->capacity = 16;
    result->count = 0;
    result->values = (int *)malloc(result->capacity * sizeof(int));
    if (!result->values) {
        return STRPARSER_ERR_MEMORY;
    }

    const char *ptr = input;
    const char *end = input + input_len;

    while (ptr < end) {
        /* Skip whitespace */
        while (ptr < end && isspace((unsigned char)*ptr)) {
            ptr++;
        }
        if (ptr >= end) break;

        /* Parse integer */
        int negative = 0;
        if (*ptr == '-') {
            negative = 1;
            ptr++;
        } else if (*ptr == '+') {
            ptr++;
        }

        if (ptr >= end || !isdigit((unsigned char)*ptr)) {
            /* Skip to next comma if invalid */
            while (ptr < end && *ptr != ',') ptr++;
            if (ptr < end) ptr++;
            continue;
        }

        long value = 0;
        while (ptr < end && isdigit((unsigned char)*ptr)) {
            value = value * 10 + (*ptr - '0');
            if (value > INT_MAX) {
                value = INT_MAX;
            }
            ptr++;
        }

        if (negative) {
            value = -value;
        }

        /* Grow array if needed */
        if (result->count >= result->capacity) {
            size_t new_capacity = result->capacity * 2;
            int *new_values = (int *)realloc(result->values,
                                              new_capacity * sizeof(int));
            if (!new_values) {
                free(result->values);
                result->values = NULL;
                return STRPARSER_ERR_MEMORY;
            }
            result->values = new_values;
            result->capacity = new_capacity;
        }

        result->values[result->count++] = (int)value;

        /* Skip to comma or end */
        while (ptr < end && isspace((unsigned char)*ptr)) {
            ptr++;
        }
        if (ptr < end && *ptr == ',') {
            ptr++;
        }
    }

    return STRPARSER_OK;
}

void strparser_free_int_list(strparser_int_list_t *result) {
    if (result) {
        free(result->values);
        result->values = NULL;
        result->count = 0;
        result->capacity = 0;
    }
}

int strparser_split(const char *input, size_t input_len, char delimiter,
                    strparser_token_t *tokens, size_t max_tokens,
                    size_t *num_tokens) {
    if (!input || !tokens || !num_tokens) {
        return STRPARSER_ERR_NULL;
    }

    *num_tokens = 0;

    if (input_len == 0 || max_tokens == 0) {
        return STRPARSER_OK;
    }

    const char *ptr = input;
    const char *end = input + input_len;
    const char *token_start = ptr;

    while (ptr <= end && *num_tokens < max_tokens) {
        if (ptr == end || *ptr == delimiter) {
            tokens[*num_tokens].start = token_start;
            tokens[*num_tokens].length = ptr - token_start;
            (*num_tokens)++;

            if (ptr < end) {
                token_start = ptr + 1;
            }
        }
        ptr++;
    }

    return STRPARSER_OK;
}

int strparser_parse_kv(const char *input, size_t input_len,
                       strparser_kv_t *kv) {
    if (!input || !kv) {
        return STRPARSER_ERR_NULL;
    }

    if (input_len == 0) {
        return STRPARSER_ERR_EMPTY;
    }

    /* Find the '=' separator */
    const char *eq = NULL;
    for (size_t i = 0; i < input_len; i++) {
        if (input[i] == '=') {
            eq = &input[i];
            break;
        }
    }

    if (!eq) {
        return STRPARSER_ERR_FORMAT;
    }

    /* Extract key */
    size_t key_len = eq - input;
    if (key_len >= sizeof(kv->key)) {
        key_len = sizeof(kv->key) - 1;
    }

    /* Trim leading whitespace from key */
    const char *key_start = input;
    while (key_start < eq && isspace((unsigned char)*key_start)) {
        key_start++;
        key_len--;
    }

    /* Trim trailing whitespace from key */
    while (key_len > 0 && isspace((unsigned char)key_start[key_len - 1])) {
        key_len--;
    }

    if (key_len >= sizeof(kv->key)) {
        key_len = sizeof(kv->key) - 1;
    }

    memcpy(kv->key, key_start, key_len);
    kv->key[key_len] = '\0';

    /* Extract value */
    const char *val_start = eq + 1;
    size_t val_len = (input + input_len) - val_start;

    /* Trim leading whitespace from value */
    while (val_len > 0 && isspace((unsigned char)*val_start)) {
        val_start++;
        val_len--;
    }

    /* Trim trailing whitespace from value */
    while (val_len > 0 && isspace((unsigned char)val_start[val_len - 1])) {
        val_len--;
    }

    if (val_len >= sizeof(kv->value)) {
        val_len = sizeof(kv->value) - 1;
    }

    memcpy(kv->value, val_start, val_len);
    kv->value[val_len] = '\0';

    return STRPARSER_OK;
}

int strparser_parse_kv_list(const char *input, size_t input_len,
                            char delimiter, strparser_kv_t *kvs,
                            size_t max_kvs, size_t *num_kvs) {
    if (!input || !kvs || !num_kvs) {
        return STRPARSER_ERR_NULL;
    }

    *num_kvs = 0;

    if (input_len == 0 || max_kvs == 0) {
        return STRPARSER_OK;
    }

    strparser_token_t tokens[STRPARSER_MAX_TOKENS];
    size_t num_tokens;

    int ret = strparser_split(input, input_len, delimiter,
                              tokens, STRPARSER_MAX_TOKENS, &num_tokens);
    if (ret != STRPARSER_OK) {
        return ret;
    }

    for (size_t i = 0; i < num_tokens && *num_kvs < max_kvs; i++) {
        if (tokens[i].length > 0) {
            ret = strparser_parse_kv(tokens[i].start, tokens[i].length,
                                     &kvs[*num_kvs]);
            if (ret == STRPARSER_OK) {
                (*num_kvs)++;
            }
            /* Skip invalid key-value pairs */
        }
    }

    return STRPARSER_OK;
}

int strparser_url_decode(const char *input, size_t input_len,
                         char *output, size_t output_len,
                         size_t *decoded_len) {
    if (!input || !output || !decoded_len) {
        return STRPARSER_ERR_NULL;
    }

    if (output_len == 0) {
        return STRPARSER_ERR_OVERFLOW;
    }

    *decoded_len = 0;
    size_t i = 0;

    while (i < input_len && *decoded_len < output_len - 1) {
        if (input[i] == '%' && i + 2 < input_len &&
            is_hex_digit(input[i + 1]) && is_hex_digit(input[i + 2])) {
            /* Percent-encoded character */
            int hi = hex_to_int(input[i + 1]);
            int lo = hex_to_int(input[i + 2]);
            output[*decoded_len] = (char)((hi << 4) | lo);
            (*decoded_len)++;
            i += 3;
        } else if (input[i] == '+') {
            /* Plus sign represents space */
            output[*decoded_len] = ' ';
            (*decoded_len)++;
            i++;
        } else {
            /* Regular character */
            output[*decoded_len] = input[i];
            (*decoded_len)++;
            i++;
        }
    }

    output[*decoded_len] = '\0';

    if (i < input_len) {
        return STRPARSER_ERR_OVERFLOW;
    }

    return STRPARSER_OK;
}

int strparser_hex_decode(const char *input, size_t input_len,
                         uint8_t *output, size_t output_len,
                         size_t *decoded_len) {
    if (!input || !output || !decoded_len) {
        return STRPARSER_ERR_NULL;
    }

    *decoded_len = 0;

    /* Hex string must have even length */
    if (input_len % 2 != 0) {
        return STRPARSER_ERR_FORMAT;
    }

    size_t expected_bytes = input_len / 2;
    if (expected_bytes > output_len) {
        return STRPARSER_ERR_OVERFLOW;
    }

    for (size_t i = 0; i < input_len; i += 2) {
        if (!is_hex_digit(input[i]) || !is_hex_digit(input[i + 1])) {
            return STRPARSER_ERR_FORMAT;
        }

        int hi = hex_to_int(input[i]);
        int lo = hex_to_int(input[i + 1]);
        output[*decoded_len] = (uint8_t)((hi << 4) | lo);
        (*decoded_len)++;
    }

    return STRPARSER_OK;
}

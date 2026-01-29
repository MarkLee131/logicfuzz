/*
 * strparser.h - Simple String Parser Library
 * A demonstration library for fuzzing with LogicFuzz
 */

#ifndef STRPARSER_H
#define STRPARSER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Error codes */
#define STRPARSER_OK            0
#define STRPARSER_ERR_NULL     -1
#define STRPARSER_ERR_EMPTY    -2
#define STRPARSER_ERR_FORMAT   -3
#define STRPARSER_ERR_OVERFLOW -4
#define STRPARSER_ERR_MEMORY   -5

/* Maximum sizes */
#define STRPARSER_MAX_TOKENS   256
#define STRPARSER_MAX_LINE     4096

/* Token structure */
typedef struct {
    const char *start;
    size_t length;
} strparser_token_t;

/* Key-value pair structure */
typedef struct {
    char key[128];
    char value[256];
} strparser_kv_t;

/* Result structure for parsed integers */
typedef struct {
    int *values;
    size_t count;
    size_t capacity;
} strparser_int_list_t;

/*
 * Parse a comma-separated list of integers.
 *
 * @param input     Input string (e.g., "1,2,3,4,5")
 * @param input_len Length of input string
 * @param result    Output structure for parsed integers
 * @return          STRPARSER_OK on success, error code on failure
 */
int strparser_parse_int_list(const char *input, size_t input_len,
                             strparser_int_list_t *result);

/*
 * Free resources allocated by strparser_parse_int_list.
 */
void strparser_free_int_list(strparser_int_list_t *result);

/*
 * Split a string by delimiter into tokens.
 *
 * @param input     Input string to split
 * @param input_len Length of input string
 * @param delimiter Delimiter character
 * @param tokens    Output array of tokens
 * @param max_tokens Maximum number of tokens to extract
 * @param num_tokens Output: actual number of tokens found
 * @return          STRPARSER_OK on success, error code on failure
 */
int strparser_split(const char *input, size_t input_len, char delimiter,
                    strparser_token_t *tokens, size_t max_tokens,
                    size_t *num_tokens);

/*
 * Parse a key=value format string.
 *
 * @param input     Input string (e.g., "name=value")
 * @param input_len Length of input string
 * @param kv        Output key-value pair
 * @return          STRPARSER_OK on success, error code on failure
 */
int strparser_parse_kv(const char *input, size_t input_len,
                       strparser_kv_t *kv);

/*
 * Parse multiple key=value pairs separated by delimiter.
 *
 * @param input     Input string (e.g., "key1=val1;key2=val2")
 * @param input_len Length of input string
 * @param delimiter Delimiter between key-value pairs
 * @param kvs       Output array of key-value pairs
 * @param max_kvs   Maximum number of pairs to parse
 * @param num_kvs   Output: actual number of pairs parsed
 * @return          STRPARSER_OK on success, error code on failure
 */
int strparser_parse_kv_list(const char *input, size_t input_len,
                            char delimiter, strparser_kv_t *kvs,
                            size_t max_kvs, size_t *num_kvs);

/*
 * Decode URL-encoded string (percent decoding).
 *
 * @param input      Input URL-encoded string
 * @param input_len  Length of input string
 * @param output     Output buffer for decoded string
 * @param output_len Size of output buffer
 * @param decoded_len Output: length of decoded string
 * @return           STRPARSER_OK on success, error code on failure
 */
int strparser_url_decode(const char *input, size_t input_len,
                         char *output, size_t output_len,
                         size_t *decoded_len);

/*
 * Parse a simple hex string into bytes.
 *
 * @param input      Input hex string (e.g., "48656c6c6f")
 * @param input_len  Length of input string
 * @param output     Output buffer for decoded bytes
 * @param output_len Size of output buffer
 * @param decoded_len Output: number of bytes decoded
 * @return           STRPARSER_OK on success, error code on failure
 */
int strparser_hex_decode(const char *input, size_t input_len,
                         uint8_t *output, size_t output_len,
                         size_t *decoded_len);

#ifdef __cplusplus
}
#endif

#endif /* STRPARSER_H */

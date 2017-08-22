typedef enum { REPGP_INPUT_FILE, REPGP_INPUT_STDIN, REPGP_INPUT_BUFFER } repgp_input_t;

struct repgp_stream {
    repgp_input_t type;

    union {
        /* Used by REPGP_INPUT_FILE */
        char *filepath;

        /* Used by REPGP_INPUT_STDIN */
        struct stdin_input {
            size_t         size;
            unsigned char *in;
        } std_in;
    };
};

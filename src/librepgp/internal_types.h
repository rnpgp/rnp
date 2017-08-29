typedef enum {

    /* Operates on standard input/output */
    REPGP_STREAM_FILE,

    /* Stores filepath to file */
    REPGP_STREAM_STD,

    /* Operates on memory buffer */
    REPGP_STREAM_BUFFER

} repgp_stream_type_t;

struct repgp_stream {
    repgp_stream_type_t type;

    union {
        /* Used by REPGP_STREAM_FILE */
        char *filepath;

        /* Used by REPGP_STREAM_STD
         * or REPGP_STREAM_BUFFER */
        struct {
            unsigned char *data;
            size_t         size;
        } std, buffer;
    };
};

struct repgp_io {
    struct repgp_stream *in;
    struct repgp_stream *out;
};

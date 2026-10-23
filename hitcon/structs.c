/*
 * msgpack-c structs for reversing / GDB understanding
 *
 * This is a reverse-engineering-friendly C file.
 * It is not the full msgpack-c source code; it contains the important
 * structs you usually see in memory after msgpack parsing.
 *
 * On x86-64, common sizes:
 *   sizeof(msgpack_object)    == 0x18
 *   sizeof(msgpack_object_kv) == 0x30
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* ============================================================
 * msgpack_object.type numbers
 * ============================================================
 *
 * These are the numbers you see in GDB after msgpack parses data.
 */

typedef enum msgpack_object_type {
    MSGPACK_OBJECT_NIL              = 0,   /* Python: None */
    MSGPACK_OBJECT_BOOLEAN          = 1,   /* Python: True / False */
    MSGPACK_OBJECT_POSITIVE_INTEGER = 2,   /* Python: 123 */
    MSGPACK_OBJECT_NEGATIVE_INTEGER = 3,   /* Python: -123 */

    MSGPACK_OBJECT_FLOAT64          = 4,   /* Python: 1.23 */
    MSGPACK_OBJECT_FLOAT            = 4,

    MSGPACK_OBJECT_STR              = 5,   /* Python: "AAAA" */
    MSGPACK_OBJECT_ARRAY            = 6,   /* Python: ["A", "B"] */
    MSGPACK_OBJECT_MAP              = 7,   /* Python: {"key": "value"} */
    MSGPACK_OBJECT_BIN              = 8,   /* Python: b"AAAA" */
    MSGPACK_OBJECT_EXT              = 9,   /* Python: msgpack.ExtType(1, b"AAAA") */

    MSGPACK_OBJECT_FLOAT32          = 10   /* rarely used by Python packer */
} msgpack_object_type;


/* ============================================================
 * Forward declarations
 * ============================================================ */

struct msgpack_object;
struct msgpack_object_kv;
struct msgpack_zone;


/* ============================================================
 * msgpack_object sub-structs
 * ============================================================ */

/*
 * Used when:
 *   obj.type == MSGPACK_OBJECT_ARRAY
 *   obj.type == 6
 *
 * GDB layout inside msgpack_object:
 *   obj + 0x08 = array.size
 *   obj + 0x10 = array.ptr
 */
typedef struct msgpack_object_array {
    uint32_t size;                  /* number of elements */
    struct msgpack_object *ptr;     /* pointer to msgpack_object array */
} msgpack_object_array;


/*
 * Used when:
 *   obj.type == MSGPACK_OBJECT_MAP
 *   obj.type == 7
 *
 * GDB layout inside msgpack_object:
 *   obj + 0x08 = map.size
 *   obj + 0x10 = map.ptr
 */
typedef struct msgpack_object_map {
    uint32_t size;                  /* number of key-value pairs */
    struct msgpack_object_kv *ptr;  /* pointer to msgpack_object_kv array */
} msgpack_object_map;


/*
 * Used when:
 *   obj.type == MSGPACK_OBJECT_STR
 *   obj.type == 5
 *
 * Example Python:
 *   "deadbeef"
 */
typedef struct msgpack_object_str {
    uint32_t size;                  /* string length */
    const char *ptr;                /* pointer to string bytes */
} msgpack_object_str;


/*
 * Used when:
 *   obj.type == MSGPACK_OBJECT_BIN
 *   obj.type == 8
 *
 * Example Python:
 *   b"AAAA"
 */
typedef struct msgpack_object_bin {
    uint32_t size;                  /* byte length */
    const char *ptr;                /* pointer to raw bytes */
} msgpack_object_bin;


/*
 * Used when:
 *   obj.type == MSGPACK_OBJECT_EXT
 *   obj.type == 9
 *
 * Example Python:
 *   msgpack.ExtType(1, b"AAAA")
 */
typedef struct msgpack_object_ext {
    int8_t type;                    /* extension type id */
    uint32_t size;                  /* ext data size */
    const char *ptr;                /* pointer to ext data */
} msgpack_object_ext;


/* ============================================================
 * Main msgpack_object
 * ============================================================
 *
 * A msgpack_object is:
 *   type + union
 *
 * The type tells you which union field to read.
 *
 * Examples:
 *
 *   obj.type == 2:
 *       read obj.via.u64
 *
 *   obj.type == 5:
 *       read obj.via.str.size
 *       read obj.via.str.ptr
 *
 *   obj.type == 6:
 *       read obj.via.array.size
 *       read obj.via.array.ptr
 *
 *   obj.type == 7:
 *       read obj.via.map.size
 *       read obj.via.map.ptr
 */

typedef union msgpack_object_union {
    bool boolean;                   /* type 1 */
    uint64_t u64;                   /* type 2 */
    int64_t i64;                    /* type 3 */
    double f64;                     /* type 4 */

    msgpack_object_array array;     /* type 6 */
    msgpack_object_map map;         /* type 7 */
    msgpack_object_str str;         /* type 5 */
    msgpack_object_bin bin;         /* type 8 */
    msgpack_object_ext ext;         /* type 9 */
} msgpack_object_union;


typedef struct msgpack_object {
    msgpack_object_type type;       /* 0,1,2,3,4,5,6,7,8,9,10 */
    msgpack_object_union via;       /* interpreted based on type */
} msgpack_object;


/*
 * Used when object is a map.
 *
 * One map entry:
 *   key = msgpack_object
 *   val = msgpack_object
 *
 * On x86-64:
 *   sizeof(msgpack_object)    is usually 0x18
 *   sizeof(msgpack_object_kv) is usually 0x30
 */
typedef struct msgpack_object_kv {
    msgpack_object key;
    msgpack_object val;
} msgpack_object_kv;


/* ============================================================
 * msgpack_unpacked
 * ============================================================
 *
 * This is the parsed result wrapper.
 *
 * You may see this on stack:
 *
 *   +0x00 zone pointer
 *   +0x08 root object type
 *   +0x10 root object size / integer / etc
 *   +0x18 root object ptr
 *
 * Example:
 *
 *   +0x00 -> 0x555555821a30
 *   +0x08 = 7
 *   +0x10 = 2
 *   +0x18 -> 0x555555821a78
 *
 * Means:
 *
 *   unpacked.zone = 0x555555821a30;
 *   unpacked.data.type = MSGPACK_OBJECT_MAP;
 *   unpacked.data.via.map.size = 2;
 *   unpacked.data.via.map.ptr = 0x555555821a78;
 */

typedef struct msgpack_unpacked {
    struct msgpack_zone *zone;      /* arena / memory pool */
    msgpack_object data;            /* root parsed object */
} msgpack_unpacked;


/* ============================================================
 * msgpack_zone
 * ============================================================
 *
 * msgpack_zone is an arena / memory pool.
 * Parsed strings, arrays, maps, and key-value objects can live in it.
 */

typedef struct msgpack_zone_finalizer {
    void (*func)(void *data);
    void *data;
} msgpack_zone_finalizer;


typedef struct msgpack_zone_finalizer_array {
    msgpack_zone_finalizer *tail;
    msgpack_zone_finalizer *end;
    msgpack_zone_finalizer *array;
} msgpack_zone_finalizer_array;


typedef struct msgpack_zone_chunk {
    struct msgpack_zone_chunk *next;
} msgpack_zone_chunk;


typedef struct msgpack_zone_chunk_list {
    size_t free;                    /* remaining bytes in current chunk */
    char *ptr;                      /* current allocation pointer */
    msgpack_zone_chunk *head;       /* chunk list head */
} msgpack_zone_chunk_list;


/*
 * x86-64 layout:
 *
 *   +0x00 chunk_list.free
 *   +0x08 chunk_list.ptr
 *   +0x10 chunk_list.head
 *   +0x18 finalizer_array.tail
 *   +0x20 finalizer_array.end
 *   +0x28 finalizer_array.array
 *   +0x30 chunk_size
 */
typedef struct msgpack_zone {
    msgpack_zone_chunk_list chunk_list;
    msgpack_zone_finalizer_array finalizer_array;
    size_t chunk_size;
} msgpack_zone;

typedef struct msg_unpacker {
    char *buffer;
    size_t used;
    size_t free;
    size_t off;
    size_t parsed;
    msgpack_zone *z;
    size_t initial_buffer_size;
    void *ctx;
} msg_unpacker;

void msgpack_unpacker_destroy(msg_unpacker *mpac)
{
    msgpack_zone_free(mpac->z);
    free(mpac->ctx);
    decr_count(mpac->buffer);
}

/* ============================================================
 * Simplified msgpack_unpack_context
 * ============================================================
 *
 * This one is internal and can vary by msgpack-c version.
 * For reversing, this layout is useful enough to recognize parser state.
 */

typedef struct msgpack_unpack_user {
    msgpack_zone **z;
    bool referenced;
} msgpack_unpack_user;


typedef struct msgpack_unpack_stack {
    msgpack_object obj;             /* current array/map object */
    size_t count;                   /* remaining items / pairs */
    unsigned int ct;                /* container state */
    msgpack_object map_key;         /* saved key while parsing map value */
} msgpack_unpack_stack;


#define MSGPACK_EMBED_STACK_SIZE 32


/*
 * Approx x86-64 layout:
 *
 *   +0x00 user.z
 *   +0x08 user.referenced
 *   +0x10 cs
 *   +0x14 trail
 *   +0x18 top
 *   +0x20 stack[0]
 *
 * Each stack entry is around:
 *
 *   +0x00 obj
 *   +0x18 count
 *   +0x20 ct
 *   +0x28 map_key
 */
typedef struct msgpack_unpack_context {
    msgpack_unpack_user user;
    unsigned int cs;                /* current parser state */
    unsigned int trail;             /* remaining bytes needed */
    unsigned int top;               /* stack depth */
    msgpack_unpack_stack stack[MSGPACK_EMBED_STACK_SIZE];
} msgpack_unpack_context;


/* ============================================================
 * Optional compile-time size checks for x86-64
 * ============================================================
 *
 * Compile test:
 *   gcc -DTEST_MSGPACK_STRUCTS msgpack_c_structs.c -o test
 */

#ifdef TEST_MSGPACK_STRUCTS
#include <stdio.h>

int main(void) {
    printf("sizeof(msgpack_object)         = 0x%zx\n", sizeof(msgpack_object));
    printf("sizeof(msgpack_object_kv)      = 0x%zx\n", sizeof(msgpack_object_kv));
    printf("sizeof(msgpack_object_array)   = 0x%zx\n", sizeof(msgpack_object_array));
    printf("sizeof(msgpack_object_map)     = 0x%zx\n", sizeof(msgpack_object_map));
    printf("sizeof(msgpack_object_str)     = 0x%zx\n", sizeof(msgpack_object_str));
    printf("sizeof(msgpack_object_bin)     = 0x%zx\n", sizeof(msgpack_object_bin));
    printf("sizeof(msgpack_object_ext)     = 0x%zx\n", sizeof(msgpack_object_ext));
    printf("sizeof(msgpack_unpacked)       = 0x%zx\n", sizeof(msgpack_unpacked));
    printf("sizeof(msgpack_zone)           = 0x%zx\n", sizeof(msgpack_zone));
    printf("sizeof(msgpack_unpack_stack)   = 0x%zx\n", sizeof(msgpack_unpack_stack));
    printf("sizeof(msgpack_unpack_context) = 0x%zx\n", sizeof(msgpack_unpack_context));
    return 0;
}
#endif

struct packet{
    long long mode;
    char pad1[8];
    long long *name_ptr;
    char pad2[248]; 
    long long fd_packet;
    short blksize; // 280
    char pad3[2];
    int tsize; // 284
    char timeout; // 288
    char pad4;
    int sign; // 292

    char dest_host[0x10];// 206
    int client_len;
    
    int state;
    char error[0x200]; // 320
};

typedef union msgpack_object_union {
    bool boolean;                   /* type 1 */
    uint64_t u64;                   /* type 2 */
    int64_t i64;                    /* type 3 */
    double f64;                     /* type 4 */

    msgpack_object_array array;     /* type 6 */
    msgpack_object_map map;         /* type 7 */
    msgpack_object_str str;         /* type 5 */
    msgpack_object_bin bin;         /* type 8 */
    msgpack_object_ext ext;         /* type 9 */
} msgpack_object_union;


typedef struct msgpack_object {
    msgpack_object_type type;       /* 0,1,2,3,4,5,6,7,8,9,10 */
    msgpack_object_union via;       /* interpreted based on type */
} msgpack_object;

typedef struct msgpack_object_kv {
    msgpack_object key;
    msgpack_object val;
} msgpack_object_kv;

struct req
{
    
};


struct  sbuffer
{
    long long used;
    long long ptr;
    long long size;
};


struct opt{
    char name[0x3f];
    __int16_t value; 
};

struct stat{
    st.st_size   // file size
    st.st_mode   // file type + permissions
    st.st_uid    // owner user id
    st.st_gid    // owner group id
    st.st_mtime  // last modified time
}

typedef struct _IO_FILE FILE;

struct _IO_FILE
{
    int _flags;                    // 0x00

    char *_IO_read_ptr;            // 0x08
    char *_IO_read_end;            // 0x10
    char *_IO_read_base;           // 0x18

    char *_IO_write_base;          // 0x20
    char *_IO_write_ptr;           // 0x28
    char *_IO_write_end;           // 0x30

    char *_IO_buf_base;            // 0x38
    char *_IO_buf_end;             // 0x40

    char *_IO_save_base;           // 0x48
    char *_IO_backup_base;         // 0x50
    char *_IO_save_end;            // 0x58

    struct _IO_marker *_markers;   // 0x60
    struct _IO_FILE *_chain;       // 0x68

    int _fileno;                   // 0x70
    int _flags2;                   // 0x74

    __off_t _old_offset;           // 0x78

    unsigned short _cur_column;    // 0x80
    signed char _vtable_offset;    // 0x82
    char _shortbuf[1];             // 0x83

    _IO_lock_t *_lock;             // 0x88

    __off64_t _offset;             // 0x90

    struct _IO_codecvt *_codecvt;  // 0x98
    struct _IO_wide_data *_wide_data; // 0xa0

    struct _IO_FILE *_freeres_list; // 0xa8
    void *_freeres_buf;            // 0xb0

    size_t __pad5;                 // 0xb8
    int _mode;                     // 0xc0

    char _unused2[
        15 * sizeof(int)
        - 4 * sizeof(void *)
        - sizeof(size_t)
    ];                             // 0xc4
};                                  // sizeof = 0xd8 on x86-64

struct _IO_FILE_plus
{
    struct _IO_FILE file;           // 0x00
    const struct _IO_jump_t *vtable;// 0xd8
};                                  // sizeof = 0xe0 on x86-64

struct _IO_FILE_plus
{
    FILE file;
    const struct _IO_jump_t *vtable;
};

struct packer_t {
    char *sbuffer;
    char *sbuffer_write_func;
}
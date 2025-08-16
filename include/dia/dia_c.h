#ifndef DIA_C_H
#define DIA_C_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DIA_OK  0
#define DIA_ERR (-1)

// Initialize the underlying pairing library. Must be called once.
void init_dia();

// Frees any buffer previously allocated by the library.
void free_byte_buffer(unsigned char* buf);

#ifdef __cplusplus
}
#endif

#endif // DIA_C_H

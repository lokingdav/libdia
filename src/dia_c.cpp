#include "dia/dia_c.h"
#include "dia/dia.hpp"
#include <vector>
#include <cstring>
#include <string>

// Helper to copy a C++ Bytes vector to a newly allocated C buffer
void copy_to_c_buf(const ecgroup::Bytes& vec, unsigned char** buf_out, size_t* len_out) {
    *len_out = vec.size();
    *buf_out = new unsigned char[*len_out];
    memcpy(*buf_out, vec.data(), *len_out);
}

void init_dia() {
    ecgroup::init_pairing();
}

void free_byte_buffer(unsigned char* buf) {
    delete[] buf;
}

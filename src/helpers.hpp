#ifndef DIA_HELPERS_HPP
#define DIA_HELPERS_HPP

#include "crypto/ecgroup.hpp"
#include <cstddef>
#include <cstdint>
#include <string>
#include <initializer_list>
#include <vector>

namespace dia {
namespace utils {

    // Existing hex helpers
    std::string bytes_to_hex(const ecgroup::Bytes& bytes);
    ecgroup::Bytes hex_to_bytes(const std::string& hex);

    // Generic serialization primitives
    ecgroup::Bytes to_bytes(const std::string& s);

    void        append_u32_be(ecgroup::Bytes& out, uint32_t v);
    uint32_t    read_u32_be(const ecgroup::Bytes& in, std::size_t& off);

    void            append_lp(ecgroup::Bytes& out, const ecgroup::Bytes& b);
    ecgroup::Bytes  read_lp(const ecgroup::Bytes& in, std::size_t& off);

    // Strings as LP
    std::string read_string(const ecgroup::Bytes& in, std::size_t& off);

    // Hash utilities (SHA-256)
    ecgroup::Bytes hash_all(std::initializer_list<ecgroup::Bytes> inputs);
    ecgroup::Bytes hash_all(const std::vector<ecgroup::Bytes>& inputs);

    // Concatenate bytes
    ecgroup::Bytes concat_bytes(const ecgroup::Bytes& a, const ecgroup::Bytes& b);

} // namespace utils
} // namespace dia

#endif // DIA_HELPERS_HPP

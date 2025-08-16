#ifndef DIA_HELPERS_HPP
#define DIA_HELPERS_HPP

#include "ecgroup.hpp"

namespace dia {
namespace utils {

    std::string bytes_to_hex(const ecgroup::Bytes& bytes);
    ecgroup::Bytes hex_to_bytes(const std::string& hex);

} // namespace utils
} // namespace dia

#endif // DIA_HELPERS_HPP
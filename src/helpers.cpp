#include "helpers.hpp"
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace dia {
namespace utils {

std::string bytes_to_hex(const ecgroup::Bytes& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (const auto& byte : bytes) ss << std::setw(2) << static_cast<int>(byte);
    return ss.str();
}

ecgroup::Bytes hex_to_bytes(const std::string& hex) {
    if (hex.length() % 2 != 0) throw std::invalid_argument("Hex string length must be even.");
    ecgroup::Bytes bytes;
    bytes.reserve(hex.length() / 2);
    for (unsigned i = 0; i < hex.length(); i += 2) {
        uint8_t byte = static_cast<uint8_t>(std::strtol(hex.substr(i, 2).c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

using ecgroup::Bytes;

Bytes to_bytes(const std::string& s) {
    return Bytes(s.begin(), s.end());
}

void append_u32_be(Bytes& out, uint32_t v) {
    out.push_back(uint8_t((v >> 24) & 0xFF));
    out.push_back(uint8_t((v >> 16) & 0xFF));
    out.push_back(uint8_t((v >>  8) & 0xFF));
    out.push_back(uint8_t((v >>  0) & 0xFF));
}

uint32_t read_u32_be(const Bytes& in, std::size_t& off) {
    if (off + 4 > in.size()) throw std::runtime_error("decode: truncated u32");
    uint32_t v = (uint32_t(in[off+0]) << 24) |
                 (uint32_t(in[off+1]) << 16) |
                 (uint32_t(in[off+2]) <<  8) |
                 (uint32_t(in[off+3]) <<  0);
    off += 4;
    return v;
}

void append_lp(Bytes& out, const Bytes& b) {
    append_u32_be(out, static_cast<uint32_t>(b.size()));
    out.insert(out.end(), b.begin(), b.end());
}

Bytes read_lp(const Bytes& in, std::size_t& off) {
    uint32_t n = read_u32_be(in, off);
    if (off + n > in.size()) throw std::runtime_error("decode: truncated lp");
    Bytes out(in.begin() + off, in.begin() + off + n);
    off += n;
    return out;
}

std::string read_string(const Bytes& in, std::size_t& off) {
    Bytes b = read_lp(in, off);
    return std::string(b.begin(), b.end());
}

} // namespace utils
} // namespace dia

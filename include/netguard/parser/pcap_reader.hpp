#pragma once

#include "netguard/core/packet.hpp"
#include "netguard/parser/headers.hpp"
#include <string>
#include <fstream>
#include <vector>
#include <memory>
#include <functional>

namespace netguard {

class PCAPReader {
public:
    explicit PCAPReader(std::string filepath);
    ~PCAPReader();

    bool open();
    void close();
    bool is_open() const;

    bool read_next_packet(RawPacket& packet);
    std::vector<RawPacket> read_all();

    uint32_t snaplen() const { return global_header_.snaplen; }
    uint32_t link_type() const { return global_header_.network; }
    bool is_nanosecond() const { return is_nanosecond_; }

private:
    std::string filepath_;
    std::ifstream file_;
    RawPCAPHeader global_header_{};
    bool is_byteswapped_{false};
    bool is_nanosecond_{false};
    uint64_t packet_counter_{0};

    uint32_t swap32(uint32_t val) const;
    uint16_t swap16(uint16_t val) const;
};

} // namespace netguard

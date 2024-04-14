#pragma once

#include <cstdint>
#include <string>

struct Ip final {
    static const int SIZE = 4;

    // constructor
    Ip() {}
    Ip(const uint32_t r) : ip_(r) {}
    Ip(const std::string r);

    // casting operator
    operator uint32_t() const { return ip_; } // default
    explicit operator std::string() const;

    // comparison operator
    bool operator == (const Ip& r) const { return ip_ == r.ip_; }

    bool isLocalHost() const { // 127.*.*.*
        uint8_t prefix = (ip_ & 0xFF000000) >> 24;
        return prefix == 0x7F;
    }

    bool isBroadcast() const { // 255.255.255.255
        return ip_ == 0xFFFFFFFF;
    }

    bool isMulticast() const { // 224.0.0.0 ~ 239.255.255.255
        uint8_t prefix = (ip_ & 0xFF000000) >> 24;
        return prefix >= 0xE0 && prefix < 0xF0;
    }

protected:
    uint32_t ip_;
};

struct ipv4_hdr
{
#define IPTOS_LOWDELAY      0x10
#define IPTOS_THROUGHPUT    0x08
#define IPTOS_RELIABILITY   0x04
#define IPTOS_LOWCOST       0x02
#define IP_RF 0x8000        /* reserved fragment flag */
#define IP_DF 0x4000        /* dont fragment flag */
#define IP_MF 0x2000        /* more fragments flag */
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */

    u_int8_t VerIHL; /*header length | version*/
    u_int8_t ip_tos;       /* type of service */

    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;

    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    //struct in_addr ip_src, ip_dst; /* source and dest address */
    Ip ip_src, ip_dst;
};

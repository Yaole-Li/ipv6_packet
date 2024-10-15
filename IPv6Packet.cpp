#include "IPv6Packet.h"
#include <iostream>
#include <iomanip> // for std::hex and std::setw
#include <stdexcept>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip6.h>  // 添加这行，用于 struct ip6_hdr 的定义
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <cstring>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <cstdio> // for popen and pclose
#include <sys/types.h>
#include <sys/socket.h>

#ifdef __APPLE__
#include <net/if_dl.h>
#include <net/if_types.h>
#elif defined(__linux__)
#include <linux/if_packet.h>
#endif

// 构造函数：初始化IPv6Packet对象
IPv6Packet::IPv6Packet(const std::string& destMAC, const std::string& destIPv6, 
                       const std::vector<uint8_t>& payload, 
                       const std::vector<uint8_t>& extensionHeaderContent, 
                       bool fragmentFlag,
                       uint16_t fragmentOffset,
                       bool moreFragments,
                       uint32_t identification)
    : destMAC(destMAC), destIPv6(destIPv6), 
      payload(payload), 
      extensionHeaderContent(extensionHeaderContent),
      packetLength(0), packetHeaderAddress(nullptr),
      fragmentFlag(fragmentFlag),
      fragmentOffset(fragmentOffset), 
      moreFragments(moreFragments), 
      identification(identification) {
    fetchLocalMAC();  // 获取本地MAC地址
    fetchLocalIPv6(); // 获取本地IPv6地址
}


// 构造完整的IPv6数据包
void IPv6Packet::constructPacket() {
    std::cout << "---------[constructPacket]---------" << std::endl;
    packet.clear(); // 清空当前数据包内容
    std::cout << "[IPv6Packet.cpp] 初始数据包长度: " << packet.size() << " 字节" << std::endl;

    addIPv6Header(); // 添加IPv6基本头部
    //std::cout << "[IPv6Packet.cpp] 添加IPv6基本头部后数据包长度: " << packet.size() << " 字节" << std::endl;

    if (fragmentFlag) {
        addFragmentHeader(); // 如果需要分片，添加分片头部
        // std::cout << "[IPv6Packet.cpp] 添加分片头部后数据包长度: " << packet.size() << " 字节" << std::endl;
    }

    addExtensionHeader(); // 添加目的选项报头
    // std::cout << "[IPv6Packet.cpp] 添加目的选项报头后数据包长度: " << packet.size() << " 字节" << std::endl;
    
    // 添加负载数据并输出负载内容
    packet.insert(packet.end(), payload.begin(), payload.end());
    // std::cout << "[IPv6Packet.cpp] 添加负载后数据包长度: " << packet.size() << " 字节" << std::endl;

    packetLength = packet.size(); // 更新数据包长度
    packetHeaderAddress = packet.data(); // 设置数据包头部地址

    // 更新IPv6头部中的负载长度字段
    uint16_t payloadLength = packetLength - sizeof(struct ip6_hdr);
    packet[4] = (payloadLength >> 8) & 0xFF;
    packet[5] = payloadLength & 0xFF;

    std::cout << "[IPv6Packet.cpp] 构造的数据包总长度: " << packetLength << " 字节" << std::endl;
    std::cout << "---------[constructPacket End]---------" << std::endl;
}

// 获取构造好的数据包
const std::vector<uint8_t>& IPv6Packet::getPacket() const {
    return packet;
}



// 获取本地MAC地址
void IPv6Packet::fetchLocalMAC() {
    // std::cout << "[IPv6Packet.cpp] 获取本地MAC地址" << std::endl;
    
    struct ifaddrs *ifap, *ifaptr;

    if (getifaddrs(&ifap) == 0) {
        for (ifaptr = ifap; ifaptr != nullptr; ifaptr = ifaptr->ifa_next) {
#ifdef __APPLE__
            if (ifaptr->ifa_addr->sa_family == AF_LINK) {
                struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifaptr->ifa_addr;
                if (sdl->sdl_type == IFT_ETHER) {
                    unsigned char *ptr = (unsigned char *)LLADDR(sdl);
                    char mac[18];
                    snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                            ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
                    srcMAC = mac;
                    // std::cout << "[IPv6Packet.cpp] 本地MAC地址: " << srcMAC << std::endl;
                    freeifaddrs(ifap);
                    return;
                }
            }
#elif defined(__linux__)
            if (ifaptr->ifa_addr->sa_family == AF_PACKET) {
                struct sockaddr_ll *s = (struct sockaddr_ll*)ifaptr->ifa_addr;
                if (s->sll_halen == 6) {
                    char mac[18];
                    snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                             s->sll_addr[0], s->sll_addr[1], s->sll_addr[2],
                             s->sll_addr[3], s->sll_addr[4], s->sll_addr[5]);
                    srcMAC = mac;
                    // std::cout << "[IPv6Packet.cpp] 本地MAC地址: " << srcMAC << std::endl;
                    freeifaddrs(ifap);
                    return;
                }
            }
#endif
        }
        freeifaddrs(ifap);
    }


    throw std::runtime_error("无法获取MAC地址");
}


/*
void IPv6Packet::fetchLocalMAC() {
    std::cout << "[IPv6Packet.cpp] 获取本地MAC地址" << std::endl;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        throw std::runtime_error("无法创建socket");
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    
    // 假设您使用的是 "eth0" 网卡，请根据您的系统修改网卡名称
    strncpy(ifr.ifr_name, "ens33", IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        close(fd);
        throw std::runtime_error("无法获取MAC地址");
    }

    unsigned char* ptr = (unsigned char*)ifr.ifr_hwaddr.sa_data;
    char mac[18];
    snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x", 
             ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);

    srcMAC = mac;
    std::cout << "[IPv6Packet.cpp] 本地MAC地址: " << srcMAC << std::endl;

    close(fd);
}
*/

// 获取本地IPv6地址
void IPv6Packet::fetchLocalIPv6() {
    // std::cout << "[IPv6Packet.cpp] 获取本地IPv6地址" << std::endl;
    struct ifaddrs* ifaddr;
    struct ifaddrs* ifa;
    int family, s;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) {
        throw std::runtime_error("无法获取网络接口");
    }

    bool found = false;
    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr)
            continue;

        family = ifa->ifa_addr->sa_family;

        if (family == AF_INET6) {
            s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in6),
                            host, NI_MAXHOST, nullptr, 0, NI_NUMERICHOST);
            if (s != 0) {
                std::cout << "getnameinfo() 失败: " << gai_strerror(s) << std::endl;
                continue;
            }

            // 忽略链路本地地址和回环地址
            if (strncmp(host, "fe80", 4) == 0 || strcmp(host, "::1") == 0) {
                continue;
            }

            srcIPv6 = host;
            // std::cout << "[IPv6Packet.cpp] 本地IPv6地址: " << srcIPv6 << std::endl;
            found = true;
            break;
        }
    }

    freeifaddrs(ifaddr);

    if (!found) {
        throw std::runtime_error("未找到有效的IPv6地址");
    }
}

// 添加IPv6基本头部
void IPv6Packet::addIPv6Header() {
    std::cout << "[IPv6Packet.cpp] 添加IPv6头部" << std::endl;

    // 版本(4位) + 流量类别(8位) + 流标签(20位)
    uint32_t version_traffic_flow = (6 << 28); // 版本6
    packet.push_back((version_traffic_flow >> 24) & 0xFF);
    packet.push_back((version_traffic_flow >> 16) & 0xFF);
    packet.push_back((version_traffic_flow >> 8) & 0xFF);
    packet.push_back(version_traffic_flow & 0xFF);

    // 负载长度(16位) - 先占位，再填充正确的值
    packet.push_back(0);
    packet.push_back(0);

    // 下一个头部(8位) + 跳数限制(8位)
    packet.push_back(fragmentFlag ? 44 : 60); // 44表示分片头部，60表示目的选项头部
    packet.push_back(64);   // 默认跳数限制

    // 源地址(128位)
    struct in6_addr src_addr;
    inet_pton(AF_INET6, srcIPv6.c_str(), &src_addr);
    packet.insert(packet.end(), src_addr.s6_addr, src_addr.s6_addr + 16);

    // 目的地址(128位)
    struct in6_addr dest_addr;
    inet_pton(AF_INET6, destIPv6.c_str(), &dest_addr);
    packet.insert(packet.end(), dest_addr.s6_addr, dest_addr.s6_addr + 16);

    // 计算并设置正确的负载长度
    uint16_t payload_length = packet.size() - sizeof(struct ip6_hdr);
    if (!payload.empty()) {
        payload_length += payload.size();
    }
    if (!extensionHeaderContent.empty()) {
        payload_length += (extensionHeaderContent.size()+7)/8*8 + 2;  // +2 for the header length and next header fields
    }
    if (fragmentFlag) {
        payload_length += 8;  // 分片头部的长度
    }

    // 更新负载长度字段
    packet[4] = (payload_length >> 8) & 0xFF;
    packet[5] = payload_length & 0xFF;

    std::cout << "[IPv6Packet.cpp] IPv6头部添加完成，负载长度: " << payload_length << " 字节" << std::endl;
}

// 添加分片头部
void IPv6Packet::addFragmentHeader() {
    std::cout << "[IPv6Packet.cpp] 添加分片头部" << std::endl;
    std::cout << "[IPv6Packet.cpp] 分片偏移量: " << fragmentOffset << " (8字节单位)" << std::endl;

    // Next Header (8位) - 指示下一个头部的类型
    packet.push_back(60); // 60表示目的选项头部

    // Reserved (8位)
    packet.push_back(0x00); // 保留字段，设置为0

    // Fragment Offset (13位) + Res (2位) + M Flag (1位)
    uint16_t fragmentOffsetAndFlags = (fragmentOffset << 3);  // 不需要再乘以 8
    if (moreFragments) {
        fragmentOffsetAndFlags |= 1;
    }
    std::cout << "[IPv6Packet.cpp] 分片偏移和标志: 0x" << std::hex << fragmentOffsetAndFlags << std::dec << std::endl;
    packet.push_back((fragmentOffsetAndFlags >> 8) & 0xFF);
    packet.push_back(fragmentOffsetAndFlags & 0xFF);

    // Identification (32位)
    packet.push_back((identification >> 24) & 0xFF);
    packet.push_back((identification >> 16) & 0xFF);
    packet.push_back((identification >> 8) & 0xFF);
    packet.push_back(identification & 0xFF);

    std::cout << "[IPv6Packet.cpp] 分片标识: " << identification << std::endl;
}

// 添加目的选项报头
void IPv6Packet::addExtensionHeader() {
    std::cout << "---------[addExtensionHeader]---------" << std::endl;
    std::cout << "[IPv6Packet.cpp] 添加目的选项报头" << std::endl;
    size_t initialSize = packet.size();

    // Next Header (8位) - 指示下一个头部的类型
    packet.push_back(0x3B); // No Next Header
    // std::cout << "添加 Next Header 后大小: " << packet.size() - initialSize << " 字节" << std::endl;

    // 计算填充长度
    uint8_t paddingLength = (8 - ((extensionHeaderContent.size() + 2) % 8)) % 8;

    // Header Extension Length (8位) - 以8字节为单位，不包括前8个字节
    uint8_t hdr_ext_len = (2 + extensionHeaderContent.size() + paddingLength) / 8 - 1;
    packet.push_back(hdr_ext_len);
    // std::cout << "添加 Header Extension Length 后大小: " << packet.size() - initialSize << " 字节" << std::endl;

    // 添加选项类型和选项长度
    packet.push_back(0x00);
    packet.push_back(static_cast<uint8_t>(extensionHeaderContent.size()));
    // std::cout << "添加选项类型和长度后大小: " << packet.size() - initialSize << " 字节" << std::endl;

    // 添加选项内容
    packet.insert(packet.end(), extensionHeaderContent.begin(), extensionHeaderContent.end());
    // std::cout << "添加选项内容后大小: " << packet.size() - initialSize << " 字节" << std::endl;

    // 添加填充
    for (uint8_t i = 0; i < paddingLength; ++i) {
        packet.push_back(0x00);
    }
    // std::cout << "添加填充后大小: " << packet.size() - initialSize << " 字节" << std::endl;

    std::cout << "[IPv6Packet.cpp] 目的选项报头总长度: " << packet.size() - initialSize << " 字节" << std::endl;
    // std::cout << "[IPv6Packet.cpp] 添加的填充长度: " << static_cast<int>(paddingLength) << " 字节" << std::endl;
    std::cout << "---------[addExtensionHeader End]---------" << std::endl;
}

// 输出数据包的详细信息
void IPv6Packet::printPacketDetails() const {
    std::cout << "[IPv6Packet.cpp] 数据包详细信息：" << std::endl;
    std::cout << "源MAC地址: " << srcMAC << std::endl;
    std::cout << "目标MAC地址: " << destMAC << std::endl;
    std::cout << "源IPv6地址: " << srcIPv6 << std::endl;
    std::cout << "目标IPv6地址: " << destIPv6 << std::endl;
    std::cout << "是否分片: " << (fragmentFlag ? "是" : "否") << std::endl;

    std::cout << "扩展头部内容: ";
    for (const auto& byte : extensionHeaderContent) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
    }
    std::cout << std::endl;

    std::cout << "负载内容: ";
    for (const auto& byte : payload) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
    }
    std::cout << std::endl;
}
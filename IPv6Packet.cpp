#include "IPv6Packet.h"
#include <iostream>
#include <iomanip> // for std::hex and std::setw
#include <stdexcept>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <cstring>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <cstdio> // for popen and pclose
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if_dl.h>
#include <net/if_types.h>  // 添加这行来包含 IFT_ETHER 的定义

// 构造函数：初始化IPv6Packet对象
IPv6Packet::IPv6Packet(const std::string& destMAC, const std::string& destIPv6, const std::vector<uint8_t>& payload, const std::vector<uint8_t>& extensionHeaderContent, bool fragmentFlag,
                        uint16_t fragmentOffset,
                        bool moreFragments,
                        uint32_t identification)
    : destMAC(destMAC), destIPv6(destIPv6), payload(payload), 
      extensionHeaderContent(extensionHeaderContent), fragmentFlag(fragmentFlag),
      fragmentOffset(fragmentOffset), moreFragments(moreFragments), 
      identification(identification), packetLength(0), packetHeaderAddress(nullptr) {
    fetchLocalMAC();  // 获取本地MAC地址
    fetchLocalIPv6(); // 获取本地IPv6地址
}

// 构造完整的IPv6数据包
void IPv6Packet::constructPacket() {
    packet.clear(); // 清空当前数据包内容
    addIPv6Header(); // 添加IPv6基本头部
    if (fragmentFlag) {
        addFragmentHeader(); // 如果需要分片，添加分片头部
    }
    addExtensionHeader(); // 添加目的选项报头
    packet.insert(packet.end(), payload.begin(), payload.end()); // 添加负载数据
    packetLength = packet.size(); // 更新数据包长度
    packetHeaderAddress = packet.data(); // 设置数据包头部地址
}

// 获取构造好的数据包
const std::vector<uint8_t>& IPv6Packet::getPacket() const {
    return packet;
}

// 获取本地MAC地址
void IPv6Packet::fetchLocalMAC() {
    std::cout << "[IPv6Packet.cpp] 获取本地MAC地址" << std::endl;
    
    struct ifaddrs *ifap, *ifaptr;
    unsigned char *ptr;

    if (getifaddrs(&ifap) == 0) {
        for (ifaptr = ifap; ifaptr != nullptr; ifaptr = ifaptr->ifa_next) {
            if (ifaptr->ifa_addr->sa_family == AF_LINK) {
                struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifaptr->ifa_addr;
                if (sdl->sdl_type == IFT_ETHER) {
                    ptr = (unsigned char *)LLADDR(sdl);
                    char mac[18];
                    snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x", 
                             ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
                    srcMAC = mac;
                    std::cout << "[IPv6Packet.cpp] 本地MAC地址: " << srcMAC << std::endl;
                    freeifaddrs(ifap);
                    return;
                }
            }
        }
        freeifaddrs(ifap);
    }

    throw std::runtime_error("无法获取MAC地址");
}

// 获取本地IPv6地址
void IPv6Packet::fetchLocalIPv6() {
    std::cout << "[IPv6Packet.cpp] 获取本地IPv6地址" << std::endl;
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
            std::cout << "[IPv6Packet.cpp] 本地IPv6地址: " << srcIPv6 << std::endl;
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

    // 负载长度(16位)
    uint16_t payload_length = payload.size() + extensionHeaderContent.size();
    if (fragmentFlag) {
        payload_length += 8; // 分片头部长度
    }
    packet.push_back((payload_length >> 8) & 0xFF);
    packet.push_back(payload_length & 0xFF);

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
}

// 添加分片头部
void IPv6Packet::addFragmentHeader() {
    std::cout << "[IPv6Packet.cpp] 添加分片头部" << std::endl;

    // Next Header (8位) - 指示下一个头部的类型
    packet.push_back(60); // 60表示目的选项头部

    // Reserved (8位)
    packet.push_back(0x00); // 保留字段，设置为0

    // Fragment Offset (13位) + Res (2位) + M Flag (1位)
    uint16_t fragmentOffsetAndFlags = (fragmentOffset << 3);
    if (moreFragments) {
        fragmentOffsetAndFlags |= 1;
    }
    packet.push_back((fragmentOffsetAndFlags >> 8) & 0xFF);
    packet.push_back(fragmentOffsetAndFlags & 0xFF);

    // Identification (32位)
    packet.push_back((identification >> 24) & 0xFF);
    packet.push_back((identification >> 16) & 0xFF);
    packet.push_back((identification >> 8) & 0xFF);
    packet.push_back(identification & 0xFF);
}

// 添加目的选项报头
void IPv6Packet::addExtensionHeader() {
    std::cout << "[IPv6Packet.cpp] 添加目的选项报头" << std::endl;

    // Next Header (8位) - 指示下一个头部的类型
    packet.push_back(0x3B); // No Next Header

    // Header Extension Length (8位) - 以8字节为单位，不包括前8个字节
    uint8_t hdr_ext_len = (extensionHeaderContent.size() + 2) / 8; // 计算扩展头部长度
    packet.push_back(hdr_ext_len);

    // 添加选项内容
    packet.insert(packet.end(), extensionHeaderContent.begin(), extensionHeaderContent.end());
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
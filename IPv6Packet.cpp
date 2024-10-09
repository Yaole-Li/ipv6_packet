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

// 构造函数：初始化IPv6Packet对象
IPv6Packet::IPv6Packet(const std::string& destMAC, const std::string& destIPv6, const std::vector<uint8_t>& payload, const std::vector<uint8_t>& extensionHeaderContent, bool fragmentFlag)
    : destMAC(destMAC), destIPv6(destIPv6), payload(payload), extensionHeaderContent(extensionHeaderContent), fragmentFlag(fragmentFlag), packetLength(0), packetHeaderAddress(nullptr) {
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
    std::cout << "获取本地MAC地址使用ifconfig" << std::endl;
    std::string command = "ifconfig eth0 | grep ether | awk '{print $2}'"; // 使用适当的接口名称
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        throw std::runtime_error("无法运行ifconfig命令");
    }

    char buffer[128];
    std::string mac_address = "";
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        mac_address += buffer;
    }
    pclose(pipe);

    // 移除可能存在的换行符
    mac_address.erase(mac_address.find_last_not_of(" \n\r\t") + 1);
    srcMAC = mac_address; // 设置本地MAC地址
    std::cout << "本地MAC地址: " << srcMAC << std::endl;
}

// 获取本地IPv6地址
void IPv6Packet::fetchLocalIPv6() {
    std::cout << "获取本地IPv6地址" << std::endl;
    struct ifaddrs* ifaddr;
    if (getifaddrs(&ifaddr) == -1) {
        throw std::runtime_error("无法获取网络接口");
    }

    for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr || ifa->ifa_addr->sa_family != AF_INET6) {
            continue;
        }

        char addr[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &((struct sockaddr_in6*)ifa->ifa_addr)->sin6_addr, addr, sizeof(addr))) {
            // 忽略链路本地地址和回环地址
            if (strncmp(addr, "fe80", 4) == 0 || strcmp(addr, "::1") == 0) {
                continue;
            }
            srcIPv6 = addr; // 设置本地IPv6地址
            std::cout << "本地IPv6地址: " << srcIPv6 << std::endl;
            break;
        }
    }

    freeifaddrs(ifaddr);
}

// 添加IPv6基本头部
void IPv6Packet::addIPv6Header() {
    std::cout << "添加IPv6头部，源地址: " << srcIPv6 << " 目的地址: " << destIPv6 << std::endl;

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
    std::cout << "添加分片头部" << std::endl;

    // Next Header (8位) - 指示下一个头部的类型
    packet.push_back(60); // 60表示目的选项头部

    // Reserved (8位)
    packet.push_back(0x00); // 示例值，通常为0

    // Fragment Offset (13位) + Res (2位) + M Flag (1位)
    uint16_t fragmentOffsetAndFlags = 0; // 示例值，实际需要根据分片情况设置
    packet.push_back((fragmentOffsetAndFlags >> 8) & 0xFF);
    packet.push_back(fragmentOffsetAndFlags & 0xFF);

    // Identification (32位)
    uint32_t identification = 0; // 示例值，实际需要生成唯一标识符
    packet.push_back((identification >> 24) & 0xFF);
    packet.push_back((identification >> 16) & 0xFF);
    packet.push_back((identification >> 8) & 0xFF);
    packet.push_back(identification & 0xFF);
}

// 添加目的选项报头
void IPv6Packet::addExtensionHeader() {
    std::cout << "添加目的选项报头" << std::endl;

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
    std::cout << "数据包详细信息：" << std::endl;
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
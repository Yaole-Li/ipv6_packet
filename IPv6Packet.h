#ifndef IPV6_PACKET_H
#define IPV6_PACKET_H

#include <string>
#include <vector>

// IPv6Packet类用于构造和管理IPv6数据包
class IPv6Packet {
public:
    // 构造函数：初始化IPv6Packet对象
    IPv6Packet(const std::string& destMAC, const std::string& destIPv6, const std::vector<uint8_t>& payload, const std::vector<uint8_t>& extensionHeaderContent, bool fragmentFlag);

    // 构造完整的IPv6数据包
    void constructPacket();

    // 获取构造好的数据包
    const std::vector<uint8_t>& getPacket() const;

    // 获取本地MAC地址
    void fetchLocalMAC();

    // 获取本地IPv6地址
    void fetchLocalIPv6();

    // 输出数据包的详细信息
    void printPacketDetails() const;

    // 获取目标MAC地址
    const std::string& getDestMAC() const { return destMAC; }

    // 获取目标IPv6地址
    const std::string& getDestIPv6() const { return destIPv6; }

    // 获取扩展头部内容
    const std::vector<uint8_t>& getExtensionHeaderContent() const { return extensionHeaderContent; }

    // 获取负载数据
    const std::vector<uint8_t>& getPayload() const { return payload; }

private:
    std::string srcMAC; // 本地MAC地址
    std::string destMAC; // 目标MAC地址
    std::string srcIPv6; // 本地IPv6地址
    std::string destIPv6; // 目标IPv6地址
    std::vector<uint8_t> extensionHeaderContent; // 扩展头部内容
    std::vector<uint8_t> payload; // 负载数据
    std::vector<uint8_t> packet; // 完整的数据包
    size_t packetLength; // 数据包长度
    uint8_t* packetHeaderAddress; // 数据包头部地址
    bool fragmentFlag; // 分片标志

    // 添加IPv6基本头部
    void addIPv6Header();

    // 添加分片头部
    void addFragmentHeader();

    // 添加目的选项报头
    void addExtensionHeader();
};

#endif // IPV6_PACKET_H

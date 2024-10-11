#include "Sender.h"
#include <iostream>
#include <chrono>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

// 构造函数：初始化 Sender 对象
Sender::Sender(int windowSize, size_t mtu, const std::string& interface)
    : windowSize(windowSize), nextSequenceNumber(0), base(0), mtu(mtu), interface(interface) {
    // 初始化 libpcap，用于发送数据包
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        throw std::runtime_error("无法打开网络接口: " + std::string(errbuf));
    }
    
    // 计算最大分片大小
    maxFragmentSize = mtu - 40 - 8;  // IPv6 header (40 bytes) + Fragment header (8 bytes)
}

// 析构函数：清理资源
Sender::~Sender() {
    if (handle != nullptr) {
        pcap_close(handle);
    }
}

// 添加新的数据包到发送队列
void Sender::addPacket(const std::string& destMAC, const std::string& destIPv6, 
                       const std::vector<uint8_t>& payload, 
                       const std::vector<uint8_t>& extensionHeaderContent,
                       bool fragmentFlag) {
    // 创建新的 IPv6Packet 对象并添加到队列
    auto packet = std::make_shared<IPv6Packet>(destMAC, destIPv6, payload, extensionHeaderContent, fragmentFlag);
    packetQueue.push_back(packet);
}

// 尝试发送下一个数据包
bool Sender::sendPacket() {
    std::cout << "[Sender.cpp] 尝试发送数据包，当前序列号: " << nextSequenceNumber << std::endl;
    // 检查是否在滑动窗口内且队列非空
    if (nextSequenceNumber < base + windowSize && !packetQueue.empty()) {
        auto& packet = packetQueue.front();
        // 对数据包进行分片
        std::vector<std::vector<uint8_t>> fragments = fragmentPacket(*packet);
        bool allSent = true;
        // 发送所有分片
        for (size_t i = 0; i < fragments.size(); ++i) {
            bool moreFragments = (i < fragments.size() - 1);
            // uint16_t fragmentOffset = i * (mtu - 40 - 8) / 8;  // 计算分片偏移
            uint16_t fragmentOffset = i * maxFragmentSize / 8;  // 计算分片偏移
            if (!sendFragment(fragments[i], nextSequenceNumber, fragmentOffset, moreFragments)) {
                allSent = false;
                break;
            }
        }
        if (allSent) {
            std::cout << "成功发送数据包，序列号: " << nextSequenceNumber << std::endl;
            // 更新流表，增加序列号，移除已发送的数据包
            updateFlowTable(nextSequenceNumber, true, false);
            nextSequenceNumber++;
            packetQueue.erase(packetQueue.begin());
            return true;
        } else {
            std::cout << "发送数据包失败，序列号: " << nextSequenceNumber << std::endl;
        }
    }
    return false;
}

// 处理接收到的 ACK
void Sender::handleAck(uint32_t ackNumber) {
    std::cout << "[Sender.cpp] 收到 ACK，确认号: " << ackNumber << std::endl;
    if (ackNumber >= base) {
        // 更新已确认的数据包状态
        for (uint32_t i = base; i <= ackNumber; i++) {
            if (flowTable.find(i) != flowTable.end()) {
                flowTable[i].acknowledged = true;
            }
        }
        // 移动滑动窗口
        base = ackNumber + 1;
        std::cout << "收到ACK，更新base为: " << base << std::endl;
    }
}

// 检查超时的数据包
void Sender::checkTimeouts() {
    std::cout << "[Sender.cpp] 检查超时数据包" << std::endl;
    auto now = std::chrono::steady_clock::now();
    for (auto& entry : flowTable) {
        if (entry.second.sent && !entry.second.acknowledged) {
            // 计算经过的时间
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - entry.second.sentTime).count();
            if (elapsed > 5) { // 5秒超时
                std::cout << "数据包超时，序列号: " << entry.first << std::endl;
                retransmitPacket(entry.first);
            }
        }
    }
}

// 更新流表
void Sender::updateFlowTable(uint32_t sequenceNumber, bool sent, bool acknowledged) {
    flowTable[sequenceNumber] = {packetQueue.front(), sent, acknowledged, std::chrono::steady_clock::now(), std::vector<bool>()};
}

// 重新发送数据包
void Sender::retransmitPacket(uint32_t sequenceNumber) {
    std::cout << "[Sender.cpp] 重新发送数据包，序列号: " << sequenceNumber << std::endl;
    if (flowTable.find(sequenceNumber) != flowTable.end()) {
        auto& packetStatus = flowTable[sequenceNumber];
        // 重新分片并发送
        std::vector<std::vector<uint8_t>> fragments = fragmentPacket(*(packetStatus.packet));
        for (size_t i = 0; i < fragments.size(); ++i) {
            bool moreFragments = (i < fragments.size() - 1);
            // uint16_t fragmentOffset = i * (mtu - 40 - 8) / 8;
            uint16_t fragmentOffset = i * maxFragmentSize / 8;  // 计算分片偏移
            sendFragment(fragments[i], sequenceNumber, fragmentOffset, moreFragments);
        }
        packetStatus.sent = true;
        packetStatus.sentTime = std::chrono::steady_clock::now();
    }
}

// 将数据包分片
std::vector<std::vector<uint8_t>> Sender::fragmentPacket(const IPv6Packet& packet) {
    std::vector<std::vector<uint8_t>> fragments;
    const std::vector<uint8_t>& extensionHeader = packet.getExtensionHeaderContent();
    const std::vector<uint8_t>& payload = packet.getPayload();
    
    // 定义各种头部和尾部的大小
    size_t ethernetHeaderSize = 14;  // 以太网帧头大小
    size_t ethernetTrailerSize = 4;  // 以太网帧尾大小 (CRC)
    size_t ipv6HeaderSize = 40;      // IPv6 基本头部大小
    size_t fragmentHeaderSize = 8;   // 分片头部大小
    
    // 计算可用于 IPv6 包内容的最大大小
    size_t maxIPv6PacketSize = mtu - ethernetHeaderSize - ethernetTrailerSize;
    
    // 计算可用于分片内容的最大大小
    size_t maxFragmentSize = maxIPv6PacketSize - ipv6HeaderSize - fragmentHeaderSize;

    uint32_t identification = generateUniqueIdentification();

    if (payload.empty()) {
        // 没有负载，只有目的选项报头
        if (extensionHeader.size() > maxFragmentSize) {
            // 目的选项报头需要分片
            for (size_t offset = 0; offset < extensionHeader.size(); offset += maxFragmentSize) {
                size_t fragmentSize = std::min(maxFragmentSize, extensionHeader.size() - offset);
                std::vector<uint8_t> fragment(extensionHeader.begin() + offset, extensionHeader.begin() + offset + fragmentSize);
                
                IPv6Packet fragmentPacket(packet.getDestMAC(), packet.getDestIPv6(), 
                                          std::vector<uint8_t>(), fragment, true, 
                                          offset / 8, 
                                          offset + fragmentSize < extensionHeader.size(), 
                                          identification);
                fragmentPacket.constructPacket();
                fragments.push_back(fragmentPacket.getPacket());
            }
        } else {
            // 目的选项报头不需要分片
            IPv6Packet fragmentPacket(packet.getDestMAC(), packet.getDestIPv6(), 
                                      std::vector<uint8_t>(), extensionHeader, false, 
                                      0, false, identification);
            fragmentPacket.constructPacket();
            fragments.push_back(fragmentPacket.getPacket());
        }
    } else {
        // 有负载
        size_t totalSize = extensionHeader.size() + payload.size();
        if (totalSize > maxFragmentSize) {
            // 需要分片
            std::vector<uint8_t> combinedData;
            combinedData.insert(combinedData.end(), extensionHeader.begin(), extensionHeader.end());
            combinedData.insert(combinedData.end(), payload.begin(), payload.end());

            for (size_t offset = 0; offset < totalSize; offset += maxFragmentSize) {
                size_t fragmentSize = std::min(maxFragmentSize, totalSize - offset);
                std::vector<uint8_t> fragment(combinedData.begin() + offset, combinedData.begin() + offset + fragmentSize);
                
                IPv6Packet fragmentPacket(packet.getDestMAC(), packet.getDestIPv6(), 
                                          std::vector<uint8_t>(), fragment, true, 
                                          offset / 8, 
                                          offset + fragmentSize < totalSize, 
                                          identification);
                fragmentPacket.constructPacket();
                fragments.push_back(fragmentPacket.getPacket());
            }
        } else {
            // 不需要分片
            IPv6Packet fragmentPacket(packet.getDestMAC(), packet.getDestIPv6(), 
                                      payload, extensionHeader, false, 
                                      0, false, identification);
            fragmentPacket.constructPacket();
            fragments.push_back(fragmentPacket.getPacket());
        }
    }

    return fragments;
}

// 发送单个分片
bool Sender::sendFragment(const std::vector<uint8_t>& fragmentPacket, uint32_t sequenceNumber, uint16_t fragmentOffset, bool moreFragments) {
    (void)moreFragments;  // 避免未使用参数的警告
    
    // 添加以太网帧头和尾
    std::vector<uint8_t> ethernetFrame = addEthernetFrame(fragmentPacket);
    
    // 使用 libpcap 发送数据包
    if (pcap_sendpacket(handle, ethernetFrame.data(), ethernetFrame.size()) != 0) {
        std::cerr << "发送数据包失败: " << pcap_geterr(handle) << std::endl;
        return false;
    }
    
    std::cout << "[Sender.cpp] 发送分片，序列号: " << sequenceNumber << ", 偏移: " << fragmentOffset 
              << ", 大小: " << ethernetFrame.size() << " 字节" << std::endl;
    return true;
}

// 将数据包添加以太网帧头和帧尾
std::vector<uint8_t> Sender::addEthernetFrame(const std::vector<uint8_t>& ipv6Packet) {
    std::vector<uint8_t> ethernetFrame;
    
    // 添加以太网帧头（14字节）
    struct ether_header header;
    // 解析目标 MAC 地址
    std::string destMAC = "00:11:22:33:44:55";  // 这里需要替换为实际的目标 MAC 地址
    sscanf(destMAC.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
           &header.ether_dhost[0], &header.ether_dhost[1], &header.ether_dhost[2],
           &header.ether_dhost[3], &header.ether_dhost[4], &header.ether_dhost[5]);
    // 解析源 MAC 地址
    std::string srcMAC = "AA:BB:CC:DD:EE:FF";  // 这里需要替换为实际的源 MAC 地址
    sscanf(srcMAC.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
           &header.ether_shost[0], &header.ether_shost[1], &header.ether_shost[2],
           &header.ether_shost[3], &header.ether_shost[4], &header.ether_shost[5]);
    // 设置以太网类型为 IPv6
    header.ether_type = htons(ETHERTYPE_IPV6);
    
    // 将以太网帧头添加到帧中
    ethernetFrame.insert(ethernetFrame.end(), reinterpret_cast<uint8_t*>(&header), 
                         reinterpret_cast<uint8_t*>(&header) + sizeof(struct ether_header));
    
    // 添加 IPv6 数据包
    ethernetFrame.insert(ethernetFrame.end(), ipv6Packet.begin(), ipv6Packet.end());
    
    // 计算并添加 CRC
    uint32_t crc = calculateCRC(ethernetFrame);
    ethernetFrame.push_back((crc >> 24) & 0xFF);
    ethernetFrame.push_back((crc >> 16) & 0xFF);
    ethernetFrame.push_back((crc >> 8) & 0xFF);
    ethernetFrame.push_back(crc & 0xFF);
    
    return ethernetFrame;
}

// CRC32 计算
uint32_t Sender::calculateCRC(const std::vector<uint8_t>& data) {
    uint32_t crc = 0xFFFFFFFF;
    for (uint8_t byte : data) {
        crc ^= byte;
        for (int i = 0; i < 8; i++) {
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
        }
    }
    return ~crc;
}

uint32_t Sender::generateUniqueIdentification() {
    static uint32_t counter = 0;
    return ++counter;
}

/*
Sender 类流程图：

+-------------------+
|     初始化        |
|  (构造函数)       |
+-------------------+
          |
          v
+-------------------+
|   添加数据包      |
|  (addPacket)      |
+-------------------+
          |
          v
+-------------------+
|   发送数据包      |
|  (sendPacket)     |
+-------------------+
          |
          v
+-------------------+
|    分片数据包     |
| (fragmentPacket)  |
+-------------------+
          |
          v
+-------------------+
|   发送单个分片    |
|  (sendFragment)   |
+-------------------+
          |
          v
+-------------------+
|  添加以太网帧     |
|(addEthernetFrame) |
+-------------------+
          |
          v
+-------------------+
|    计算 CRC       |
|  (calculateCRC)   |
+-------------------+
          |
          v
+-------------------+
|   处理 ACK        |
|   (handleAck)     |
+-------------------+
          |
          v
+-------------------+
|   检查超时        |
| (checkTimeouts)   |
+-------------------+
          |
          v
+-------------------+
|   重传数据包      |
|(retransmitPacket) |
+-------------------+

注：流程可能会根据实际情况循环或跳转
*/
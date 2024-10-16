#include "Sender.h"
#include <iostream>
#include <chrono>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <iomanip>

// 构造函数：初始化 Sender 对象
Sender::Sender(int windowSize, size_t mtu, const std::string& interface)
    : windowSize(windowSize), nextSequenceNumber(0), base(0), mtu(mtu), interface(interface) {
    // 初始化 libpcap，用于发送数据包
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        throw std::runtime_error("无法打开网络接口: " + std::string(errbuf));
    }
    
    // 初始化用于接收 ACK 的 pcap 句柄
    ack_handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (ack_handle == nullptr) {
        throw std::runtime_error("无法打开网络接口以接收 ACK: " + std::string(errbuf));
    }

    // 设置过滤器，只捕获 IPv6 数据包且协议号为 253 的包
    std::string filter = "ip6 and ip6[6] == 253";
    struct bpf_program fp;
    if (pcap_compile(ack_handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "无法编译过滤器: " << pcap_geterr(ack_handle) << std::endl;
        throw std::runtime_error("过滤器编译失败");
    }
    if (pcap_setfilter(ack_handle, &fp) == -1) {
        std::cerr << "无法设置过滤器: " << pcap_geterr(ack_handle) << std::endl;
        throw std::runtime_error("设置过滤器失败");
    }
    pcap_freecode(&fp);
}

// 析构函数：清理资源
Sender::~Sender() {
    if (handle != nullptr) {
        pcap_close(handle);
    }
    if (ack_handle != nullptr) {
        pcap_close(ack_handle);
    }
}

// 添加新的数据包到发送队列
void Sender::addPacket(const std::string& destMAC, const std::string& destIPv6, 
                       const std::vector<uint8_t>& payload, 
                       const std::vector<uint8_t>& extensionHeaderContent,
                       bool fragmentFlag) {
    std::cout << "---------[addPacket]---------" << std::endl;
    std::cout << "[Sender.cpp] 添加新数据包到发送队列" << std::endl;
    
    // 输出 extensionHeaderContent
    std::cout << "[Sender.cpp] 扩展头部内容 (大小: " << extensionHeaderContent.size() << " 字节):" << std::endl;
    // for (size_t i = 0; i < extensionHeaderContent.size(); ++i) {
    //     std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(extensionHeaderContent[i]) << " ";
    //    if ((i + 1) % 16 == 0 || i == extensionHeaderContent.size() - 1) std::cout << std::endl;
    //}
    std::cout << std::dec;  // 恢复为十进制输出

    // 输出 payload
    std::cout << "[Sender.cpp] 负载内容 (大小: " << payload.size() << " 字节):" << std::endl;
    // for (size_t i = 0; i < payload.size(); ++i) {
    //     std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(payload[i]) << " ";
    //     if ((i + 1) % 16 == 0 || i == payload.size() - 1) std::cout << std::endl;
    // }
    std::cout << std::dec;  // 恢复为十进制输出

    // 创建新的 IPv6Packet 对象并添加到队列
    auto packet = std::make_shared<IPv6Packet>(destMAC, destIPv6, payload, extensionHeaderContent, fragmentFlag);
    packetQueue.push_back(packet);

    std::cout << "[Sender.cpp] 数据包已添加到发送队列" << std::endl;
    std::cout << "---------[addPacket End]---------" << std::endl;
}

// 尝试发送下一个数据包
bool Sender::sendPacket() {
    std::cout << "---------[sendPacket]---------" << std::endl;
    std::cout << "[Sender.cpp] 尝试发送数据包，当前序列号: " << nextSequenceNumber << std::endl;
    if (nextSequenceNumber < base + windowSize && !packetQueue.empty()) {
        auto& packet = packetQueue.front();
        // 对据包进行分片
        std::vector<std::vector<uint8_t>> fragments = fragmentPacket(*packet);
        bool allSent = true;
        // 发送所有分片
        for (const auto& fragment : fragments) {
            // 直接从分片头部读取偏移量
            uint16_t fragmentOffset = 0;
            bool moreFragments = false;
            if (fragment.size() >= sizeof(struct ip6_hdr) + sizeof(struct ip6_frag)) {
                const struct ip6_hdr* ip6Header = reinterpret_cast<const struct ip6_hdr*>(fragment.data());
                if (ip6Header->ip6_nxt == IPPROTO_FRAGMENT) {
                    const struct ip6_frag* fragHeader = reinterpret_cast<const struct ip6_frag*>(fragment.data() + sizeof(struct ip6_hdr));
                    fragmentOffset = ntohs(fragHeader->ip6f_offlg & IP6F_OFF_MASK) / 8; //这里除以八才是偏移量，因为偏移量以8字节为单位
                    moreFragments = (fragHeader->ip6f_offlg & IP6F_MORE_FRAG) != 0;
                }
            }
            if (!sendFragment(fragment, nextSequenceNumber, fragmentOffset, moreFragments)) {
                allSent = false;
                break;
            }
        }
        if (allSent) {
            std::cout << "[Sender.cpp] 成功发送数据包，序列号: " << nextSequenceNumber << std::endl;
            updateFlowTable(nextSequenceNumber, true, false);
            nextSequenceNumber++;  // 只有在成功发送后才增加序列号
            packetQueue.erase(packetQueue.begin());
            std::cout << "---------[sendPacket End]---------" << std::endl;
            return true;
        } else {
            std::cout << "[Sender.cpp] 发送数据包失败，序列号: " << nextSequenceNumber << std::endl;
        }
    } else {
        std::cout << "[Sender.cpp] 没有新的数据包需要发送" << std::endl;
    }
    std::cout << "---------[sendPacket End]---------" << std::endl;
    return false;
}

// 处理接收到的 ACK
void Sender::handleAck(uint32_t ackNumber) {
    std::cout << "---------[handleAck]---------" << std::endl;
    std::cout << "[Sender.cpp] 处理 ACK，确认号: " << ackNumber << std::endl;
    if (ackNumber >= base) {
        // 更新已确认的数据包状态
        for (uint32_t i = base; i <= ackNumber; i++) {
            if (flowTable.find(i) != flowTable.end()) {
                flowTable[i].acknowledged = true;
                std::cout << "[Sender.cpp] 数据包 " << i << " 发送确认" << std::endl;
            }
        }
        // 移动滑动窗口
        base = ackNumber + 1;
        std::cout << "[Sender.cpp] 更新滑动窗口基准序列号为: " << base << std::endl;
    } else {
        std::cout << "[Sender.cpp] 收到重复 ACK，序列号: " << ackNumber << std::endl;
    }
    std::cout << "---------[handleAck End]---------" << std::endl;
}

// 检查超时的数据包
void Sender::checkTimeouts() {
    std::cout << "---------[checkTimeouts]---------" << std::endl;
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
    std::cout << "---------[checkTimeouts End]---------" << std::endl;
}

// 更新流表
void Sender::updateFlowTable(uint32_t sequenceNumber, bool sent, bool acknowledged) {
    flowTable[sequenceNumber] = {packetQueue.front(), sent, acknowledged, std::chrono::steady_clock::now(), std::vector<bool>()};
}

// 重新发送数据包
void Sender::retransmitPacket(uint32_t sequenceNumber) {
    std::cout << "[Sender.cpp] 重新发送数据包列号: " << sequenceNumber << std::endl;
    if (flowTable.find(sequenceNumber) != flowTable.end()) {
        auto& packetStatus = flowTable[sequenceNumber];
        // 重新分片并发送
        std::vector<std::vector<uint8_t>> fragments = fragmentPacket(*(packetStatus.packet));
        for (size_t i = 0; i < fragments.size(); ++i) {
            bool moreFragments = (i < fragments.size() - 1);
            // 计算分偏移时使用与 fragmentPacket 中相同的逻辑
            size_t ethernetHeaderSize = 14;
            size_t ethernetTrailerSize = 4;
            size_t ipv6HeaderSize = 40;
            size_t fragmentHeaderSize = 8;
            size_t extensionHeaderSize = packetStatus.packet->getExtensionHeaderContent().size();
            size_t maxFragmentPayloadSize = mtu - ethernetHeaderSize - ethernetTrailerSize - ipv6HeaderSize - fragmentHeaderSize - extensionHeaderSize;
            uint16_t fragmentOffset = i * maxFragmentPayloadSize / 8;
            sendFragment(fragments[i], sequenceNumber, fragmentOffset, moreFragments);
        }
        packetStatus.sent = true;
        packetStatus.sentTime = std::chrono::steady_clock::now();
    }
}

// 将数据包分片
std::vector<std::vector<uint8_t>> Sender::fragmentPacket(const IPv6Packet& packet) {
    std::cout << "---------[fragmentPacket]---------" << std::endl;
    std::vector<std::vector<uint8_t>> fragments;
    const std::vector<uint8_t>& extensionHeader = packet.getExtensionHeaderContent();
    const std::vector<uint8_t>& payload = packet.getPayload();
    
    std::cout << "[Sender.cpp] 扩展头部大小: " << extensionHeader.size() << " 字节" << std::endl;
    std::cout << "[Sender.cpp] 有效负载大小: " << payload.size() << " 字节" << std::endl;

    // 定义各种头部和尾部的大小
    size_t ethernetHeaderSize = 14;  // 以太网帧头大小
    size_t ethernetTrailerSize = 4;  // 以太网帧尾大小 (CRC)
    size_t ipv6HeaderSize = 40;      // IPv6 基本头部大小
    size_t fragmentHeaderSize = 8;   // 分片头部大小
    
    // 计算可用于 IPv6 包内容的最大大小
    size_t maxIPv6PacketSize = mtu - ethernetHeaderSize - ethernetTrailerSize;
    
    // 计算可用于分片内容的最大大小
    maxFragmentPayloadSize = maxIPv6PacketSize - ipv6HeaderSize - fragmentHeaderSize;

    std::cout << "[Sender.cpp] MTU: " << mtu << " 字节" << std::endl;
    std::cout << "[Sender.cpp] 最大 IPv6 包大小: " << maxIPv6PacketSize << " 字节" << std::endl;
    std::cout << "[Sender.cpp] 最大分片负载大小: " << maxFragmentPayloadSize << " 字节" << std::endl;

    uint32_t identification = generateUniqueIdentification();

    if (payload.empty()) {
        // 没有有效负载，只有扩展头部（目的选项报头）
        std::cout << "[Sender.cpp] 没有有效负载，只处理扩展头部" << std::endl;
        if (extensionHeader.size() > maxFragmentPayloadSize) {
            // 需要对扩展头部进行分片
            for (size_t offset = 0; offset < extensionHeader.size(); offset += maxFragmentPayloadSize) {
                size_t fragmentSize = std::min(maxFragmentPayloadSize, extensionHeader.size() - offset);
                std::vector<uint8_t> fragment(extensionHeader.begin() + offset, extensionHeader.begin() + offset + fragmentSize);
                
                bool moreFragments = (offset + fragmentSize < extensionHeader.size());
                IPv6Packet fragmentPacket(packet.getDestMAC(), packet.getDestIPv6(), 
                                          std::vector<uint8_t>(), fragment, true, 
                                          offset / 8, 
                                          moreFragments, 
                                          identification);
                fragmentPacket.constructPacket();
                fragments.push_back(fragmentPacket.getPacket());
            }
        } else {
            // 扩展头部不需要分片
            IPv6Packet fragmentPacket(packet.getDestMAC(), packet.getDestIPv6(), 
                                      std::vector<uint8_t>(), extensionHeader, false, 
                                      0, false, identification);
            fragmentPacket.constructPacket();
            fragments.push_back(fragmentPacket.getPacket());
        }
    } else {
        // 有有效负载
        std::cout << "[Sender.cpp] 有有效负载，处理有效负载分片" << std::endl;
        
        // 计算目的选项报头的总大小
        size_t destinationOptionsHeaderSize = 2 + 2; // 基本大小：2字节的头部 + 至少2字节的选项和填充
        if (!extensionHeader.empty()) {
            destinationOptionsHeaderSize += ((extensionHeader.size() + 7) / 8) * 8; // 向上取整到8的倍数
        }

        std::cout << "[Sender.cpp] 目的选项报头的总大小: " << destinationOptionsHeaderSize << " 字节" << std::endl;
        size_t maxPayloadPerFragment = maxFragmentPayloadSize - destinationOptionsHeaderSize;
        
        if (payload.size() > maxPayloadPerFragment) {
            // 需要对有效负载进行分片
            for (size_t offset = 0; offset < payload.size();) {
                size_t fragmentSize = std::min(maxPayloadPerFragment, payload.size() - offset);
                // 确保 fragmentSize 是 8 的倍数，除非是最后一个分片
                if (offset + fragmentSize < payload.size()) {
                    fragmentSize = (fragmentSize / 8) * 8;
                }
                std::cout << "[Sender.cpp] 当前分片大小: " << fragmentSize << " 字节" << std::endl;
                
                std::vector<uint8_t> fragmentPayload(payload.begin() + offset, payload.begin() + offset + fragmentSize);
                
                bool moreFragments = (offset + fragmentSize < payload.size());
                uint16_t fragmentOffsetIn8ByteUnits = offset / 8;  // 转换为 8 字节单位
                std::cout << "[Sender.cpp] 分片偏移量 (8字节单位): " << fragmentOffsetIn8ByteUnits << std::endl;
                
                IPv6Packet fragmentPacket(packet.getDestMAC(), packet.getDestIPv6(), 
                                          fragmentPayload, extensionHeader, true, 
                                          fragmentOffsetIn8ByteUnits, 
                                          moreFragments, 
                                          identification);
                fragmentPacket.constructPacket();
                fragments.push_back(fragmentPacket.getPacket());

                offset += fragmentSize;  // 使用实际的 fragmentSize 来增加 offset
            }
        } else {
            // 有效负载不需要分片
            std::cout << "[Sender.cpp] 负载无需分片，大小: " << payload.size() << " 字节" << std::endl;
            IPv6Packet fragmentPacket(packet.getDestMAC(), packet.getDestIPv6(), 
                                      payload, extensionHeader, false, 
                                      0, false, identification);
            fragmentPacket.constructPacket();
            fragments.push_back(fragmentPacket.getPacket());
        }
    }

    std::cout << "[Sender.cpp] 生成的分片数量: " << fragments.size() << std::endl;
    std::cout << "---------[fragmentPacket End]---------" << std::endl;
    return fragments;
}

// 发送单个分片
bool Sender::sendFragment(const std::vector<uint8_t>& fragmentPacket, uint32_t sequenceNumber, uint16_t fragmentOffset, bool moreFragments) {
    std::cout << "---------[sendFragment]---------" << std::endl;
    (void)moreFragments;  // 避免使用参数的警告
    
    // 添加以太网帧头和尾
    std::vector<uint8_t> ethernetFrame = addEthernetFrame(fragmentPacket);
    
    // 使用 libpcap 发送数据包
    if (pcap_sendpacket(handle, ethernetFrame.data(), ethernetFrame.size()) != 0) {
        std::cerr << "发送数据包失败: " << pcap_geterr(handle) << std::endl;
        std::cout << "---------[sendFragment End]---------" << std::endl;
        return false;
    }
    
    std::cout << "[Sender.cpp] 发送分片，序列号: " << sequenceNumber << ", 偏移: " << fragmentOffset 
              << ", 大小: " << ethernetFrame.size() << " 字节" << std::endl;
    std::cout << "---------[sendFragment End]---------" << std::endl;
    return true;
}

// 将数据包添加以太网帧头和帧尾
std::vector<uint8_t> Sender::addEthernetFrame(const std::vector<uint8_t>& ipv6Packet) {
    std::cout << "---------[addEthernetFrame]---------" << std::endl;
    std::vector<uint8_t> ethernetFrame;
    
    // 添加以太网帧头（14字节）
    struct ether_header header;
    // 解析目标 MAC 地址
    std::string destMAC = "32:0b:56:af:a6:cf";  // 这里需要替换为实际的目标 MAC 地址
    sscanf(destMAC.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
           &header.ether_dhost[0], &header.ether_dhost[1], &header.ether_dhost[2],
           &header.ether_dhost[3], &header.ether_dhost[4], &header.ether_dhost[5]);
    // 解析源 MAC 地址
    std::string srcMAC = "32:0b:56:af:a6:cf";  // 这里需要替换为实源 MAC 地址
    sscanf(srcMAC.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
           &header.ether_shost[0], &header.ether_shost[1], &header.ether_shost[2],
           &header.ether_shost[3], &header.ether_shost[4], &header.ether_shost[5]);
    // 设以太网类型为 IPv6
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
    
    std::cout << "---------[addEthernetFrame End]---------" << std::endl;
    return ethernetFrame;
}

// CRC32 计算
uint32_t Sender::calculateCRC(const std::vector<uint8_t>& data) {
    std::cout << "---------[calculateCRC]---------" << std::endl;
    uint32_t crc = 0xFFFFFFFF;
    for (uint8_t byte : data) {
        crc ^= byte;
        for (int i = 0; i < 8; i++) {
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
        }
    }
    std::cout << "---------[calculateCRC End]---------" << std::endl;
    return ~crc;
}

uint32_t Sender::generateUniqueIdentification() {
    static uint32_t counter = 0;
    return ++counter;
}

void Sender::receiveAck() {
    std::cout << "---------[receiveAck]---------" << std::endl;
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(ack_handle, &header, &packet);
    if (res == 1) {
        std::cout << "[Sender.cpp] 接收到潜在的 ACK 数据包，大小: " << header->len << " 字节" << std::endl;
        uint32_t ack_number = processAckPacket(packet, header->len);
        if (ack_number != 0) {
            std::cout << "[Sender.cpp] 接收到有效的 ACK，确认号: " << ack_number << std::endl;
            handleAck(ack_number);
        } else {
            std::cout << "[Sender.cpp] 接收到的数据包不是有效的 ACK" << std::endl;
        }
    } else if (res == 0) {
        std::cout << "[Sender.cpp] 等待 ACK 超时" << std::endl;
    } else {
        std::cout << "[Sender.cpp] 接收 ACK 时发生错误: " << pcap_geterr(ack_handle) << std::endl;
    }
    std::cout << "---------[receiveAck End]---------" << std::endl;
}

uint32_t Sender::processAckPacket(const uint8_t* packet, int size) {
    std::cout << "---------[processAckPacket]---------" << std::endl;
    std::cout << "[Sender.cpp] 开始处理潜在的 ACK 数据包" << std::endl;
    
    // 跳过以太网头部
    const uint8_t* ipv6_packet = packet + 14;
    int ipv6_size = size - 14;

    if (ipv6_size < static_cast<int>(sizeof(struct ip6_hdr) + 12)) {
        std::cout << "[Sender.cpp] 数据包太小，不是有效的 ACK 包" << std::endl;
        std::cout << "---------[processAckPacket End]---------" << std::endl;
        return 0;
    }

    struct ip6_hdr* ipv6_header = (struct ip6_hdr*)ipv6_packet;
    
    std::cout << "[Sender.cpp] IPv6 下一个头部: " << (int)ipv6_header->ip6_nxt << std::endl;

    if (ipv6_header->ip6_nxt == 253) {  // 我们的自定义协议号
        const uint8_t* ack_data = ipv6_packet + sizeof(struct ip6_hdr);
        uint32_t ack_number = ntohl(*reinterpret_cast<const uint32_t*>(ack_data));
        uint32_t original_packet_id = ntohl(*reinterpret_cast<const uint32_t*>(ack_data + 4));
        uint16_t src_port = ntohs(*reinterpret_cast<const uint16_t*>(ack_data + 8));
        uint16_t dst_port = ntohs(*reinterpret_cast<const uint16_t*>(ack_data + 10));

        std::cout << "[Sender.cpp] 接收到 ACK，确认号: " << ack_number 
                  << ", 原始包 ID: " << original_packet_id
                  << ", 源端口: " << src_port
                  << ", 目标端口: " << dst_port << std::endl;

        std::cout << "---------[processAckPacket End]---------" << std::endl;
        return ack_number;
    }

    std::cout << "[Sender.cpp] 不是预期的 ACK 包" << std::endl;
    std::cout << "---------[processAckPacket End]---------" << std::endl;
    return 0;
}

/*
Sender 类流图：

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

void printPacketDetails(const std::vector<uint8_t>& packet) {
    std::cout << "数据包内容 (十六进制):" << std::endl;
    for (size_t i = 0; i < packet.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(packet[i]) << " ";
        if ((i + 1) % 16 == 0) std::cout << std::endl;
    }
    std::cout << std::dec << std::endl;
}

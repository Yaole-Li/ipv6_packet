#include "Receiver.h"
#include <iostream>
#include <chrono>
#include <pcap.h>
#include <netinet/ip6.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include "IPv6Packet.h"
#include <netinet/icmp6.h>
#include <iomanip>
#include <pcap/pcap.h>

// 构造函数：初始化接收器
Receiver::Receiver(int windowSize, size_t mtu, const std::string& interface, int threadCount)
    : windowSize(windowSize), mtu(mtu), interface(interface), threadCount(threadCount), 
      running(true), receivedPacketCount(0), stopRequested(false) {
    // 初始化 libpcap，用于接收数据包
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        throw std::runtime_error("无法打开网络接口: " + std::string(errbuf));
    }

    // 检查是否可以在此接口上发送数据包
    if (pcap_datalink(handle) == DLT_NULL) {
        std::cerr << "警告: 此接口可能不支持发送数据包" << std::endl;
    }

    // 尝试获取接口标志
    int dlt = pcap_datalink(handle);
    std::cout << "数据链路类型: " << pcap_datalink_val_to_name(dlt) << std::endl;

    // 初始化工作线程相关的数据结构
    packetQueues.resize(threadCount);
    queueMutexes.resize(threadCount);
    queueCVs.resize(threadCount);
    for (int i = 0; i < threadCount; ++i) {
        queueMutexes[i] = std::make_unique<std::mutex>();
        queueCVs[i] = std::make_unique<std::condition_variable>();
    }

    // 初始化 IPv6Packet 象，用于获取本地 MAC 和 IP 地址
    dummyPacket = std::make_unique<IPv6Packet>("", "", std::vector<uint8_t>(), std::vector<uint8_t>(), false);
}

// 析构函数：清理资源
Receiver::~Receiver() {
    running = false;
    // 所有工作线程退出
    for (auto& cv : queueCVs) {
        cv->notify_all();
    }
    // 等待所有工作程结束
    for (auto& thread : workerThreads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    // 关闭 libpcap 句柄
    if (handle != nullptr) {
        pcap_close(handle);
    }
}

// 开始接收数据包的主循环
void Receiver::startReceiving() {
    // 创建工作线程
    for (int i = 0; i < threadCount; ++i) {
        workerThreads.emplace_back(&Receiver::workerThread, this, i);
    }

    // 创建一个定时器线程来定期清理超时的数据流
    std::thread cleanupThread([this]() {
        while (running) {
            std::this_thread::sleep_for(std::chrono::minutes(1));  // 每分钟检查一次
            cleanupTimedOutFlows();  // 调用清理函数
        }
    });

    // 启动 libpcap 循环，开始捕获数据包
    pcap_loop(handle, 0, [](u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
        auto* receiver = reinterpret_cast<Receiver*>(userData);
        if (receiver->stopRequested.load()) {
            pcap_breakloop(receiver->handle);
        } else {
            receiver->packetHandler(userData, pkthdr, packet);
        }
    }, reinterpret_cast<u_char*>(this));

    // 等待所有工作线程结束
    for (auto& thread : workerThreads) {
        if (thread.joinable()) {
            thread.join();
        }
    }

    cleanupThread.join();  // 等待清理线程结束
}

// libpcap 回调函数，用于处理接收到的数据包
void Receiver::packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    // std::cout << "[Receiver.cpp] 接收到数据包，大小: " << pkthdr->len << " 字节" << std::endl;
    (void)userData;

    bool flag = true;

    // 更新接收到的数据包计数
    receivedPacketCount++;

    // 解析以太网帧头
    struct ether_header* ethHeader = (struct ether_header*)packet;
    if (ntohs(ethHeader->ether_type) != ETHERTYPE_IPV6) {
        // std::cout << "非 IPv6 数据包，忽略" << std::endl;
        flag = false;
        return;
    }

    // 解析 IPv6 头
    struct ip6_hdr* ipv6Header = (struct ip6_hdr*)(packet + sizeof(struct ether_header));
    
    // 检查目的 IPv6 地址是否为本机地址
    char destIP[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ipv6Header->ip6_dst, destIP, INET6_ADDRSTRLEN);
    if (std::string(destIP) != dummyPacket->getSrcIPv6()) {
        // std::cout << "数据包目的地址不是本机，忽略" << std::endl;
        flag = false;
        return;
    }

    // 检查是否包含我们特定的标识
    uint8_t nextHeader = ipv6Header->ip6_nxt;
    const uint8_t* currentHeader = (const uint8_t*)(ipv6Header + 1);
    bool hasDstOpt = false;

    while (nextHeader == IPPROTO_FRAGMENT || nextHeader == IPPROTO_DSTOPTS) {
        if (nextHeader == IPPROTO_FRAGMENT) {
            struct ip6_frag* fragHeader = (struct ip6_frag*)currentHeader;
            nextHeader = fragHeader->ip6f_nxt;
            currentHeader += sizeof(struct ip6_frag);
        } else if (nextHeader == IPPROTO_DSTOPTS) {
            hasDstOpt = true;
            break;
        }
    }

    if (!hasDstOpt) {
        // std::cout << "数据包不包含目的选项头部，忽略" << std::endl;
        flag = false;
        return;
    }

    if (flag) {
        std::cout << "[Receiver.cpp] 接收到数据包，大小: " << pkthdr->len << " 字节" << std::endl;
    }
    
    std::vector<uint8_t> packetData(packet, packet + pkthdr->len);

    // 提取流标识并计算哈希值，决定用哪个工作队列
    FlowKey flowKey = extractFlowKey(packetData);
    size_t queueIndex = std::hash<FlowKey>{}(flowKey) % threadCount;

    // 将数据包放入相应的工作队列
    std::unique_lock<std::mutex> lock(*queueMutexes[queueIndex]);
    packetQueues[queueIndex].push(std::move(packetData));
    lock.unlock();
    queueCVs[queueIndex]->notify_one();

    std::cout << "数据包已加入处理队列" << std::endl;
}

// 工作线程函数
void Receiver::workerThread(int threadId) {
    while (running) {
        std::vector<uint8_t> packetData;
        {
            std::unique_lock<std::mutex> lock(*queueMutexes[threadId]);
            queueCVs[threadId]->wait(lock, [this, threadId] { 
                return !packetQueues[threadId].empty() || !running; 
            });

            if (!running && packetQueues[threadId].empty()) break;

            packetData = std::move(packetQueues[threadId].front());
            packetQueues[threadId].pop();
        }

        handlePacket(packetData);
    }
}

// 处理单个数据包
void Receiver::handlePacket(const std::vector<uint8_t>& packetData) {
    std::cout << "---------[handlePacket]---------" << std::endl;
    std::cout << "[Receiver.cpp] 处理数据包，大小: " << packetData.size() << " 字节" << std::endl;
    
    // 跳过以太网头部（通常是14字节）
    const uint8_t* ipv6Packet = packetData.data() + 14;
    int ipv6PacketSize = packetData.size() - 14 - 4;

    if (!checkIPv6Header(ipv6Packet, ipv6PacketSize)) {
        std::cout << "[Receiver.cpp] IPv6 头部不完整，丢弃数据包" << std::endl;
        return;
    }

    FlowKey flowKey = extractFlowKey(packetData);
    bool hasPayload = checkPayload(ipv6Packet, ipv6PacketSize);

    std::cout << "[Receiver.cpp] 数据包" << (hasPayload ? "包含" : "不包含") << "有效载荷" << std::endl;

    std::unique_lock<std::mutex> lock(flowsMutex);
    if (flows.find(flowKey) == flows.end()) {
        flows[flowKey] = std::make_shared<FlowState>();
        flows[flowKey]->expectedSequenceNumber = 0;
        addFlowToQueue(flowKey);
    } else {
        updateFlowActivity(flowKey);
    }
    auto flowState = flows[flowKey];
    lock.unlock();

    // 处理数据包
    std::unique_lock<std::mutex> flowLock(flowState->flowMutex);
    uint32_t ackNumber = 0;
    if (!hasPayload) {
        ackNumber = reassembleExtensionHeader(flowKey, ipv6Packet, ipv6PacketSize);
    } else {
        ackNumber = reassemblePayload(flowKey, ipv6Packet, ipv6PacketSize);
    }
    flowLock.unlock();

    // 发送 ACK
    if (ackNumber != 0) {
        std::cout << "[Receiver.cpp] 准备发送 ACK，确认号: " << ackNumber << std::endl;
        sendAck(flowKey, ackNumber);
    }
    std::cout << "---------[handlePacket End]---------" << std::endl;
}

// 更新 extractFlowKey 方法
FlowKey Receiver::extractFlowKey(const std::vector<uint8_t>& packetData) {
    struct ether_header* ethHeader = (struct ether_header*)packetData.data();
    struct ip6_hdr* ip6Header = (struct ip6_hdr*)(packetData.data() + sizeof(struct ether_header));
    
    char srcIP[INET6_ADDRSTRLEN], destIP[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip6Header->ip6_src, srcIP, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &ip6Header->ip6_dst, destIP, INET6_ADDRSTRLEN);

    char srcMAC[18];
    snprintf(srcMAC, sizeof(srcMAC), "%02x:%02x:%02x:%02x:%02x:%02x",
             ethHeader->ether_shost[0], ethHeader->ether_shost[1], ethHeader->ether_shost[2],
             ethHeader->ether_shost[3], ethHeader->ether_shost[4], ethHeader->ether_shost[5]);

    // 假设源端口和目标端口在IPv6头部之后
    uint16_t srcPort = ntohs(*(uint16_t*)(packetData.data() + sizeof(struct ether_header) + sizeof(struct ip6_hdr)));
    uint16_t destPort = ntohs(*(uint16_t*)(packetData.data() + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + 2));

    // 提取 identification 字段
    uint32_t identification = 0;
    if (ip6Header->ip6_nxt == IPPROTO_FRAGMENT) {
        struct ip6_frag* fragHeader = (struct ip6_frag*)(packetData.data() + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
        identification = ntohl(fragHeader->ip6f_ident);
    }

    return FlowKey{identification, srcIP, destIP, srcPort, destPort, srcMAC};
}

// 检查 IPv6 头部是否完整
bool Receiver::checkIPv6Header(const uint8_t* packet, int packetSize) {
    std::cout << "---------[checkIPv6Header]---------" << std::endl;
    (void)packet;  // 避免未使用参数的警告
    if (static_cast<size_t>(packetSize) < sizeof(struct ip6_hdr)) {
        return false;
    }
    // 可以添加更多的头部检查逻辑
    std::cout << "---------[checkIPv6Header End]---------" << std::endl;
    return true;
}

// 检查是否有有效载荷
bool Receiver::checkPayload(const uint8_t* packet, int packetSize) {
    std::cout << "---------[checkPayload]---------" << std::endl;
    (void)packetSize;  // 避免未使用参数的警告
    struct ip6_hdr* ip6Header = (struct ip6_hdr*)packet;
    uint16_t payloadLen = ntohs(ip6Header->ip6_plen);
    
    // 计算基本头部和扩展头部的总长度
    int headerSize = sizeof(struct ip6_hdr);  // IPv6 基本头部大小
    uint8_t nextHeader = ip6Header->ip6_nxt;
    const uint8_t* currentHeader = packet + headerSize;
    
    std::cout << "[Receiver.cpp] IPv6 基本头部大小: " << headerSize << " 字节" << std::endl;
    std::cout << "[Receiver.cpp] 下一个头部类型: " << (int)nextHeader << std::endl;

    while (nextHeader == IPPROTO_FRAGMENT || nextHeader == IPPROTO_DSTOPTS) {
        if (nextHeader == IPPROTO_FRAGMENT) {
            struct ip6_frag* fragHeader = (struct ip6_frag*)currentHeader;
            headerSize += sizeof(struct ip6_frag);
            // std::cout << "[Receiver.cpp] 加上分片头部的头部大小: " << headerSize << " 字节" << std::endl;
            nextHeader = fragHeader->ip6f_nxt;
            currentHeader += sizeof(struct ip6_frag);
            std::cout << "[Receiver.cpp] 发现分片头部，大小: " << sizeof(struct ip6_frag) << " 字节" << std::endl;
        } else if (nextHeader == IPPROTO_DSTOPTS) {
            struct ip6_dest* dstopt = (struct ip6_dest*)currentHeader;
            // std::cout << "[Receiver.cpp] dstopt->ip6d_len大小: " << int(dstopt->ip6d_len) << " 字节" << std::endl;
            int optLen = (dstopt->ip6d_len) * 8 + 2;  // 正确计算目的选项头部的大小
            headerSize += optLen;
            // std::cout << "[Receiver.cpp] 加上目的选项的头部大小: " << headerSize << " 字节" << std::endl;
            nextHeader = dstopt->ip6d_nxt;
            currentHeader += optLen;
            std::cout << "[Receiver.cpp] 发现目的选项头部，大小: " << optLen << " 字节" << std::endl;
        }
        std::cout << "[Receiver.cpp] 下一个头部类型: " << (int)nextHeader << std::endl;
    }

    // 计算有效载荷长度
    int effectivePayloadSize = payloadLen - (headerSize - sizeof(struct ip6_hdr));
    bool hasEffectivePayload = (effectivePayloadSize > 0);

    std::cout << "[Receiver.cpp] 检查有效载荷: " << std::endl;
    std::cout << "  总长度 = " << packetSize << " 字节" << std::endl;
    std::cout << "  IPv6负载长度 = " << payloadLen << " 字节" << std::endl;
    std::cout << "  头部总长度 = " << headerSize << " 字节" << std::endl;
    std::cout << "  有效载荷长度 = " << effectivePayloadSize << " 字节" << std::endl;
    std::cout << "  是否有有效载荷: " << (hasEffectivePayload ? "是" : "否") << std::endl;

    // 打印数据包的十六进制内容
    /*
    std::cout << "[Receiver.cpp] 数据包内容 (十六进制):" << std::endl;
    for (int i = 0; i < packetSize; ++i) {
        printf("%02X ", packet[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
    */
    
    std::cout << "---------[checkPayload End]---------" << std::endl;
    return hasEffectivePayload;
}

// 重组扩展头部分（目的选项报头）
uint32_t Receiver::reassembleExtensionHeader(const FlowKey& flowKey, const uint8_t* packet, int packetSize) {
    std::cout << "---------[reassembleExtensionHeader]---------" << std::endl;
    std::cout << "[Receiver.cpp] 重组扩展头部，流标识: " << flowKey.srcIP << ":" << flowKey.srcPort << " -> " 
              << flowKey.destIP << ":" << flowKey.destPort << std::endl;
    struct ip6_hdr* ip6Header = (struct ip6_hdr*)packet;
    uint8_t nextHeader = ip6Header->ip6_nxt;
    int headerLen = sizeof(struct ip6_hdr);
    uint32_t ackNumber = 0;

    while (headerLen < packetSize) {
        switch (nextHeader) {
            case IPPROTO_DSTOPTS: {
                // 处的选项报头
                struct ip6_dest* dstopt = (struct ip6_dest*)(packet + headerLen);
                int optLen = (dstopt->ip6d_len + 1) * 8;  // 目的选项报头的长度

                // 提取目的选项报头内容，跳过批次ID
                std::vector<uint8_t> dstoptContent(packet + headerLen + 2 + 8, packet + headerLen + optLen);

                // 更新流表，使用分片偏移作为序列号
                uint16_t fragmentOffset = 0;
                if (ip6Header->ip6_nxt == IPPROTO_FRAGMENT) {
                    struct ip6_frag* fragHeader = (struct ip6_frag*)(packet + sizeof(struct ip6_hdr));
                    fragmentOffset = ntohs(fragHeader->ip6f_offlg & IP6F_OFF_MASK);
                }
                ackNumber = updateFlowTable(flowKey, fragmentOffset, dstoptContent);

                nextHeader = dstopt->ip6d_nxt;
                headerLen += optLen;
                break;
            }
            case IPPROTO_FRAGMENT:
                // 处理分片头部
                ackNumber = handleFragment(flowKey, packet + headerLen, packetSize - headerLen);
                return ackNumber;  // 分片头部之后就负载或者下一个扩展头，在这里结束处理
            default:
                // 未知的头部类型或者已经到达负载部分，停止处理
                return ackNumber;
        }
    }
    std::cout << "---------[reassembleExtensionHeader End]---------" << std::endl;
    return ackNumber;
}

// 重组负载部分
uint32_t Receiver::reassemblePayload(const FlowKey& flowKey, const uint8_t* packet, int packetSize) {
    std::cout << "---------[reassemblePayload]---------" << std::endl;
    std::cout << "[Receiver.cpp] 重组有效载荷，流标识: " << flowKey.srcIP << ":" << flowKey.srcPort << " -> " 
              << flowKey.destIP << ":" << flowKey.destPort << std::endl;
    
    struct ip6_hdr* ip6Header = (struct ip6_hdr*)packet;
    int headerLen = sizeof(struct ip6_hdr);
    uint16_t payloadLen = ntohs(ip6Header->ip6_plen);

    // 计算实际的有效载荷开始位置
    int extensionHeaderSize = 0;
    uint8_t nextHeader = ip6Header->ip6_nxt;
    const uint8_t* currentHeader = packet + headerLen;
    
    while (nextHeader == IPPROTO_FRAGMENT || nextHeader == IPPROTO_DSTOPTS) {
        if (nextHeader == IPPROTO_FRAGMENT) {
            struct ip6_frag* fragHeader = (struct ip6_frag*)currentHeader;
            extensionHeaderSize += sizeof(struct ip6_frag);
            nextHeader = fragHeader->ip6f_nxt;
            currentHeader += sizeof(struct ip6_frag);
        } else if (nextHeader == IPPROTO_DSTOPTS) {
            struct ip6_dest* dstopt = (struct ip6_dest*)currentHeader;
            int optLen = (dstopt->ip6d_len + 1) * 8;
            extensionHeaderSize += optLen;
            nextHeader = dstopt->ip6d_nxt;
            currentHeader += optLen;
        }
    }

    int effectivePayloadSize = payloadLen - extensionHeaderSize;
    if (headerLen + payloadLen <= packetSize && effectivePayloadSize > 0) {
        std::vector<uint8_t> effectivePayload(packet + headerLen + extensionHeaderSize, 
                                              packet + headerLen + payloadLen);
        
        uint16_t fragmentOffset = 0;
        if (ip6Header->ip6_nxt == IPPROTO_FRAGMENT) {
            struct ip6_frag* fragHeader = (struct ip6_frag*)(packet + sizeof(struct ip6_hdr));
            fragmentOffset = ntohs(fragHeader->ip6f_offlg & IP6F_OFF_MASK);
        }

        std::cout << "[Receiver.cpp] 有效载荷大小: " << effectivePayload.size() 
                  << " 字节, 分片偏移: " << fragmentOffset << std::endl;

        std::cout << "---------[reassemblePayload End]---------" << std::endl;
        return updateFlowTable(flowKey, fragmentOffset, effectivePayload);
    }

    std::cout << "[Receiver.cpp] 无有效载荷或数据包大小不正确" << std::endl;
    std::cout << "---------[reassemblePayload End]---------" << std::endl;
    return 0;
}

// 更新 handleFragment 方法
uint32_t Receiver::handleFragment(const FlowKey& flowKey, const uint8_t* fragmentHeader, int remainingSize) {
    if (static_cast<size_t>(remainingSize) < sizeof(struct ip6_frag)) {
        return 0;
    }

    struct ip6_frag* fragHeader = (struct ip6_frag*)fragmentHeader;
    uint16_t fragmentOffset = ntohs(fragHeader->ip6f_offlg & IP6F_OFF_MASK);
    bool moreFragments = (fragHeader->ip6f_offlg & IP6F_MORE_FRAG) != 0;

    std::vector<uint8_t> fragmentData(fragmentHeader + sizeof(struct ip6_frag),
                                      fragmentHeader + remainingSize);
    
    // 更新流表
    std::unique_lock<std::mutex> lock(flowsMutex);
    auto& flowState = flows[flowKey];
    lock.unlock();

    std::unique_lock<std::mutex> flowLock(flowState->flowMutex);
    flowState->flowTable[fragmentOffset] = {fragmentData, true, std::chrono::steady_clock::now()};

    if (!moreFragments) {
        // 尝试重组数据包
        std::vector<uint8_t> reassembledPacket = reassemblePacket(flowState->flowTable);
        if (!reassembledPacket.empty()) {
            // 处理重组后的数据包
            handleReassembledPacket(flowKey, reassembledPacket);
            // 清理流表
            flowState->flowTable.clear();
            return fragmentOffset + fragmentData.size();  // 返回最后一个分片的结束位置
        }
    }

    return 0;  // 如果不是最后一个分片或重组失败，返回0
}

// 处理重组后的数据包
std::vector<uint8_t> Receiver::handleReassembledPacket(const FlowKey& flowKey, const std::vector<uint8_t>& reassembledPacket) {
    (void)flowKey;
    // 解析重组后的数据包
    size_t headerSize = sizeof(struct ip6_hdr);  // IPv6 基本头部大小
    size_t extensionHeaderSize = 0;  // 扩展头部大小（包括目的选项报头）
    
    // 解析扩展头部
    uint8_t nextHeader = reassembledPacket[6];  // 下一个头部字段在IPv6头部的第6个字节
    size_t offset = headerSize;
    while (nextHeader == IPPROTO_DSTOPTS) {
        struct ip6_dest* dstopt = (struct ip6_dest*)(reassembledPacket.data() + offset);
        extensionHeaderSize += (dstopt->ip6d_len + 1) * 8;
        offset += (dstopt->ip6d_len + 1) * 8;
        nextHeader = dstopt->ip6d_nxt;
    }
    
    // 检查是否有负载数据
    if (reassembledPacket.size() > headerSize + extensionHeaderSize) {
        // 有负载数据，返回负载内容
        return std::vector<uint8_t>(reassembledPacket.begin() + headerSize + extensionHeaderSize, 
                                    reassembledPacket.end());
    } else {
        // 没有负载数据，返回目的选项报头内容（不包括前8个字节的数据流ID）
        return std::vector<uint8_t>(reassembledPacket.begin() + headerSize + 8, 
                                    reassembledPacket.begin() + headerSize + extensionHeaderSize);
    }
}

// 发送 ACK
void Receiver::sendAck(const FlowKey& flowKey, uint32_t ackNumber) {
    std::cout << "---------[sendAck]---------" << std::endl;
    std::cout << "[Receiver.cpp] 准备发送 ACK: " << ackNumber << " 给 " << flowKey.srcIP << ":" << flowKey.srcPort << std::endl;

    // 构造以太网帧头
    struct ether_header ethHeader;
    sscanf(flowKey.srcMAC.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
           &ethHeader.ether_dhost[0], &ethHeader.ether_dhost[1], &ethHeader.ether_dhost[2],
           &ethHeader.ether_dhost[3], &ethHeader.ether_dhost[4], &ethHeader.ether_dhost[5]);
    sscanf(dummyPacket->getSrcMAC().c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
           &ethHeader.ether_shost[0], &ethHeader.ether_shost[1], &ethHeader.ether_shost[2],
           &ethHeader.ether_shost[3], &ethHeader.ether_shost[4], &ethHeader.ether_shost[5]);
    ethHeader.ether_type = htons(ETHERTYPE_IPV6);

    // 构造 IPv6 头部
    struct ip6_hdr ipv6Header;
    memset(&ipv6Header, 0, sizeof(ipv6Header));
    ipv6Header.ip6_flow = htonl((6 << 28));
    ipv6Header.ip6_plen = htons(12);  // ACK 号(4) + 原始包标识符(4) + 源端口(2) + 目标端口(2)
    ipv6Header.ip6_nxt = 253;  // 使用自定义协议号
    ipv6Header.ip6_hlim = 64;
    inet_pton(AF_INET6, flowKey.destIP.c_str(), &ipv6Header.ip6_src);
    inet_pton(AF_INET6, flowKey.srcIP.c_str(), &ipv6Header.ip6_dst);

    // 构造 ACK 负载
    std::vector<uint8_t> ackPayload;
    uint32_t networkAckNumber = htonl(ackNumber);
    ackPayload.insert(ackPayload.end(), reinterpret_cast<uint8_t*>(&networkAckNumber), reinterpret_cast<uint8_t*>(&networkAckNumber) + 4);
    uint32_t originalPacketId = htonl(flowKey.identification);
    ackPayload.insert(ackPayload.end(), reinterpret_cast<uint8_t*>(&originalPacketId), reinterpret_cast<uint8_t*>(&originalPacketId) + 4);
    uint16_t srcPort = htons(flowKey.srcPort);
    ackPayload.insert(ackPayload.end(), reinterpret_cast<uint8_t*>(&srcPort), reinterpret_cast<uint8_t*>(&srcPort) + 2);
    uint16_t dstPort = htons(flowKey.destPort);
    ackPayload.insert(ackPayload.end(), reinterpret_cast<uint8_t*>(&dstPort), reinterpret_cast<uint8_t*>(&dstPort) + 2);

    // 构造完整的数据包
    std::vector<uint8_t> packet;
    packet.insert(packet.end(), reinterpret_cast<uint8_t*>(&ethHeader), reinterpret_cast<uint8_t*>(&ethHeader) + sizeof(ethHeader));
    packet.insert(packet.end(), reinterpret_cast<uint8_t*>(&ipv6Header), reinterpret_cast<uint8_t*>(&ipv6Header) + sizeof(ipv6Header));
    packet.insert(packet.end(), ackPayload.begin(), ackPayload.end());

    // 打印详细的 ACK 包内容
    /*
    std::cout << "[Receiver.cpp] ACK 包详细内容:" << std::endl;
    std::cout << "  IPv6 头部:" << std::endl;
    std::cout << "    版本: " << ((ntohl(ipv6Header.ip6_flow) & 0xF0000000) >> 28) << std::endl;
    std::cout << "    流量类: " << ((ntohl(ipv6Header.ip6_flow) & 0x0FF00000) >> 20) << std::endl;
    std::cout << "    流标签: " << (ntohl(ipv6Header.ip6_flow) & 0x000FFFFF) << std::endl;
    std::cout << "    负载长度: " << ntohs(ipv6Header.ip6_plen) << std::endl;
    std::cout << "    下一个头部: " << (int)ipv6Header.ip6_nxt << std::endl;
    std::cout << "    跳数限制: " << (int)ipv6Header.ip6_hlim << std::endl;
    char srcIP[INET6_ADDRSTRLEN], dstIP[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ipv6Header.ip6_src, srcIP, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &ipv6Header.ip6_dst, dstIP, INET6_ADDRSTRLEN);
    std::cout << "    源 IP: " << srcIP << std::endl;
    std::cout << "    目标 IP: " << dstIP << std::endl;
    
    std::cout << "  ACK 负载:" << std::endl;
    std::cout << "    ACK 号: " << ackNumber << std::endl;
    std::cout << "    原始包 ID: " << flowKey.identification << std::endl;
    std::cout << "    源端口: " << flowKey.srcPort << std::endl;
    std::cout << "    目标端口: " << flowKey.destPort << std::endl;

    std::cout << "  完整数据包 (十六进制):" << std::endl;
    for (size_t i = 0; i < packet.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)packet[i] << " ";
        if ((i + 1) % 16 == 0) std::cout << std::endl;
    }
    std::cout << std::dec << std::endl;
    */

    // 发送数据包
    int result = pcap_inject(handle, packet.data(), packet.size());
    if (result == -1) {
        std::cerr << "[Receiver.cpp] 发送 ACK 失败: " << pcap_geterr(handle) << std::endl;
        std::cerr << "[Receiver.cpp] 错误代码: " << errno << " (" << strerror(errno) << ")" << std::endl;
    } else {
        std::cout << "[Receiver.cpp] ACK 发送成功，确认号: " << ackNumber 
                  << " 发送给 " << flowKey.srcIP << ":" << flowKey.srcPort 
                  << "，大小: " << result << " 字节" << std::endl;
    }

    // 检查 pcap 句柄状态
    struct pcap_stat stats;
    int status = pcap_stats(handle, &stats);
    if (status == 0) {
        std::cout << "[Receiver.cpp] pcap 统计: 接收 " << stats.ps_recv 
                  << ", 丢弃 " << stats.ps_drop 
                  << ", 接口丢弃 " << stats.ps_ifdrop << std::endl;
    } else {
        std::cerr << "[Receiver.cpp] 无法获取 pcap 统计: " << pcap_geterr(handle) << std::endl;
    }
    std::cout << "---------[sendAck End]---------" << std::endl;
}

// 计算 ICMPv6 校验和
uint16_t Receiver::calculateICMPv6Checksum(const std::vector<uint8_t>& packet, const struct ip6_hdr& ipv6Header) {
    // 1. 准备 IPv6 伪头部
    struct {
        uint8_t src[16];
        uint8_t dst[16];
        uint32_t length;
        uint8_t zeros[3];
        uint8_t next_header;
    } pseudo_header;

    memcpy(pseudo_header.src, &ipv6Header.ip6_src, 16);
    memcpy(pseudo_header.dst, &ipv6Header.ip6_dst, 16);
    pseudo_header.length = htonl(packet.size() - sizeof(struct ip6_hdr));
    memset(pseudo_header.zeros, 0, 3);
    pseudo_header.next_header = IPPROTO_ICMPV6;

    // 2. 计算校验和
    uint32_t sum = 0;

    // 2.1 计算伪头部的校验和
    uint16_t* ptr = reinterpret_cast<uint16_t*>(&pseudo_header);
    for (size_t i = 0; i < sizeof(pseudo_header) / 2; ++i) {
        sum += ntohs(*ptr++);
    }

    // 2.2 计算 ICMPv6 消息的校验和
    ptr = reinterpret_cast<uint16_t*>(const_cast<uint8_t*>(packet.data() + sizeof(struct ip6_hdr)));
    int icmpv6_len = packet.size() - sizeof(struct ip6_hdr);
    for (int i = 0; i < icmpv6_len / 2; ++i) {
        sum += ntohs(*ptr++);
    }

    // 如果 ICMPv6 消息长度为奇数，处理最后一个字节
    if (icmpv6_len % 2) {
        sum += *(reinterpret_cast<uint8_t*>(ptr)) << 8;
    }

    // 3. 将高 16 位与低 16 位相加
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // 4. 取反
    return static_cast<uint16_t>(~sum);
}

// 更新流表
uint32_t Receiver::updateFlowTable(const FlowKey& flowKey, uint32_t sequenceNumber, const std::vector<uint8_t>& data) {
    std::cout << "---------[updateFlowTable]---------" << std::endl;
    std::cout << "[Receiver.cpp] 更新流表，序列号: " << sequenceNumber << ", 数据大小: " << data.size() << " 字节" << std::endl;
    auto& flowState = flows[flowKey];
    flowState->flowTable[sequenceNumber] = {data, true, std::chrono::steady_clock::now()};

    // 查找连续的最高序列号
    uint32_t highestContiguousSequence = flowState->expectedSequenceNumber;
    while (flowState->flowTable.find(highestContiguousSequence) != flowState->flowTable.end()) {
        highestContiguousSequence += flowState->flowTable[highestContiguousSequence].data.size();
    }

    // 更新期望的序列号
    flowState->expectedSequenceNumber = highestContiguousSequence;

    std::cout << "---------[updateFlowTable End]---------" << std::endl;
    return highestContiguousSequence - 1;  // 返回最高连续序列号作为 ACK
}

// 检查是否可以向上层传递数据
void Receiver::checkAndDeliverData(const FlowKey& flowKey) {
    std::unique_lock<std::mutex> lock(flowsMutex);
    auto flowState = flows[flowKey];
    lock.unlock();

    std::unique_lock<std::mutex> flowLock(flowState->flowMutex);
    while (flowState->flowTable.find(flowState->expectedSequenceNumber) != flowState->flowTable.end()) {
        const auto& packetStatus = flowState->flowTable[flowState->expectedSequenceNumber];
        if (packetStatus.received) {
            // 向上层传递数据
            deliverData(flowKey, packetStatus.data);
            flowState->flowTable.erase(flowState->expectedSequenceNumber);
            flowState->expectedSequenceNumber++;
        } else {
            break;
        }
    }
    flowLock.unlock();
}

// 向上层传递数据
std::vector<uint8_t> Receiver::deliverData(const FlowKey& flowKey, const std::vector<uint8_t>& data) {
    std::cout << "[Receiver.cpp] deliverData: 开始处理数据包" << std::endl;
    std::cout << "[Receiver.cpp] deliverData: 数据包大小: " << data.size() << " 字节" << std::endl;
    std::cout << "[Receiver.cpp] deliverData: 原始数据内容: ";
    for (const auto& byte : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
    }
    std::cout << std::dec << std::endl;

    // 解析数据包
    size_t headerSize = sizeof(struct ip6_hdr);  // IPv6 基本头部大小
    size_t extensionHeaderSize = 0;  // 扩展头部大小（包括目的选项报头和可能的分片头部）
    
    // 解析扩展头部
    uint8_t nextHeader = data[6];  // 下一个头部字段在IPv6头部的第6个字节
    size_t offset = headerSize;
    bool hasFragmentHeader = false;

    std::cout << "[Receiver.cpp] deliverData: 开始解析扩展头部" << std::endl;
    while (nextHeader == IPPROTO_FRAGMENT || nextHeader == IPPROTO_DSTOPTS) {
        if (nextHeader == IPPROTO_FRAGMENT) {
            std::cout << "[Receiver.cpp] deliverData: 发现分片头部" << std::endl;
            struct ip6_frag* fragHeader = (struct ip6_frag*)(data.data() + offset);
            extensionHeaderSize += sizeof(struct ip6_frag);
            offset += sizeof(struct ip6_frag);
            nextHeader = fragHeader->ip6f_nxt;
            hasFragmentHeader = true;
        } else if (nextHeader == IPPROTO_DSTOPTS) {
            std::cout << "[Receiver.cpp] deliverData: 发现目的选项头部" << std::endl;
            struct ip6_dest* dstopt = (struct ip6_dest*)(data.data() + offset);
            extensionHeaderSize += (dstopt->ip6d_len + 1) * 8;
            offset += (dstopt->ip6d_len + 1) * 8;
            nextHeader = dstopt->ip6d_nxt;
        }
    }
    
    std::cout << "[Receiver.cpp] deliverData: 扩展头部大小: " << extensionHeaderSize << " 字节" << std::endl;

    std::vector<uint8_t> result;
    // 检查是否有负载数据
    if (data.size() > headerSize + extensionHeaderSize) {
        std::cout << "[Receiver.cpp] deliverData: 发现负载数据" << std::endl;
        // 有负载数据，返回负载内容
        result = std::vector<uint8_t>(data.begin() + headerSize + extensionHeaderSize, data.end());
    } else {
        std::cout << "[Receiver.cpp] deliverData: 没有负载数据，返回目的选项报头内容" << std::endl;
        // 没有负载数据，返回目的选项报头内容（不包括前8个字节的数据流ID）
        size_t startOffset = headerSize;
        if (hasFragmentHeader) {
            startOffset += sizeof(struct ip6_frag);
        }
        startOffset += 8;  // 跳过数据流ID
        result = std::vector<uint8_t>(data.begin() + startOffset, 
                                      data.begin() + headerSize + extensionHeaderSize);
    }

    std::cout << "[Receiver.cpp] deliverData: 提取的内容大小: " << result.size() << " 字节" << std::endl;
    std::cout << "[Receiver.cpp] deliverData: 提取的内容: ";
    for (const auto& byte : result) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
    }
    std::cout << std::dec << std::endl;

    // 将接收到的数据添加到 receivedData
    {
        std::lock_guard<std::mutex> lock(receivedDataMutex);
        receivedData.push_back(result);
    }

    // 判断是否是最后一个分片的逻辑
    bool isLastFragment = false;
    if (hasFragmentHeader) {
        struct ip6_frag* fragHeader = (struct ip6_frag*)(data.data() + sizeof(struct ip6_hdr));
        uint16_t fragmentOffset = ntohs(fragHeader->ip6f_offlg & IP6F_OFF_MASK);
        uint8_t moreFragments = fragHeader->ip6f_offlg & IP6F_MORE_FRAG;
        isLastFragment = (moreFragments == 0 && fragmentOffset != 0);
    } else {
        isLastFragment = true;  // 如果没有分片头部，就认为是整的包
    }

    std::cout << "[Receiver.cpp] deliverData: 是否为最后一个分片: " << (isLastFragment ? "是" : "否") << std::endl;

    if (isLastFragment) {
        removeFlowFromQueue(flowKey);
    }

    std::cout << "[Receiver.cpp] deliverData: 处理成功" << std::endl;
    return result;
}

// 重组分片的数据包
std::vector<uint8_t> Receiver::reassemblePacket(const std::map<uint32_t, PacketStatus>& fragments) {
    std::vector<uint8_t> reassembledPacket;
    uint16_t expectedOffset = 0;

    for (const auto& fragment : fragments) {
        if (fragment.first != expectedOffset) {
            // 分片不连续，无法重组
            return std::vector<uint8_t>();
        }
        reassembledPacket.insert(reassembledPacket.end(), 
                                 fragment.second.data.begin(), 
                                 fragment.second.data.end());
        expectedOffset += fragment.second.data.size();
    }

    return reassembledPacket;
}

void Receiver::stop() {
    stopRequested = true;
    running = false;
    // 通知所有工作线程
    for (auto& cv : queueCVs) {
        cv->notify_all();
    }
    // 中断 pcap 循环
    pcap_breakloop(handle);
}

// 清理超时的数据流
void Receiver::cleanupTimedOutFlows() {
    std::cout << "---------[cleanupTimedOutFlows]---------" << std::endl;
    std::cout << "[Receiver.cpp] 开始清理超时数据流" << std::endl;
    std::lock_guard<std::mutex> lock(flowListMutex);
    auto now = std::chrono::steady_clock::now();
    auto it = flowList.begin();
    while (it != flowList.end()) {
        if (now - it->lastActivityTime >= FLOW_TIMEOUT) {
            std::cout << "清理超时的数据流: " << it->flowKey.srcIP << ":" << it->flowKey.srcPort 
                      << " -> " << it->flowKey.destIP << ":" << it->flowKey.destPort 
                      << " (ID: " << it->flowKey.identification << ")" << std::endl;
            flowMap.erase(it->flowKey);
            flows.erase(it->flowKey);  // 同时从 flows 中移除
            it = flowList.erase(it);
        } else {
            // 一旦遇到未超时的流，就可以停止检查
            break;
        }
    }
    std::cout << "---------[cleanupTimedOutFlows End]---------" << std::endl;
}

// 添加 addFlowToQueue 方法的实现
void Receiver::addFlowToQueue(const FlowKey& flowKey) {
    std::lock_guard<std::mutex> lock(flowListMutex);
    auto it = flowMap.find(flowKey);
    if (it == flowMap.end()) {
        // 如果数据流不存在，添加到列表末尾
        flowList.push_back({flowKey, std::chrono::steady_clock::now()});
        flowMap[flowKey] = --flowList.end();
    } else {
        // 如果数据流已存在，更新其活动时间并移动到列表末尾
        it->second->lastActivityTime = std::chrono::steady_clock::now();
        flowList.splice(flowList.end(), flowList, it->second);
    }
}

// 添加 removeFlowFromQueue 方法的实现
void Receiver::removeFlowFromQueue(const FlowKey& flowKey) {
    std::lock_guard<std::mutex> lock(flowListMutex);
    auto it = flowMap.find(flowKey);
    if (it != flowMap.end()) {
        flowList.erase(it->second);
        flowMap.erase(it);
    }
}

// 添加 updateFlowActivity 方法的实现
void Receiver::updateFlowActivity(const FlowKey& flowKey) {
    std::lock_guard<std::mutex> lock(flowListMutex);
    auto it = flowMap.find(flowKey);
    if (it != flowMap.end()) {
        it->second->lastActivityTime = std::chrono::steady_clock::now();
        flowList.splice(flowList.end(), flowList, it->second);
    }
}

// 在文件末尾添加这个新方法的实现
std::vector<std::vector<uint8_t>> Receiver::getReceivedData() {
    std::lock_guard<std::mutex> lock(receivedDataMutex);
    return receivedData;
}

// 实现新的方法来获取接收到的数据包数量
size_t Receiver::getReceivedPacketCount() const {
    return receivedPacketCount.load();
}

/*
Receiver 工作程：

1. 初始化
   - 构造函数被调用，初始化参数（窗口大小、MTU、网络接口等）
   - 创建 libpcap 句柄，准备捕获数包
   - 初始工作线程相关的数据结构（队列、互斥锁、条件变量）

2. 启动接收过程 (startReceiving)
   - 创建多个工作线程
   - 启动 libpcap 循环，开始捕获数据

3. 数据包捕获 (packetHandler)
   - libpcap 捕获到数据包时调用 packetHandler
   - 提取流标识（FlowKey），计算哈希值
   - 将据包放入相应的工作队列

4. 工作线程处理 (workerThread)
   - 工作线程不断从队列中获取数据包
   - 调用 handlePacket 处理每个数据包

5. 数据包处理 (handlePacket)
   - 检查 IPv6 头部完整性
   - 提取流标识信息
   - 检查是否有负载
   - 获取或创建对应流状态
   - 根据是否有负载，调用 reassembleExtensionHeader 或 reassemblePayload
   - 发送 ACK

6. 重组扩展头部 (reassembleExtensionHeader)
   - 解析扩展头部（主要是目的选报头）
   - 提目的选项报头内容
   - 更新流表

7. 重组负载 (reassemblePayload)
   - 提取负载内容
   - 更新流表

8. 处理分片 (handleFragmentHeader)
   - 解析分片头部
   - 提取分片数据
   - 更新流表
   - 如果是最后一个分片，尝试重组完整数据包

9. 重组数据包 (reassemblePacket)
   - 按序号拼接所有分片

10. 处理重组后的数据包 (handleReassembledPacket)
    - 解析重组后的数据包
    - 提取目的选项报头内容或负载内容
    - 返回提取的内容

11. 更流表 (updateFlowTable)
    - 将接收到的数据包信息添加到流表中
    - 调用 checkAndDeliverData 检查是否可以传递数据

12. 检查和传递数据 (checkAndDeliverData)
    - 检查是否有连续的数据包可以传递
    - 调用 deliverData 传递数据
    - 更新期望的下一个序列号

13. 传递数据 (deliverData)
    - 解析数据包
    - 提取目的选项报头内容或负载内容
    - 返回提取的内容

14. 发送 ACK (sendAck)
    - 创建 ACK 数据包
    - 使用 libpcap 发送 ACK

整个过程中，Receiver 持续接收数据包，处理分片，重组数据包，并在适当的时候向上层传递数据。
同时，它通过发 ACK 来确认接收到的数据包，实现可靠的数据传输。
多线程的设计允许并行处理来自不同数据流的数据包，提高了处理效率。
*/
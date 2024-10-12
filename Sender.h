#ifndef SENDER_H
#define SENDER_H

#include "IPv6Packet.h"
#include <map>
#include <chrono>
#include <vector>
#include <memory>
#include <pcap.h>

// Sender 类负责管理 IPv6 数据包的发送、重传和流量控制
class Sender {
public:
    // 构造函数：初始化发送器
    // windowSize: 滑动窗口大小
    // mtu: 最大传输单元
    // interface: 网络接口名称
    Sender(int windowSize, size_t mtu, const std::string& interface);

    // 析构函数
    ~Sender();

    // 创建并添加新的 IPv6Packet 到发送队列
    // destMAC: 目标 MAC 地址
    // destIPv6: 目标 IPv6 地址
    // payload: 负载数据
    // extensionHeaderContent: 扩展头部内容
    // fragmentFlag: 是否需要分片
    void addPacket(const std::string& destMAC, const std::string& destIPv6, 
                   const std::vector<uint8_t>& payload, 
                   const std::vector<uint8_t>& extensionHeaderContent,
                   bool fragmentFlag);

    // 尝试发送下一个数据包
    // 返回值: 是否成功发送
    bool sendPacket();

    // 处理接收到的 ACK
    // ackNumber: 确认号
    void handleAck(uint32_t ackNumber);

    // 检查并处理超时的数据包
    void checkTimeouts();

    // 接收并处理 ACK
    void receiveAck();

private:
    // 数据包状态结构体
    struct PacketStatus {
        std::shared_ptr<IPv6Packet> packet;  // 指向 IPv6Packet 的智能指针
        bool sent;                           // 是否已发送
        bool acknowledged;                   // 是否已确认
        std::chrono::steady_clock::time_point sentTime;  // 发送时间
        std::vector<bool> fragmentsAcknowledged;  // 各分片的确认状态
    };

    int windowSize;         // 滑动窗口大小
    uint32_t nextSequenceNumber;  // 下一个要发送的序列号
    uint32_t base;          // 滑动窗口的基序列号
    std::map<uint32_t, PacketStatus> flowTable;  // 流表，记录每个数据包的状态
    size_t mtu;             // 最大传输单元

    std::vector<std::shared_ptr<IPv6Packet>> packetQueue;  // 待发送的数据包队列

    // 更新流表
    // sequenceNumber: 序列号
    // sent: 是否已发送
    // acknowledged: 是否已确认
    void updateFlowTable(uint32_t sequenceNumber, bool sent, bool acknowledged);

    // 重新发送指定序列号的数据包
    // sequenceNumber: 需要重传的数据包序列号
    void retransmitPacket(uint32_t sequenceNumber);

    // 将数据包分片
    // packet: 需要分片的 IPv6Packet
    // 返回值: 分片后的数据向量
    std::vector<std::vector<uint8_t>> fragmentPacket(const IPv6Packet& packet);

    // 发送单个分片
    // fragment: 分片数据
    // sequenceNumber: 序列号
    // fragmentOffset: 分片偏移
    // moreFragments: 是否还有更多分片
    // 返回值: 是否成功发送
    bool sendFragment(const std::vector<uint8_t>& fragment, uint32_t sequenceNumber, uint16_t fragmentOffset, bool moreFragments);

    // 将数据包添加以太网帧头和帧尾
    // ipv6Packet: IPv6数据包
    // 返回值: 添加了以太网帧头和帧尾的完整数据包
    std::vector<uint8_t> addEthernetFrame(const std::vector<uint8_t>& ipv6Packet);

    // CRC32 计算
    // data: 需要计算CRC的数据
    // 返回值: CRC值
    uint32_t calculateCRC(const std::vector<uint8_t>& data);

    std::string interface;  // 网络接口名称
    pcap_t* handle;         // libpcap 句柄

    // 生成唯一的标识符
    uint32_t generateUniqueIdentification();

    size_t maxFragmentSize;  // 最大分片大小

    // 用于接收 ACK 的 pcap 句柄
    pcap_t* ack_handle;

    // 处理接收到的 ACK 数据包
    uint32_t processAckPacket(const uint8_t* packet, int size);
};

#endif // SENDER_H

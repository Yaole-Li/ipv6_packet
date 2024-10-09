#ifndef RECEIVER_H
#define RECEIVER_H

#include "IPv6Packet.h"
#include <map>
#include <chrono>
#include <vector>
#include <memory>
#include <pcap.h>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <atomic>

// Receiver 类负责接收和处理 IPv6 数据包
class Receiver {
public:
    // 构造函数：初始化接收器
    // windowSize: 滑动窗口大小
    // mtu: 最大传输单元
    // interface: 网络接口名称
    // threadCount: 工作线程数量
    Receiver(int windowSize, size_t mtu, const std::string& interface, int threadCount);

    // 析构函数：清理资源
    ~Receiver();

    // 开始接收数据包的主循环
    void startReceiving();

private:
    // 数据包状态结构体，用于跟踪每个接收到的数据包
    struct PacketStatus {
        std::vector<uint8_t> data;  // 数据包内容
        bool received;              // 是否已接收
        std::chrono::steady_clock::time_point receiveTime;  // 接收时间
    };

    // 流标识结构体，用于唯一标识一个数据流
    struct FlowKey {
        uint64_t batchId;  // 批次ID，用于区分同一源IP的不同数据流
        std::string srcIP;
        std::string destIP;
        uint16_t srcPort;
        uint16_t destPort;
        std::string srcMAC;  // 新增：源 MAC 地址

        // 比较运算符，用于在 map 中作为键
        bool operator<(const FlowKey& other) const {
            return std::tie(batchId, srcIP, destIP, srcPort, destPort, srcMAC) < 
                   std::tie(other.batchId, other.srcIP, other.destIP, other.srcPort, other.destPort, other.srcMAC);
        }
    };

    // 流状态结构体，用于管理每个数据流的状态
    struct FlowState {
        uint32_t expectedSequenceNumber;  // 期望接收的下一个序列号
        std::map<uint32_t, PacketStatus> flowTable;  // 该流的数据包状态表
        std::mutex flowMutex;  // 用于保护该流状态的互斥锁
    };

    int windowSize;  // 滑动窗口大小
    size_t mtu;      // 最大传输单元
    std::string interface;  // 网络接口名称
    pcap_t* handle;  // libpcap 句柄
    int threadCount;  // 工作线程数量

    std::map<FlowKey, std::shared_ptr<FlowState>> flows;  // 所有数据流的状态表
    std::mutex flowsMutex;  // 用于保护 flows 的互斥锁

    std::vector<std::thread> workerThreads;  // 工作线程池
    std::vector<std::queue<std::vector<uint8_t>>> packetQueues;  // 每个工作线程的数据包队列
    std::vector<std::mutex> queueMutexes;  // 用于保护每个队列的互斥锁
    std::vector<std::condition_variable> queueCVs;  // 用于线程同步的条件变量
    std::atomic<bool> running;  // 控制接收循环的原子布尔值

    std::unique_ptr<IPv6Packet> dummyPacket;  // 用于获取本地 MAC 和 IP 地址

    // libpcap 回调函数，用于处理接收到的数据包
    void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

    // 工作线程函数
    void workerThread(int threadId);

    // 处理单个数据包
    void handlePacket(const std::vector<uint8_t>& packetData);

    // 检查 IPv6 头部是否完整
    bool checkIPv6Header(const uint8_t* packet, int packetSize);

    // 检查是否有负载数据
    bool checkPayload(const uint8_t* packet, int packetSize);

    // 重组扩展头部（目的选项报头）
    void reassembleExtensionHeader(const FlowKey& flowKey, const uint8_t* packet, int packetSize);

    // 重组负载部分
    void reassemblePayload(const FlowKey& flowKey, const uint8_t* packet, int packetSize);

    // 处理分片头部
    void handleFragmentHeader(const FlowKey& flowKey, const uint8_t* fragmentHeader, int remainingSize);

    // 处理重组后的数据包
    std::vector<uint8_t> handleReassembledPacket(const FlowKey& flowKey, const std::vector<uint8_t>& reassembledPacket);

    // 发送 ACK
    void sendAck(const FlowKey& flowKey, uint32_t ackNumber);

    // 更新流表
    void updateFlowTable(const FlowKey& flowKey, uint32_t sequenceNumber, const std::vector<uint8_t>& data);

    // 检查是否可以向上层传递数据
    void checkAndDeliverData(const FlowKey& flowKey);

    // 向上层传递数据
    std::vector<uint8_t> deliverData(const FlowKey& flowKey, const std::vector<uint8_t>& data);

    // 重组分片的数据包
    std::vector<uint8_t> reassemblePacket(const std::map<uint32_t, PacketStatus>& fragments);

    // 从数据包中提取批次ID
    uint64_t extractBatchId(const uint8_t* packet, int packetSize);

    // 从数据包中提取流标识
    FlowKey extractFlowKey(const std::vector<uint8_t>& packetData);

    // 计算 ICMPv6 校验和
    uint16_t calculateICMPv6Checksum(const std::vector<uint8_t>& packet, const struct ip6_hdr& ipv6Header);
};

#endif // RECEIVER_H

/*
Receiver 类流程图：

+-------------------+
|     初始化        |
|  (构造函数)       |
+-------------------+
          |
          v
+-------------------+
|  开始接收数据包    |
| (startReceiving)  |
+-------------------+
          |
          v
+-------------------+
|  数据包处理循环    |
| (packetHandler)   |
+-------------------+
          |
          v
+-------------------+
|   工作线程处理     |
|  (workerThread)   |
+-------------------+
          |
          v
+-------------------+
|   处理单个数据包   |
|  (handlePacket)   |
+-------------------+
          |
          v
+-------------------+
| 重组扩展头/负载    |
+-------------------+
          |
          v
+-------------------+
|   更新流表        |
|(updateFlowTable)  |
+-------------------+
          |
          v
+-------------------+
|   检查可传递数据   |
|(checkAndDeliver   |
|       Data)       |
+-------------------+
          |
          v
+-------------------+
|   发送 ACK        |
|    (sendAck)      |
+-------------------+

注：流程可能会根据实际情况循环或跳转
*/
#ifndef RECEIVER_H
#define RECEIVER_H

#include "IPv6Packet.h"
#include <map>
#include <list>
#include <chrono>
#include <vector>
#include <memory>
#include <pcap.h>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <atomic>
#include <unordered_map>
#include <iostream> 

// 流标识结构体，用于唯一标识一个数据流
struct FlowKey {
    uint32_t identification;  // 使用分片头部中的 identification 字段
    std::string srcIP;
    std::string destIP;
    uint16_t srcPort;
    uint16_t destPort;
    std::string srcMAC;  // 新增：源 MAC 地址

    // 比较运算符，用于在 map 作为键
    bool operator<(const FlowKey& other) const {
        return std::tie(identification, srcIP, destIP, srcPort, destPort, srcMAC) < 
               std::tie(other.identification, other.srcIP, other.destIP, other.srcPort, other.destPort, other.srcMAC);
    }

    // == 运算符，用于比较两个 FlowKey 对象
    bool operator==(const FlowKey& other) const {
        return identification == other.identification &&
               srcIP == other.srcIP &&
               destIP == other.destIP &&
               srcPort == other.srcPort &&
               destPort == other.destPort &&
               srcMAC == other.srcMAC;
    }
};

// 将 std::hash 特化移到这里，在 FlowKey 结构体定义之后，Receiver 类定义之前
namespace std {
    template <>
    struct hash<FlowKey> {
        size_t operator()(const FlowKey& k) const {
            return hash<uint32_t>()(k.identification) ^
                   hash<string>()(k.srcIP) ^
                   hash<string>()(k.destIP) ^
                   hash<uint16_t>()(k.srcPort) ^
                   hash<uint16_t>()(k.destPort) ^
                   hash<string>()(k.srcMAC);
        }
    };
}

// Receiver 类负责接收和处理 IPv6 数据包
class Receiver {
public:
    // 构造函数：初始化接收器
    // windowSize: 滑动窗口大小
    // mtu: 最大传输单元
    // interface: 网络接口名称
    // threadCount: 工作线程数量
    Receiver(int windowSize, size_t mtu, const std::string& interface, int threadCount);

    // 析构函数：清资源
    ~Receiver();

    // 开始接收数据包的主循环
    void startReceiving();

    // 停止接收
    void stop();

    // 获取接收到的数据
    std::vector<std::vector<uint8_t>> getReceivedData();

    // 获取接收到的数据包数量
    size_t getReceivedPacketCount() const;

private:
    // 数据包状态结构体，用于跟踪每个接收到的数据包
    struct PacketStatus {
        std::vector<uint8_t> data;  // 数据包内容
        bool received;              // 是否已接收
        std::chrono::steady_clock::time_point receiveTime;  // 接收时
        bool moreFragments;  // 是否为更多分片
    };

    // 流状态结构体，用于管理每个数据流的状态
    struct FlowState {
        uint32_t expectedSequenceNumber;  // 期望接收的下一个序列号
        std::map<uint32_t, PacketStatus> flowTable;  // 该流的数据包状态表
        std::mutex flowMutex;  // 用于保护该流状态的互斥锁
        uint32_t totalSize;    // 总的有效载荷大小

        FlowState() : expectedSequenceNumber(0), totalSize(0) {} // 构造函数

        // 检查流表是否包含所有的连续分片
        // 遍历流表中的所有分片，检查它们是否连续且完整
        // 如果所有分片都连续且接收完整，则返回true，否则返回false
        // 同时计算已接收的总数据大小，并与预期的总大小进行比较
        bool isComplete() const {
            std::cout << "[FlowState::isComplete] 开始检查完整性" << std::endl;
            std::cout << "[FlowState::isComplete] 流表大小: " << flowTable.size() << std::endl;
            std::cout << "[FlowState::isComplete] 总大小: " << totalSize << std::endl;

            if (flowTable.empty()) {
                std::cout << "[FlowState::isComplete] 流表为空，返回 false" << std::endl;
                return false;
            }

            uint32_t expectedOffset = 0;
            for (const auto& fragment : flowTable) {
                std::cout << "[FlowState::isComplete] 检查分片 - 偏移: " << fragment.first 
                          << ", 大小: " << fragment.second.data.size() << std::endl;

                if (fragment.first != expectedOffset) {
                    std::cout << "[FlowState::isComplete] 分片不连续，期望偏移: " << expectedOffset 
                              << ", 实际偏移: " << fragment.first << ", 返回 false" << std::endl;
                    return false;
                }
                expectedOffset = fragment.first + fragment.second.data.size();
            }

            bool isComplete = !flowTable.rbegin()->second.moreFragments;
            std::cout << "[FlowState::isComplete] 最后一个分片的更多分片标志: " 
                      << (flowTable.rbegin()->second.moreFragments ? "是" : "否") 
                      << ", 完整性: " << (isComplete ? "是" : "否") << std::endl;

            return isComplete;
        }

        // 添加分片数据到流表中
        void addFragment(uint32_t offset, const std::vector<uint8_t>& data, bool moreFragments) {
            flowTable[offset] = {data, true, std::chrono::steady_clock::now(), moreFragments};
            if (offset + data.size() > totalSize) {
                totalSize = offset + data.size();
            }
            std::cout << "[FlowState::addFragment] 添加分片，偏移: " << offset 
                      << ", 大小: " << data.size() 
                      << ", 更多分片: " << (moreFragments ? "是" : "否") 
                      << ", 当前总大小: " << totalSize << std::endl;
        }

        // 重组已收到的分片数据
        std::vector<uint8_t> reassemble() {
            std::vector<uint8_t> reassembledData;
            reassembledData.reserve(totalSize);
            for (const auto& fragment : flowTable) {
                reassembledData.insert(reassembledData.end(), fragment.second.data.begin(), fragment.second.data.end());
            }
            return reassembledData;
        }

        // 返回最高的连续序列号，作为 ACK 确认号
        uint32_t getHighestContiguousSequence() const {
            uint32_t highestContiguousSequence = 0;
            for (const auto& fragment : flowTable) {
                if (fragment.first == highestContiguousSequence) {
                    highestContiguousSequence += fragment.second.data.size();
                } else {
                    break;
                }
            }
            return highestContiguousSequence;
        }

        // 获取当前接收到的分片数
        size_t getFragmentCount() const {
            return flowTable.size();
        }
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
    std::vector<std::unique_ptr<std::mutex>> queueMutexes;  // 用于保护每个队列的互斥锁
    std::vector<std::unique_ptr<std::condition_variable>> queueCVs;  // 用于线程同步的条件变量
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
    uint32_t reassembleExtensionHeader(const FlowKey& flowKey, const uint8_t* packet, int packetSize);

    // 重组负载部分
    uint32_t reassemblePayload(const FlowKey& flowKey, const uint8_t* packet, int packetSize);

    // 处理分片头部
    uint32_t handleFragment(const FlowKey& flowKey, const uint8_t* fragmentHeader, int remainingSize);

    // 处理重组后的数据包
    std::vector<uint8_t> handleReassembledPacket(const FlowKey& flowKey, const std::vector<uint8_t>& reassembledPacket);

    // 发送 ACK
    void sendAck(const FlowKey& flowKey, uint32_t ackNumber);

    // 更新流表
    uint32_t updateFlowTable(const FlowKey& flowKey, uint32_t sequenceNumber, const std::vector<uint8_t>& data);

    // 检查是否可以向上层传递数据
    void checkAndDeliverData(const FlowKey& flowKey);

    // 向上层传递数据
    std::vector<uint8_t> deliverData(const FlowKey& flowKey, const std::vector<uint8_t>& data);

    // 重组分片的数据包
    std::vector<uint8_t> reassemblePacket(const std::map<uint32_t, PacketStatus>& fragments);

    // 从数据包中提取流标识
    FlowKey extractFlowKey(const std::vector<uint8_t>& packetData);

    // 计算 ICMPv6 校验和
    uint16_t calculateICMPv6Checksum(const std::vector<uint8_t>& packet, const struct ip6_hdr& ipv6Header);

    // 数据流队列条目，用于跟踪每个数据流的活动时间
    struct FlowQueueEntry {
        FlowKey flowKey;  // 数据流的唯一标识符
        std::chrono::steady_clock::time_point lastActivityTime;  // 最后活动时间
    };

    std::list<FlowQueueEntry> flowList; // 存储活跃数据流的列表
    std::unordered_map<FlowKey, std::list<FlowQueueEntry>::iterator> flowMap; // 存储数据流和其对应列表迭代器的映射
    std::mutex flowListMutex; // 保护 flowList 的互斥锁 

    // 清理超时的数据流
    void cleanupTimedOutFlows();

    // 将新的数据流添加到队列
    void addFlowToQueue(const FlowKey& flowKey);

    // 从队列中移除指定的数据流
    void removeFlowFromQueue(const FlowKey& flowKey);

    // 更新流活动时间
    void updateFlowActivity(const FlowKey& flowKey);

    // 添加 FLOW_TIMEOUT 常量
    const std::chrono::minutes FLOW_TIMEOUT{5};  // 5分钟超时

    // 添加新的私有成员来存储接收到的数据和数据包计数
    std::vector<std::vector<uint8_t>> receivedData;
    std::mutex receivedDataMutex;
    std::atomic<size_t> receivedPacketCount{0};
    std::atomic<bool> stopRequested{false};
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

注：流程可能会根据际情况循环或跳转
*/

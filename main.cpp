#include "IPv6Packet.h"
#include <iostream>
#include <vector>

using namespace std;

int main() {
    try {
        // 目标MAC地址和IPv6地址（示例值）
        string destMAC = "00:11:22:33:44:55";
        string destIPv6 = "2a02:4780:12:e732::1"; // 更新后的IPv6地址

        // 负载数据（更新为 "Payload test"）
        vector<uint8_t> payload = {'P', 'a', 'y', 'l', 'o', 'a', 'd', ' ', 't', 'e', 's', 't'};

        // 扩展头部内容（更新为 "www.baidu.com"）
        vector<uint8_t> extensionHeaderContent = {'w', 'w', 'w', '.', 'b', 'a', 'i', 'd', 'u', '.', 'c', 'o', 'm'};

        // 分片标志（示例值）
        bool fragmentFlag = false;

        // 创建IPv6Packet对象
        IPv6Packet packet(destMAC, destIPv6, payload, extensionHeaderContent, fragmentFlag);

        // 构造数据包
        packet.constructPacket();

        // 输出数据包的详细信息
        packet.printPacketDetails();
    } catch (const exception& e) {
        cerr << "发生错误: " << e.what() << endl;
    }

    return 0;
}

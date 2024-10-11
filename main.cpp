#include "Sender.h"
#include "Receiver.h"
#include "IPv6Packet.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <iomanip>
#include <future>
#include <functional>

using namespace std;

// 辅助函数：将字符串转换为十六进制表示
string stringToHex(const string& input) {
    static const char hex_digits[] = "0123456789ABCDEF";
    string output;
    output.reserve(input.length() * 2);
    for (unsigned char c : input) {
        output.push_back(hex_digits[c >> 4]);
        output.push_back(hex_digits[c & 15]);
    }
    return output;
}

int main() {
    try {
        int windowSize = 10;
        size_t mtu = 1500;
        int threadCount = 4;
        string interface = "en0";  // 注意：这可能需要根据您的系统进行调整

        // 使用 IPv6Packet 获取本机 MAC 和 IPv6 地址
        IPv6Packet dummyPacket("", "", vector<uint8_t>(), vector<uint8_t>(), false);
        string srcMAC = dummyPacket.getSrcMAC();
        string srcIPv6 = dummyPacket.getSrcIPv6();

        cout << "[main.cpp] 本机MAC地址: " << srcMAC << endl;
        cout << "[main.cpp] 本机IPv6地址: " << srcIPv6 << endl;
        cout << "[main.cpp] 使用的网络接口: " << interface << endl;

        Sender sender(windowSize, mtu, interface);
        Receiver receiver(windowSize, mtu, interface, threadCount);

        // 启动接收线程
        thread receiveThread([&receiver]() {
            receiver.startReceiving();
        });

        // 创建目的选项报头内容
        string domain = "www.baidu.com";
        vector<uint8_t> extensionHeader(domain.begin(), domain.end());
        cout << "[main.cpp] 目的选项报头内容: " << domain << " (Hex: " << stringToHex(domain) << ")" << endl;

        // 空负载
        vector<uint8_t> payload;

        // 添加数据包到发送队列
        sender.addPacket(srcMAC, srcIPv6, payload, extensionHeader, true);

        // 模拟发送和接收过程
        cout << "[main.cpp] 开始模拟发送和接收过程" << endl;
        for (int i = 0; i < 5; ++i) {
            cout << "[main.cpp] 第 " << i+1 << " 次迭代" << endl;
            sender.sendPacket();
            this_thread::sleep_for(chrono::seconds(1));
            sender.checkTimeouts();

            // 每次迭代后输出接收到的包内容
            vector<vector<uint8_t>> receivedData = receiver.getReceivedData();
            cout << "[main.cpp] 接收到的数据包数量: " << receivedData.size() << endl;
            for (size_t j = 0; j < receivedData.size(); ++j) {
                cout << "[main.cpp] 数据包 " << j + 1 << " 内容: ";
                for (const auto& byte : receivedData[j]) {
                    cout << hex << setw(2) << setfill('0') << static_cast<int>(byte) << " ";
                }
                cout << endl;

                // 尝试将内容解释为字符串
                string content(receivedData[j].begin(), receivedData[j].end());
                cout << "[main.cpp] 解释为字符串: " << content << endl;
            }
        }

        // 等待一段时间，确保接收器有足够的时间处理数据包
        this_thread::sleep_for(chrono::seconds(2));

        cout << "[main.cpp] 模拟结束，但继续接收..." << endl;

        // 持续输出接收到的数据包
        while (true) {
            vector<vector<uint8_t>> receivedData = receiver.getReceivedData();
            if (!receivedData.empty()) {
                cout << "[main.cpp] 新接收到的数据包数量: " << receivedData.size() << endl;
                for (size_t i = 0; i < receivedData.size(); ++i) {
                    cout << "[main.cpp] 数据包 " << i + 1 << " 内容: ";
                    for (const auto& byte : receivedData[i]) {
                        cout << hex << setw(2) << setfill('0') << static_cast<int>(byte) << " ";
                    }
                    cout << endl;

                    // 尝试将内容解释为字符串
                    string content(receivedData[i].begin(), receivedData[i].end());
                    cout << "[main.cpp] 解释为字符串: " << content << endl;
                }
            }
            this_thread::sleep_for(chrono::seconds(1));
        }

    } catch (const exception& e) {
        cerr << "[main.cpp] 发生错误: " << e.what() << endl;
        return 1;
    }

    return 0;
}
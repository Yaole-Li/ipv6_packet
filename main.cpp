#include "Sender.h"
#include "Receiver.h"
#include "IPv6Packet.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <iomanip>
#include <atomic>
#include <mutex>
#include <future>
#include <functional>
#include <fstream>
#include <sstream>
#include <cerrno>
#include <cstring>

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

// 用于控制程序运行的原子布尔值
atomic<bool> running(true);

// 用于保护控制台输出的互斥锁
mutex console_mutex;

// Sender 线程函数
void senderThread(Sender& sender) {
    while (running) {
        if (sender.sendPacket()) {
            cout << "[Sender Thread] 成功发送数据包" << endl;
        }
        sender.receiveAck();
        sender.checkTimeouts();
        this_thread::sleep_for(chrono::milliseconds(100));
    }
}

// Receiver 线程函数
void receiverThread(Receiver& receiver) {
    while (running) {
        vector<vector<uint8_t>> receivedData = receiver.getReceivedData();
        if (!receivedData.empty()) {
            lock_guard<mutex> lock(console_mutex);
            cout << "[Receiver] 接收到的数据包数量: " << receiver.getReceivedPacketCount() << endl;
            cout << "[Receiver] 新处理的数据包数量: " << receivedData.size() << endl;
            for (size_t i = 0; i < receivedData.size(); ++i) {
                cout << "[Receiver] 数据包 " << i + 1 << " 内容: ";
                for (const auto& byte : receivedData[i]) {
                    cout << hex << setw(2) << setfill('0') << static_cast<int>(byte) << " ";
                }
                cout << endl;

                // 尝试将内容解释为字符串
                string content(receivedData[i].begin(), receivedData[i].end());
                cout << "[Receiver] 解释为字符串: " << content << endl;
            }
        }
        this_thread::sleep_for(chrono::milliseconds(100));
    }
}

// 读取文件内容
string readFileContent(const string& filename) {
    ifstream file(filename);
    if (!file) {
        cerr << "无法打开文件: " << filename << endl;
        cerr << "错误原因: " << strerror(errno) << endl;
        return "";
    }
    stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
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

        cout << "[main] 本机MAC地址: " << srcMAC << endl;
        cout << "[main] 本机IPv6地址: " << srcIPv6 << endl;
        cout << "[main] 使用的网络接口: " << interface << endl;

        Sender sender(windowSize, mtu, interface);
        Receiver receiver(windowSize, mtu, interface, threadCount);

        // 创建第一种数据包：只有目的选项报头内容
        string domain = "www.baidu.com";
        vector<uint8_t> extensionHeader1(domain.begin(), domain.end());
        cout << "[main] 第一种数据包 - 目的选项报头内容: " << domain << " (Hex: " << stringToHex(domain) << ")" << endl;

        // 创建第二种数据包：目的选项报头内容 + 有效负载
        string headerContent2 = "123";
        vector<uint8_t> extensionHeader2(headerContent2.begin(), headerContent2.end());
        string payloadContent = readFileContent("../playloadtest.txt");
        vector<uint8_t> payload(payloadContent.begin(), payloadContent.end());
        cout << "[main] 第二种数据包 - 目的选项报头内容: " << headerContent2 << " (Hex: " << stringToHex(headerContent2) << ")" << endl;
        cout << "[main] 第二种数据包 - 有效负载大小: " << payload.size() << " 字节" << endl;

        // 添加第一种数据包到发送队列（无负载）
        sender.addPacket(srcMAC, srcIPv6, vector<uint8_t>(), extensionHeader1, false);
        cout << "[main] 添加第一种数据包到发送队列（无负载）" << endl;

        // 添加第二种数据包到发送队列（有负载）
        sender.addPacket(srcMAC, srcIPv6, payload, extensionHeader2, false);
        cout << "[main] 添加第二种数据包到发送队列（有负载）" << endl;

        // 创建并启动 Sender 和 Receiver 线程
        thread senderT(senderThread, ref(sender));
        thread receiverT(receiverThread, ref(receiver));

        // 启动接收器
        receiver.startReceiving();

        // 主循环
        int counter = 0;
        while (running) {
            this_thread::sleep_for(chrono::seconds(1));
            counter++;

            if (counter % 5 == 0) {  // 每5秒检查一次
                vector<vector<uint8_t>> receivedData = receiver.getReceivedData();
                cout << "[Main] 接收到的数据包数量: " << receiver.getReceivedPacketCount() << endl;
                cout << "[Main] 处理的数据包数量: " << receivedData.size() << endl;
                
                for (size_t i = 0; i < receivedData.size(); ++i) {
                    cout << "[Main] 数据包 " << i + 1 << " 内容: ";
                    for (const auto& byte : receivedData[i]) {
                        cout << hex << setw(2) << setfill('0') << static_cast<int>(byte) << " ";
                    }
                    cout << endl;

                    // 尝试将内容解释为字符串
                    string content(receivedData[i].begin(), receivedData[i].end());
                    cout << "[Main] 解释为字符串: " << content << endl;
                }
            }

            if (counter >= 60) {  // 运行60秒后退出
                running = false;
            }
        }

        // 等待线程结束
        senderT.join();
        receiverT.join();

        // 停止接收器
        receiver.stop();

        cout << "[main] 程序正常结束" << endl;

    } catch (const exception& e) {
        cerr << "[main] 发生错误: " << e.what() << endl;
        return 1;
    }

    return 0;
}

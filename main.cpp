#include "Sender.h"
#include "Receiver.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>

// 辅助函数：将字符串转换为十六进制表示
std::string stringToHex(const std::string& input) {
    static const char hex_digits[] = "0123456789ABCDEF";
    std::string output;
    output.reserve(input.length() * 2);
    for (unsigned char c : input) {
        output.push_back(hex_digits[c >> 4]);
        output.push_back(hex_digits[c & 15]);
    }
    return output;
}

// 辅助函数：获取本机IPv6地址和对应的网络接口名称
std::pair<std::string, std::string> getLocalIPv6AddressAndInterface() {
    struct ifaddrs *ifaddr, *ifa;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        if (ifa->ifa_addr->sa_family == AF_INET6) {
            int s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in6),
                                host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                printf("getnameinfo() failed: %s\n", gai_strerror(s));
                exit(EXIT_FAILURE);
            }
            if (strncmp(host, "fe80", 4) != 0) {  // 忽略链路本地地址
                std::string ipv6 = std::string(host);
                std::string interface = std::string(ifa->ifa_name);
                freeifaddrs(ifaddr);
                return {ipv6, interface};
            }
        }
    }

    freeifaddrs(ifaddr);
    return {"", ""};
}

// 辅助函数：获取指定网络接口的MAC地址
std::string getMACAddress(const std::string& interface) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("socket");
        return "";
    }

    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl");
        close(fd);
        return "";
    }

    close(fd);

    char mac[18];
    snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             (unsigned char)ifr.ifr_hwaddr.sa_data[0],
             (unsigned char)ifr.ifr_hwaddr.sa_data[1],
             (unsigned char)ifr.ifr_hwaddr.sa_data[2],
             (unsigned char)ifr.ifr_hwaddr.sa_data[3],
             (unsigned char)ifr.ifr_hwaddr.sa_data[4],
             (unsigned char)ifr.ifr_hwaddr.sa_data[5]);

    return std::string(mac);
}

int main() {
    try {
        int windowSize = 10;
        size_t mtu = 1500;
        int threadCount = 4;

        // 获取本机IPv6地址和网络接口名称
        auto [destIPv6, interface] = getLocalIPv6AddressAndInterface();
        if (destIPv6.empty() || interface.empty()) {
            throw std::runtime_error("无法获取本机IPv6地址或网络接口名称");
        }
        std::cout << "目标IPv6地址（本机）: " << destIPv6 << std::endl;
        std::cout << "使用的网络接口: " << interface << std::endl;

        // 获取本机MAC地址
        std::string srcMAC = getMACAddress(interface);
        if (srcMAC.empty()) {
            throw std::runtime_error("无法获取本机MAC地址");
        }
        std::cout << "本机MAC地址: " << srcMAC << std::endl;

        Sender sender(windowSize, mtu, interface);
        Receiver receiver(windowSize, mtu, interface, threadCount);

        // 启动接收线程
        std::thread receiveThread([&receiver]() {
            receiver.startReceiving();
        });

        // 创建目的选项报头内容
        std::string domain = "www.baidu.com";
        std::vector<uint8_t> extensionHeader(domain.begin(), domain.end());
        std::cout << "目的选项报头内容: " << domain << " (Hex: " << stringToHex(domain) << ")" << std::endl;

        // 空负载
        std::vector<uint8_t> payload;

        // 添加数据包到发送队列
        sender.addPacket(srcMAC, destIPv6, payload, extensionHeader, true);

        // 模拟发送和接收过程
        std::cout << "开始模拟发送和接收过程" << std::endl;
        for (int i = 0; i < 5; ++i) {
            std::cout << "第 " << i+1 << " 次迭代" << std::endl;
            sender.sendPacket();
            std::this_thread::sleep_for(std::chrono::seconds(1));
            sender.checkTimeouts();
        }

        // 等待一段时间，确保接收器有足够的时间处理数据包
        std::this_thread::sleep_for(std::chrono::seconds(2));

        std::cout << "模拟结束，停止接收" << std::endl;
        receiver.stop();
        receiveThread.join();

        // 输出接收到的包内容
        std::vector<std::vector<uint8_t>> receivedData = receiver.getReceivedData();
        std::cout << "接收到的数据包数量: " << receivedData.size() << std::endl;
        for (size_t i = 0; i < receivedData.size(); ++i) {
            std::cout << "数据包 " << i + 1 << " 内容: ";
            for (const auto& byte : receivedData[i]) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
            }
            std::cout << std::endl;

            // 尝试将内容解释为字符串
            std::string content(receivedData[i].begin(), receivedData[i].end());
            std::cout << "解释为字符串: " << content << std::endl;
        }

        std::cout << "程序正常结束" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "发生错误: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
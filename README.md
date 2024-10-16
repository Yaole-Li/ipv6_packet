# IPv6 协议栈实现

## 项目概述

本项目实现了一个简单的 IPv6 协议栈，包含数据包的构造、发送和接收功能。项目主要包括以下模块：

1. **IPv6Packet**: 负责构造带有 IPv6 目的选项报头的 IPv6 数据包。
2. **Sender**: 负责发送数据包并维护发送流表。
3. **Receiver**: 负责接收数据包并维护接收流表。

## 模块功能

### 1. IPv6Packet

- **功能描述**: 根据 IPv6 数据包的格式进行数据包的构造。
- **输入**: 目的 MAC 地址、目的 IPv6 地址、扩展头内容、负载内容。
- **输出**: 构造好的 IPv6 数据包。
- **主要方法**:
  - `constructPacket()`: 构造完整的 IPv6 数据包。
  - `addIPv6Header()`: 添加 IPv6 基本头部。
  - `addFragmentHeader()`: 添加分片头部（如果需要）。
  - `addExtensionHeader()`: 添加目的选项报头。
  - `fetchLocalMAC()`: 获取本地 MAC 地址。
  - `fetchLocalIPv6()`: 获取本地 IPv6 地址。
- **特殊字段**:
  - 目的选项报头的前 8 个字节用作数据流 ID。

### 2. Sender

- **功能描述**: 发送 IPv6 数据包，并维护发送流表来跟踪每个数据包的状态。
- **主要方法**:
  - `addPacket()`: 添加新的数据包到发送队列。
  - `sendPacket()`: 尝试发送下一个数据包。
  - `handleAck()`: 处理接收到的 ACK。
  - `checkTimeouts()`: 检查并处理超时的数据包。
  - `fragmentPacket()`: 将数据包分片（如果需要）。
- **流量控制**:
  - 使用滑动窗口协议。
  - 维护发送流表，记录每个数据包的发送状态和确认状态。

### 3. Receiver

- **功能描述**: 接收 IPv6 数据包，并维护接收流表来跟踪每个数据包的状态。
- **主要方法**:
  - `startReceiving()`: 开始接收数据包。
  - `handlePacket()`: 处理接收到的数据包。
  - `reassembleExtensionHeader()`: 重组扩展头部（目的选项报头）。
  - `reassemblePayload()`: 重组负载部分。
  - `handleFragmentHeader()`: 处理分片头部。
  - `checkAndDeliverData()`: 检查是否可以向上层传递数据。
- **多线程处理**:
  - 使用多个工作线程并行处理来自不同流的数据包。
  - 使用四元组（源 IP、目的 IP、源端口、目的端口）和批次 ID 来区分不同的数据流。

## 私有协议约定

1. **数据流 ID**:
   - 位置：目的选项报头的前 8 个字节。
   - 用途：用于唯一标识不同的数据流，即使它们来自相同的源 IP 和端口。

2. **分片处理**:
   - 当数据包大小超过 MTU 时，进行分片。
   - 分片信息包含在 IPv6 分片头部中。

3. **ACK 机制**:
   - Receiver 接收到数据包后，发送 ACK 确认。
   - ACK 号为已正确接收的最高序列号。

4. **超时重传**:
   - Sender 对未收到 ACK 的数据包进行超时检查。
   - 超时时间为 5 秒（可配置）。

5. **流量控制**:
   - 使用滑动窗口协议。
   - 窗口大小可在 Sender 初始化时配置。

## 数据包结构

1. **IPv6 基本头部** (40 字节)
2. **分片头部** (8 字节，如果需要分片)
3. **目的选项报头**:
   - 前 8 字节：数据流 ID
   - 剩余部分：其他选项数据
4. **负载数据**

## 使用说明

1. 初始化 Sender 和 Receiver，指定窗口大小、MTU 和网络接口。
2. 使用 Sender 的 `addPacket()` 方法添加要发送的数据包。
3. 调用 Sender 的 `sendPacket()` 方法发送数据包。
4. 启动 Receiver 的 `startReceiving()` 方法开始接收数据包。
5. 定期调用 Sender 的 `checkTimeouts()` 方法处理超时重传。

## 注意事项

- 确保正确设置网络接口和 IPv6 地址。
- 适当调整滑动窗口大小和超时时间以优化性能。
- 在实际部署时，需要考虑网络安全性，如数据加密和身份验证。

## 未来改进
- 实现更复杂的拥塞控制算法。
- 添加 QoS (Quality of Service) 支持。
- 优化多线程处理以提高性能。
- 增加更多的错误处理和异常情况的处理。

## 编译说明

### 使用 CMake

1. 创建构建目录：
   ```bash
   mkdir build
   cd build
   ```

2. 生成构建文件：
   ```bash
   cmake ..
   ```

3. 编译项目：
   ```bash
   make
   ```

可执行文件将会在 `bin` 目录下生成。

### 使用 G++ 直接编译

如果你更喜欢直接使用 G++，可以使用以下命令：

```bash
g++ -std=c++17 -Wall -Wextra -pedantic -g \
    main.cpp IPv6Packet.cpp Sender.cpp Receiver.cpp \
    -I. \
    -lpcap -lpthread \
    -o bin/IPv6ProtocolStack
```

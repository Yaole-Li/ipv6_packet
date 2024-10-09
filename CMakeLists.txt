cmake_minimum_required(VERSION 3.10)

# 项目名称
project(IPv6PacketProject)

# 设置C++标准
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# 添加源文件
set(SOURCES
    main.cpp
    IPv6Packet.cpp
)

# 添加可执行文件
add_executable(IPv6PacketExecutable ${SOURCES})

# 链接必要的库
target_link_libraries(IPv6PacketExecutable pcap)

# 设置可执行文件的输出目录
set_target_properties(IPv6PacketExecutable PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "../bin"
)

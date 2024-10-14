cmake_minimum_required(VERSION 3.10)

# 项目名称
project(IPv6ProtocolStack)

# 设置C++标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# 添加编译选项
add_compile_options(-Wall -Wextra -pedantic -g)

# 查找必要的库
find_package(Threads REQUIRED)
find_library(PCAP_LIBRARY pcap)

if(NOT PCAP_LIBRARY)
    message(FATAL_ERROR "libpcap not found. Please install libpcap-devel package.")
endif()

# 添加所有的源文件
set(SOURCES
    main.cpp
    IPv6Packet.cpp
    Sender.cpp
    Receiver.cpp
)

# 添加头文件目录
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# 添加可执行文件
add_executable(IPv6ProtocolStack ${SOURCES})

# 链接必要的库
target_link_libraries(IPv6ProtocolStack
    PRIVATE
    ${CMAKE_THREAD_LIBS_INIT}
    ${PCAP_LIBRARY}
)

# 设置可执行文件的输出目录
set_target_properties(IPv6ProtocolStack PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "../bin"
)

# 如果是Debug模式，添加调试信息
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(IPv6ProtocolStack PRIVATE -g)
endif()

# 添加安装规则
install(TARGETS IPv6ProtocolStack
    RUNTIME DESTINATION bin
)

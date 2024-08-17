cmake_minimum_required(VERSION 3.9)

project(MuduoNet C CXX)

# 设置C和C++标准
set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 11)

# 设置全局包含目录
include_directories(${PROJECT_SOURCE_DIR}/include)

# 定义编译选项和库依赖项变量
set(COMMON_COMPILE_OPTIONS 
    -g 
    -W 
    -Wall 
    -Wpointer-arith 
    -Wno-unused-parameter 
    -Wno-unused-function
)

set(COMMON_LIBRARIES 
    pthread 
    hugetlbfs 
    rt
)

# 分别添加四个文件夹中的源文件
aux_source_directory(${PROJECT_SOURCE_DIR}/src/base_components SRC_BASE)
aux_source_directory(${PROJECT_SOURCE_DIR}/src/log_services SRC_LOG)
aux_source_directory(${PROJECT_SOURCE_DIR}/src/net_services SRC_NET)
aux_source_directory(${PROJECT_SOURCE_DIR}/src/netmap_usrstack SRC_NETMAP)

# 为每个文件夹生成一个动态链接库，并应用公共编译选项和库依赖项
add_library(base_components SHARED ${SRC_BASE})
target_compile_options(base_components PRIVATE ${COMMON_COMPILE_OPTIONS})
target_link_libraries(base_components PRIVATE ${COMMON_LIBRARIES})

add_library(log_services SHARED ${SRC_LOG})
target_compile_options(log_services PRIVATE ${COMMON_COMPILE_OPTIONS})
target_link_libraries(log_services PRIVATE ${COMMON_LIBRARIES})

add_library(net_services SHARED ${SRC_NET})
target_compile_options(net_services PRIVATE ${COMMON_COMPILE_OPTIONS})
target_link_libraries(net_services PRIVATE ${COMMON_LIBRARIES})

add_library(netmap_usrstack SHARED ${SRC_NETMAP})
target_compile_options(netmap_usrstack PRIVATE ${COMMON_COMPILE_OPTIONS})
target_link_libraries(netmap_usrstack PRIVATE ${COMMON_LIBRARIES})

# 创建两个可执行文件，分别链接所有四个动态库
add_executable(test_muduo test_muduo.cc)
target_link_libraries(test_muduo PRIVATE base_components log_services net_services netmap_usrstack)

add_executable(test_net test_net.c)
target_link_libraries(test_net PRIVATE base_components log_services net_services netmap_usrstack)

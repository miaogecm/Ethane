cmake_minimum_required(VERSION 3.10)
project(ethane C ASM)

set(CMAKE_C_STANDARD 99)
#set(CMAKE_C_FLAGS "-march=native -D_FILE_OFFSET_BITS=64")
#set(CMAKE_C_FLAGS "-march=native -D_FILE_OFFSET_BITS=64 -g -O0")
set(CMAKE_C_FLAGS "-march=native -D_FILE_OFFSET_BITS=64 -g -O3")

include_directories(./)

add_library(ethane SHARED ethanefs.c dmpool_rdma.c dmm.c avl.c kv.c tabhash.c logger.c cachefs.c sharedfs.c oplogger.c dmlocktab.c third_party/libaco/aco.c third_party/libaco/acosw.S coro.c config.c trace.c bench.c rand.c)
target_link_libraries(ethane ibverbs pthread zookeeper_mt cyaml lttng-ust dl prom promhttp jemalloc backtrace)

add_executable(logd logd.c third_party/argparse/argparse.c)
target_link_libraries(logd ethane)

add_executable(memd memd.c third_party/argparse/argparse.c)
target_link_libraries(memd ethane)

add_executable(launch launch.c third_party/argparse/argparse.c)
target_link_libraries(launch ethane)

add_executable(eshell eshell.c third_party/argparse/argparse.c)
target_link_libraries(eshell ethane)

add_executable(format format.c third_party/argparse/argparse.c)
target_link_libraries(format ethane)

add_library(bench SHARED examples/bench.c examples/random.c)
target_link_libraries(bench ethane)

add_executable(dmperf dmperf.c third_party/argparse/argparse.c)
target_link_libraries(dmperf ethane)

add_executable(ddio ddio.c)
target_link_libraries(ddio pci ethane)

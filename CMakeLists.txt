cmake_minimum_required(VERSION 2.6)
project(radiotap)

add_definitions("-D_BSD_SOURCE -DRADIOTAP_SUPPORT_OVERRIDES")

add_library(radiotap SHARED radiotap.c)
set_target_properties(radiotap PROPERTIES
	COMPILE_FLAGS "-Wall -Wextra -lpcap -L/home/chaosbringer/Documents/embbed/openwrt_course/staging_dir/target-mipsel_24kc_musl/root-ramips/usr/lib")

install(TARGETS radiotap DESTINATION lib)
install(FILES radiotap.h radiotap_iter.h DESTINATION include)

add_executable(parse parse.c)
set_target_properties(parse PROPERTIES
		      COMPILE_FLAGS "-Wall -Wextra -lpcap")
target_link_libraries(parse radiotap pcap)


add_custom_target(radiotap_check ALL
		  COMMAND ${CMAKE_SOURCE_DIR}/check/check.sh ${CMAKE_BINARY_DIR}
		  DEPENDS ${CMAKE_SOURCE_DIR}/check/*
		  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/check/
		  COMMENT "Check examples")
add_dependencies(radiotap_check parse)

set(CMAKE_SYSTEM_NAME Linux)
set(TOOLCHAIN_DIR /home/chaosbringer/Documents/embbed/openwrt_course/staging_dir/toolchain-mipsel_24kc_gcc-7.3.0_musl)

#set(TOOLCHAIN_DIR /home/chaosbringer/Documents/embbed/openwrt_course/staging_dir/target-mipsel_24kc_musl)
SET(CMAKE_C_COMPILER ${TOOLCHAIN_DIR}/bin/mipsel-openwrt-linux-gcc)
SET(CMAKE_CXX_COMPILER ${TOOLCHAIN_DIR}/bin/mipsel-openwrt-linux-g++)
SET(CMAKE_STRIP ${TOOLCHAIN_DIR}/bin/mipsel-openwrt-linux-strip)

SET(CMAKE_FIND_ROOT_PATH  /home/chaosbringer/Documents/embbed/openwrt_course/staging_dir/target-mipsel_24kc_musl/)
set(CMAKE_SYSROOT /home/chaosbringer/Documents/embbed/openwrt_course/staging_dir/target-mipsel_24kc_musl/root-ramips)

SET(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM ONLY)
SET(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
SET(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE NEVER)
set(CMAKE_FIND_LIBRARY_PREFIXES lib )
set(CMAKE_FIND_LIBRARY_SUFFIXES .a )
set(CMAKE_LIBRARY_PATH ${CMAKE_FIND_ROOT_PATH}/usr/lib)

#find_library(LIBS_PCAP NAMES pcap PATHS /home/chaosbringer/Documents/embbed/openwrt_course/staging_dir/target-mipsel_24kc_musl/usr/lib)
include_directories(/home/chaosbringer/Documents/embbed/openwrt_course/staging_dir/target-mipsel_24kc_musl/usr/include)

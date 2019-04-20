# This code is part of Pcap_DNSProxy
# Pcap_DNSProxy, a local DNS server based on packet capturing
# Copyright (C) 2012-2019 Chengr28
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.


# CMake minimum version
cmake_minimum_required(VERSION 3.1)

# Project name, build type, list all include and source files.
project(Pcap_DNSProxy)
set(CMAKE_BUILD_TYPE "Release")
include_directories(${CMAKE_CURRENT_LIST_DIR}/Include)
aux_source_directory(${CMAKE_CURRENT_LIST_DIR}/Source PCAP_DNSPROXY_SOURCE_FILES)
add_executable(${PROJECT_NAME} ${PCAP_DNSPROXY_SOURCE_FILES})

# Compiling and linking flags
## See https://developers.redhat.com/blog/2018/03/21/compiler-and-linker-flags-gcc.
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
IF(CMAKE_SYSTEM_NAME MATCHES "Darwin")
	add_definitions(-std=c++14)
ENDIF(CMAKE_SYSTEM_NAME MATCHES "Darwin")
IF(NOT PLATFORM_OPENWRT)
	set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
	IF(CMAKE_VERSION VERSION_LESS "3.9")
		add_definitions(-flto)
	ENDIF(CMAKE_VERSION VERSION_LESS "3.9")
	set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
	add_definitions(-D_FORTIFY_SOURCE=2)
	add_definitions(-D_GLIBCXX_ASSERTIONS)
	add_definitions(-fasynchronous-unwind-tables)
#	add_definitions(-fcf-protection=full)
	add_definitions(-fexceptions)
	IF(NOT CMAKE_SYSTEM_NAME MATCHES "Darwin")
		add_definitions(-fopenmp)
#		add_definitions(-fsplit-stack)
	ENDIF(NOT CMAKE_SYSTEM_NAME MATCHES "Darwin")
#	add_definitions(-fstack-clash-protection)
	add_definitions(-fstack-protector-strong)
	add_definitions(-g)
	add_definitions(-grecord-gcc-switches)
	add_definitions(-march=native)
#	add_definitions(-mcet)
	add_definitions(-pipe)
	add_definitions(-O3)
ENDIF(NOT PLATFORM_OPENWRT)

# Platform and library definitions
IF(PLATFORM_OPENWRT)
	add_definitions(-DPLATFORM_OPENWRT)
	install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION sbin)
ENDIF(PLATFORM_OPENWRT)
IF(ENABLE_LIBSODIUM)
	add_definitions(-DENABLE_LIBSODIUM)
ENDIF(ENABLE_LIBSODIUM)
IF(ENABLE_PCAP)
	add_definitions(-DENABLE_PCAP)
ENDIF(ENABLE_PCAP)
IF(ENABLE_TLS)
	add_definitions(-DENABLE_TLS)
ENDIF(ENABLE_TLS)

# Libraries linking
## Static linking need
IF(ENABLE_STATIC_LIB)
	set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -s -static -Wl,--whole-archive -lpthread -Wl,--no-whole-archive")
ENDIF(ENABLE_STATIC_LIB)
## All needed
IF(CMAKE_SYSTEM_NAME MATCHES "FreeBSD" OR CMAKE_SYSTEM_NAME MATCHES "Darwin")
	include_directories("/usr/local/include")
ENDIF(CMAKE_SYSTEM_NAME MATCHES "FreeBSD" OR CMAKE_SYSTEM_NAME MATCHES "Darwin")
find_package(Threads REQUIRED)
target_link_libraries(${PROJECT_NAME} ${CMAKE_THREAD_LIBS_INIT})
find_library(LIBEVENT_LIBRARIES event_core)
target_link_libraries(${PROJECT_NAME} ${LIBEVENT_LIBRARIES})
## Libraries needed
IF(ENABLE_LIBSODIUM)
	find_library(LIBSODIUM_LIBRARIES sodium)
	target_link_libraries(${PROJECT_NAME} ${LIBSODIUM_LIBRARIES})
ENDIF(ENABLE_LIBSODIUM)
IF(ENABLE_PCAP)
	find_library(LIBPCAP_LIBRARIES pcap)
	target_link_libraries(${PROJECT_NAME} ${LIBPCAP_LIBRARIES})
ENDIF(ENABLE_PCAP)
IF(ENABLE_TLS)
	find_package(OpenSSL REQUIRED)
	target_link_libraries(${PROJECT_NAME} ${OPENSSL_LIBRARIES})
	IF(ENABLE_STATIC_LIB)
		find_library(LIBDL_LIBRARIES dl)
		target_link_libraries(${PROJECT_NAME} ${LIBDL_LIBRARIES})
		find_library(LIBZ_LIBRARIES z)
		target_link_libraries(${PROJECT_NAME} ${LIBZ_LIBRARIES})
	ENDIF(ENABLE_STATIC_LIB)
ENDIF(ENABLE_TLS)

# This code is part of Pcap_DNSProxy
# Pcap_DNSProxy, a local DNS server based on WinPcap and LibPcap
# Copyright (C) 2012-2018 Chengr28
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

# Project name, build type and list all source files.
project(Pcap_DNSProxy)
set(CMAKE_BUILD_TYPE "Release")
set(MAIN_SRC_FILES
		"Base.h"
		"Capture.h"
		"Configuration.h"
		"Definition.h"
		"DNSCurveControl.h"
		"DNSCurveRequest.h"
		"Include.h"
		"Initialization.h"
		"Main.h"
		"Monitor.h"
		"Network.h"
		"PacketData.h"
		"Platform.h"
		"PrintLog.h"
		"Process.h"
		"Protocol.h"
		"Proxy.h"
		"Request.h"
		"Service.h"
		"Structure.h"
		"Template.h"
		"TransportSecurity.h"
		"Type.h"
		"Base.cpp"
		"Capture.cpp"
		"Configuration.cpp"
		"DNSCurveControl.cpp"
		"DNSCurveRequest.cpp"
		"Initialization.cpp"
		"Main.cpp"
		"Monitor.cpp"
		"Network.cpp"
		"PacketData.cpp"
		"PrintLog.cpp"
		"Process.cpp"
		"Protocol.cpp"
		"Proxy.cpp"
		"ReadCommand.cpp"
		"ReadHosts.cpp"
		"ReadIPFilter.cpp"
		"ReadParameter.cpp"
		"Request.cpp"
		"Service.cpp"
		"TransportSecurity.cpp")
add_executable(Pcap_DNSProxy ${MAIN_SRC_FILES})

# Compiling and linking flags
## See https://developers.redhat.com/blog/2018/03/21/compiler-and-linker-flags-gcc.
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
IF(APPLE)
	add_definitions(-std=c++14)
ENDIF(APPLE)
IF(NOT PLATFORM_OPENWRT)
	IF(CMAKE_VERSION VERSION_LESS "3.9")
		add_definitions(-flto)
	ELSE(CMAKE_VERSION VERSION_LESS "3.9")
		set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
	ENDIF(CMAKE_VERSION VERSION_LESS "3.9")
	set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
	add_definitions(-D_FORTIFY_SOURCE=2)
	add_definitions(-D_GLIBCXX_ASSERTIONS)
	add_definitions(-fasynchronous-unwind-tables)
#	add_definitions(-fcf-protection=full)
	add_definitions(-fexceptions)
	IF(NOT APPLE)
		add_definitions(-fopenmp)
#		add_definitions(-fsplit-stack)
	ENDIF(NOT APPLE)
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
	install(TARGETS Pcap_DNSProxy RUNTIME DESTINATION sbin)
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

# Static libraries linking if needed
IF(STATIC_LIB)
	set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -s -static -Wl,--whole-archive -lpthread -Wl,--no-whole-archive")
ENDIF(STATIC_LIB)

# Libraries linking
## All needed
find_package(Threads REQUIRED)
target_link_libraries(Pcap_DNSProxy ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(Pcap_DNSProxy event)
## Libraries needed
IF(ENABLE_LIBSODIUM)
	target_link_libraries(Pcap_DNSProxy sodium)
ENDIF(ENABLE_LIBSODIUM)
IF(ENABLE_PCAP)
	target_link_libraries(Pcap_DNSProxy pcap)
ENDIF(ENABLE_PCAP)
IF(ENABLE_TLS)
	find_package(OpenSSL REQUIRED)
	target_link_libraries(Pcap_DNSProxy ${OPENSSL_LIBRARIES})
	IF(STATIC_LIB)
		target_link_libraries(Pcap_DNSProxy dl)
		target_link_libraries(Pcap_DNSProxy z)
	ENDIF(STATIC_LIB)
ENDIF(ENABLE_TLS)

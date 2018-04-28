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

# Project name, build type and all source files
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

# Compiling and linking flags
## C++ 14 standard definitions
set(CMAKE_CXX_STANDARD 14)
## Platform definitions
IF(PLATFORM_OPENWRT)
	add_definitions(-DPLATFORM_OPENWRT)
ELSE(PLATFORM_OPENWRT)
	add_definitions(-flto -fpic)
ENDIF(PLATFORM_OPENWRT)
## Library definitions
IF(ENABLE_LIBSODIUM)
	add_definitions(-DENABLE_LIBSODIUM)
ENDIF(ENABLE_LIBSODIUM)
IF(ENABLE_PCAP)
	add_definitions(-DENABLE_PCAP)
ENDIF(ENABLE_PCAP)
IF(ENABLE_TLS)
	add_definitions(-DENABLE_TLS)
ENDIF(ENABLE_TLS)

# Static libraries linking if needed and executable file name
add_executable(Pcap_DNSProxy ${MAIN_SRC_FILES})
IF(STATIC_LIB)
	set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -s -static -Wl,--whole-archive -lpthread -Wl,--no-whole-archive")
ENDIF(STATIC_LIB)
IF(PLATFORM_OPENWRT)
	install(TARGETS Pcap_DNSProxy RUNTIME DESTINATION sbin)
ENDIF(PLATFORM_OPENWRT)

# Libraries linking
find_package(Threads REQUIRED)
target_link_libraries(Pcap_DNSProxy ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(Pcap_DNSProxy event)
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

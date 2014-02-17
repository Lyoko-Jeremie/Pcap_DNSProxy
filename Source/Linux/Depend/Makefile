# This code is part of Pcap_DNSProxy
# Copyright (C) 2012-2014 Chengr28
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


#Prepare
Target_Name = Pcap_DNSProxy
CC = g++
COM_FLAGS = -std=c++11 -O3 -pthread -fpic -c
LNK_FLAGS = -std=c++11 -O3 -pthread -lpcap -Xlinker 
SRC_DIR = Source/
OBJ_DIR = ./Object/
READ_TEMP = 

all : Warning Directory Target BuildService clean
Warning : 
		@echo WARNING:
		@echo Before compiling Pcap_DNSProxy, please confirm all dependency packpages has been install.
		@echo Dependency packpages of Pcap_DNSProxy are GCC\(C++/g++, must support C++ 11 standard\) and libpcap.
		@echo Dependency packpages of libpcap are GCC, bison, m4, flex and libpcap-dev.
		@echo If not sure libpcap installed success or not, run \"man pcap\" in terminal.
		@echo When libpcap installed success, you can see like those messages on screen:
		@echo --------------------------------------------------
		@echo PCAP\(3PCAP\) ... PCAP\(3PCAP\)
		@echo NAME
		@echo pcap - Packet Capture library
		@echo SYNOPSIS
		@echo \#include \<pcap/pcap.h\>
		@echo ...
		@echo --------------------------------------------------
		@echo Enjoy it =w=
		@-read READ_TEMP
Directory : 
		@echo Creating directory of object files.
		@-mkdir Object
BuildService : 
		@echo Building system service
		@chown root:root PcapDNSProxyService
		@chmod 777 PcapDNSProxyService

#Compile
Target : ClassInitialization.o PrintError.o Protocol.o Configuration.o Capture.o Request.o Process.o Monitor.o Main.o
		@echo Linking all object files.
		@$(CC) $(LNK_FLAGS) $(OBJ_DIR)*.o -o $(Target_Name)
ClassInitialization.o : $(SRC_DIR)ClassInitialization.cc
		@echo Compiling ClassInitialization module.
		@$(CC) $(COM_FLAGS) ./$(SRC_DIR)ClassInitialization.cc -o $(OBJ_DIR)ClassInitialization.o
PrintError.o : $(SRC_DIR)PrintError.cc
		@echo Compiling PrintError module.
		@$(CC) $(COM_FLAGS) ./$(SRC_DIR)PrintError.cc -o $(OBJ_DIR)PrintError.o
Protocol.o : $(SRC_DIR)Protocol.cc
		@echo Compiling Protocol module.
		@$(CC) $(COM_FLAGS) ./$(SRC_DIR)Protocol.cc -o $(OBJ_DIR)Protocol.o
Configuration.o : Source/Configuration.cc
		@echo Compiling Configuration module.
		@$(CC) $(COM_FLAGS) ./$(SRC_DIR)Configuration.cc -o $(OBJ_DIR)Configuration.o
Capture.o : $(SRC_DIR)Capture.cc
		@echo Compiling Capture module.
		@$(CC) $(COM_FLAGS) ./$(SRC_DIR)Capture.cc -o $(OBJ_DIR)Capture.o
Request.o : $(SRC_DIR)Request.cc
		@echo Compiling Request module.
		@$(CC) $(COM_FLAGS) ./$(SRC_DIR)Request.cc -o $(OBJ_DIR)Request.o
Process.o : $(SRC_DIR)Process.cc
		@echo Compiling Process module.
		@$(CC) $(COM_FLAGS) ./$(SRC_DIR)Process.cc -o $(OBJ_DIR)Process.o
Monitor.o : $(SRC_DIR)Monitor.cc
		@echo Compiling Monitor module.
		@$(CC) $(COM_FLAGS) ./$(SRC_DIR)Monitor.cc -o $(OBJ_DIR)Monitor.o
Main.o : $(SRC_DIR)Main.cc
		@echo Compiling Main module.
		@$(CC) $(COM_FLAGS) ./$(SRC_DIR)Main.cc -o $(OBJ_DIR)Main.o

#Cleanup
.PHONY : clean
clean : 
		@echo Cleaning.
		@-rm -r Object

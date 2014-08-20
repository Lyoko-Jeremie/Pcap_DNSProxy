# This code is part of Pcap_DNSProxy(Linux)
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
OBJ_DIR = ./Object/

all : Directory Target BuildService clean
Directory : 
		@echo Attention: You should use ROOT permissions to run this making!
		@echo Creating directory of object files
		@-mkdir $(OBJ_DIR)
BuildService : 
		@echo Building system service
		@cp ./Example/PcapDNSProxyService .
		@sudo chown root:root PcapDNSProxyService
		@sudo chmod 777 PcapDNSProxyService
		@cp ./Example/Config.conf .
		@cp ./Example/Hosts.conf .

#Compile
Target : ClassInitialization.o PrintError.o Protocol.o Configuration.o Capture.o Request.o Process.o Monitor.o Main.o
		@echo Linking all object files.
		@sudo $(CC) $(LNK_FLAGS) $(OBJ_DIR)*.o -o $(Target_Name)
ClassInitialization.o : ./ClassInitialization.cc
		@echo Compiling ClassInitialization module.
		@$(CC) $(COM_FLAGS) ./ClassInitialization.cc -o $(OBJ_DIR)ClassInitialization.o
PrintError.o : ./PrintError.cc
		@echo Compiling PrintError module.
		@$(CC) $(COM_FLAGS) ./PrintError.cc -o $(OBJ_DIR)PrintError.o
Protocol.o : ./Protocol.cc
		@echo Compiling Protocol module.
		@$(CC) $(COM_FLAGS) ./Protocol.cc -o $(OBJ_DIR)Protocol.o
Configuration.o : ./Configuration.cc
		@echo Compiling Configuration module.
		@$(CC) $(COM_FLAGS) ./Configuration.cc -o $(OBJ_DIR)Configuration.o
Capture.o : ./Capture.cc
		@echo Compiling Capture module.
		@$(CC) $(COM_FLAGS) ./Capture.cc -o $(OBJ_DIR)Capture.o
Request.o : ./Request.cc
		@echo Compiling Request module.
		@$(CC) $(COM_FLAGS) ./Request.cc -o $(OBJ_DIR)Request.o
Process.o : ./Process.cc
		@echo Compiling Process module.
		@$(CC) $(COM_FLAGS) ./Process.cc -o $(OBJ_DIR)Process.o
Monitor.o : ./Monitor.cc
		@echo Compiling Monitor module.
		@$(CC) $(COM_FLAGS) ./Monitor.cc -o $(OBJ_DIR)Monitor.o
Main.o : ./Main.cc
		@echo Compiling Main module.
		@$(CC) $(COM_FLAGS) ./Main.cc -o $(OBJ_DIR)Main.o

#Cleanup
.PHONY : clean
clean : 
		@echo Cleaning.
		@-rm -r Object
		@echo Finish, please confirm the service has been installed.

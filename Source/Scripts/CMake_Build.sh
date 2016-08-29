#!/bin/bash
# 
# This code is part of Pcap_DNSProxy
# A local DNS server based on WinPcap and LibPcap
# Copyright (C) 2012-2016 Chengr28
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


# Set variables and create release directories.
CMakeShell="cmake "
if (uname -s | grep -iq "Darwin"); then
	ThreadNum=`sysctl -n hw.ncpu`
else
	ThreadNum=`grep "processor" /proc/cpuinfo | sort -u | wc -l`
fi
cd ..
rm -Rrf Object
mkdir Release

# Build Pcap_DNSProxy.
mkdir Object
cd Object
if !(echo "$*" | grep -iq -e "--disable-libsodium"); then
	CMakeShell="${CMakeShell}-DENABLE_LIBSODIUM=ON "
fi
if !(echo "$*" | grep -iq -e "--disable-libpcap"); then
	CMakeShell="${CMakeShell}-DENABLE_PCAP=ON "
fi
if (echo "$*" | grep -iq -e "--enable-static"); then
	CMakeShell="${CMakeShell}-DSTATIC_LIB=ON "
fi
CMakeShell="${CMakeShell}../Pcap_DNSProxy"
${CMakeShell}
make -j${ThreadNum}
cd ..
mv -f Object/Pcap_DNSProxy Release
rm -Rrf Object

# Program settings
cp ExampleConfig/PcapDNSProxyService Release/PcapDNSProxyService
cp ExampleConfig/Pcap_DNSProxy.service Release/Pcap_DNSProxy.service
cp ExampleConfig/pcap_dnsproxy.service.plist Release/pcap_dnsproxy.service.plist
cp ExampleConfig/Config.ini Release/Config.conf
cp ExampleConfig/Hosts.ini Release/Hosts.conf
cp ExampleConfig/IPFilter.ini Release/IPFilter.conf
cp ExampleConfig/Routing.txt Release/Routing.txt
cp ExampleConfig/WhiteList.txt Release/WhiteList.txt
chmod -R 755 Release
chmod -R 755 Scripts

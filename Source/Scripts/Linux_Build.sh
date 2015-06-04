#!/bin/sh
# 
# This code is part of Pcap_DNSProxy
# A local DNS server based on WinPcap and LibPcap
# Copyright (C) 2012-2015 Chengr28
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


# Back to Pcap_DNSProxy main directory
cd ..

# Build KeyPairGenerator.
mkdir Object
cd Object
CMakeShell="cmake "
if !(echo "$*" | grep -iq -e "--disable-libsodium"); then
	CMakeShell="${CMakeShell}\-DENABLE_LIBSODIUM=ON "
fi
CMakeShell="${CMakeShell}../KeyPairGenerator"
${CMakeShell}
make
cd ..
mkdir Release
mv -f Object/KeyPairGenerator Release
rm -Rrf Object

# Build Pcap_DNSProxy.
mkdir Object
cd Object
CMakeShell="cmake "
if !(echo "$*" | grep -iq -e "--disable-libsodium"); then
	CMakeShell="${CMakeShell}-DENABLE_LIBSODIUM=ON "
fi
if !(echo "$*" | grep -iq -e "--disable-libpcap"); then
	CMakeShell="${CMakeShell}-DENABLE_PCAP=ON "
fi
CMakeShell="${CMakeShell}../Pcap_DNSProxy"
${CMakeShell}
make
cd ..
mv -f Object/Pcap_DNSProxy Release
rm -Rrf Object

# Set program.
chmod 755 Release/KeyPairGenerator
chmod 755 Release/Pcap_DNSProxy
chmod 755 Scripts/Linux_Install.Systemd.sh
chmod 755 Scripts/Linux_Install.SysV.sh
chmod 755 Scripts/Linux_Uninstall.Systemd.sh
chmod 755 Scripts/Linux_Uninstall.SysV.sh
cp ExampleConfig/PcapDNSProxyService Release/PcapDNSProxyService
cp ExampleConfig/Pcap_DNSProxy.service Release/Pcap_DNSProxy.service
cp ExampleConfig/Config.ini Release/Config.conf
cp ExampleConfig/Hosts.ini Release/Hosts.conf
cp ExampleConfig/IPFilter.ini Release/IPFilter.conf
cp ExampleConfig/Routing.txt Release/Routing.txt
cp ExampleConfig/White_List.txt Release/White_List.txt

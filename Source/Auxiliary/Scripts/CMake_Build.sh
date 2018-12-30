#!/usr/bin/env bash
# 
# This code is part of Pcap_DNSProxy
# Pcap_DNSProxy, a local DNS server based on WinPcap and LibPcap
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


# Create release directories and set permissions.
cd ../..
rm -Rrf Object
mkdir Release
chmod -R 755 Auxiliary/Scripts

# Set thread number variable.
if (uname -s | grep -iq "FreeBSD" || uname -s | grep -iq "Darwin"); then
	ThreadNum=`sysctl -n hw.ncpu`
else 
	ThreadNum=`nproc`
fi

# Build Pcap_DNSProxy.
mkdir Object
cd Object
CMakeShell="cmake "
if !(echo "$*" | grep -iq -e "--disable-libpcap"); then
	CMakeShell="${CMakeShell}-DENABLE_PCAP=ON "
fi
if !(echo "$*" | grep -iq -e "--disable-libsodium"); then
	CMakeShell="${CMakeShell}-DENABLE_LIBSODIUM=ON "
fi
if !(echo "$*" | grep -iq -e "--disable-tls"); then
	CMakeShell="${CMakeShell}-DENABLE_TLS=ON "
fi
if (echo "$*" | grep -iq -e "--enable-static"); then
	CMakeShell="${CMakeShell}-DSTATIC_LIB=ON "
fi
CMakeShell="${CMakeShell}../Pcap_DNSProxy"
${CMakeShell}
make -j ${ThreadNum}
cd ..

# Cleanup
mv -f Object/Pcap_DNSProxy Release
rm -Rrf Object

# Program settings
if (uname -s | grep -iq "Darwin"); then
	cp Auxiliary/Scripts/macOS_Install.sh Release/macOS_Install.sh
	cp Auxiliary/Scripts/macOS_Uninstall.sh Release/macOS_Uninstall.sh
	cp Auxiliary/ExampleConfig/pcap_dnsproxy.service.plist Release/pcap_dnsproxy.service.plist
else 
	cp Auxiliary/Scripts/Linux_Install.Systemd.sh Release/Linux_Install.Systemd.sh
	cp Auxiliary/Scripts/Linux_Install.SysV.sh Release/Linux_Install.SysV.sh
	cp Auxiliary/Scripts/Linux_Uninstall.Systemd.sh Release/Linux_Uninstall.Systemd.sh
	cp Auxiliary/Scripts/Linux_Uninstall.SysV.sh Release/Linux_Uninstall.SysV.sh
	cp Auxiliary/ExampleConfig/PcapDNSProxyService Release/PcapDNSProxyService
	cp Auxiliary/ExampleConfig/Pcap_DNSProxy.service Release/Pcap_DNSProxy.service
fi
cp Auxiliary/ExampleConfig/Config.ini Release/Config.conf
cp Auxiliary/ExampleConfig/Hosts.ini Release/Hosts.conf
cp Auxiliary/ExampleConfig/IPFilter.ini Release/IPFilter.conf
cp Auxiliary/ExampleConfig/Routing.txt Release/Routing.txt
cp Auxiliary/ExampleConfig/WhiteList.txt Release/WhiteList.txt
mkdir Release/Tools
cp Auxiliary/Scripts/Update_Routing.sh Release/Tools/Update_Routing.sh
cp Auxiliary/Scripts/Update_WhiteList.sh Release/Tools/Update_WhiteList.sh
chmod -R 755 Release

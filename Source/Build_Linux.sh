# This code is part of Pcap_DNSProxy
# A local DNS server base on WinPcap and LibPcap.
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


# Build KeyPairGenerator
mkdir Object
cd Object
cmake ../KeyPairGenerator
make
cd ..
mkdir Release
mv -f Object/KeyPairGenerator Release
rm -Rrf Object

# Build Pcap_DNSProxy
mkdir Object
cd Object
cmake ../Pcap_DNSProxy
make
cd ..
mv -f Object/Pcap_DNSProxy Release
rm -Rrf Object

# Set program
chmod 777 Release/KeyPairGenerator
chmod 777 Release/Pcap_DNSProxy
chmod 777 Build_Linux.Debian.sh
cp -f ExampleConfig/PcapDNSProxyService Release/PcapDNSProxyService
chmod 777 Release/PcapDNSProxyService
cp -f ExampleConfig/Config.ini Release/Config.conf
cp -f ExampleConfig/Hosts.ini Release/Hosts.conf
cp -f ExampleConfig/IPFilter.ini Release/IPFilter.conf
cp -f ExampleConfig/Routing.txt Release/Routing.txt
cp -f ExampleConfig/White_List.txt Release/White_List.txt

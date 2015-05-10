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


# Set service
chmod 777 KeyPairGenerator
chmod 777 Pcap_DNSProxy
chmod 777 PcapDNSProxyService.plist
cp PcapDNSProxyService.plist /Library/LaunchDaemons/PcapDNSProxyService.plist
cd /Library/LaunchDaemons
chown root PcapDNSProxyService.plist
launchctl load PcapDNSProxyService.plist

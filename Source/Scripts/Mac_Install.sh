#!/bin/sh
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


chmod 755 Mac_Uninstall.sh
chmod 755 Pcap_DNSProxy
chmod -R 755 Tools
cp pcap_dnsproxy.service.plist /Library/LaunchDaemons/pcap_dnsproxy.service.plist
cd /Library/LaunchDaemons
chmod 644 pcap_dnsproxy.service.plist
launchctl load pcap_dnsproxy.service.plist

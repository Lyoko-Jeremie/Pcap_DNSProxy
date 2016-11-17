#!/usr/bin/env bash
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


# Download latest domain data from dnsmasq-china-list project and write header.
echo
curl -O https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf
CurrentDate=`date +%Y-%m-%d`
echo -e "[Local Hosts]\n## China mainland domains\n## Source: https://github.com/felixonmars/dnsmasq-china-list" > WhiteList.txt
echo -n "## Last update: " >> WhiteList.txt
echo $CurrentDate >> WhiteList.txt
echo -e "\n" >> WhiteList.txt
sed -e "s|114.114.114.114$||" -e "s|^s|S|" accelerated-domains.china.conf >> WhiteList.txt

# Download domain data of Google in China part.
echo
read -p "Use google.china.conf in dnsmasq-china-list? [Y/N]:" yn
if [ "${yn}" == "Y" ] || [ "${yn}" == "y" ]; then
	echo
	curl -O https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/google.china.conf
	sed -e "s|114.114.114.114$||" -e "s|^s|S|" google.china.conf >> WhiteList.txt
	rm -rf google.china.conf
fi

# Cleanup
rm -rf accelerated-domains.china.conf
echo

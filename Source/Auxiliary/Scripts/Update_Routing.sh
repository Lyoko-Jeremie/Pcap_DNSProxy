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


# Download latest address data from APNIC and write header.
echo
curl -O https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest
CurrentDate=`date +%Y-%m-%d`
echo -e "[Local Routing]\n## China mainland routing blocks\n## Sources: https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest" > Routing.txt
echo -n "## Last update: " >> Routing.txt
echo $CurrentDate >> Routing.txt
echo -e "\n" >> Routing.txt

# IPv4
echo "## IPv4" >> Routing.txt
cat delegated-apnic-latest | grep ipv4 | grep CN | awk -F\| '{printf("%s/%d\n", $4, 32-log($5)/log(2))}' >> Routing.txt
echo "\n" >> Routing.txt

# IPv6
echo "## IPv6" >> Routing.txt
cat delegated-apnic-latest | grep ipv6 | grep CN | awk -F\| '{printf("%s/%d\n", $4, $5)}' >> Routing.txt

# Cleanup
rm -rf delegated-apnic-latest
echo

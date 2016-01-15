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


# All source files
set(SHA3_SRC_FILES
		"brg_endian.h"
		"KeccakF-1600-interface.h"
		"KeccakHash.h"
		"KeccakSponge.h"
		"SnP.h"
		"SnP-FBWL-default.h"
		"SnP-interface.h"
		"SnP-Relaned.h"
		"KeccakF-1600-compact64.cpp"
		"KeccakHash.cpp"
		"KeccakSponge.cpp"
		"SnP-FBWL-default.cpp")

# Libraries linking
add_library(SHA3 ${SHA3_SRC_FILES})

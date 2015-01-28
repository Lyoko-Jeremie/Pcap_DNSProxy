// This code is part of Pcap_DNSProxy(Windows)
// Pcap_DNSProxy, A local DNS server base on WinPcap and LibPcap.
// Copyright (C) 2012-2015 Chengr28
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either
// version 2 of the License, or (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.


#include "Pcap_DNSProxy.h"

//Compare two addresses
size_t __fastcall CompareAddresses(const void *OriginalAddrBegin, const void *OriginalAddrEnd, const uint16_t Protocol)
{
	if (Protocol == AF_INET6) //IPv6
	{
		auto AddrBegin = (in6_addr *)OriginalAddrBegin, AddrEnd = (in6_addr *)OriginalAddrEnd;
		for (size_t Index = 0;Index < sizeof(in6_addr) / sizeof(uint16_t);Index++)
		{
			if (ntohs(AddrBegin->u.Word[Index]) > ntohs(AddrEnd->u.Word[Index]))
			{
				return ADDRESS_COMPARE_GREATER;
			}
			else if (AddrBegin->u.Word[Index] == AddrEnd->u.Word[Index])
			{
				if (Index == sizeof(in6_addr) / sizeof(uint16_t) - 1U)
					return ADDRESS_COMPARE_EQUAL;
				else
					continue;
			}
			else {
				return ADDRESS_COMPARE_LESS;
			}
		}
	}
	else { //IPv4
		auto AddrBegin = (in_addr *)OriginalAddrBegin, AddrEnd = (in_addr *)OriginalAddrEnd;
		if (AddrBegin->S_un.S_un_b.s_b1 > AddrEnd->S_un.S_un_b.s_b1)
		{
			return ADDRESS_COMPARE_GREATER;
		}
		else if (AddrBegin->S_un.S_un_b.s_b1 == AddrEnd->S_un.S_un_b.s_b1)
		{
			if (AddrBegin->S_un.S_un_b.s_b2 > AddrEnd->S_un.S_un_b.s_b2)
			{
				return ADDRESS_COMPARE_GREATER;
			}
			else if (AddrBegin->S_un.S_un_b.s_b2 == AddrEnd->S_un.S_un_b.s_b2)
			{
				if (AddrBegin->S_un.S_un_b.s_b3 > AddrEnd->S_un.S_un_b.s_b3)
				{
					return ADDRESS_COMPARE_GREATER;
				}
				else if (AddrBegin->S_un.S_un_b.s_b3 == AddrEnd->S_un.S_un_b.s_b3)
				{
					if (AddrBegin->S_un.S_un_b.s_b4 > AddrEnd->S_un.S_un_b.s_b4)
						return ADDRESS_COMPARE_GREATER;
					else if (AddrBegin->S_un.S_un_b.s_b4 == AddrEnd->S_un.S_un_b.s_b4)
						return ADDRESS_COMPARE_EQUAL;
					else
						return ADDRESS_COMPARE_LESS;
				}
				else {
					return ADDRESS_COMPARE_LESS;
				}
			}
			else {
				return ADDRESS_COMPARE_LESS;
			}
		}
		else {
			return ADDRESS_COMPARE_LESS;
		}
	}

	return EXIT_SUCCESS;
}

/* Old version(2015-01-28)
//Sort ResultBlacklist(All)
bool __fastcall SortResultBlacklistALL(const ResultBlacklistTable &ResultBlacklistTableIter)
{
	return ResultBlacklistTableIter.PatternString.empty();
}

//Sort HostsList(Banned)
bool __fastcall SortHostsListBANNED(const HostsTable &HostsTableIter)
{
	return (HostsTableIter.Type == HOSTS_BANNED);
}

//Sort HostsList(White)
bool __fastcall SortHostsListWHITE(const HostsTable &HostsTableIter)
{
	return (HostsTableIter.Type == HOSTS_WHITE);
}

//Sort HostsList(Normal)
bool __fastcall SortHostsListNORMAL(const HostsTable &HostsTableIter)
{
	return (HostsTableIter.Type == HOSTS_NORMAL);
}
*/

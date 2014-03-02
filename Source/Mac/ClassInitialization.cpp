// This code is part of Pcap_DNSProxy(Mac)
// Copyright (C) 2012-2014 Chengr28
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

extern regex_t IPv4PrivateB, IPv6ULA, IPv6LUC;

//Configuration class constructor
Configuration::Configuration()
{
	memset(this, 0, sizeof(Configuration));
	DomainTestOptions.DomainTest = nullptr, PaddingDataOptions.PaddingData = nullptr, LocalhostServerOptions.LocalhostServer = nullptr;
	try {
		DomainTestOptions.DomainTest = new char[PACKET_MAXSIZE/8](); //Maximum length of whole level domain is 253 bytes(Section 2.3.1 in RFC 1035).
		PaddingDataOptions.PaddingData = new char[PACKET_MAXSIZE/8](); //The length of ICMP padding data must between 18 bytes and 64 bytes.
		LocalhostServerOptions.LocalhostServer = new char[PACKET_MAXSIZE/8](); //Maximum length of whole level domain is 253 bytes(Section 2.3.1 in RFC 1035).
	}
	catch (std::bad_alloc)
	{
		delete[] DomainTestOptions.DomainTest;
		delete[] PaddingDataOptions.PaddingData;
		delete[] LocalhostServerOptions.LocalhostServer;
		return;
	}
	
	memset(DomainTestOptions.DomainTest, 0, PACKET_MAXSIZE/8);
	memset(PaddingDataOptions.PaddingData, 0, PACKET_MAXSIZE/8);
	memset(LocalhostServerOptions.LocalhostServer, 0, PACKET_MAXSIZE/8);
	return;
}

//Configuration class destructors
Configuration::~Configuration()
{
	delete[] DomainTestOptions.DomainTest;
	delete[] PaddingDataOptions.PaddingData;
	delete[] LocalhostServerOptions.LocalhostServer;
	return;
}

//HostsTable class constructor
HostsTable::HostsTable()
{
	memset(this, 0, sizeof(HostsTable));
	return;
}

//PortTable class constructor
PortTable::PortTable()
{
	RecvData = nullptr, SendPort = nullptr;
	try {
		RecvData = new SOCKET_DATA[THREAD_MAXNUM*THREAD_PARTNUM](); //Receive SOCKETs area: 0 is IPv6/UDP, 1 is IPv4/UDP, 2 is IPv6/TCP, 3 is IPv4/TCP
		SendPort = new uint16_t[THREAD_MAXNUM*THREAD_PARTNUM]();
	}
	catch (std::bad_alloc)
	{
		delete[] RecvData;
		delete[] SendPort;
		return;
	}
	
	memset(RecvData, 0, sizeof(SOCKET_DATA)*THREAD_MAXNUM*THREAD_PARTNUM);
	memset(SendPort, 0, sizeof(uint16_t)*THREAD_MAXNUM*THREAD_PARTNUM);
	return;
}

//PortTable class destructors
PortTable::~PortTable()
{
	delete[] RecvData;
	delete[] SendPort;
	return;
}

//Some Regular Expression of special addresses initialization(Linux/Mac)
void RegexInitialization()
{
	regcomp(&IPv4PrivateB, ".(1[6-9]|2[0-9]|3[01]).172.in-addr.arpa", REG_EXTENDED|REG_ICASE|REG_NOSUB);
	regcomp(&IPv6ULA, ".f.[cd].([0-9]|[a-f]).([0-9]|[a-f]).ip6.arpa", REG_EXTENDED|REG_ICASE|REG_NOSUB);
	regcomp(&IPv6LUC, ".f.f.([89]|[ab]).([0-9]|[a-f]).ip6.arpa", REG_EXTENDED|REG_ICASE|REG_NOSUB);
	return;
}

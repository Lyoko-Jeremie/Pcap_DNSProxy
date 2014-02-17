// This code is part of Pcap_DNSProxy
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

extern Configuration Parameter;

//Local DNS server initialization
size_t MonitorInitialization()
{
//Get Hop Limits with common DNS request
	if (Parameter.DNSTarget.IPv6)
	{
		std::thread IPv6TestDoaminThread(DomainTest, AF_INET6);
		IPv6TestDoaminThread.detach();
	}
	if (Parameter.DNSTarget.IPv4)
	{
		std::thread IPv4TestDoaminThread(DomainTest, AF_INET);
		IPv4TestDoaminThread.detach();
	}

//Get Hop Limits with ICMP Echo
	if (Parameter.ICMPOptions.ICMPSpeed > 0)
	{
		if (Parameter.DNSTarget.IPv4)
		{
			std::thread ICMPThread(ICMPEcho);
			ICMPThread.detach();
		}

		if (Parameter.DNSTarget.IPv6)
		{
			std::thread ICMPv6Thread(ICMPv6Echo);
			ICMPv6Thread.detach();
		}
	}

	SOCKET_DATA LocalhostData = {0};
//Set localhost socket(IPv6/UDP)
	LocalhostData.Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	Parameter.LocalSocket[0] = LocalhostData.Socket;
	if (Parameter.ServerMode)
		((sockaddr_in6 *)&LocalhostData.SockAddr)->sin6_addr = in6addr_any;
	else 
		((sockaddr_in6 *)&LocalhostData.SockAddr)->sin6_addr = in6addr_loopback;
	((sockaddr_in6 *)&LocalhostData.SockAddr)->sin6_family = AF_INET6;
	((sockaddr_in6 *)&LocalhostData.SockAddr)->sin6_port = htons(DNS_Port);
	LocalhostData.AddrLen = sizeof(sockaddr_in6);

	std::thread IPv6UDPMonitor(UDPMonitor, LocalhostData);
	memset(&LocalhostData, 0, sizeof(SOCKET_DATA));

//Set localhost socket(IPv6/TCP)
	LocalhostData.Socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	Parameter.LocalSocket[2] = LocalhostData.Socket;
	if (Parameter.ServerMode)
		((sockaddr_in6 *)&LocalhostData.SockAddr)->sin6_addr = in6addr_any;
	else 
		((sockaddr_in6 *)&LocalhostData.SockAddr)->sin6_addr = in6addr_loopback;
	((sockaddr_in6 *)&LocalhostData.SockAddr)->sin6_family = AF_INET6;
	((sockaddr_in6 *)&LocalhostData.SockAddr)->sin6_port = htons(DNS_Port);
	LocalhostData.AddrLen = sizeof(sockaddr_in6);

	std::thread IPv6TCPMonitor(TCPMonitor, LocalhostData);
	memset(&LocalhostData, 0, sizeof(SOCKET_DATA));

//Set localhost socket(IPv4/UDP)
	LocalhostData.Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	Parameter.LocalSocket[1] = LocalhostData.Socket;
	if (Parameter.ServerMode)
		((sockaddr_in *)&LocalhostData.SockAddr)->sin_addr.s_addr = INADDR_ANY;
	else 
		((sockaddr_in *)&LocalhostData.SockAddr)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	((sockaddr_in *)&LocalhostData.SockAddr)->sin_family = AF_INET;
	((sockaddr_in *)&LocalhostData.SockAddr)->sin_port = htons(DNS_Port);
	LocalhostData.AddrLen = sizeof(sockaddr_in);

	std::thread IPv4UDPMonitor(UDPMonitor, LocalhostData);
	memset(&LocalhostData, 0, sizeof(SOCKET_DATA));

//Set localhost socket(IPv4/TCP)
	LocalhostData.Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	Parameter.LocalSocket[3] = LocalhostData.Socket;
	if (Parameter.ServerMode)
		((sockaddr_in *)&LocalhostData.SockAddr)->sin_addr.s_addr = INADDR_ANY;
	else 
		((sockaddr_in *)&LocalhostData.SockAddr)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	((sockaddr_in *)&LocalhostData.SockAddr)->sin_family = AF_INET;
	((sockaddr_in *)&LocalhostData.SockAddr)->sin_port = htons(DNS_Port);
	LocalhostData.AddrLen = sizeof(sockaddr_in);
			
	std::thread IPv4TCPMonitor(TCPMonitor, LocalhostData);
	memset(&LocalhostData, 0, sizeof(SOCKET_DATA));

//Join threads
	if (IPv6UDPMonitor.joinable())
		IPv6UDPMonitor.join();
	if (IPv4UDPMonitor.joinable())
		IPv4UDPMonitor.join();
	if (IPv6TCPMonitor.joinable())
		IPv6TCPMonitor.join();
	if (IPv4TCPMonitor.joinable())
		IPv4TCPMonitor.join();

	return EXIT_SUCCESS;
}

//Local DNS server with UDP protocol
size_t UDPMonitor(const SOCKET_DATA LocalhostData)
{
	if ((!Parameter.DNSTarget.IPv6 && LocalhostData.AddrLen == sizeof(sockaddr_in6)) || //IPv6
		(!Parameter.DNSTarget.IPv4 && LocalhostData.AddrLen == sizeof(sockaddr_in))) //IPv4
	{
		close(LocalhostData.Socket);
		return FALSE;
	}

//Socket initialization
	if (LocalhostData.Socket == RETURN_ERROR)
	{
		PrintError(Socket_Error, L"UDP Monitor socket initialization failed", errno, 0);

		close(LocalhostData.Socket);
		return EXIT_FAILURE;
	}

	if (bind(LocalhostData.Socket, (sockaddr *)&LocalhostData.SockAddr, LocalhostData.AddrLen) == RETURN_ERROR)
	{
		PrintError(Socket_Error, L"Bind UDP Monitor socket error", errno, 0);

		close(LocalhostData.Socket);
		return EXIT_FAILURE;
	}

//Initialization
	char *Buffer = nullptr;
	try {
		Buffer = new char[PACKET_MAXSIZE*THREAD_MAXNUM]();
	}
	catch (std::bad_alloc)
	{
		PrintError(System_Error, L"Memory allocation failed", 0, 0);

		close(LocalhostData.Socket);
		return EXIT_FAILURE;
	}
	memset(Buffer, 0, PACKET_MAXSIZE*THREAD_MAXNUM);

//Start Monitor
	ssize_t RecvLength = 0;
	size_t Index = 0;
	while (true)
	{
		memset(Buffer + PACKET_MAXSIZE*Index, 0, PACKET_MAXSIZE);
		RecvLength = recvfrom(LocalhostData.Socket, Buffer + PACKET_MAXSIZE*Index, PACKET_MAXSIZE, 0, (sockaddr *)&(LocalhostData.SockAddr), (socklen_t *)&LocalhostData.AddrLen);

		if (RecvLength >= (ssize_t)(sizeof(dns_hdr) + sizeof(dns_qry)))
		{
			if (LocalhostData.AddrLen == sizeof(sockaddr_in6))
			{
				std::thread RecvProcess(RequestProcess, Buffer + PACKET_MAXSIZE*Index, RecvLength, LocalhostData, IPPROTO_UDP, Index);
				RecvProcess.detach();
			}
			if (LocalhostData.AddrLen == sizeof(sockaddr_in))
			{
				std::thread RecvProcess(RequestProcess, Buffer + PACKET_MAXSIZE*Index, RecvLength, LocalhostData, IPPROTO_UDP, Index + THREAD_MAXNUM);
				RecvProcess.detach();
			}

			Index = (Index + 1)%THREAD_MAXNUM;
		}
	}

	delete[] Buffer;
	close(LocalhostData.Socket);
	return EXIT_SUCCESS;
}

//Local DNS server with TCP protocol
size_t TCPMonitor(const SOCKET_DATA LocalhostData)
{
	if ((!Parameter.DNSTarget.IPv6 && LocalhostData.AddrLen == sizeof(sockaddr_in6)) || //IPv6
		(!Parameter.DNSTarget.IPv4 && LocalhostData.AddrLen == sizeof(sockaddr_in))) //IPv4
	{
		close(LocalhostData.Socket);
		return FALSE;
	}

//Socket initialization
	if (LocalhostData.Socket == RETURN_ERROR)
	{
		PrintError(Socket_Error, L"TCP Monitor socket initialization failed", errno, 0);

		close(LocalhostData.Socket);
		return EXIT_FAILURE;
	}

	if(bind(LocalhostData.Socket, (sockaddr *)&LocalhostData.SockAddr, LocalhostData.AddrLen) == RETURN_ERROR)
	{
		PrintError(Socket_Error, L"Bind TCP Monitor socket error", errno, 0);

		close(LocalhostData.Socket);
		return EXIT_FAILURE;
	}

	if (listen(LocalhostData.Socket, SOMAXCONN) == RETURN_ERROR)
	{
		PrintError(Socket_Error, L"TCP Monitor socket listening initialization failed", errno, 0);

		close(LocalhostData.Socket);
		return EXIT_FAILURE;
	}

//Start Monitor
	SOCKET_DATA ClientData = {0};
	size_t Index = 0;
	while (true)
	{
		memset(&ClientData, 0, sizeof(SOCKET_DATA));
		ClientData.Socket = accept(LocalhostData.Socket, (sockaddr *)&ClientData.SockAddr, (socklen_t *)&LocalhostData.AddrLen);
		if (ClientData.Socket == RETURN_ERROR)
		{
			close(ClientData.Socket);
			continue;
		}

		ClientData.AddrLen = LocalhostData.AddrLen;
		std::thread TCPReceiveThread(TCPReceiveProcess, ClientData, Index);
		TCPReceiveThread.detach();

		Index = (Index + 1)%THREAD_MAXNUM;
	}

	close(LocalhostData.Socket);
	return EXIT_SUCCESS;
}

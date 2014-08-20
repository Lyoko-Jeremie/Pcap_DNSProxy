// This code is part of Pcap_DNSProxy(Linux)
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

pcap_if *pThedevs = nullptr;

extern Configuration Parameter;
extern PortTable PortList;

//Capture initialization
size_t CaptureInitialization()
{
//Initialization
	char *ErrBuffer = nullptr;
	wchar_t *wErrBuffer = nullptr;
	try {
		ErrBuffer = new char[PCAP_ERRBUF_SIZE]();
		wErrBuffer = new wchar_t[PCAP_ERRBUF_SIZE]();
	}
	catch (std::bad_alloc)
	{
		PrintError(System_Error, L"Memory allocation failed", 0, 0);
		
		delete[] ErrBuffer;
		delete[] wErrBuffer;
		return EXIT_FAILURE;
	}
	memset(ErrBuffer, 0, PCAP_ERRBUF_SIZE);
	memset(wErrBuffer, 0, sizeof(wchar_t)*PCAP_ERRBUF_SIZE);

	pcap_if *AvailableDevices = nullptr;
	std::string AvailableDevicesName;
	bool Non_Loopback = false;
	size_t Index = 0;
	for (Index = 0;Index < 90;Index++) //Retry to get device list in 15 minutes
	{
//Open all devices
		if (pcap_findalldevs(&pThedevs, ErrBuffer) == RETURN_ERROR)
		{
			mbstowcs(wErrBuffer, ErrBuffer, strlen(ErrBuffer));
			PrintError(LibPcap_Error, wErrBuffer, 0, 0);

			delete[] ErrBuffer;
			delete[] wErrBuffer;
			return EXIT_FAILURE;
		}

//Permissions check and check available network devices
		if (pThedevs == nullptr)
		{
			PrintError(System_Error, L"Insufficient permissions", 0, 0);

			delete[] ErrBuffer;
			delete[] wErrBuffer;
			return EXIT_FAILURE;
		}
		else {
			AvailableDevices = pThedevs;
			while (AvailableDevices != nullptr)
			{
				AvailableDevicesName = AvailableDevices->name;
				AvailableDevices = AvailableDevices->next;
				if (AvailableDevicesName.find("lo") == std::string::npos && AvailableDevicesName.find("any") == std::string::npos)
					Non_Loopback = true;
			}

			if (!Non_Loopback)
			{
				if (Index == 89)
				{
					PrintError(LibPcap_Error, L"Not any available network devices", 0, 0);
					
					delete[] ErrBuffer;
					delete[] wErrBuffer;
					pcap_freealldevs(pThedevs);
					return EXIT_FAILURE;
				}
				
				pcap_freealldevs(pThedevs);
				sleep(10); //6 times in a minute
				continue;
			}
			else {
				break;
			}
		}
	}

//Start capturing
	std::thread CaptureThread(Capture, pThedevs);
	CaptureThread.detach();
	return EXIT_SUCCESS;
}

//Capture process
size_t Capture(const pcap_if *pDrive)
{
//Initialization
	pcap_t *pAdHandle = nullptr;
	pcap_pkthdr *pHeader = nullptr;
	wchar_t *ErrBuffer = nullptr, *DrviceName = nullptr;
	char *Addr = nullptr, *Buffer = nullptr;
	try {
		ErrBuffer = new wchar_t[PCAP_ERRBUF_SIZE]();
		DrviceName = new wchar_t[PACKET_MAXSIZE/8]();
		Addr = new char[PACKET_MAXSIZE/8]();
		Buffer = new char[PACKET_MAXSIZE*THREAD_MAXNUM*THREAD_PARTNUM]();
	}
	catch (std::bad_alloc)
	{
		PrintError(System_Error, L"Memory allocation failed", 0, 0);

		delete[] ErrBuffer;
		delete[] Addr;
		delete[] Buffer;
		delete[] DrviceName;
		return EXIT_FAILURE;
	}
	memset(ErrBuffer, 0, sizeof(wchar_t) * PCAP_ERRBUF_SIZE);
	memset(DrviceName, 0, sizeof(wchar_t) * PACKET_MAXSIZE/8);
	memset(Addr, 0, PACKET_MAXSIZE/8);
	memset(Buffer, 0, PACKET_MAXSIZE*THREAD_MAXNUM*THREAD_PARTNUM);

//Open device(Linux)
	if ((pAdHandle = pcap_open_live(pDrive->name, PACKET_MAXSIZE, FALSE, TIME_OUT/4, Buffer)) == nullptr)
	{
		mbstowcs(ErrBuffer, Buffer, strlen(Buffer));
		PrintError(LibPcap_Error, ErrBuffer, 0, 0);

		delete[] ErrBuffer;
		delete[] Addr;
		delete[] Buffer;
		delete[] DrviceName;
		return EXIT_FAILURE;
	}

//Check device type(Linux)
	mbstowcs(DrviceName, pDrive->name, strlen(pDrive->name));
	if (pcap_datalink(pAdHandle) != DLT_EN10MB) //Ethernet
	{
		if (pcap_datalink(pAdHandle) != DLT_NULL && pcap_datalink(pAdHandle) != DLT_NFLOG) //BSD loopback encapsulation and Linux NETLINK NFLOG socket log messages
		{
			static const wchar_t *PcapDatalinkError = L" is not a Ethernet device";
			wcsncpy(ErrBuffer, DrviceName, wcslen(DrviceName));
			wcsncpy(ErrBuffer + wcslen(DrviceName), PcapDatalinkError, wcslen(PcapDatalinkError));
			PrintError(LibPcap_Error, ErrBuffer, 0, 0);
		}
		
		delete[] ErrBuffer;
		delete[] Addr;
		delete[] Buffer;
		delete[] DrviceName;
		pcap_close(pAdHandle);
		return EXIT_FAILURE;
	}

//Set capture filter
	bool Local = false;
	std::string FilterRules = ("(src host ");
	if (Parameter.DNSTarget.IPv6 && Parameter.DNSTarget.IPv4) //Both of IPv4 and IPv6
	{
	//Check Local DNS server
		if ((Parameter.DNSTarget.IPv6 && Parameter.DNSTarget.Local_IPv6) || //IPv6 Local DNS server available
			(Parameter.DNSTarget.IPv4 && Parameter.DNSTarget.Local_IPv4)) //IPv4 Local DNS server available
				Local = true;

	//Both of IPv6 and IPv4, the filter is "(src host (IPv4Target or Local_IPv4Target or IPv6Target or Local_IPv6Target)) or (pppoes and src host (IPv4Target or Local_IPv4Target or IPv6Target or Local_IPv6Target))"
	//When Local DNS server is not available, the filter is (src host (IPv4Target or IPv6Target)) or (pppoes and src host (IPv4Target or IPv6Target))"
		std::string BothAddr("(");
		inet_ntop(AF_INET, (char *)&Parameter.DNSTarget.IPv4Target, Addr, PACKET_MAXSIZE/8);
		if (Local)
			inet_ntop(AF_INET, (char *)&Parameter.DNSTarget.Local_IPv4Target, Buffer, PACKET_MAXSIZE/8);
		BothAddr.append(Addr);
		if (Local)
		{
			BothAddr.append(" or ");
			BothAddr.append(Buffer);
		}
		BothAddr.append(" or ");
		memset(Addr, 0, PACKET_MAXSIZE/8);
		memset(Buffer, 0, PACKET_MAXSIZE/8);
		inet_ntop(AF_INET6, (char *)&Parameter.DNSTarget.IPv6Target, Addr, PACKET_MAXSIZE/8);
		if (Local)
			inet_ntop(AF_INET6, (char *)&Parameter.DNSTarget.Local_IPv6Target, Buffer, PACKET_MAXSIZE/8);
		BothAddr.append(Addr);
		if (Local)
		{
			BothAddr.append(" or ");
			BothAddr.append(Buffer);
		}
		BothAddr.append(")");

		FilterRules.append(BothAddr);
		FilterRules.append(") or (pppoes and src host ");
		FilterRules.append(BothAddr);
	}
	else {
	//Check Local DNS server
		if ((Parameter.DNSTarget.IPv6 && Parameter.DNSTarget.Local_IPv6) || //IPv6 Local DNS server available
			(Parameter.DNSTarget.IPv4 && Parameter.DNSTarget.Local_IPv4)) //IPv4 Local DNS server available
				Local = true;

	//IPv6 only, the filter is "(src host (IPv6Target or Local_IPv6Target)) or (pppoes and src host (IPv6Target or Local_IPv6Target))"
	//When Local DNS server is not available, the filter is "(src host IPv6Target) or (pppoes and src host IPv6Target)"
		if (Parameter.DNSTarget.IPv6)
		{
			inet_ntop(AF_INET6, (char *)&Parameter.DNSTarget.IPv6Target, Addr, PACKET_MAXSIZE/8);
			if (Local)
				inet_ntop(AF_INET6, (char *)&Parameter.DNSTarget.Local_IPv6Target, Buffer, PACKET_MAXSIZE/8);
		}
	//IPv4 only, the filter is "(src host (IPv4Target or Local_IPv4Target)) or (pppoes and src host (IPv4Target or Local_IPv4Target))"
	//When Local DNS server is not available, the filter is "(src host IPv4Target) or (pppoes and src host IPv4Target)"
		else {
			inet_ntop(AF_INET, (char *)&Parameter.DNSTarget.IPv4Target, Addr, PACKET_MAXSIZE/8);
			if (Local)
				inet_ntop(AF_INET, (char *)&Parameter.DNSTarget.Local_IPv4Target, Buffer, PACKET_MAXSIZE/8);
		}
		if (Local)
			FilterRules.append("(");
		FilterRules.append(Addr);
		if (Local)
		{
			FilterRules.append(" or ");
			FilterRules.append(Buffer);
			FilterRules.append(")");
		}
		FilterRules.append(") or (pppoes and src host ");
		if (Local)
			FilterRules.append("(");
		FilterRules.append(Addr);
		if (Local)
		{
			FilterRules.append(" or ");
			FilterRules.append(Buffer);
			FilterRules.append(")");
		}
	}
	delete[] Addr;
	memset(Buffer, 0, PACKET_MAXSIZE/8);
	FilterRules.append(")");

//Compile the string into a filter program(Linux)
	bpf_program FCode = {0};
	if (pcap_compile(pAdHandle, &FCode, FilterRules.c_str(), TRUE, FALSE) == RETURN_ERROR)
	{
		char *Pcap_GetErr = pcap_geterr(pAdHandle);
		mbstowcs(ErrBuffer, Pcap_GetErr, strlen(Pcap_GetErr));
		PrintError(LibPcap_Error, ErrBuffer, 0, 0);

		delete[] ErrBuffer;
		delete[] Buffer;
		delete[] DrviceName;
		pcap_freecode(&FCode);
		pcap_close(pAdHandle);
		return EXIT_FAILURE;
	}
	
//Specify a filter program(Linux/Mac)
	if (pcap_setfilter(pAdHandle, &FCode) == RETURN_ERROR)
	{
		char *Pcap_GetErr = pcap_geterr(pAdHandle);
		mbstowcs(ErrBuffer, Pcap_GetErr, strlen(Pcap_GetErr));
		PrintError(LibPcap_Error, ErrBuffer, 0, 0);

		delete[] ErrBuffer;
		delete[] Buffer;
		delete[] DrviceName;
		pcap_freecode(&FCode);
		pcap_close(pAdHandle);
		return EXIT_FAILURE;
	}

//Copy device name from pThedevs
	if (pDrive->next != nullptr)
	{
		std::thread CaptureThread(Capture, pDrive->next);
		CaptureThread.detach();
	}
	else {
		pcap_freealldevs(pThedevs);
	}

//Start capture
	const u_char *PacketData = nullptr;
	ssize_t Result = 0;
	size_t Index = 0, HeaderLength = sizeof(eth_hdr);
	
	eth_hdr *eth = nullptr;
	while(true)
	{
		Result = pcap_next_ex(pAdHandle, &pHeader, &PacketData);
		switch (Result)
		{
			case RETURN_ERROR: //An error occurred
			{
				sleep(Parameter.Hosts);
				continue;
/*
			//The device is offline, wait for retrying(Linux/Mac)
				static const wchar_t PcapNextExError[] = L"An error occurred in ";
				wcsncpy(ErrBuffer, PcapNextExError, wcslen(PcapNextExError));
				wcsncpy(ErrBuffer + wcslen(PcapNextExError), DrviceName, wcslen(DrviceName));
				PrintError(LibPcap_Error, ErrBuffer, 0, 0);
				
				delete[] ErrBuffer;
				delete[] Buffer;
				delete[] DrviceName;
				pcap_freecode(&FCode);
				pcap_close(pAdHandle);
				return EXIT_FAILURE;
*/
			}break;
			case -2: //EOF was reached reading from an offline capture
			{
				static const wchar_t PcapNextExError[] = L"EOF was reached reading from an offline capture in ";
				wcsncpy(ErrBuffer, PcapNextExError, wcslen(PcapNextExError));
				wcsncpy(ErrBuffer + wcslen(PcapNextExError), DrviceName, wcslen(DrviceName));
				PrintError(LibPcap_Error, ErrBuffer, 0, 0);
				
				delete[] ErrBuffer;
				delete[] Buffer;
				delete[] DrviceName;
				pcap_freecode(&FCode);
				pcap_close(pAdHandle);
				return EXIT_FAILURE;
			}break;
			case FALSE: //0, The timeout set with pcap_open_live() has elapsed. In this case pkt_header and pkt_data don't point to a valid packet.
				continue;
			case TRUE: //1, The packet has been read without problems
			{
				memset(Buffer + PACKET_MAXSIZE*Index, 0, PACKET_MAXSIZE);

				eth = (eth_hdr *)PacketData;
				HeaderLength = sizeof(eth_hdr);
				if (eth->Type == htons(ETHERTYPE_PPPOES)) //PPPoE(Such as ADSL, a part of school networks)
				{
					pppoe_hdr *pppoe = (pppoe_hdr *)(PacketData + HeaderLength);
					HeaderLength += sizeof(pppoe_hdr);
					if ((pppoe->Protocol == htons(PPPOETYPE_IPV4) || pppoe->Protocol == htons(PPPOETYPE_IPV6)) && //IPv4 or IPv6 over PPPoE
						pHeader->caplen - HeaderLength > sizeof(ipv4_hdr) && pHeader->caplen - HeaderLength < PACKET_MAXSIZE)
					{
						memcpy(Buffer + PACKET_MAXSIZE*Index, PacketData + HeaderLength, pHeader->caplen - HeaderLength);
						std::thread IPMethod(IPLayer, Buffer + PACKET_MAXSIZE*Index, pHeader->caplen - HeaderLength, ntohs(pppoe->Protocol));
						IPMethod.detach();

						Index = (Index + 1)%(THREAD_MAXNUM*THREAD_PARTNUM);
					}
				}
				else if ((eth->Type == htons(ETHERTYPE_IP) || eth->Type == htons(ETHERTYPE_IPV6)) && //IPv4 or IPv6 (Such as LAN/WLAN/IEEE 802.1X, some Mobile Communications Standard drives which disguise as a LAN)
					pHeader->caplen - HeaderLength > sizeof(ipv4_hdr) && pHeader->caplen - HeaderLength < PACKET_MAXSIZE)
				{
					memcpy(Buffer + PACKET_MAXSIZE*Index, PacketData + HeaderLength, pHeader->caplen - HeaderLength);
					std::thread IPMethod(IPLayer, Buffer + PACKET_MAXSIZE*Index, pHeader->caplen - HeaderLength, ntohs(eth->Type));
					IPMethod.detach();

					Index = (Index + 1)%(THREAD_MAXNUM*THREAD_PARTNUM);
				}
				else {
					continue;
				}
			}break;
			default: {
				continue;
			}
		}
	}

	delete[] ErrBuffer;
	delete[] Buffer;
	delete[] DrviceName;
	pcap_freecode(&FCode);
	pcap_close(pAdHandle);
	return EXIT_SUCCESS;
}

//Network Layer(Internet Protocol/IP) process
size_t IPLayer(const char *Recv, const size_t Length, const uint16_t Protocol)
{
//Initialization
	char *Buffer = nullptr;
	try {
		Buffer = new char[PACKET_MAXSIZE]();
	}
	catch (std::bad_alloc) 
	{
		PrintError(System_Error, L"Memory allocation failed", 0, 0);

		return EXIT_FAILURE;
	}
	memset(Buffer, 0, PACKET_MAXSIZE);
	memcpy(Buffer, Recv, Length);

	if (Parameter.DNSTarget.IPv6 && (Protocol == PPPOETYPE_IPV6 || Protocol == ETHERTYPE_IPV6)) //IPv6
	{
		ipv6_hdr *ipv6 = (ipv6_hdr *)Buffer;

//Get Hop Limits from IPv6 DNS server
/*	//Length of packets
		if (Length > sizeof(ipv6_hdr) + sizeof(udp_hdr) + sizeof(dns_hdr) + sizeof(dns_qry) + 1)
			Parameter.HopLimitOptions.IPv6HopLimit = ipv6->HopLimit;
*/
	//ICMPv6 Protocol
		if (Parameter.ICMPOptions.ICMPSpeed > 0 && ipv6->NextHeader == IPPROTO_ICMPV6 && 
			Length - sizeof(ipv6_hdr) >= sizeof(icmpv6_hdr))
		{
			if (ICMPCheck(Buffer, Length, AF_INET6))
				Parameter.HopLimitOptions.IPv6HopLimit = ipv6->HopLimit;

			delete[] Buffer;
			return EXIT_SUCCESS;
		}
	//TCP Protocol
		else if (ipv6->NextHeader == IPPROTO_TCP && Parameter.TCPOptions && 
			Length - sizeof(ipv6_hdr) >= sizeof(tcp_hdr))
		{
			if (TCPCheck((Buffer + sizeof(ipv6_hdr))))
				Parameter.HopLimitOptions.IPv6HopLimit = ipv6->HopLimit;

			delete[] Buffer;
			return EXIT_SUCCESS;
		}
//End
		else if (ipv6->NextHeader == IPPROTO_UDP && Length - sizeof(ipv6_hdr) >= sizeof(udp_hdr))
		{
			udp_hdr *udp = (udp_hdr *)(Buffer + sizeof(ipv6_hdr));
		//Validate UDP checksum
			if (UDPChecksum(Buffer, Length, AF_INET6) != 0)
			{
				delete[] Buffer;
				return EXIT_SUCCESS;
			}

			if (udp->Src_Port == htons(DNS_Port) && Length - sizeof(ipv6_hdr) - sizeof(udp_hdr) >= sizeof(dns_hdr))
			{
			//Responses of Local DNS
				if (memcmp((char *)&ipv6->Src, (char *)&Parameter.DNSTarget.Local_IPv6Target, sizeof(in6_addr)) == 0)
				{
					DNSMethod(Buffer + sizeof(ipv6_hdr), Length - sizeof(ipv6_hdr), AF_INET6, true);
					
					delete[] Buffer;
					return EXIT_SUCCESS;
				}

			//Domain Test and DNS Options check and get Hop Limit form Domain Test
				bool SignHopLimit = false;
				if (DTDNSOCheck(Buffer + sizeof(ipv6_hdr) + sizeof(udp_hdr), SignHopLimit))
				{
					if (SignHopLimit)
						Parameter.HopLimitOptions.IPv6HopLimit = ipv6->HopLimit;
				}
				else {
					delete[] Buffer;
					return EXIT_SUCCESS;
				}

			//Process
				if (ipv6->HopLimit > Parameter.HopLimitOptions.IPv6HopLimit - Parameter.HopLimitOptions.HopLimitFluctuation && ipv6->HopLimit < Parameter.HopLimitOptions.IPv6HopLimit + Parameter.HopLimitOptions.HopLimitFluctuation) //Hop Limit must not a ramdom number
				{
					DNSMethod(Buffer + sizeof(ipv6_hdr), Length - sizeof(ipv6_hdr), AF_INET6, false);

					delete[] Buffer;
					return EXIT_SUCCESS;
				}
			}
		}
	}
	else if (Parameter.DNSTarget.IPv4 && (Protocol == PPPOETYPE_IPV4 || Protocol == ETHERTYPE_IP)) //IPv4
	{
		ipv4_hdr *ipv4 = (ipv4_hdr *)Buffer;
	//Validate IPv4 pcaket
		if (ipv4->IHL != 5 || //Standard IPv4 header
			GetChecksum((uint16_t *)Buffer, sizeof(ipv4_hdr)) != 0 || //Validate IPv4 header checksum
			(Parameter.IPv4Options && (ipv4->TOS != 0 || ipv4->Flags != 0))) //TOS and Flags should not be set.
		{
			delete[] Buffer;
			return EXIT_SUCCESS;
		}
	//End

//Get Hop Limits from IPv6 DNS server
/*	//Length of packets
		if (Length > sizeof(ipv4_hdr) + sizeof(udp_hdr) + sizeof(dns_hdr) + sizeof(dns_qry) + 1)
			Parameter.HopLimitOptions.IPv6HopLimit = ipv4->TTL;
*/
	//ICMP Protocol
		if (Parameter.ICMPOptions.ICMPSpeed > 0 && ipv4->Protocol == IPPROTO_ICMP && 
			Length - sizeof(ipv4_hdr) >= sizeof(icmp_hdr))
		{
			if (ICMPCheck(Buffer, Length, AF_INET))
				Parameter.HopLimitOptions.IPv4TTL = ipv4->TTL;

			delete[] Buffer;
			return EXIT_SUCCESS;
		}
	//TCP Protocol
		else if (ipv4->Protocol == IPPROTO_TCP && Parameter.TCPOptions && 
			Length - sizeof(ipv4_hdr) >= sizeof(tcp_hdr))
		{
			if (TCPCheck((Buffer + sizeof(ipv4_hdr))))
				Parameter.HopLimitOptions.IPv4TTL = ipv4->TTL;

			delete[] Buffer;
			return EXIT_SUCCESS;
		}
//End
		else if (ipv4->Protocol == IPPROTO_UDP && Length - sizeof(ipv4_hdr) >= sizeof(udp_hdr))
		{
			udp_hdr *udp = (udp_hdr *)(Buffer + sizeof(ipv4_hdr));
		//Validate UDP checksum
			if (UDPChecksum(Buffer, Length, AF_INET) != 0)
			{
				delete[] Buffer;
				return EXIT_SUCCESS;
			}
		//End

			if (udp->Src_Port == htons(DNS_Port) && Length - sizeof(ipv4_hdr) - sizeof(udp_hdr) >= sizeof(dns_hdr))
			{
			//Responses of Local DNS
				if (ipv4->Src.s_addr == Parameter.DNSTarget.Local_IPv4Target.s_addr)
				{
					DNSMethod(Buffer + sizeof(ipv4_hdr), Length - sizeof(ipv4_hdr), AF_INET, true);
					
					delete[] Buffer;
					return EXIT_SUCCESS;
				}

			//Domain Test and DNS Options check and get TTL form Domain Test
				bool SignHopLimit = false;
				if (DTDNSOCheck(Buffer + sizeof(ipv4_hdr) + sizeof(udp_hdr), SignHopLimit))
				{
					if (SignHopLimit)
						Parameter.HopLimitOptions.IPv4TTL = ipv4->TTL;
				}
				else {
					delete[] Buffer;
					return EXIT_SUCCESS;
				}

			//Process
				if (ipv4->TTL > Parameter.HopLimitOptions.IPv4TTL - Parameter.HopLimitOptions.HopLimitFluctuation && ipv4->TTL < Parameter.HopLimitOptions.IPv4TTL + Parameter.HopLimitOptions.HopLimitFluctuation) //TTL must not a ramdom number
				{
					DNSMethod(Buffer + sizeof(ipv4_hdr), Length - sizeof(ipv4_hdr), AF_INET, false);

					delete[] Buffer;
					return EXIT_SUCCESS;
				}
			}
		}
	}

	delete[] Buffer;
	return EXIT_SUCCESS;
}

//ICMP header options check(Linux)
inline bool ICMPCheck(const char *Buffer, const size_t Length, const size_t Protocol)
{
	if (Protocol == AF_INET6) //ICMPv6
	{
		icmpv6_hdr *icmp = (icmpv6_hdr *)(Buffer + sizeof(ipv6_hdr));
	//Validate ICMPv6 checksum
		if (ICMPv6Checksum(Buffer, Length) != 0)
			return false;
	//End
		
		if (icmp->Type == ICMPV6_REPLY && icmp->Code == 0 && //ICMPv6 reply
			ntohs(icmp->ID) == Parameter.ICMPOptions.ICMPID && ntohs(icmp->Sequence) == Parameter.ICMPOptions.ICMPSequence) //Validate ICMP packet
				return true;
	}
	else { //ICMP
		icmp_hdr *icmp = (icmp_hdr *)(Buffer + sizeof(ipv4_hdr));
	//Validate ICMP checksum
		if (GetChecksum((uint16_t *)(Buffer + sizeof(ipv4_hdr)), Length - sizeof(ipv4_hdr)) != 0)
			return false;
	//End

		if (icmp->Type == 0 && icmp->Code == 0 && //ICMP reply
			ntohs(icmp->ID) == Parameter.ICMPOptions.ICMPID && ntohs(icmp->Sequence) == Parameter.ICMPOptions.ICMPSequence && icmp->Nonce == Parameter.ICMPOptions.ICMPNonce && //Validate ICMP packet
			Length - sizeof(ipv4_hdr) - sizeof(icmp_hdr) == Parameter.PaddingDataOptions.PaddingDataLength - 1)
		{
	//Validate ICMP additional data
			if (memcmp(Parameter.PaddingDataOptions.PaddingData, (char *)icmp + sizeof(icmp_hdr), Parameter.PaddingDataOptions.PaddingDataLength - 1) == 0)
				return true;
		}
	//End
	}

	return false;
}

//TCP header options check
inline bool TCPCheck(const char *Buffer)
{
	tcp_hdr *tcp = (tcp_hdr *)Buffer;
	if ((tcp->Acknowledge == 0 && tcp->FlagsAll.Flags == 0x004 && tcp->Windows == 0) || //TCP Flags are 0x004(RST) which ACK shoule be 0 and Window size should be 0
		(tcp->HeaderLength > 5 && tcp->FlagsAll.Flags == 0x012)) //TCP option usually should not empty(MSS, SACK_PERM and WS) whose Flags are 0x012(SYN/ACK).
		return true;

	return false;
}

//Domain Test and DNS Options check/DomainTestAndDNSOptionsCheck
inline bool DTDNSOCheck(const char *Buffer, bool &SignHopLimit)
{
	dns_hdr *pdns_hdr = (dns_hdr *)Buffer;

//DNS Options part
	if (pdns_hdr->Questions == 0 || //Not any Answer Record
		(pdns_hdr->Authority == 0 && pdns_hdr->Additional == 0 && pdns_hdr->Answer == 0 && //There are not any Records.
		(Parameter.DNSOptions && (ntohs(pdns_hdr->Flags)) & 0x0400) >> 10 == 1)) //Responses are not authoritative when there not any Authoritative Nameservers Record(s)/Additional Record(s).
			return false;

	if (Parameter.DNSOptions && 
		(ntohs(pdns_hdr->Answer) > 0x0001 || //More than 1 Answer Record(s)
		(pdns_hdr->Answer == 0 && (pdns_hdr->Authority != 0 || pdns_hdr->Additional != 0)))) //Authority Record(s) and/or Additional Record(s)
			SignHopLimit = true;

	if (pdns_hdr->FlagsBits.RCode == 0x0003) //No Such Name
	{
		SignHopLimit = true;

		return true;
	}

//Initialization
	char *Result = nullptr, *Compression = nullptr;
	try {
		Result = new char[PACKET_MAXSIZE/8]();
		Compression = new char[PACKET_MAXSIZE/8]();
	}
	catch (std::bad_alloc)
	{
		PrintError(System_Error, L"Memory allocation failed", 0, 0);

		delete[] Result;
		delete[] Compression;
		return false;
	}
	memset(Result, 0, PACKET_MAXSIZE/8);
	memset(Compression, 0, PACKET_MAXSIZE/8);

//Domain Test part
	size_t Length = DNSQueryToChar(Buffer + sizeof(dns_hdr), Result);
	if (Parameter.DomainTestOptions.DomainTestCheck && 
		strcmp(Result, Parameter.DomainTestOptions.DomainTest) == 0 && pdns_hdr->ID == Parameter.DomainTestOptions.DomainTestID)
	{
		SignHopLimit = true;

		delete[] Result;
		delete[] Compression;
		return true;
	}

//Check DNS Compression
	DNSQueryToChar(Buffer + sizeof(dns_hdr) + Length + sizeof(uint16_t)*2 + 1, Compression);
	if (Parameter.DNSOptions && strcmp(Result, Compression) == 0)
	{
		delete[] Result;
		delete[] Compression;
		return false;
	}

	delete[] Result;
	delete[] Compression;
	return true;
}

//Application Layer(Domain Name System/DNS) process
inline size_t DNSMethod(const char *Recv, const size_t Length, const size_t Protocol, const bool Local)
{
//Initialization
	char *Buffer = nullptr;
	try {
		Buffer = new char[PACKET_MAXSIZE]();
	}
	catch (std::bad_alloc)
	{
		PrintError(System_Error, L"Memory allocation failed", 0, 0);

		return EXIT_FAILURE;
	}
	memset(Buffer, 0, PACKET_MAXSIZE);

	size_t DNSLen = Length - sizeof(udp_hdr);
	if (DNSLen >= sizeof(dns_hdr) + sizeof(dns_qry)) //Responses must have more than one answer.
	{
		memcpy(Buffer, Recv + sizeof(udp_hdr), DNSLen);
	}
	else {
		delete[] Buffer;
		return FALSE;
	}

//DNS Responses which only have 1 Answer RR and no any Authority RRs or Additional RRs need to check.
	dns_hdr *pdns_hdr = (dns_hdr *)Buffer;
	dns_qry *pdns_qry = (dns_qry *)(Buffer + sizeof(dns_hdr) + (strlen(Buffer + sizeof(dns_hdr)) + 1));
	if (!Local && pdns_hdr->Answer == htons(0x0001) && pdns_hdr->Authority == 0 && pdns_hdr->Additional == 0)
	{
		if (pdns_qry->Classes == htons(Class_IN)) //Class IN
		{
		//Record(s) Type in responses check
			if (Parameter.DNSOptions)
			{
				uint16_t *AnswerName = (uint16_t *)(&pdns_qry->Classes + 1), *AnswerType = AnswerName + 1;
				if (*AnswerName == htons(0xC00C) && *AnswerType != pdns_qry->Type) //Types in Queries and Answers are different.
				{
					delete[] Buffer;
					return FALSE;
				}
			}

		//Fake responses check
			if (Parameter.Blacklist)
			{
			//IPv6
				if (pdns_qry->Type == htons(AAAA_Records)) //AAAA Records
				{
/*
				//Packets whose TTLs are 5 minutes are fake responses.
					uint32_t *TTL = (uint32_t *)(RequestBuffer + DNSLen - sizeof(in6_addr) - sizeof(uint16_t) - sizeof(uint32_t));
					if (ntohl(*TTL) == 300 || //Packets whose TTLs are 5 minutes are fake responses.
*/
					if (CheckSpecialAddress(Buffer + DNSLen - sizeof(in6_addr), AF_INET6))
					{
						delete[] Buffer;
						return FALSE;
					}
				}
			//IPv4
				else if (pdns_qry->Type == htons(A_Records)) //A Records
				{
/*
				//Packets whose TTLs are 5 minutes are fake responses.
					uint32_t *TTL = (uint32_t *)(RequestBuffer + DNSLen - sizeof(in_addr) - sizeof(uint16_t) - sizeof(uint32_t));
					if (ntohl(*TTL) == 300 || //Packets whose TTLs are 5 minutes are fake responses.
*/
					if (CheckSpecialAddress(Buffer + DNSLen - sizeof(in_addr), AF_INET))
					{
						delete[] Buffer;
						return FALSE;
					}
				}
			}
		}
	}

//Send

	udp_hdr *udp = (udp_hdr *)Recv;
	PortList.MatchToSend(Buffer, DNSLen, udp->Dst_Port);

	delete[] Buffer;
	return EXIT_SUCCESS;
}

//Match port(s) of response(s) and send response(s) to system socket(s) process
size_t PortTable::MatchToSend(const char *Buffer, const size_t Length, const uint16_t RequestPort)
{
//Match port
	SOCKET_DATA SystemPort = {0};
	size_t Index = 0;

	for (Index = 0;Index < THREAD_MAXNUM*THREAD_PARTNUM;Index++)
	{
		if (RequestPort == SendPort[Index])
		{
			SystemPort = RecvData[Index];

			memset(&RecvData[Index], 0, sizeof(SOCKET_DATA));
			SendPort[Index] = 0;
			break;
		}
	}

//Send to localhost
	if (Index >= THREAD_MAXNUM*THREAD_PARTNUM/2) //TCP area
	{
		char *TCPBuffer = nullptr;
		try {
			TCPBuffer = new char[PACKET_MAXSIZE]();
		}
		catch (std::bad_alloc)
		{
			PrintError(System_Error, L"Memory allocation failed", 0, 0);

			return EXIT_SUCCESS;
		}
		memset(TCPBuffer, 0, PACKET_MAXSIZE);
		uint16_t DataLength = htons((uint16_t)Length);

		memcpy(TCPBuffer, &DataLength, sizeof(uint16_t));
		memcpy(TCPBuffer + sizeof(uint16_t), Buffer, Length);
		send(SystemPort.Socket, TCPBuffer, Length + sizeof(uint16_t), MSG_NOSIGNAL);
		delete[] TCPBuffer;
	}
	else { //UDP
		sendto(SystemPort.Socket, Buffer, Length, MSG_NOSIGNAL, (sockaddr *)&(SystemPort.SockAddr), SystemPort.AddrLen);
	}

//Cleanup socket
	for (Index = 0;Index < THREAD_PARTNUM;Index++)
	{
		if (SystemPort.Socket == Parameter.LocalSocket[Index])
			return EXIT_SUCCESS;
	}

	close(SystemPort.Socket);
	return EXIT_SUCCESS;
}

// This code is part of Pcap_DNSProxy(Windows)
// Pcap_DNSProxy, A local DNS server base on WinPcap and LibPcap.
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

#define PCAP_COMPILE_OPTIMIZE          1U            //Pcap optimization on the resulting code is performed.
#define PCAP_OFFLINE_EOF_ERROR         -2            //Pcap EOF was reached reading from an offline capture.

std::string PcapFilterRules;
std::vector<std::string> PcapRunning;

extern Configuration Parameter;
extern PortTable PortList;
extern std::deque<DNSCacheData> DNSCacheList;
extern std::mutex CaptureLock, PortListLock, DNSCacheListLock;
extern AlternateSwapTable AlternateSwapList;

//Capture initialization
size_t __fastcall CaptureInit(void)
{
//Initialization
	std::shared_ptr<char> ErrBuffer(new char[PCAP_ERRBUF_SIZE]());
	std::shared_ptr<wchar_t> wErrBuffer(new wchar_t[PCAP_ERRBUF_SIZE]());
	FilterRulesInit(PcapFilterRules);
	pcap_if *pThedevs = nullptr, *pDrive = nullptr;
	std::vector<std::string>::iterator CaptureIter;
	std::string DeviceName;

//Capture Monitor
//	size_t ErrorIndex = 0;
	while (true)
	{
/*
	//Retry limit
		if (ErrorIndex == PCAP_FINALLDEVS_RETRY_TIME)
			break;
*/
	//Open all devices
//		FilterRulesInit(PcapFilterRules);
		if (pcap_findalldevs(&pThedevs, ErrBuffer.get()) == RETURN_ERROR)
		{
			if (MultiByteToWideChar(CP_ACP, NULL, ErrBuffer.get(), MBSTOWCS_NULLTERMINATE, wErrBuffer.get(), PCAP_ERRBUF_SIZE) > 0)
			{
				PrintError(LOG_ERROR_WINPCAP, wErrBuffer.get(), NULL, nullptr, NULL);
				memset(ErrBuffer.get(), 0, PCAP_ERRBUF_SIZE);
				memset(wErrBuffer.get(), 0, PCAP_ERRBUF_SIZE * sizeof(wchar_t));
			}
			else {
				PrintError(LOG_ERROR_SYSTEM, L"Multi byte(s) to wide char(s) error", NULL, nullptr, NULL);
			}

//			ErrorIndex++;
			Sleep(PCAP_DEVICESRECHECK_TIME * SECOND_TO_MILLISECOND);
			continue;
		}

	//Permissions check and check available network devices.
		if (pThedevs == nullptr)
		{
			PrintError(LOG_ERROR_WINPCAP, L"Insufficient permissions or not any available network devices", NULL, nullptr, NULL);

//			ErrorIndex++;
			Sleep(PCAP_DEVICESRECHECK_TIME * SECOND_TO_MILLISECOND);
			continue;
		}
		else {
//			ErrorIndex = 0;
		//Mark captures
			if (PcapRunning.empty())
			{
				std::thread CaptureThread(Capture, pThedevs, true);
				CaptureThread.detach();
			}
			else {
				pDrive = pThedevs;
				std::unique_lock<std::mutex> CaptureMutex(CaptureLock);
				CaptureMutex.unlock();

				while (true)
				{
					CaptureMutex.lock();
					for (CaptureIter = PcapRunning.begin();CaptureIter != PcapRunning.end();CaptureIter++)
					{
						DeviceName = pDrive->name;
						if (*CaptureIter == DeviceName)
						{
							DeviceName.clear();
							DeviceName.shrink_to_fit();
							break;
						}

						if (CaptureIter == PcapRunning.end() - 1U)
						{
							std::thread CaptureThread(Capture, pDrive, false);
							CaptureThread.detach();
							continue;
						}
					}
					CaptureMutex.unlock();

					if (pDrive->next == nullptr)
						break;
					else 
						pDrive = pDrive->next;
				}
			}
		}

		Sleep(PCAP_DEVICESRECHECK_TIME * SECOND_TO_MILLISECOND);
		pcap_freealldevs(pThedevs);
	}

	WSACleanup();
	TerminateService();
	return EXIT_SUCCESS;
}

inline void __fastcall FilterRulesInit(std::string &FilterRules)
{
//Initialization
	std::string AddressesString;
	std::shared_ptr<char> Addr(new char[ADDR_STRING_MAXSIZE]());
	FilterRules.clear();

//Minimum supported system of inet_ntop() and inet_pton() is Windows Vista. [Roy Tam]
#ifdef _WIN64
#else //x86
	sockaddr_storage SockAddr = {0};
	DWORD BufferLength = ADDR_STRING_MAXSIZE;
#endif

/*
//IPv6 tunneling protocol(6to4 and ISATAP)
	Parameter.Tunnel_IPv6 = true;
	if (Parameter.Tunnel_IPv6)
		FilterRules.append("(ip proto 41 or src host ");
	else 
*/		
	FilterRules.append("(src host ");

//Set capture filter.
	auto NonSingle = false, Connection = false;
	if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family != NULL && Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family != NULL || 
		Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL || Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL)
			NonSingle = true;

	if (NonSingle)
		AddressesString = ("(");
	//Main(IPv6)
	if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family != NULL)
	{
	#ifdef _WIN64
		inet_ntop(AF_INET6, (PSTR)&Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr, Addr.get(), ADDR_STRING_MAXSIZE);
	#else //x86
		BufferLength = ADDR_STRING_MAXSIZE;
		SockAddr.ss_family = AF_INET6;
		((PSOCKADDR_IN6)&SockAddr)->sin6_addr = Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr;
		WSAAddressToStringA((LPSOCKADDR)&SockAddr, sizeof(sockaddr_in6), NULL, Addr.get(), &BufferLength);
	#endif

		if (!Connection)
			Connection = true;
		else 
			AddressesString.append(" or ");
		AddressesString.append(Addr.get());
		memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
	}
	//Alternate(IPv6)
	if (Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL)
	{
	#ifdef _WIN64
		inet_ntop(AF_INET6, (PSTR)&Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr, Addr.get(), ADDR_STRING_MAXSIZE);
	#else //x86
		BufferLength = ADDR_STRING_MAXSIZE;
		SockAddr.ss_family = AF_INET6;
		((PSOCKADDR_IN6)&SockAddr)->sin6_addr = Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
		WSAAddressToStringA((LPSOCKADDR)&SockAddr, sizeof(sockaddr_in6), NULL, Addr.get(), &BufferLength);
	#endif

		if (!Connection)
			Connection = true;
		else 
			AddressesString.append(" or ");
		AddressesString.append(Addr.get());
		memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
	}
	//Other(Multi/IPv6)
	if (Parameter.DNSTarget.IPv6_Multi != nullptr)
	{
		for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv6_Multi)
		{
		#ifdef _WIN64
			inet_ntop(AF_INET6, (PSTR)&DNSServerDataIter.AddressData.IPv6.sin6_addr, Addr.get(), ADDR_STRING_MAXSIZE);
		#else //x86
			BufferLength = ADDR_STRING_MAXSIZE;
			SockAddr.ss_family = AF_INET6;
			((PSOCKADDR_IN6)&SockAddr)->sin6_addr = DNSServerDataIter.AddressData.IPv6.sin6_addr;
			WSAAddressToStringA((LPSOCKADDR)&SockAddr, sizeof(sockaddr_in6), NULL, Addr.get(), &BufferLength);
		#endif

			if (!Connection)
				Connection = true;
			else 
				AddressesString.append(" or ");
			AddressesString.append(Addr.get());
			memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
		}
	}
	//Main(IPv4)
	if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family != NULL)
	{
	#ifdef _WIN64
		inet_ntop(AF_INET, (PSTR)&Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr, Addr.get(), ADDR_STRING_MAXSIZE);
	#else //x86
		BufferLength = ADDR_STRING_MAXSIZE;
		SockAddr.ss_family = AF_INET;
		((PSOCKADDR_IN)&SockAddr)->sin_addr = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr;
		WSAAddressToStringA((LPSOCKADDR)&SockAddr, sizeof(sockaddr_in), NULL, Addr.get(), &BufferLength);
	#endif

		if (!Connection)
			Connection = true;
		else 
			AddressesString.append(" or ");
		AddressesString.append(Addr.get());
		memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
	}
	//Alternate(IPv4)
	if (Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL)
	{
	#ifdef _WIN64
		inet_ntop(AF_INET, (PSTR)&Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr, Addr.get(), ADDR_STRING_MAXSIZE);
	#else //x86
		BufferLength = ADDR_STRING_MAXSIZE;
		SockAddr.ss_family = AF_INET;
		((PSOCKADDR_IN)&SockAddr)->sin_addr = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
		WSAAddressToStringA((LPSOCKADDR)&SockAddr, sizeof(sockaddr_in), NULL, Addr.get(), &BufferLength);
	#endif

		if (!Connection)
			Connection = true;
		else 
			AddressesString.append(" or ");
		AddressesString.append(Addr.get());
		memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
	}
	//Other(Multi/IPv4)
	if (Parameter.DNSTarget.IPv4_Multi != nullptr)
	{
		for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv4_Multi)
		{
		#ifdef _WIN64
			inet_ntop(AF_INET, (PSTR)&DNSServerDataIter.AddressData.IPv4.sin_addr, Addr.get(), ADDR_STRING_MAXSIZE);
		#else //x86
			BufferLength = ADDR_STRING_MAXSIZE;
			SockAddr.ss_family = AF_INET;
			((PSOCKADDR_IN)&SockAddr)->sin_addr = DNSServerDataIter.AddressData.IPv4.sin_addr;
			WSAAddressToStringA((LPSOCKADDR)&SockAddr, sizeof(sockaddr_in), NULL, Addr.get(), &BufferLength);
		#endif

			if (!Connection)
				Connection = true;
			else 
				AddressesString.append(" or ");
			AddressesString.append(Addr.get());
			memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
		}
	}

/*
//IPv6 tunneling protocol(Teredo)
	if (!Parameter.Tunnel_Teredo.empty())
	{
		for (auto AddressIter:Parameter.Tunnel_Teredo)
		{
		#ifdef _WIN64
			inet_ntop(AF_INET, (PSTR)&AddressIter, Addr.get(), ADDR_STRING_MAXSIZE);
		#else //x86
			BufferLength = ADDR_STRING_MAXSIZE;
			SockAddr.ss_family = AF_INET;
			((PSOCKADDR_IN)&SockAddr)->sin_addr = AddressIter;
			WSAAddressToStringA((LPSOCKADDR)&SockAddr, sizeof(sockaddr_in), NULL, Addr.get(), &BufferLength);
		#endif

			if (!Connection)
				Connection = true;
			else 
				AddressesString.append(" or ");
			AddressesString.append(Addr.get());
			AddressesString.append(" and udp src port 3544");
			memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
		}
	}
*/
//End of address list
	Addr.reset();
	if (NonSingle)
		AddressesString.append(")");
	FilterRules.append(AddressesString);
/*
//IPv6 tunneling protocol(6to4 and ISATAP)
	if (Parameter.Tunnel_IPv6)
	{
		FilterRules.append(") or (pppoes and (ip proto 41 or src host ");
		FilterRules.append(AddressesString);
		FilterRules.append("))");
	}
	else {
*/		
	FilterRules.append(") or (pppoes and src host ");
	FilterRules.append(AddressesString);
	FilterRules.append(")");
//	}

	return;
}

//Capture process
size_t __fastcall Capture(const pcap_if *pDrive, const bool List)
{
//Initialization
	pcap_t *DeviceHandle = nullptr;
	const UCHAR *PacketData = nullptr;
	std::shared_ptr<wchar_t> DeviceName(new wchar_t[PCAP_ERRBUF_SIZE]());
	std::shared_ptr<char> Buffer(new char[PACKET_MAXSIZE * BUFFER_RING_MAXNUM]());

//Open device
	if ((DeviceHandle = pcap_open(pDrive->name, PACKET_MAXSIZE, PCAP_OPENFLAG_NOCAPTURE_LOCAL, PCAP_CAPTURE_TIMEOUT, NULL, Buffer.get())) == nullptr)
	{
		std::shared_ptr<wchar_t> ErrBuffer(new wchar_t[PCAP_ERRBUF_SIZE]());
		if (MultiByteToWideChar(CP_ACP, NULL, Buffer.get(), MBSTOWCS_NULLTERMINATE, ErrBuffer.get(), PCAP_ERRBUF_SIZE) > 0)
			PrintError(LOG_ERROR_WINPCAP, ErrBuffer.get(), NULL, nullptr, NULL);
		else 
			PrintError(LOG_ERROR_SYSTEM, L"Multi byte(s) to wide char(s) error", NULL, nullptr, NULL);

		return EXIT_FAILURE;
	}

//Check device type
	if (MultiByteToWideChar(CP_ACP, NULL, pDrive->name, MBSTOWCS_NULLTERMINATE, DeviceName.get(), PCAP_ERRBUF_SIZE) <= 0)
	{
		PrintError(LOG_ERROR_SYSTEM, L"Multi byte(s) to wide char(s) error", NULL, nullptr, NULL);
		wcsncpy_s(DeviceName.get(), PCAP_ERRBUF_SIZE, L"<Error device name>", lstrlenW(L"<Error device name>"));
	}
	if (pcap_datalink(DeviceHandle) != DLT_EN10MB && pcap_datalink(DeviceHandle) != DLT_PPP_ETHER && pcap_datalink(DeviceHandle) != DLT_EN3MB) //All Ethernet type
	{
		std::shared_ptr<wchar_t> ErrBuffer(new wchar_t[PCAP_ERRBUF_SIZE]());
		wcsncpy_s(ErrBuffer.get(), PCAP_ERRBUF_SIZE, DeviceName.get(), lstrlenW(DeviceName.get()));
		wcsncpy_s(ErrBuffer.get() + lstrlenW(DeviceName.get()), PCAP_ERRBUF_SIZE - lstrlenW(DeviceName.get()), L" is not a Ethernet device", lstrlenW(L" is not a Ethernet device"));
		PrintError(LOG_ERROR_WINPCAP, ErrBuffer.get(), NULL, nullptr, NULL);

		pcap_close(DeviceHandle);
		return EXIT_FAILURE;
	}

//Compile the string into a filter program.
	std::shared_ptr<bpf_program> BPF_Code(new bpf_program());
	if (pcap_compile(DeviceHandle, BPF_Code.get(), PcapFilterRules.c_str(), PCAP_COMPILE_OPTIMIZE, (bpf_u_int32)pDrive->addresses->netmask) == RETURN_ERROR)
	{
		std::shared_ptr<wchar_t> ErrBuffer(new wchar_t[PCAP_ERRBUF_SIZE]());
		if (MultiByteToWideChar(CP_ACP, NULL, pcap_geterr(DeviceHandle), MBSTOWCS_NULLTERMINATE, ErrBuffer.get(), PCAP_ERRBUF_SIZE) > 0)
			PrintError(LOG_ERROR_WINPCAP, ErrBuffer.get(), NULL, nullptr, NULL);
		else 
			PrintError(LOG_ERROR_SYSTEM, L"Multi byte(s) to wide char(s) error", NULL, nullptr, NULL);

//		pcap_freecode(BPF_Code.get());
		pcap_close(DeviceHandle);
		return EXIT_FAILURE;
	}

//Specify a filter program.
	if (pcap_setfilter(DeviceHandle, BPF_Code.get()) == RETURN_ERROR)
	{
		std::shared_ptr<wchar_t> ErrBuffer(new wchar_t[PCAP_ERRBUF_SIZE]());
		if (MultiByteToWideChar(CP_ACP, NULL, pcap_geterr(DeviceHandle), MBSTOWCS_NULLTERMINATE, ErrBuffer.get(), PCAP_ERRBUF_SIZE) > 0)
			PrintError(LOG_ERROR_WINPCAP, ErrBuffer.get(), NULL, nullptr, NULL);
		else 
			PrintError(LOG_ERROR_SYSTEM, L"Multi byte(s) to wide char(s) error", NULL, nullptr, NULL);

		pcap_freecode(BPF_Code.get());
		pcap_close(DeviceHandle);
		return EXIT_FAILURE;
	}

//Start capture(s) with other device(s).
	std::string CaptureDevice(pDrive->name);
	std::unique_lock<std::mutex> CaptureMutex(CaptureLock);
	PcapRunning.push_back(CaptureDevice);
	CaptureMutex.unlock();
	if (List && pDrive->next != nullptr)
	{
		std::thread CaptureThread(Capture, pDrive->next, true);
		CaptureThread.detach();
	}

//Start capture.
	SSIZE_T Result = 0;
	size_t Index = 0, HeaderLength = 0;

	pcap_pkthdr *PacketHeader = nullptr;
	eth_hdr *peth_hdr = nullptr;
	pppoe_hdr *ppppoe_hdr = nullptr;
	while (true)
	{
		Result = pcap_next_ex(DeviceHandle, &PacketHeader, &PacketData);
		switch (Result)
		{
			case RETURN_ERROR: //An error occurred.
			{
				std::shared_ptr<wchar_t> ErrBuffer(new wchar_t[PCAP_ERRBUF_SIZE]());

			//Devices are offline or other errors, wait for retrying.
				wcsncpy_s(ErrBuffer.get(), PCAP_ERRBUF_SIZE, L"An error occurred in ", lstrlenW(L"An error occurred in "));
				wcsncpy_s(ErrBuffer.get() + lstrlenW(L"An error occurred in "), PCAP_ERRBUF_SIZE - lstrlenW(L"An error occurred in "), DeviceName.get(), lstrlenW(DeviceName.get()));
				PrintError(LOG_ERROR_WINPCAP, ErrBuffer.get(), NULL, nullptr, NULL);

				CaptureMutex.lock();
				for (auto CaptureIter = PcapRunning.begin();CaptureIter != PcapRunning.end();CaptureIter++)
				{
					if (*CaptureIter == CaptureDevice)
					{
						PcapRunning.erase(CaptureIter);
						PcapRunning.shrink_to_fit();
						break;
					}
				}
				
				pcap_freecode(BPF_Code.get());
				pcap_close(DeviceHandle);
				return EXIT_FAILURE;
			}break;
			case PCAP_OFFLINE_EOF_ERROR:
			{
				std::shared_ptr<wchar_t> ErrBuffer(new wchar_t[PCAP_ERRBUF_SIZE]());

			//Devices are offline or other errors, wait for retrying.
				wcsncpy_s(ErrBuffer.get(), PCAP_ERRBUF_SIZE, L"EOF was reached reading from an offline capture in ", lstrlenW(L"EOF was reached reading from an offline capture in "));
				wcsncpy_s(ErrBuffer.get() + lstrlenW(L"EOF was reached reading from an offline capture in "), PCAP_ERRBUF_SIZE - lstrlenW(L"EOF was reached reading from an offline capture in "), DeviceName.get(), lstrlenW(DeviceName.get()));
				PrintError(LOG_ERROR_WINPCAP, ErrBuffer.get(), NULL, nullptr, NULL);

				CaptureMutex.lock();
				for (auto CaptureIter = PcapRunning.begin();CaptureIter != PcapRunning.end();CaptureIter++)
				{
					if (*CaptureIter == CaptureDevice)
					{
						PcapRunning.erase(CaptureIter);
						PcapRunning.shrink_to_fit();
						break;
					}
				}
				
				pcap_freecode(BPF_Code.get());
				pcap_close(DeviceHandle);
				return EXIT_FAILURE;
			}break;
			case FALSE: //0, Timeout set with pcap_open_live() has elapsed. In this case pkt_header and pkt_data don't point to a valid packet.
			{
				continue;
			}
			case TRUE: //1, Packet has been read without problems.
			{
				memset(Buffer.get() + PACKET_MAXSIZE * Index, 0, PACKET_MAXSIZE);

				peth_hdr = (eth_hdr *)PacketData;
				HeaderLength = sizeof(eth_hdr);
			//PPPoE(Such as ADSL, a part of organization networks)
				if (peth_hdr->Type == htons(ETHERTYPE_PPPOES) && PacketHeader->caplen > HeaderLength + sizeof(pppoe_hdr))
				{
					ppppoe_hdr = (pppoe_hdr *)(PacketData + HeaderLength);
					HeaderLength += sizeof(pppoe_hdr);
					if (ppppoe_hdr->Protocol == htons(PPPOETYPE_IPV6) && Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family != NULL && PacketHeader->caplen > HeaderLength + sizeof(ipv6_hdr) || //IPv6 over PPPoE
						ppppoe_hdr->Protocol == htons(PPPOETYPE_IPV4) && Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family != NULL && PacketHeader->caplen > HeaderLength + sizeof(ipv4_hdr)) //IPv4 over PPPoE
					{
						memcpy(Buffer.get() + PACKET_MAXSIZE * Index, PacketData + HeaderLength, PacketHeader->caplen - HeaderLength);
						std::thread NetworkLayerThread(NetworkLayer, Buffer.get() + PACKET_MAXSIZE * Index, PacketHeader->caplen - HeaderLength, ntohs(ppppoe_hdr->Protocol));
						NetworkLayerThread.detach();

						Index = (Index + 1U) % BUFFER_RING_MAXNUM;
					}
				}
			//LAN/WLAN/IEEE 802.1X, some Mobile Communications Standard/MCS drives which disguise as a LAN
				else if (peth_hdr->Type == htons(ETHERTYPE_IPV6) && Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family != NULL && PacketHeader->caplen > HeaderLength + sizeof(ipv6_hdr) || //IPv6 over Ethernet
					peth_hdr->Type == htons(ETHERTYPE_IP) && Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family != NULL && PacketHeader->caplen > HeaderLength + sizeof(ipv4_hdr)) //IPv4 over Ethernet
				{
					memcpy(Buffer.get() + PACKET_MAXSIZE * Index, PacketData + HeaderLength, PacketHeader->caplen - HeaderLength);
					std::thread NetworkLayerThread(NetworkLayer, Buffer.get() + PACKET_MAXSIZE * Index, PacketHeader->caplen - HeaderLength, ntohs(peth_hdr->Type));
					NetworkLayerThread.detach();

					Index = (Index + 1U) % BUFFER_RING_MAXNUM;
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

	pcap_freecode(BPF_Code.get());
	pcap_close(DeviceHandle);
	return EXIT_SUCCESS;
}

//Network Layer(Internet Protocol/IP) process
size_t __fastcall NetworkLayer(const PSTR Recv, const size_t Length, const uint16_t Protocol)
{
//Initialization
	std::shared_ptr<char> Buffer(new char[Length]());
	memcpy(Buffer.get(), Recv, Length);
//	size_t ServerAttribute = 0;

	if (Protocol == PPPOETYPE_IPV6 || Protocol == ETHERTYPE_IPV6 /* || Protocol == AF_INET6 */ ) //IPv6
	{
		auto pipv6_hdr = (ipv6_hdr *)Buffer.get();

	//Validate IPv6 header.
		if (ntohs(pipv6_hdr->PayloadLength) > Length - sizeof(ipv6_hdr))
			return EXIT_FAILURE;
/*
	//Mark Alternate address(es).
		if (memcmp(&pipv6_hdr->Src, &Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr, sizeof(in6_addr)) == 0)
			ServerAttribute = ALTERNATE_SERVER;
		else //Main
			ServerAttribute = PREFERRED_SERVER;
*/
	//Get Hop Limits from IPv6 DNS server.
	//ICMPv6 Protocol
		if (Parameter.ICMPOptions.ICMPSpeed > 0 && pipv6_hdr->NextHeader == IPPROTO_ICMPV6 && ntohs(pipv6_hdr->PayloadLength) >= sizeof(icmpv6_hdr))
		{
		//Validate ICMPv6 checksum.
			if (ICMPv6Checksum((PUINT8)Buffer.get(), ntohs(pipv6_hdr->PayloadLength), pipv6_hdr->Dst, pipv6_hdr->Src) != CHECKSUM_SUCCESS)
				return EXIT_FAILURE;

			if (ICMPCheck(Buffer.get() + sizeof(ipv6_hdr), ntohs(pipv6_hdr->PayloadLength), AF_INET6))
			{
			//Mark HopLimit.
				if (memcmp(&pipv6_hdr->Src, &Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr, sizeof(in6_addr)) == 0) //PREFERRED_SERVER
				{
					Parameter.DNSTarget.IPv6.HopLimitData.HopLimit = pipv6_hdr->HopLimit;
				}
				else if (memcmp(&pipv6_hdr->Src, &Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr, sizeof(in6_addr)) == 0) //ALTERNATE_SERVER
				{
					Parameter.DNSTarget.Alternate_IPv6.HopLimitData.HopLimit = pipv6_hdr->HopLimit;
				}
				else { //Other(Multi)
					if (Parameter.DNSTarget.IPv6_Multi != nullptr)
					{
						for (auto DNSServerDataIter = Parameter.DNSTarget.IPv6_Multi->begin();DNSServerDataIter != Parameter.DNSTarget.IPv6_Multi->end();DNSServerDataIter++)
						{
							if (memcmp(&pipv6_hdr->Src, &DNSServerDataIter->AddressData.IPv6.sin6_addr, sizeof(in6_addr)) == 0)
							{
								DNSServerDataIter->HopLimitData.HopLimit = pipv6_hdr->HopLimit;
								break;
							}
						}
					}
				}
			}
		}

	//TCP Protocol
		if (Parameter.TCPDataCheck && pipv6_hdr->NextHeader == IPPROTO_TCP && ntohs(pipv6_hdr->PayloadLength) >= sizeof(tcp_hdr))
		{
		//Validate TCP checksum.
			if (TCPUDPChecksum((PUINT8)Buffer.get(), ntohs(pipv6_hdr->PayloadLength), AF_INET6, IPPROTO_TCP) != CHECKSUM_SUCCESS)
				return EXIT_FAILURE;

			if (TCPCheck(Buffer.get() + sizeof(ipv6_hdr)))
			{
			//Mark HopLimit.
				if (memcmp(&pipv6_hdr->Src, &Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr, sizeof(in6_addr)) == 0) //PREFERRED_SERVER
				{
					Parameter.DNSTarget.IPv6.HopLimitData.HopLimit = pipv6_hdr->HopLimit;
				}
				else if (memcmp(&pipv6_hdr->Src, &Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr, sizeof(in6_addr)) == 0) //ALTERNATE_SERVER
				{
					Parameter.DNSTarget.Alternate_IPv6.HopLimitData.HopLimit = pipv6_hdr->HopLimit;
				}
				else { //Other(Multi)
					if (Parameter.DNSTarget.IPv6_Multi != nullptr)
					{
						for (auto DNSServerDataIter = Parameter.DNSTarget.IPv6_Multi->begin();DNSServerDataIter != Parameter.DNSTarget.IPv6_Multi->end();DNSServerDataIter++)
						{
							if (memcmp(&pipv6_hdr->Src, &DNSServerDataIter->AddressData.IPv6.sin6_addr, sizeof(in6_addr)) == 0)
							{
								DNSServerDataIter->HopLimitData.HopLimit = pipv6_hdr->HopLimit;
								break;
							}
						}
					}
				}
			}

			return EXIT_SUCCESS;
		}

	//UDP Protocol
		if (pipv6_hdr->NextHeader == IPPROTO_UDP && ntohs(pipv6_hdr->PayloadLength) > sizeof(udp_hdr) + sizeof(dns_hdr))
		{
		//Validate UDP checksum.
			if (TCPUDPChecksum((PUINT8)Buffer.get(), ntohs(pipv6_hdr->PayloadLength), AF_INET6, IPPROTO_UDP) != CHECKSUM_SUCCESS)
				return EXIT_FAILURE;

			auto pudp_hdr = (udp_hdr *)(Buffer.get() + sizeof(ipv6_hdr));
			auto PortAndHopLimitSign = false;
			if (Parameter.DNSTarget.IPv6_Multi != nullptr)
			{
				for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv6_Multi)
				{
					if (pudp_hdr->SrcPort == DNSServerDataIter.AddressData.IPv6.sin6_port)
					{
						PortAndHopLimitSign = true;
						break;
					}
				}
			}

		//Port check
			if (pudp_hdr->SrcPort == Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_port || 
				pudp_hdr->SrcPort == Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_port || 
				PortAndHopLimitSign)
			{
			//Domain Test and DNS Options check and get Hop Limit form Domain Test.
				PortAndHopLimitSign = false;
				if (DTDNSDCheck(Buffer.get() + sizeof(ipv6_hdr) + sizeof(udp_hdr), /* ntohs(pipv6_hdr->PayloadLength) - sizeof(udp_hdr), */ PortAndHopLimitSign))
				{
					if (PortAndHopLimitSign)
					{
					//Mark HopLimit.
						if (memcmp(&pipv6_hdr->Src, &Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr, sizeof(in6_addr)) == 0) //PREFERRED_SERVER
						{
							Parameter.DNSTarget.IPv6.HopLimitData.HopLimit = pipv6_hdr->HopLimit;
						}
						else if (memcmp(&pipv6_hdr->Src, &Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr, sizeof(in6_addr)) == 0) //ALTERNATE_SERVER
						{
							Parameter.DNSTarget.Alternate_IPv6.HopLimitData.HopLimit = pipv6_hdr->HopLimit;
						}
						else { //Other(Multi)
							if (Parameter.DNSTarget.IPv6_Multi != nullptr)
							{
								for (auto DNSServerDataIter = Parameter.DNSTarget.IPv6_Multi->begin();DNSServerDataIter != Parameter.DNSTarget.IPv6_Multi->end();DNSServerDataIter++)
								{
									if (memcmp(&pipv6_hdr->Src, &DNSServerDataIter->AddressData.IPv6.sin6_addr, sizeof(in6_addr)) == 0)
									{
										DNSServerDataIter->HopLimitData.HopLimit = pipv6_hdr->HopLimit;
										break;
									}
								}
							}
						}
					}
				}
				else {
					return EXIT_FAILURE;
				}

			//Hop Limit must not a ramdom value.
				if ((SSIZE_T)pipv6_hdr->HopLimit > (SSIZE_T)Parameter.DNSTarget.IPv6.HopLimitData.HopLimit - (SSIZE_T)Parameter.HopLimitFluctuation && (size_t)pipv6_hdr->HopLimit < (size_t)Parameter.DNSTarget.IPv6.HopLimitData.HopLimit + (size_t)Parameter.HopLimitFluctuation)
				{
					DNSMethod(Buffer.get() + sizeof(ipv6_hdr), ntohs(pipv6_hdr->PayloadLength), AF_INET6);
					return EXIT_SUCCESS;
				}
			}
		}
	}
	else { //IPv4
		auto pipv4_hdr = (ipv4_hdr *)Buffer.get();
	//Validate IPv4 header(Part 1).
		if ( /* ntohs(pipv4_hdr->Length) <= sizeof(ipv4_hdr) || */ ntohs(pipv4_hdr->Length) <= pipv4_hdr->IHL * IPv4_IHL_BYTES_TIMES || ntohs(pipv4_hdr->Length) > Length || 
			GetChecksum((PUINT16)Buffer.get(), sizeof(ipv4_hdr)) != CHECKSUM_SUCCESS) //Validate IPv4 header checksum.
				return EXIT_FAILURE;

	//IPv4 options check
		if (Parameter.IPv4DataCheck)
		{
		//TOS and Flags should not be set.
			if (pipv4_hdr->TOS != 0 && pipv4_hdr->Flags != 0)
				return EXIT_FAILURE;

		//No standard header length and header ID check
			if (pipv4_hdr->IHL > IPV4_STANDARDIHL || pipv4_hdr->ID == 0)
			{
			//Mark TTL.
				if (pipv4_hdr->Src.S_un.S_addr == Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr.S_un.S_addr) //PREFERRED_SERVER
				{
					Parameter.DNSTarget.IPv4.HopLimitData.TTL = pipv4_hdr->TTL;
				}
				else if (pipv4_hdr->Src.S_un.S_addr == Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr.S_un.S_addr) //ALTERNATE_SERVER
				{
					Parameter.DNSTarget.Alternate_IPv4.HopLimitData.TTL = pipv4_hdr->TTL;
				}
				else { //Other(Multi)
					if (Parameter.DNSTarget.IPv4_Multi != nullptr)
					{
						for (auto DNSServerDataIter = Parameter.DNSTarget.IPv4_Multi->begin();DNSServerDataIter != Parameter.DNSTarget.IPv4_Multi->end();DNSServerDataIter++)
						{
							if (pipv4_hdr->Src.S_un.S_addr == DNSServerDataIter->AddressData.IPv4.sin_addr.S_un.S_addr)
							{
								DNSServerDataIter->HopLimitData.TTL = pipv4_hdr->TTL;
								break;
							}
						}
					}
				}
			}
		}

/*
	//Mark Alternate address(es).
		if (pipv4_hdr->Src.S_un.S_addr == Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr.S_un.S_addr)
			ServerAttribute = ALTERNATE_SERVER;
		else //Main
			ServerAttribute = PREFERRED_SERVER;
*/

	//Get TTL from IPv4 DNS server.
	//ICMP Protocol
		if (Parameter.ICMPOptions.ICMPSpeed > 0 && pipv4_hdr->Protocol == IPPROTO_ICMP && ntohs(pipv4_hdr->Length) >= pipv4_hdr->IHL * IPv4_IHL_BYTES_TIMES + sizeof(icmp_hdr))
		{
		//Validate ICMP checksum.
			if (GetChecksum((PUINT16)(Buffer.get() + pipv4_hdr->IHL * IPv4_IHL_BYTES_TIMES), ntohs(pipv4_hdr->Length) - pipv4_hdr->IHL * IPv4_IHL_BYTES_TIMES) != CHECKSUM_SUCCESS)
				return EXIT_FAILURE;

			if (ICMPCheck(Buffer.get() + pipv4_hdr->IHL * IPv4_IHL_BYTES_TIMES, ntohs(pipv4_hdr->Length) - pipv4_hdr->IHL * IPv4_IHL_BYTES_TIMES, AF_INET))
			{
			//Mark TTL.
				if (pipv4_hdr->Src.S_un.S_addr == Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr.S_un.S_addr) //PREFERRED_SERVER
				{
					Parameter.DNSTarget.IPv4.HopLimitData.TTL = pipv4_hdr->TTL;
				}
				else if (pipv4_hdr->Src.S_un.S_addr == Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr.S_un.S_addr) //ALTERNATE_SERVER
				{
					Parameter.DNSTarget.Alternate_IPv4.HopLimitData.TTL = pipv4_hdr->TTL;
				}
				else { //Other(Multi)
					if (Parameter.DNSTarget.IPv4_Multi != nullptr)
					{
						for (auto DNSServerDataIter = Parameter.DNSTarget.IPv4_Multi->begin();DNSServerDataIter != Parameter.DNSTarget.IPv4_Multi->end();DNSServerDataIter++)
						{
							if (pipv4_hdr->Src.S_un.S_addr == DNSServerDataIter->AddressData.IPv4.sin_addr.S_un.S_addr)
							{
								DNSServerDataIter->HopLimitData.TTL = pipv4_hdr->TTL;
								break;
							}
						}
					}
				}
			}

			return EXIT_SUCCESS;
		}

	//TCP Protocol
		if (Parameter.TCPDataCheck && pipv4_hdr->Protocol == IPPROTO_TCP && ntohs(pipv4_hdr->Length) >= pipv4_hdr->IHL * IPv4_IHL_BYTES_TIMES + sizeof(tcp_hdr))
		{
		//Validate TCP checksum.
			if (TCPUDPChecksum((PUINT8)Buffer.get(), ntohs(pipv4_hdr->Length) - pipv4_hdr->IHL * IPv4_IHL_BYTES_TIMES, AF_INET, IPPROTO_TCP) != CHECKSUM_SUCCESS)
				return EXIT_FAILURE;

			if (TCPCheck(Buffer.get() + pipv4_hdr->IHL * IPv4_IHL_BYTES_TIMES))
			{
			//Mark TTL.
				if (pipv4_hdr->Src.S_un.S_addr == Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr.S_un.S_addr) //PREFERRED_SERVER
				{
					Parameter.DNSTarget.IPv4.HopLimitData.TTL = pipv4_hdr->TTL;
				}
				else if (pipv4_hdr->Src.S_un.S_addr == Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr.S_un.S_addr) //ALTERNATE_SERVER
				{
					Parameter.DNSTarget.Alternate_IPv4.HopLimitData.TTL = pipv4_hdr->TTL;
				}
				else { //Other(Multi)
					if (Parameter.DNSTarget.IPv4_Multi != nullptr)
					{
						for (auto DNSServerDataIter = Parameter.DNSTarget.IPv4_Multi->begin();DNSServerDataIter != Parameter.DNSTarget.IPv4_Multi->end();DNSServerDataIter++)
						{
							if (pipv4_hdr->Src.S_un.S_addr == DNSServerDataIter->AddressData.IPv4.sin_addr.S_un.S_addr)
							{
								DNSServerDataIter->HopLimitData.TTL = pipv4_hdr->TTL;
								break;
							}
						}
					}
				}
			}

			return EXIT_SUCCESS;
		}

/*
	//IPv6 tunneling protocol(6to4 and ISATAP)
		if (Parameter.Tunnel_IPv6 && pipv4_hdr->Protocol == IPPROTO_IPV6 && ntohs(pipv4_hdr->Length) > pipv4_hdr->IHL * IPv4_IHL_BYTES_TIMES + sizeof(ipv6_hdr))
			return NetworkLayer(Buffer.get() + pipv4_hdr->IHL * IPv4_IHL_BYTES_TIMES, ntohs(pipv4_hdr->Length) - pipv4_hdr->IHL * IPv4_IHL_BYTES_TIMES, AF_INET6);
*/

	//UDP Protocol
		if (pipv4_hdr->Protocol == IPPROTO_UDP && ntohs(pipv4_hdr->Length) > pipv4_hdr->IHL * IPv4_IHL_BYTES_TIMES + sizeof(udp_hdr) + sizeof(dns_hdr))
		{
		//Validate UDP checksum.
			if (TCPUDPChecksum((PUINT8)Buffer.get(), ntohs(pipv4_hdr->Length) - pipv4_hdr->IHL * IPv4_IHL_BYTES_TIMES, AF_INET, IPPROTO_UDP) != CHECKSUM_SUCCESS)
				return EXIT_FAILURE;

			auto pudp_hdr = (udp_hdr *)(Buffer.get() + pipv4_hdr->IHL * IPv4_IHL_BYTES_TIMES);
			auto PortAndHopLimitSign = false;
			if (Parameter.DNSTarget.IPv4_Multi != nullptr)
			{
				for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv4_Multi)
				{
					if (pudp_hdr->SrcPort == DNSServerDataIter.AddressData.IPv4.sin_port)
					{
						PortAndHopLimitSign = true;
						break;
					}
				}
			}

		//Port check
			if ( /* ntohs(pipv4_hdr->Length) > pipv4_hdr->IHL * IPv4_IHL_BYTES_TIMES + sizeof(udp_hdr) + sizeof(dns_hdr) && ( */
				pudp_hdr->SrcPort == Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_port || 
				pudp_hdr->SrcPort == Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_port || 
				PortAndHopLimitSign /* ) */ )
			{
			//Domain Test and DNS Options check and get TTL form Domain Test.
				PortAndHopLimitSign = false;
				if (DTDNSDCheck(Buffer.get() + pipv4_hdr->IHL * IPv4_IHL_BYTES_TIMES + sizeof(udp_hdr), /* ntohs(pipv4_hdr->Length) - pipv4_hdr->IHL * IPv4_IHL_BYTES_TIMES - sizeof(udp_hdr), */ PortAndHopLimitSign))
				{
					if (PortAndHopLimitSign)
					{
					//Mark TTL.
						if (pipv4_hdr->Src.S_un.S_addr == Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr.S_un.S_addr) //PREFERRED_SERVER
						{
							Parameter.DNSTarget.IPv4.HopLimitData.TTL = pipv4_hdr->TTL;
						}
						else if (pipv4_hdr->Src.S_un.S_addr == Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr.S_un.S_addr) //ALTERNATE_SERVER
						{
							Parameter.DNSTarget.Alternate_IPv4.HopLimitData.TTL = pipv4_hdr->TTL;
						}
						else { //Other(Multi)
							if (Parameter.DNSTarget.IPv4_Multi != nullptr)
							{
								for (auto DNSServerDataIter = Parameter.DNSTarget.IPv4_Multi->begin();DNSServerDataIter != Parameter.DNSTarget.IPv4_Multi->end();DNSServerDataIter++)
								{
									if (pipv4_hdr->Src.S_un.S_addr == DNSServerDataIter->AddressData.IPv4.sin_addr.S_un.S_addr)
									{
										DNSServerDataIter->HopLimitData.TTL = pipv4_hdr->TTL;
										break;
									}
								}
							}
						}
					}
				}
				else {
					return EXIT_FAILURE;
				}

			//TTL must not a ramdom value.
				if ((SSIZE_T)pipv4_hdr->TTL > (SSIZE_T)Parameter.DNSTarget.IPv4.HopLimitData.TTL - (SSIZE_T)Parameter.HopLimitFluctuation && (size_t)pipv4_hdr->TTL < (size_t)Parameter.DNSTarget.IPv4.HopLimitData.TTL + (size_t)Parameter.HopLimitFluctuation)
				{
					DNSMethod(Buffer.get() + pipv4_hdr->IHL * IPv4_IHL_BYTES_TIMES, ntohs(pipv4_hdr->Length) - pipv4_hdr->IHL * IPv4_IHL_BYTES_TIMES, AF_INET);
					return EXIT_SUCCESS;
				}
			}
/*
		//IPv6 tunneling protocol(Teredo)
			else if (ntohs(pipv4_hdr->Length) > pipv4_hdr->IHL * IPv4_IHL_BYTES_TIMES + sizeof(udp_hdr) + sizeof(ipv6_hdr) && 
					!Parameter.Tunnel_Teredo.empty() && udp->SrcPort == htons(IPPORT_TEREDO))
			{
				return NetworkLayer(Buffer.get() + pipv4_hdr->IHL * IPv4_IHL_BYTES_TIMES + sizeof(udp_hdr), ntohs(pipv4_hdr->Length) - pipv4_hdr->IHL * IPv4_IHL_BYTES_TIMES - sizeof(udp_hdr), AF_INET6);
			}
*/
		}
	}

	return EXIT_SUCCESS;
}

//ICMP header options check
inline bool __fastcall ICMPCheck(const PSTR Buffer, const size_t Length, const uint16_t Protocol)
{
	if (Protocol == AF_INET6) //ICMPv6
	{
		auto picmpv6_hdr = (icmpv6_hdr *)Buffer;
		if (picmpv6_hdr->Type == ICMPV6_TYPE_REPLY && picmpv6_hdr->Code == ICMPV6_CODE_REPLY && //ICMPv6 Echo reply
			picmpv6_hdr->ID == Parameter.ICMPOptions.ICMPID /* && picmpv6_hdr->Sequence == Parameter.ICMPOptions.ICMPSequence */ ) //Validate ICMP packet.
				return true;
	}
	else { //ICMP
		auto picmp_hdr = (icmp_hdr *)Buffer;
		if (picmp_hdr->Type == ICMP_TYPE_ECHO && picmp_hdr->Code == ICMP_CODE_ECHO && //ICMP Echo reply
		//Validate ICMP packet
			picmp_hdr->ID == Parameter.ICMPOptions.ICMPID && /* picmp_hdr->Sequence == Parameter.ICMPOptions.ICMPSequence && */
			Length == sizeof(icmp_hdr) + Parameter.ICMPOptions.PaddingDataLength - 1U && 
			memcmp(Parameter.ICMPOptions.PaddingData, (PSTR)picmp_hdr + sizeof(icmp_hdr), Parameter.ICMPOptions.PaddingDataLength - 1U) == 0) //Validate ICMP additional data.
				return true;
	}

	return false;
}

//TCP header options check
inline bool __fastcall TCPCheck(const PSTR Buffer)
{
	auto ptcp_hdr = (tcp_hdr *)Buffer;
	if (ptcp_hdr->Acknowledge == 0 && ptcp_hdr->StatusFlags.Flags == TCP_RST_STATUS && ptcp_hdr->Windows == 0 || //TCP Flags are 0x004(RST) which ACK shoule be 0 and Window size should be 0.
		ptcp_hdr->HeaderLength > TCP_STANDARDHL && ptcp_hdr->StatusFlags.Flags == TCP_SYN_ACK_STATUS) //TCP option usually should not empty(MSS, SACK_PERM and WS) whose Flags are 0x012(SYN/ACK).
			return true;

	return false;
}

//Domain Test and DNS Data check/DomainTestAndDNSDataCheck
inline bool __fastcall DTDNSDCheck(const PSTR Buffer, /* const size_t Length, */ bool &SignHopLimit)
{
	auto pdns_hdr = (dns_hdr *)Buffer;

//DNS Options part
	if (pdns_hdr->Questions == 0 || //Not any Answer Record in response(s)
		Parameter.DNSDataCheck && pdns_hdr->Additional == 0 && 
	//Responses are not authoritative when there are not any Authoritative Nameservers Records/Additional Records.
		(pdns_hdr->Authority == 0 && pdns_hdr->Answer == 0 && (ntohs(pdns_hdr->Flags) & 0x0400) >> 10U == 1U || //xxxxx1xxxxxxxxxx & 0000010000000000 >> 10 == 1
	//Additional Records EDNS0 Label check
		Parameter.EDNS0Label))
			return false;
	if (Parameter.DNSDataCheck && pdns_hdr->Answer != htons(U16_NUM_1) || //Less than or more than 1 Answer Record
		pdns_hdr->Authority != 0 || pdns_hdr->Additional != 0) //Authority Record(s) and/or Additional Record(s)
			SignHopLimit = true;

//No Such Name, not standard query response and no error check.
	if ((ntohs(pdns_hdr->Flags) & DNS_RCODE_NO_SUCH_NAME) == DNS_RCODE_NO_SUCH_NAME || //xxxxxxxxxxxxxx11 & 0000000000000011 == 0000000000000011 -> 0x0003
		pdns_hdr->Flags != htons(DNS_SQR_NE))
	{
		SignHopLimit = true;
		return true;
	}

//Domain Test part
	size_t DomainLength = 0;
	if (strlen(Buffer + sizeof(dns_hdr)) < DOMAIN_MAXSIZE)
	{
		std::shared_ptr<char> Result(new char[DOMAIN_MAXSIZE]());
		DomainLength = DNSQueryToChar(Buffer + sizeof(dns_hdr), Result.get());
		if (Parameter.DomainTestOptions.DomainTestData != nullptr && strlen(Parameter.DomainTestOptions.DomainTestData) >= DomainLength && 
			memcmp(Result.get(), Parameter.DomainTestOptions.DomainTestData, DomainLength) == 0 && pdns_hdr->ID == Parameter.DomainTestOptions.DomainTestID)
		{
			SignHopLimit = true;
			return true;
		}

	//Check DNS Compression.
		if (Parameter.DNSDataCheck && DomainLength > 2U &&
			*(PUINT16)(Buffer + sizeof(dns_hdr) + strlen(Buffer + sizeof(dns_hdr)) + sizeof(dns_qry) + 1U) != htons(DNS_QUERY_PTR) && 
			strlen(Buffer + sizeof(dns_hdr) + strlen(Buffer + sizeof(dns_hdr)) + 1U + sizeof(dns_qry)) < DOMAIN_MAXSIZE)
		{
			std::shared_ptr<char> Compression(new char[DOMAIN_MAXSIZE]());

			size_t DomainLengthTemp = DNSQueryToChar(Buffer + sizeof(dns_hdr) + strlen(Buffer + sizeof(dns_hdr)) + 1U + sizeof(dns_qry), Compression.get());
			if (DomainLength == DomainLengthTemp && 
				memcmp(Result.get(), Compression.get(), DomainLengthTemp) == 0)
					return false;
		}
	}
	else {
		return false;
	}

	return true;
}

//Application Layer(Domain Name System/DNS) process
inline size_t __fastcall DNSMethod(const PSTR Recv, const size_t Length, const uint16_t Protocol)
{
//Mark port and responses answer(s) check
	if (Length <= sizeof(udp_hdr) + sizeof(dns_hdr) + 1U + sizeof(dns_qry) || 
		(Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckDNSLastResult(Recv + sizeof(udp_hdr), Length - sizeof(udp_hdr)))
			return EXIT_FAILURE;

	auto pudp_hdr = (udp_hdr *)Recv;
	auto pdns_hdr = (dns_hdr *)(Recv + sizeof(udp_hdr));
	size_t DataLength = Length - sizeof(udp_hdr);
//UDP Truncated check(TC bit in DNS Header has been set)
	if ((ntohs(pdns_hdr->Flags) & 0x0200) >> 9U == 1U && pdns_hdr->Answer == 0) //xxxxxx1xxxxxxxxx & 0000001000000000 >> 9 == 1
	{
		std::shared_ptr<char> RecvBuffer(new char[LARGE_PACKET_MAXSIZE]());
		SOCKET_DATA TargetData = {0};
		if (Protocol == AF_INET6) //IPv6
			TargetData.AddrLen = sizeof(sockaddr_in6);
		else //IPv4
			TargetData.AddrLen = sizeof(sockaddr_in);

	//Retry with TCP
		pdns_hdr->Flags = htons(DNS_STANDARD);
		DataLength = TCPRequest(Recv + sizeof(udp_hdr), DataLength, RecvBuffer.get(), LARGE_PACKET_MAXSIZE, TargetData, false, false);
		if (DataLength > sizeof(dns_hdr) + 1U + sizeof(dns_qry))
		{
			MatchPortToSend(RecvBuffer.get(), DataLength, pudp_hdr->DstPort);
			return EXIT_SUCCESS;
		}
		else {
			DataLength = Length - sizeof(udp_hdr);
		}
	}

//Send
	MatchPortToSend(Recv + sizeof(udp_hdr), DataLength, pudp_hdr->DstPort);
	return EXIT_SUCCESS;
}

//Match port of responses and send responses to system socket(s) process
inline size_t __fastcall MatchPortToSend(const PSTR Buffer, const size_t Length, const uint16_t Port)
{
	SOCKET_DATA RequesterData = {0};
	size_t Index = 0;
	auto MarkIndex = false;

//Match port
	std::unique_lock<std::mutex> PortListMutex(PortListLock);
	for (Index = 0;Index < QUEUE_MAXLEN * QUEUE_PARTNUM;Index++)
	{
		if (MarkIndex)
		{
			Index--;
			break;
		}

		if (PortList.RecvData[Index].AddrLen != 0)
		{
			for (auto SOCKDATA_InnerIter = PortList.SendData[Index].begin();SOCKDATA_InnerIter != PortList.SendData[Index].end();SOCKDATA_InnerIter++)
			{
				if (SOCKDATA_InnerIter->AddrLen == sizeof(sockaddr_in6) && SOCKDATA_InnerIter->SockAddr.ss_family == AF_INET6) //IPv6
				{
					if (Port == ((PSOCKADDR_IN6)&SOCKDATA_InnerIter->SockAddr)->sin6_port)
					{
						AlternateSwapList.PcapAlternateTimeout[Index] = 0;
						RequesterData = PortList.RecvData[Index];
						memset(&PortList.RecvData[Index], 0, sizeof(SOCKET_DATA));
						PortList.SendData[Index].clear();
						PortList.SendData[Index].shrink_to_fit();

						MarkIndex = true;
						break;
					}
				}
				else if (SOCKDATA_InnerIter->AddrLen == sizeof(sockaddr_in) && SOCKDATA_InnerIter->SockAddr.ss_family == AF_INET) //IPv4
				{
					if (Port == ((PSOCKADDR_IN)&SOCKDATA_InnerIter->SockAddr)->sin_port)
					{
						AlternateSwapList.PcapAlternateTimeout[Index] = 0;
						RequesterData = PortList.RecvData[Index];
						memset(&PortList.RecvData[Index], 0, sizeof(SOCKET_DATA));
						PortList.SendData[Index].clear();
						PortList.SendData[Index].shrink_to_fit();

						MarkIndex = true;
						break;
					}
				}
			}
		}
	}
	PortListMutex.unlock();

/* Old version(2014-07-19)
	for (Index = 0;Index < QUEUE_MAXLEN * QUEUE_PARTNUM;Index++)
	{
		if (PortList.SendData[Index].SockAddr.ss_family == sizeof(sockaddr_in6)) //IPv6
		{
			if (Port == ((PSOCKADDR_IN6)&PortList.SendData[Index].SockAddr)->sin6_port)
			{
				AlternateSwapList.PcapAlternateTimeout[Index] = 0;
				SystemPort = PortList.RecvData[Index];
				memset(&PortList.RecvData[Index], 0, sizeof(SOCKET_DATA));
				memset(&PortList.SendData[Index], 0, sizeof(SOCKET_DATA));
				break;
			}
		}
		else { //IPv4
			if (Port == ((PSOCKADDR_IN)&PortList.SendData[Index].SockAddr)->sin_port)
			{
				AlternateSwapList.PcapAlternateTimeout[Index] = 0;
				SystemPort = PortList.RecvData[Index];
				memset(&PortList.RecvData[Index], 0, sizeof(SOCKET_DATA));
				memset(&PortList.SendData[Index], 0, sizeof(SOCKET_DATA));
				break;
			}
		}
	}
*/

//Drop resopnses which not in PortList.
	if (RequesterData.Socket == 0 || RequesterData.AddrLen == 0 || RequesterData.SockAddr.ss_family == 0)
		return EXIT_FAILURE;

//Mark DNS Cache
	if (Parameter.CacheType > 0)
		MarkDomainCache(Buffer, Length);

//Send to localhost
	if (Index >= QUEUE_MAXLEN * QUEUE_PARTNUM / 2U) //TCP area
	{
		std::shared_ptr<char> TCPBuffer(new char[sizeof(uint16_t) + Length]());
		memcpy(TCPBuffer.get(), Buffer, Length);
		if (AddLengthToTCPDNSHeader(TCPBuffer.get(), Length, sizeof(uint16_t) + Length) == EXIT_FAILURE)
			return EXIT_FAILURE;

		send(RequesterData.Socket, TCPBuffer.get(), (int)(Length + sizeof(uint16_t)), NULL);
		closesocket(RequesterData.Socket);
		return EXIT_SUCCESS;
	}
	else { //UDP
	//UDP Truncated check
		if (Length > Parameter.EDNS0PayloadSize)
		{
			std::shared_ptr<char> UDPBuffer(new char[sizeof(dns_hdr) + strlen(Buffer + sizeof(dns_hdr)) + 1U + sizeof(dns_qry) + sizeof(dns_edns0_label)]());
			memcpy(UDPBuffer.get(), Buffer, sizeof(dns_hdr) + strlen(Buffer + sizeof(dns_hdr)) + 1U + sizeof(dns_qry));
			auto pdns_hdr = (dns_hdr *)UDPBuffer.get();
			pdns_hdr->Flags = htons(DNS_SQR_NETC);
			pdns_hdr->Additional = htons(U16_NUM_1);
			auto pdns_edns0_label = (dns_edns0_label *)(UDPBuffer.get() + sizeof(dns_hdr) + strlen(Buffer + sizeof(dns_hdr)) + 1U + sizeof(dns_qry));
			pdns_edns0_label->Type = htons(DNS_EDNS0_RECORDS);
			pdns_edns0_label->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);

			sendto(RequesterData.Socket, UDPBuffer.get(), (int)(sizeof(dns_hdr) + strlen(Buffer + sizeof(dns_hdr)) + 1U + sizeof(dns_qry) + sizeof(dns_edns0_label)), NULL, (PSOCKADDR)&RequesterData.SockAddr, RequesterData.AddrLen);
		}
		else {
			sendto(RequesterData.Socket, Buffer, (int)Length, NULL, (PSOCKADDR)&RequesterData.SockAddr, RequesterData.AddrLen);
		}
	}

//Cleanup socket
	for (auto LocalSocketIter:Parameter.LocalSocket)
	{
		if (LocalSocketIter == RequesterData.Socket)
			return EXIT_SUCCESS;
	}

	closesocket(RequesterData.Socket);
	return EXIT_SUCCESS;
}

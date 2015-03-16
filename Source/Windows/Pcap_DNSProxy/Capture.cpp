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


#include "Capture.h"

//Capture initialization
size_t __fastcall CaptureInit(void)
{
//Initialization
	std::shared_ptr<char> ErrBuffer(new char[PCAP_ERRBUF_SIZE]());
	memset(ErrBuffer.get(), 0, PCAP_ERRBUF_SIZE);
	std::shared_ptr<wchar_t> wErrBuffer(new wchar_t[PCAP_ERRBUF_SIZE]());
	wmemset(wErrBuffer.get(), 0, PCAP_ERRBUF_SIZE);
	FilterRulesInit(PcapFilterRules);
	pcap_if *pThedevs = nullptr, *pDrive = nullptr;
	std::vector<std::string>::iterator CaptureIter;

//Capture Monitor
	std::unique_lock<std::mutex> CaptureMutex(CaptureLock);
	CaptureMutex.unlock();
	for (;;)
	{
	//Open all devices.
		if (pcap_findalldevs(&pThedevs, ErrBuffer.get()) == PCAP_ERROR)
		{
			if (MultiByteToWideChar(CP_ACP, 0, ErrBuffer.get(), MBSTOWCS_NULLTERMINATE, wErrBuffer.get(), PCAP_ERRBUF_SIZE) > 0)
			{
				PrintError(LOG_ERROR_WINPCAP, wErrBuffer.get(), 0, nullptr, 0);
				memset(ErrBuffer.get(), 0, PCAP_ERRBUF_SIZE);
				wmemset(wErrBuffer.get(), 0, PCAP_ERRBUF_SIZE);
			}
			else {
				PrintError(LOG_ERROR_SYSTEM, L"Multi bytes to wide chars error", 0, nullptr, 0);
			}

			Sleep(PCAP_DEVICESRECHECK_TIME * SECOND_TO_MILLISECOND);
			continue;
		}

	//Permissions check and check available network devices.
		if (pThedevs == nullptr)
		{
			PrintError(LOG_ERROR_WINPCAP, L"Insufficient permissions or no any available network devices", 0, nullptr, 0);

			Sleep(PCAP_DEVICESRECHECK_TIME * SECOND_TO_MILLISECOND);
			continue;
		}
		else {
		//Mark captures.
			if (PcapRunning.empty())
			{
				std::thread CaptureThread(Capture, pThedevs, true);
				CaptureThread.detach();
			}
			else {
				pDrive = pThedevs;

			//Scan all devices.
				while (pDrive != nullptr)
				{
//					Sleep(LOOP_INTERVAL_TIME);
					CaptureMutex.lock();
					for (CaptureIter = PcapRunning.begin();CaptureIter != PcapRunning.end();CaptureIter++)
					{
						if (CaptureIter == PcapRunning.end() - 1U)
						{
							std::thread CaptureThread(Capture, pDrive, false);
							CaptureThread.detach();

							break;
						}
						else if (*CaptureIter == pDrive->name)
						{
							break;
						}
					}
					CaptureMutex.unlock();
					pDrive = pDrive->next;
				}
			}
		}

		Sleep(PCAP_DEVICESRECHECK_TIME * SECOND_TO_MILLISECOND);
		pcap_freealldevs(pThedevs);
	}

	WSACleanup();
	PrintError(LOG_ERROR_SYSTEM, L"Capture module Monitor terminated", 0, nullptr, 0);

	exit(EXIT_FAILURE);
	return EXIT_SUCCESS;
}

void __fastcall FilterRulesInit(std::string &FilterRules)
{
//Initialization
	std::string AddressesString;
	std::shared_ptr<char> Addr(new char[ADDR_STRING_MAXSIZE]());
	memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
	FilterRules.clear();

//Minimum supported system of inet_ntop() and inet_pton() is Windows Vista(Windows XP with SP3 support). [Roy Tam]
#ifdef _WIN64
#else //x86
	std::shared_ptr<sockaddr_storage> SockAddr(new sockaddr_storage());
	memset(SockAddr.get(), 0, sizeof(sockaddr_storage));
	DWORD BufferLength = ADDR_STRING_MAXSIZE;
#endif

	FilterRules.append("(src host ");

//Set capture filter., nullptr, Addr.get(), &BufferLength);
	auto NonSingle = false, IsConnection = false;
	if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0 && Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0 || 
		Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 || Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0)
			NonSingle = true;

	if (NonSingle)
		AddressesString = ("(");
	//Main(IPv6)
	if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0)
	{
	#ifdef _WIN64
		inet_ntop(AF_INET6, (PSTR)&Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr, Addr.get(), ADDR_STRING_MAXSIZE);
	#else //x86
		if (Parameter.Inet_Ntop_PTR != nullptr)
		{
			(*Parameter.Inet_Ntop_PTR)(AF_INET6, (PSTR)&Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr, Addr.get(), ADDR_STRING_MAXSIZE);
		}
		else {
			BufferLength = ADDR_STRING_MAXSIZE;
			SockAddr->ss_family = AF_INET6;
			((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr;
			WSAAddressToStringA((LPSOCKADDR)SockAddr.get(), sizeof(sockaddr_in6), nullptr, Addr.get(), &BufferLength);
		}
	#endif

		if (!IsConnection)
			IsConnection = true;
		else 
			AddressesString.append(" or ");
		AddressesString.append(Addr.get());
		memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
	}
	//Alternate(IPv6)
	if (Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0)
	{
	#ifdef _WIN64
		inet_ntop(AF_INET6, (PSTR)&Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr, Addr.get(), ADDR_STRING_MAXSIZE);
	#else //x86
		if (Parameter.Inet_Ntop_PTR != nullptr)
		{
			(*Parameter.Inet_Ntop_PTR)(AF_INET6, (PSTR)&Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr, Addr.get(), ADDR_STRING_MAXSIZE);
		}
		else {
			BufferLength = ADDR_STRING_MAXSIZE;
			SockAddr->ss_family = AF_INET6;
			((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
			WSAAddressToStringA((LPSOCKADDR)SockAddr.get(), sizeof(sockaddr_in6), nullptr, Addr.get(), &BufferLength);
		}
	#endif

		if (!IsConnection)
			IsConnection = true;
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
			if (Parameter.Inet_Ntop_PTR != nullptr)
			{
				(*Parameter.Inet_Ntop_PTR)(AF_INET6, (PSTR)&DNSServerDataIter.AddressData.IPv6.sin6_addr, Addr.get(), ADDR_STRING_MAXSIZE);
			}
			else {
				BufferLength = ADDR_STRING_MAXSIZE;
				SockAddr->ss_family = AF_INET6;
				((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = DNSServerDataIter.AddressData.IPv6.sin6_addr;
				WSAAddressToStringA((LPSOCKADDR)SockAddr.get(), sizeof(sockaddr_in6), nullptr, Addr.get(), &BufferLength);
			}
		#endif

			if (!IsConnection)
				IsConnection = true;
			else 
				AddressesString.append(" or ");
			AddressesString.append(Addr.get());
			memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
		}
	}
	//Main(IPv4)
	if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0)
	{
	#ifdef _WIN64
		inet_ntop(AF_INET, (PSTR)&Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr, Addr.get(), ADDR_STRING_MAXSIZE);
	#else //x86
		if (Parameter.Inet_Ntop_PTR != nullptr)
		{
			(*Parameter.Inet_Ntop_PTR)(AF_INET, (PSTR)&Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr, Addr.get(), ADDR_STRING_MAXSIZE);
		}
		else {
			BufferLength = ADDR_STRING_MAXSIZE;
			SockAddr->ss_family = AF_INET;
			((PSOCKADDR_IN)SockAddr.get())->sin_addr = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr;
			WSAAddressToStringA((LPSOCKADDR)SockAddr.get(), sizeof(sockaddr_in), nullptr, Addr.get(), &BufferLength);
		}
	#endif

		if (!IsConnection)
			IsConnection = true;
		else 
			AddressesString.append(" or ");
		AddressesString.append(Addr.get());
		memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
	}
	//Alternate(IPv4)
	if (Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0)
	{
	#ifdef _WIN64
		inet_ntop(AF_INET, (PSTR)&Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr, Addr.get(), ADDR_STRING_MAXSIZE);
	#else //x86
		if (Parameter.Inet_Ntop_PTR != nullptr)
		{
			(*Parameter.Inet_Ntop_PTR)(AF_INET, (PSTR)&Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr, Addr.get(), ADDR_STRING_MAXSIZE);
		}
		else {
			BufferLength = ADDR_STRING_MAXSIZE;
			SockAddr->ss_family = AF_INET;
			((PSOCKADDR_IN)SockAddr.get())->sin_addr = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
			WSAAddressToStringA((LPSOCKADDR)SockAddr.get(), sizeof(sockaddr_in), nullptr, Addr.get(), &BufferLength);
		}
	#endif

		if (!IsConnection)
			IsConnection = true;
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
			if (Parameter.Inet_Ntop_PTR != nullptr)
			{
				(*Parameter.Inet_Ntop_PTR)(AF_INET, (PSTR)&DNSServerDataIter.AddressData.IPv4.sin_addr, Addr.get(), ADDR_STRING_MAXSIZE);
			}
			else {
				BufferLength = ADDR_STRING_MAXSIZE;
				SockAddr->ss_family = AF_INET;
				((PSOCKADDR_IN)SockAddr.get())->sin_addr = DNSServerDataIter.AddressData.IPv4.sin_addr;
				WSAAddressToStringA((LPSOCKADDR)SockAddr.get(), sizeof(sockaddr_in), nullptr, Addr.get(), &BufferLength);
			}
		#endif

			if (!IsConnection)
				IsConnection = true;
			else 
				AddressesString.append(" or ");
			AddressesString.append(Addr.get());
			memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
		}
	}

//End of address list
	Addr.reset();
	if (NonSingle)
		AddressesString.append(")");
	FilterRules.append(AddressesString);
	FilterRules.append(") or (pppoes and src host ");
	FilterRules.append(AddressesString);
	FilterRules.append(")");

	return;
}

//Capture process
size_t __fastcall Capture(const pcap_if *pDrive, const bool IsCaptureList)
{
//Devices check
	if (pDrive->name == nullptr || pDrive->addresses == nullptr)
	{
		if (IsCaptureList && pDrive->next != nullptr)
		{
			std::thread CaptureThread(Capture, pDrive->next, true);
			CaptureThread.detach();
		}

		return EXIT_SUCCESS;
	}
	
//Initialization
	pcap_t *DeviceHandle = nullptr;
	std::shared_ptr<wchar_t> DeviceName(new wchar_t[PCAP_ERRBUF_SIZE]());
	memset(DeviceName.get(), 0, PCAP_ERRBUF_SIZE);
	std::shared_ptr<char> Buffer(new char[ORIGINAL_PACKET_MAXSIZE * BUFFER_RING_MAXNUM]());
	memset(Buffer.get(), 0, ORIGINAL_PACKET_MAXSIZE * BUFFER_RING_MAXNUM);

//Open device
	if ((DeviceHandle = pcap_open(pDrive->name, ORIGINAL_PACKET_MAXSIZE, PCAP_OPENFLAG_NOCAPTURE_LOCAL, PCAP_CAPTURE_TIMEOUT, nullptr, Buffer.get())) == nullptr)
	{
		std::shared_ptr<wchar_t> ErrBuffer(new wchar_t[PCAP_ERRBUF_SIZE]());
		wmemset(ErrBuffer.get(), 0, PCAP_ERRBUF_SIZE);
		if (MultiByteToWideChar(CP_ACP, 0, Buffer.get(), MBSTOWCS_NULLTERMINATE, ErrBuffer.get(), PCAP_ERRBUF_SIZE) > 0)
			PrintError(LOG_ERROR_WINPCAP, ErrBuffer.get(), 0, nullptr, 0);
		else 
			PrintError(LOG_ERROR_SYSTEM, L"Multi bytes to wide chars error", 0, nullptr, 0);

		return EXIT_FAILURE;
	}

//Check device type
	if (MultiByteToWideChar(CP_ACP, 0, pDrive->name, MBSTOWCS_NULLTERMINATE, DeviceName.get(), PCAP_ERRBUF_SIZE) <= 0)
	{
		PrintError(LOG_ERROR_SYSTEM, L"Multi bytes to wide chars error", 0, nullptr, 0);
//		wcsncpy(DeviceName.get(), L"<Error device name>", wcslen(L"<Error device name>"));
		wcsncpy_s(DeviceName.get(), PCAP_ERRBUF_SIZE, L"<Error device name>", wcslen(L"<Error device name>"));
	}
	if (pcap_datalink(DeviceHandle) != DLT_EN10MB && pcap_datalink(DeviceHandle) != DLT_PPP_ETHER && pcap_datalink(DeviceHandle) != DLT_EN3MB) //All Ethernet type
	{
		std::shared_ptr<wchar_t> ErrBuffer(new wchar_t[PCAP_ERRBUF_SIZE]());
		wmemset(ErrBuffer.get(), 0, PCAP_ERRBUF_SIZE);
//		wcsncpy(ErrBuffer.get(), DeviceName.get(), wcsnlen_s(DeviceName.get(), PCAP_ERRBUF_SIZE));
//		wcsncpy(ErrBuffer.get() + wcsnlen_s(DeviceName.get(), PCAP_ERRBUF_SIZE), L" is not a Ethernet device", wcslen(L" is not a Ethernet device"));
		wcsncpy_s(ErrBuffer.get(), PCAP_ERRBUF_SIZE, DeviceName.get(), wcsnlen_s(DeviceName.get(), PCAP_ERRBUF_SIZE));
		wcsncpy_s(ErrBuffer.get() + wcsnlen_s(DeviceName.get(), PCAP_ERRBUF_SIZE), PCAP_ERRBUF_SIZE - wcsnlen_s(DeviceName.get(), PCAP_ERRBUF_SIZE), L" is not a Ethernet device", wcslen(L" is not a Ethernet device"));
		PrintError(LOG_ERROR_WINPCAP, ErrBuffer.get(), 0, nullptr, 0);

		pcap_close(DeviceHandle);
		return EXIT_FAILURE;
	}

//Compile the string into a filter program.
	std::shared_ptr<bpf_program> BPF_Code(new bpf_program());
	memset(BPF_Code.get(), 0, sizeof(bpf_program));
	if (pcap_compile(DeviceHandle, BPF_Code.get(), PcapFilterRules.c_str(), PCAP_COMPILE_OPTIMIZE, (bpf_u_int32)pDrive->addresses->netmask) == PCAP_ERROR)
	{
		std::shared_ptr<wchar_t> ErrBuffer(new wchar_t[PCAP_ERRBUF_SIZE]());
		wmemset(ErrBuffer.get(), 0, PCAP_ERRBUF_SIZE);
		if (MultiByteToWideChar(CP_ACP, 0, pcap_geterr(DeviceHandle), MBSTOWCS_NULLTERMINATE, ErrBuffer.get(), PCAP_ERRBUF_SIZE) > 0)
			PrintError(LOG_ERROR_WINPCAP, ErrBuffer.get(), 0, nullptr, 0);
		else 
			PrintError(LOG_ERROR_SYSTEM, L"Multi bytes to wide chars error", 0, nullptr, 0);

		pcap_close(DeviceHandle);
		return EXIT_FAILURE;
	}

//Specify a filter program.
	if (pcap_setfilter(DeviceHandle, BPF_Code.get()) == PCAP_ERROR)
	{
		std::shared_ptr<wchar_t> ErrBuffer(new wchar_t[PCAP_ERRBUF_SIZE]());
		wmemset(ErrBuffer.get(), 0, PCAP_ERRBUF_SIZE);
		if (MultiByteToWideChar(CP_ACP, 0, pcap_geterr(DeviceHandle), MBSTOWCS_NULLTERMINATE, ErrBuffer.get(), PCAP_ERRBUF_SIZE) > 0)
			PrintError(LOG_ERROR_WINPCAP, ErrBuffer.get(), 0, nullptr, 0);
		else 
			PrintError(LOG_ERROR_SYSTEM, L"Multi bytes to wide chars error", 0, nullptr, 0);

		pcap_freecode(BPF_Code.get());
		pcap_close(DeviceHandle);
		return EXIT_FAILURE;
	}

//Start captures with other devices.
	std::string CaptureDevice(pDrive->name);
	PcapRunning.push_back(CaptureDevice);
	if (IsCaptureList && pDrive->next != nullptr)
	{
		std::thread CaptureThread(Capture, pDrive->next, true);
		CaptureThread.detach();
	}

//Start capture.
	SSIZE_T Result = 0;
	size_t Index = 0, HeaderLength = 0;
	const UCHAR *PacketData = nullptr;
	pcap_pkthdr *PacketHeader = nullptr;
	peth_hdr Ethernet_Header = nullptr;
	ppppoe_hdr PPPoE_Header = nullptr;
	for (;;)
	{
		Result = pcap_next_ex(DeviceHandle, &PacketHeader, &PacketData);
		switch (Result)
		{
			case PCAP_ERROR: //An error occurred.
			{
				std::shared_ptr<wchar_t> ErrBuffer(new wchar_t[PCAP_ERRBUF_SIZE]());
				wmemset(ErrBuffer.get(), 0, PCAP_ERRBUF_SIZE);

			//Devices are offline or other errors, wait for retrying.
//				wcsncpy(ErrBuffer.get(), L"An error occurred in ", wcslen(L"An error occurred in "));
//				wcsncpy(ErrBuffer.get() + wcslen(L"An error occurred in "), DeviceName.get(), wcsnlen_s(DeviceName.get(), PCAP_ERRBUF_SIZE));
				wcsncpy_s(ErrBuffer.get(), PCAP_ERRBUF_SIZE, L"An error occurred in ", wcslen(L"An error occurred in "));
				wcsncpy_s(ErrBuffer.get() + wcslen(L"An error occurred in "), PCAP_ERRBUF_SIZE - wcslen(L"An error occurred in "), DeviceName.get(), wcsnlen_s(DeviceName.get(), PCAP_ERRBUF_SIZE));
				PrintError(LOG_ERROR_WINPCAP, ErrBuffer.get(), 0, nullptr, 0);

			//Delete from devices list.
				std::unique_lock<std::mutex> CaptureMutex(CaptureLock);
				for (auto CaptureIter = PcapRunning.begin();CaptureIter != PcapRunning.end();)
				{
					if (*CaptureIter == CaptureDevice)
					{
						CaptureIter = PcapRunning.erase(CaptureIter);
						if (CaptureIter == PcapRunning.end())
							break;
					}
					else {
						CaptureIter++;
					}
				}
				PcapRunning.shrink_to_fit();
				CaptureMutex.unlock();
				
				pcap_freecode(BPF_Code.get());
				pcap_close(DeviceHandle);
				return EXIT_FAILURE;
			}break;
			case PCAP_OFFLINE_EOF_ERROR:
			{
				std::shared_ptr<wchar_t> ErrBuffer(new wchar_t[PCAP_ERRBUF_SIZE]());
				wmemset(ErrBuffer.get(), 0, PCAP_ERRBUF_SIZE);

			//Devices are offline or other errors, wait for retrying.
//				wcsncpy(ErrBuffer.get(), L"EOF was reached reading from an offline capture in ", wcslen(L"EOF was reached reading from an offline capture in "));
//				wcsncpy(ErrBuffer.get() + wcslen(L"EOF was reached reading from an offline capture in "), DeviceName.get(), wcsnlen_s(DeviceName.get(), PCAP_ERRBUF_SIZE));
				wcsncpy_s(ErrBuffer.get(), PCAP_ERRBUF_SIZE, L"EOF was reached reading from an offline capture in ", wcslen(L"EOF was reached reading from an offline capture in "));
				wcsncpy_s(ErrBuffer.get() + wcslen(L"EOF was reached reading from an offline capture in "), PCAP_ERRBUF_SIZE - wcslen(L"EOF was reached reading from an offline capture in "), DeviceName.get(), wcsnlen_s(DeviceName.get(), PCAP_ERRBUF_SIZE));
				PrintError(LOG_ERROR_WINPCAP, ErrBuffer.get(), 0, nullptr, 0);

			//Delete from devices list.
				std::unique_lock<std::mutex> CaptureMutex(CaptureLock);
				for (auto CaptureIter = PcapRunning.begin();CaptureIter != PcapRunning.end();)
				{
					if (*CaptureIter == CaptureDevice)
					{
						CaptureIter = PcapRunning.erase(CaptureIter);
						if (CaptureIter == PcapRunning.end())
							break;
					}
					else {
						CaptureIter++;
					}
				}
				PcapRunning.shrink_to_fit();
				CaptureMutex.unlock();
				
				pcap_freecode(BPF_Code.get());
				pcap_close(DeviceHandle);
				return EXIT_FAILURE;
			}break;
			case FALSE: //0, Timeout set with pcap_open_live() has elapsed. In this case pkt_header and pkt_data don't point to a valid packet.
			{
				Sleep(LOOP_INTERVAL_TIME);
				continue;
			}
			case TRUE: //1, Packet has been read without problems.
			{
				memset(Buffer.get() + ORIGINAL_PACKET_MAXSIZE * Index, 0, ORIGINAL_PACKET_MAXSIZE);

				Ethernet_Header = (peth_hdr)PacketData;
				HeaderLength = sizeof(eth_hdr);

			//PPPoE(Such as ADSL, a part of organization networks)
				if (Ethernet_Header->Type == htons(ETHERTYPE_PPPOES) && PacketHeader->caplen > HeaderLength + sizeof(pppoe_hdr))
				{
					PPPoE_Header = (pppoe_hdr *)(PacketData + HeaderLength);
					HeaderLength += sizeof(pppoe_hdr);
					if (PPPoE_Header->Protocol == htons(PPPOETYPE_IPV6) && Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0 && PacketHeader->caplen > HeaderLength + sizeof(ipv6_hdr) || //IPv6 over PPPoE
						PPPoE_Header->Protocol == htons(PPPOETYPE_IPV4) && Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0 && PacketHeader->caplen > HeaderLength + sizeof(ipv4_hdr)) //IPv4 over PPPoE
					{
//						memcpy(Buffer.get() + ORIGINAL_PACKET_MAXSIZE * Index, PacketData + HeaderLength, PacketHeader->caplen - HeaderLength);
						memcpy_s(Buffer.get() + ORIGINAL_PACKET_MAXSIZE * Index, ORIGINAL_PACKET_MAXSIZE, PacketData + HeaderLength, PacketHeader->caplen - HeaderLength);
						std::thread NetworkLayerThread(NetworkLayer, Buffer.get() + ORIGINAL_PACKET_MAXSIZE * Index, PacketHeader->caplen - HeaderLength, ntohs(PPPoE_Header->Protocol));
						NetworkLayerThread.detach();

						Index = (Index + 1U) % BUFFER_RING_MAXNUM;
					}
				}

			//LAN/WLAN/IEEE 802.1X, some Mobile Communications Standard/MCS drives which disguise as a LAN
				else if (Ethernet_Header->Type == htons(ETHERTYPE_IPV6) && Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0 && PacketHeader->caplen > HeaderLength + sizeof(ipv6_hdr) || //IPv6 over Ethernet
					Ethernet_Header->Type == htons(ETHERTYPE_IP) && Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0 && PacketHeader->caplen > HeaderLength + sizeof(ipv4_hdr)) //IPv4 over Ethernet
				{
//					memcpy(Buffer.get() + ORIGINAL_PACKET_MAXSIZE * Index, PacketData + HeaderLength, PacketHeader->caplen - HeaderLength);
					memcpy_s(Buffer.get() + ORIGINAL_PACKET_MAXSIZE * Index, ORIGINAL_PACKET_MAXSIZE, PacketData + HeaderLength, PacketHeader->caplen - HeaderLength);
					std::thread NetworkLayerThread(NetworkLayer, Buffer.get() + ORIGINAL_PACKET_MAXSIZE * Index, PacketHeader->caplen - HeaderLength, ntohs(Ethernet_Header->Type));
					NetworkLayerThread.detach();

					Index = (Index + 1U) % BUFFER_RING_MAXNUM;
				}
				else {
					Sleep(LOOP_INTERVAL_TIME);
					continue;
				}
			}break;
			default: {
				Sleep(LOOP_INTERVAL_TIME);
				continue;
			}
		}
	}

	pcap_freecode(BPF_Code.get());
	pcap_close(DeviceHandle);
	PrintError(LOG_ERROR_SYSTEM, L"Capture module Monitor terminated", 0, nullptr, 0);
	return EXIT_SUCCESS;
}

//Network Layer(Internet Protocol/IP) process
size_t __fastcall NetworkLayer(const PSTR Recv, const size_t Length, const uint16_t Protocol)
{
//Initialization
	std::shared_ptr<char> Buffer(new char[Length]());
	memset(Buffer.get(), 0, Length);
//	memcpy(Buffer.get(), Recv, Length);
	memcpy_s(Buffer.get(), Length, Recv, Length);

	if (Protocol == PPPOETYPE_IPV6 || Protocol == ETHERTYPE_IPV6 /* || Protocol == AF_INET6 */ ) //IPv6
	{
		auto IPv6_Header = (pipv6_hdr)Buffer.get();

	//Validate IPv6 header.
		if (ntohs(IPv6_Header->PayloadLength) > Length - sizeof(ipv6_hdr))
			return EXIT_FAILURE;

	//Mark source of packet.
		PDNS_SERVER_DATA PacketSource = nullptr;
		if (memcmp(&IPv6_Header->Src, &Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr, sizeof(in6_addr)) == 0)
		{
			PacketSource = &Parameter.DNSTarget.IPv6;
		}
		else if (memcmp(&IPv6_Header->Src, &Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr, sizeof(in6_addr)) == 0)
		{
			PacketSource = &Parameter.DNSTarget.Alternate_IPv6;
		}
		else if (Parameter.DNSTarget.IPv6_Multi != nullptr)
		{
			for (size_t Index = 0;Index < Parameter.DNSTarget.IPv6_Multi->size();Index++)
			{
				if (memcmp(&IPv6_Header->Src, &Parameter.DNSTarget.IPv6_Multi->at(Index).AddressData.IPv6.sin6_addr, sizeof(in6_addr)) == 0)
				{
					PacketSource = &Parameter.DNSTarget.IPv6_Multi->at(Index);
					break;
				}
			}

			if (PacketSource == nullptr)
				return EXIT_FAILURE;
		}
		else {
			return EXIT_FAILURE;
		}

	//Get Hop Limits from IPv6 DNS server.
	//ICMPv6 Protocol
		if (Parameter.ICMPSpeed > 0 && IPv6_Header->NextHeader == IPPROTO_ICMPV6 && ntohs(IPv6_Header->PayloadLength) >= sizeof(icmpv6_hdr))
		{
		//Validate ICMPv6 checksum.
			if (ICMPv6Checksum((PUINT8)Buffer.get(), ntohs(IPv6_Header->PayloadLength), IPv6_Header->Dst, IPv6_Header->Src) != CHECKSUM_SUCCESS)
				return EXIT_FAILURE;

			if (ICMPCheck(Buffer.get() + sizeof(ipv6_hdr), ntohs(IPv6_Header->PayloadLength), AF_INET6))
				PacketSource->HopLimitData.HopLimit = IPv6_Header->HopLimit;;

			Parameter.TunnelAvailable_IPv6 = false;
			return EXIT_SUCCESS;
		}

	//TCP Protocol
		if (Parameter.TCPDataCheck && IPv6_Header->NextHeader == IPPROTO_TCP && ntohs(IPv6_Header->PayloadLength) >= sizeof(tcp_hdr))
		{
		//Validate TCP checksum.
			if (TCPUDPChecksum((PUINT8)Buffer.get(), ntohs(IPv6_Header->PayloadLength), AF_INET6, IPPROTO_TCP) != CHECKSUM_SUCCESS)
				return EXIT_FAILURE;

			if (TCPCheck(Buffer.get() + sizeof(ipv6_hdr)))
				PacketSource->HopLimitData.HopLimit = IPv6_Header->HopLimit;

			Parameter.TunnelAvailable_IPv6 = false;
			return EXIT_SUCCESS;
		}

	//UDP Protocol
		if (IPv6_Header->NextHeader == IPPROTO_UDP && /* ntohs(IPv6_Header->PayloadLength) > sizeof(udp_hdr) + sizeof(dns_hdr) */ ntohs(IPv6_Header->PayloadLength) >= sizeof(udp_hdr) + DNS_PACKET_MINSIZE)
		{
		//Validate UDP checksum.
			if (TCPUDPChecksum((PUINT8)Buffer.get(), ntohs(IPv6_Header->PayloadLength), AF_INET6, IPPROTO_UDP) != CHECKSUM_SUCCESS)
				return EXIT_FAILURE;

			auto UDP_Header = (pudp_hdr)(Buffer.get() + sizeof(ipv6_hdr));
		//Port check
			if (UDP_Header->SrcPort == PacketSource->AddressData.IPv6.sin6_port)
			{
			//Domain Test and DNS Options check and get Hop Limit form Domain Test.
				auto IsMarkPortHopLimit = false;
				if (CheckResponseData(Buffer.get() + sizeof(ipv6_hdr) + sizeof(udp_hdr), ntohs(IPv6_Header->PayloadLength) - sizeof(udp_hdr), false, &IsMarkPortHopLimit))
				{
					if (IsMarkPortHopLimit)
						PacketSource->HopLimitData.HopLimit = IPv6_Header->HopLimit;
				}
				else {
					return EXIT_FAILURE;
				}

			//Hop Limit must not a ramdom value.
				if ((size_t)IPv6_Header->HopLimit + (size_t)Parameter.HopLimitFluctuation > (size_t)PacketSource->HopLimitData.HopLimit && (size_t)IPv6_Header->HopLimit < (size_t)PacketSource->HopLimitData.HopLimit + (size_t)Parameter.HopLimitFluctuation)
				{
//					DNSMethod(Buffer.get() + sizeof(ipv6_hdr), ntohs(IPv6_Header->PayloadLength), AF_INET6);
					MatchPortToSend(Buffer.get() + sizeof(ipv6_hdr) + sizeof(udp_hdr), ntohs(IPv6_Header->PayloadLength) - sizeof(udp_hdr), UDP_Header->DstPort);
					Parameter.TunnelAvailable_IPv6 = false;
					return EXIT_SUCCESS;
				}
			}
		}
	}
	else { //IPv4
		auto IPv4_Header = (pipv4_hdr)Buffer.get();

	//Validate IPv4 header.
		if (ntohs(IPv4_Header->Length) <= IPv4_Header->IHL * IPv4_IHL_BYTES_TIMES || ntohs(IPv4_Header->Length) > Length || 
			GetChecksum((PUINT16)Buffer.get(), sizeof(ipv4_hdr)) != CHECKSUM_SUCCESS) //Validate IPv4 header checksum.
				return EXIT_FAILURE;

	//Mark source of packet.
		PDNS_SERVER_DATA PacketSource = nullptr;
		if (IPv4_Header->Src.S_un.S_addr == Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr.S_un.S_addr)
		{
			PacketSource = &Parameter.DNSTarget.IPv4;
		}
		else if (IPv4_Header->Src.S_un.S_addr == Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr.S_un.S_addr)
		{
			PacketSource = &Parameter.DNSTarget.Alternate_IPv4;
		}
		else if (Parameter.DNSTarget.IPv4_Multi != nullptr)
		{
			for (size_t Index = 0;Index < Parameter.DNSTarget.IPv4_Multi->size();Index++)
			{
				if (IPv4_Header->Src.S_un.S_addr == Parameter.DNSTarget.IPv4_Multi->at(Index).AddressData.IPv4.sin_addr.S_un.S_addr)
				{
					PacketSource = &Parameter.DNSTarget.IPv4_Multi->at(Index);
					break;
				}
			}

			if (PacketSource == nullptr)
				return EXIT_FAILURE;
		}
		else {
			return EXIT_FAILURE;
		}

	//IPv4 options check
		if (Parameter.IPv4DataCheck)
		{
		//No standard header length and header ID check
			if (IPv4_Header->IHL > IPV4_STANDARDIHL || IPv4_Header->ID == 0)
				PacketSource->HopLimitData.TTL = IPv4_Header->TTL;

		//TOS and Flags should not be set.
			if (IPv4_Header->TOS > 0 || IPv4_Header->Flags > 0)
				return EXIT_FAILURE;
		}

	//Get TTL from IPv4 DNS server.
	//ICMP Protocol
		if (Parameter.ICMPSpeed > 0 && IPv4_Header->Protocol == IPPROTO_ICMP && ntohs(IPv4_Header->Length) >= IPv4_Header->IHL * IPv4_IHL_BYTES_TIMES + sizeof(icmp_hdr))
		{
		//Validate ICMP checksum.
			if (GetChecksum((PUINT16)(Buffer.get() + IPv4_Header->IHL * IPv4_IHL_BYTES_TIMES), ntohs(IPv4_Header->Length) - IPv4_Header->IHL * IPv4_IHL_BYTES_TIMES) != CHECKSUM_SUCCESS)
				return EXIT_FAILURE;

			if (ICMPCheck(Buffer.get() + IPv4_Header->IHL * IPv4_IHL_BYTES_TIMES, ntohs(IPv4_Header->Length) - IPv4_Header->IHL * IPv4_IHL_BYTES_TIMES, AF_INET))
				PacketSource->HopLimitData.TTL = IPv4_Header->TTL;

			return EXIT_SUCCESS;
		}

	//TCP Protocol
		if (Parameter.TCPDataCheck && IPv4_Header->Protocol == IPPROTO_TCP && ntohs(IPv4_Header->Length) >= IPv4_Header->IHL * IPv4_IHL_BYTES_TIMES + sizeof(tcp_hdr))
		{
		//Validate TCP checksum.
			if (TCPUDPChecksum((PUINT8)Buffer.get(), ntohs(IPv4_Header->Length) - IPv4_Header->IHL * IPv4_IHL_BYTES_TIMES, AF_INET, IPPROTO_TCP) != CHECKSUM_SUCCESS)
				return EXIT_FAILURE;

			if (TCPCheck(Buffer.get() + IPv4_Header->IHL * IPv4_IHL_BYTES_TIMES))
				PacketSource->HopLimitData.TTL = IPv4_Header->TTL;

			return EXIT_SUCCESS;
		}

	//UDP Protocol
		if (IPv4_Header->Protocol == IPPROTO_UDP && /* ntohs(IPv4_Header->Length) > IPv4_Header->IHL * IPv4_IHL_BYTES_TIMES + sizeof(udp_hdr) + sizeof(dns_hdr) */ ntohs(IPv4_Header->Length) >= IPv4_Header->IHL * IPv4_IHL_BYTES_TIMES + sizeof(udp_hdr) + DNS_PACKET_MINSIZE)
		{
		//Validate UDP checksum.
			if (TCPUDPChecksum((PUINT8)Buffer.get(), ntohs(IPv4_Header->Length) - IPv4_Header->IHL * IPv4_IHL_BYTES_TIMES, AF_INET, IPPROTO_UDP) != CHECKSUM_SUCCESS)
				return EXIT_FAILURE;

			auto UDP_Header = (pudp_hdr)(Buffer.get() + IPv4_Header->IHL * IPv4_IHL_BYTES_TIMES);
		//Port check
			if (UDP_Header->SrcPort == PacketSource->AddressData.IPv4.sin_port)
			{
			//Domain Test and DNS Options check and get TTL form Domain Test.
				auto IsMarkPortHopLimit = false;
				if (CheckResponseData(Buffer.get() + IPv4_Header->IHL * IPv4_IHL_BYTES_TIMES + sizeof(udp_hdr), ntohs(IPv4_Header->Length) - IPv4_Header->IHL * IPv4_IHL_BYTES_TIMES - sizeof(udp_hdr), false, &IsMarkPortHopLimit))
				{
					if (IsMarkPortHopLimit)
						PacketSource->HopLimitData.TTL = IPv4_Header->TTL;
				}
				else {
					return EXIT_FAILURE;
				}

			//TTL must not a ramdom value.
				if ((size_t)IPv4_Header->TTL + (size_t)Parameter.HopLimitFluctuation > (size_t)PacketSource->HopLimitData.TTL && (size_t)IPv4_Header->TTL < (size_t)PacketSource->HopLimitData.TTL + (size_t)Parameter.HopLimitFluctuation)
				{
//					DNSMethod(Buffer.get() + IPv4_Header->IHL * IPv4_IHL_BYTES_TIMES, ntohs(IPv4_Header->Length) - IPv4_Header->IHL * IPv4_IHL_BYTES_TIMES, AF_INET);
					MatchPortToSend(Buffer.get() + IPv4_Header->IHL * IPv4_IHL_BYTES_TIMES + sizeof(udp_hdr), ntohs(IPv4_Header->Length) - IPv4_Header->IHL * IPv4_IHL_BYTES_TIMES - sizeof(udp_hdr), UDP_Header->DstPort);
					return EXIT_SUCCESS;
				}
			}
		}
	}

	return EXIT_SUCCESS;
}

//ICMP header options check
bool __fastcall ICMPCheck(const PSTR Buffer, const size_t Length, const uint16_t Protocol)
{
//ICMPv6
	if (Protocol == AF_INET6)
	{
		auto ICMPv6_Header = (picmpv6_hdr)Buffer;
		if (ICMPv6_Header->Type == ICMPV6_TYPE_REPLY && ICMPv6_Header->Code == ICMPV6_CODE_REPLY && //ICMPv6 Echo reply
			ICMPv6_Header->ID == Parameter.ICMPID /* && ICMPv6_Header->Sequence == Parameter.ICMPSequence */ ) //Validate ICMP packet.
				return true;
	}
//ICMP
	else {
		auto ICMP_Header = (picmp_hdr)Buffer;
		if (ICMP_Header->Type == ICMP_TYPE_ECHO && ICMP_Header->Code == ICMP_CODE_ECHO && //ICMP Echo reply
		//Validate ICMP packet
			ICMP_Header->ID == Parameter.ICMPID && /* ICMP_Header->Sequence == Parameter.ICMPSequence && */
			Length == sizeof(icmp_hdr) + Parameter.ICMPPaddingDataLength - 1U && 
			memcmp(Parameter.ICMPPaddingData, (PSTR)ICMP_Header + sizeof(icmp_hdr), Parameter.ICMPPaddingDataLength - 1U) == 0) //Validate ICMP additional data.
				return true;
	}

	return false;
}

//TCP header options check
bool __fastcall TCPCheck(const PSTR Buffer)
{
	auto TCP_Header = (ptcp_hdr)Buffer;
	if (TCP_Header->Acknowledge == 0 && TCP_Header->StatusFlags.Flags == TCP_RST_STATUS && TCP_Header->Windows == 0 || //TCP Flags are 0x004(RST) which ACK shoule be 0 and Window size should be 0.
		TCP_Header->HeaderLength > TCP_STANDARDHL && TCP_Header->StatusFlags.Flags == TCP_SYN_ACK_STATUS) //TCP option usually should not empty(MSS, SACK_PERM and WS) whose Flags are 0x012(SYN/ACK).
			return true;

	return false;
}

/* Old version(2015-03-08)
//Application Layer(Domain Name System/DNS) process
size_t __fastcall DNSMethod(const PSTR Recv, const size_t Length , const uint16_t Protocol)
{
//Mark port and responses answers check
	auto UDP_Header = (pudp_hdr)Recv;
	auto DNS_Header = (pdns_hdr)(Recv + sizeof(udp_hdr));
	size_t DataLength = Length - sizeof(udp_hdr);

//UDP Truncated check(TC bit in DNS Header has been set)
	if ((ntohs(DNS_Header->Flags) & 0x0200) >> 9U > 0 && DNS_Header->Answer == 0) //xxxxxx1xxxxxxxxx & 0000001000000000 >> 9 == 1
	{
		std::shared_ptr<char> RecvBuffer(new char[LARGE_PACKET_MAXSIZE]());
		std::shared_ptr<SOCKET_DATA> TargetData(new SOCKET_DATA());
		if (Protocol == AF_INET6) //IPv6
			TargetData->AddrLen = sizeof(sockaddr_in6);
		else //IPv4
			TargetData->AddrLen = sizeof(sockaddr_in);

	//Retry with TCP.
		DNS_Header->Flags = htons(DNS_STANDARD);
		DataLength = TCPRequest(Recv + sizeof(udp_hdr), DataLength, RecvBuffer.get(), LARGE_PACKET_MAXSIZE, false, false);
		if (DataLength >= DNS_PACKET_MINSIZE)
		{
			MatchPortToSend(RecvBuffer.get(), DataLength, UDP_Header->DstPort);
			return EXIT_SUCCESS;
		}
		else {
			DataLength = Length - sizeof(udp_hdr);
		}
	}

//Send back.
	MatchPortToSend(Recv + sizeof(udp_hdr), DataLength, UDP_Header->DstPort);
	return EXIT_SUCCESS;
}
*/

//Match port of responses and send responses to system sockets process
size_t __fastcall MatchPortToSend(const PSTR Buffer, const size_t Length, const uint16_t Port)
{
//Initialization
	std::shared_ptr<SOCKET_DATA> RequesterData(new SOCKET_DATA());
	memset(RequesterData.get(), 0, sizeof(SOCKET_DATA));
	size_t Index = 0;

//Match port.
	std::unique_lock<std::mutex> PortListMutex(PortListLock);
	for (Index = 0;Index < QUEUE_MAXLEN * QUEUE_PARTNUM;Index++)
	{
		if (PortList.RecvData[Index].AddrLen != 0)
		{
			for (auto SocketDataIter = PortList.SendData[Index].begin();SocketDataIter != PortList.SendData[Index].end();SocketDataIter++)
			{
			//IPv6
				if (SocketDataIter->AddrLen == sizeof(sockaddr_in6) && SocketDataIter->SockAddr.ss_family == AF_INET6)
				{
					if (Port == ((PSOCKADDR_IN6)&SocketDataIter->SockAddr)->sin6_port)
					{
						AlternateSwapList.PcapAlternateTimeout[Index] = 0;
						*RequesterData = PortList.RecvData[Index];
						memset(&PortList.RecvData[Index], 0, sizeof(SOCKET_DATA));
						PortList.SendData[Index].clear();
						PortList.SendData[Index].shrink_to_fit();

						goto StopLoop;
					}
				}
			//IPv4
				else if (SocketDataIter->AddrLen == sizeof(sockaddr_in) && SocketDataIter->SockAddr.ss_family == AF_INET)
				{
					if (Port == ((PSOCKADDR_IN)&SocketDataIter->SockAddr)->sin_port)
					{
						AlternateSwapList.PcapAlternateTimeout[Index] = 0;
						*RequesterData = PortList.RecvData[Index];
						memset(&PortList.RecvData[Index], 0, sizeof(SOCKET_DATA));
						PortList.SendData[Index].clear();
						PortList.SendData[Index].shrink_to_fit();

						goto StopLoop;
					}
				}
			}
		}
	}

//Stop loop.
	StopLoop: 
	PortListMutex.unlock();

//Drop resopnses which not in PortList.
	if (RequesterData->Socket == 0 || RequesterData->AddrLen == 0 || RequesterData->SockAddr.ss_family == 0)
		return EXIT_FAILURE;

//Mark DNS Cache.
	if (Parameter.CacheType > 0)
		MarkDomainCache(Buffer, Length);

//Send to localhost.
	if (Index >= QUEUE_MAXLEN * QUEUE_PARTNUM / 2U) //TCP area
	{
		std::shared_ptr<char> RecvBuffer(new char[Length + sizeof(uint16_t)]());
		memset(RecvBuffer.get(), 0, Length + sizeof(uint16_t));
//		memcpy(RecvBuffer.get(), Buffer, Length);
		memcpy_s(RecvBuffer.get(), Length + sizeof(uint16_t), Buffer, Length);
		if (AddLengthToTCPDNSHeader(RecvBuffer.get(), Length, Length + sizeof(uint16_t)) == EXIT_FAILURE)
			return EXIT_FAILURE;

		send(RequesterData->Socket, RecvBuffer.get(), (int)(Length + sizeof(uint16_t)), 0);
		shutdown(RequesterData->Socket, SD_BOTH);
		closesocket(RequesterData->Socket);
		return EXIT_SUCCESS;
	}
	else { //UDP
/* Old version(2015-03-08)
	//UDP Truncated check
		if (Length > Parameter.EDNS0PayloadSize)
		{
			std::shared_ptr<char> UDPBuffer(new char[DNS_PACKET_RR_LOCATE(Buffer) + sizeof(dns_record_opt)]());
//			memcpy(UDPBuffer.get(), Buffer, DNS_PACKET_RR_LOCATE(Buffer));
			memcpy_s(UDPBuffer.get(), DNS_PACKET_RR_LOCATE(Buffer) + sizeof(dns_record_opt), Buffer, DNS_PACKET_RR_LOCATE(Buffer));
			auto DNS_Header = (pdns_hdr)UDPBuffer.get();
			DNS_Header->Flags = htons(ntohs(DNS_Header->Flags) | 0x8200); //Set 1000001000000000, DNS_SQR_NETC
			DNS_Header->Additional = htons(U16_NUM_ONE);
			auto DNS_Record_OPT = (pdns_record_opt)(UDPBuffer.get() + DNS_PACKET_RR_LOCATE(Buffer));
			DNS_Record_OPT->Type = htons(DNS_RECORD_OPT);
			DNS_Record_OPT->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);

			sendto(RequesterData->Socket, UDPBuffer.get(), (int)(DNS_PACKET_RR_LOCATE(Buffer) + sizeof(dns_record_opt)), 0, (PSOCKADDR)&RequesterData->SockAddr, RequesterData->AddrLen);
		}
		else {
*/
		sendto(RequesterData->Socket, Buffer, (int)Length, 0, (PSOCKADDR)&RequesterData->SockAddr, RequesterData->AddrLen);
//		}
	}

//Clear socket.
	if (Parameter.LocalSocket != nullptr && !Parameter.LocalSocket->empty())
	for (auto SocketIter:*Parameter.LocalSocket)
	{
		if (SocketIter == RequesterData->Socket)
			return EXIT_SUCCESS;
	}

	shutdown(RequesterData->Socket, SD_BOTH);
	closesocket(RequesterData->Socket);
	return EXIT_SUCCESS;
}

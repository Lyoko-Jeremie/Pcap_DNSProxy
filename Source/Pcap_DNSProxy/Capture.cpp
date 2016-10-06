// This code is part of Pcap_DNSProxy
// A local DNS server based on WinPcap and LibPcap
// Copyright (C) 2012-2016 Chengr28
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

#if defined(ENABLE_PCAP)
//Capture initialization
void CaptureInit(
	void)
{
//Initialization and capture filter initialization
	uint8_t ErrorBuffer[PCAP_ERRBUF_SIZE] = {0};
	std::wstring Message;
	pcap_if *pThedevs = nullptr, *pDrive = nullptr;
	auto IsErrorFirstPrint = true, IsFound = false;
	std::unique_lock<std::mutex> CaptureMutex(CaptureLock, std::defer_lock);
	if (!CaptureFilterRulesInit(PcapFilterRules))
	{
		PcapFilterRules.clear();
		return;
	}

//Capture Monitor
	for (;;)
	{
	//Open all devices.
		if (pcap_findalldevs(&pThedevs, (char *)ErrorBuffer) == PCAP_ERROR)
		{
			if (MBSToWCSString(ErrorBuffer, PCAP_ERRBUF_SIZE, Message))
				PrintError(LOG_LEVEL_3, LOG_ERROR_PCAP, Message.c_str(), 0, nullptr, 0);
			else 
				PrintError(LOG_LEVEL_2, LOG_ERROR_SYSTEM, L"Convert multiple byte or wide char string error", 0, nullptr, 0);

			memset(ErrorBuffer, 0, PCAP_ERRBUF_SIZE);
			Sleep(Parameter.FileRefreshTime);
			continue;
		}

	//Permissions check and check available network devices.
		else if (pThedevs == nullptr)
		{
			if (IsErrorFirstPrint)
				IsErrorFirstPrint = false;
			else 
				PrintError(LOG_LEVEL_3, LOG_ERROR_PCAP, L"Insufficient privileges or not any available network devices.", 0, nullptr, 0);

			Sleep(Parameter.FileRefreshTime);
			continue;
		}
		else {
		//Mark captures.
			if (PcapRunningList.empty())
			{
				std::thread CaptureThread(std::bind(CaptureModule, pThedevs, true));
				CaptureThread.detach();
			}
			else {
				pDrive = pThedevs;

			//Scan all devices.
				CaptureMutex.lock();
				while (pDrive != nullptr)
				{
					if (pDrive->name != nullptr)
					{
						IsFound = true;
						for (const auto &CaptureIter:PcapRunningList)
						{
							if (CaptureIter == pDrive->name)
							{
								IsFound = false;
								break;
							}
						}

					//Start a capture monitor.
						if (IsFound)
						{
							std::thread CaptureThread(std::bind(CaptureModule, pDrive, false));
							CaptureThread.detach();
						}
					}

					pDrive = pDrive->next;
				}

				CaptureMutex.unlock();
			}
		}

		Sleep(Parameter.FileRefreshTime);
		pcap_freealldevs(pThedevs);
	}

//Monitor terminated
	PrintError(LOG_LEVEL_2, LOG_ERROR_SYSTEM, L"Capture module Monitor terminated", 0, nullptr, 0);
	return;
}

//Make filter rules of captures
bool CaptureFilterRulesInit(
	std::string &FilterRules)
{
//Initialization(Part 1)
	std::vector<PDNS_SERVER_DATA> AddrList;
	auto RepeatingItem = false;

//IPv6
	if (Parameter.RequestMode_Network == REQUEST_MODE_BOTH || Parameter.RequestMode_Network == REQUEST_MODE_IPV6 || //IPv6
		(Parameter.RequestMode_Network == REQUEST_MODE_IPV4 && Parameter.Target_Server_IPv4.AddressData.Storage.ss_family == 0)) //Non-IPv4
	{
	//Main
		if (Parameter.Target_Server_IPv6.AddressData.Storage.ss_family > 0)
			AddrList.push_back(&Parameter.Target_Server_IPv6);

	//Alternate
		if (Parameter.Target_Server_Alternate_IPv6.AddressData.Storage.ss_family > 0)
		{
		//Check repeating items.
			for (const auto &DNSServerDataIter:AddrList)
			{
				if (DNSServerDataIter->AddressData.Storage.ss_family == Parameter.Target_Server_Alternate_IPv6.AddressData.Storage.ss_family && 
					memcmp(&DNSServerDataIter->AddressData.IPv6.sin6_addr, &Parameter.Target_Server_Alternate_IPv6.AddressData.IPv6.sin6_addr, sizeof(DNSServerDataIter->AddressData.IPv6.sin6_addr)) == 0)
				{
					RepeatingItem = true;
					break;
				}
			}

		//Add to address list.
			if (!RepeatingItem)
				AddrList.push_back(&Parameter.Target_Server_Alternate_IPv6);

			RepeatingItem = false;
		}

	//Multiple list(IPv6)
		if (Parameter.Target_Server_IPv6_Multiple != nullptr)
		{
			for (auto &DNSServerDataIter:*Parameter.Target_Server_IPv6_Multiple)
			{
			//Check repeating items.
				for (const auto &DNSServerDataInnerIter:AddrList)
				{
					if (DNSServerDataInnerIter->AddressData.Storage.ss_family == DNSServerDataIter.AddressData.Storage.ss_family && 
						memcmp(&DNSServerDataInnerIter->AddressData.IPv6.sin6_addr, &DNSServerDataIter.AddressData.IPv6.sin6_addr, sizeof(DNSServerDataInnerIter->AddressData.IPv6.sin6_addr)) == 0)
					{
						RepeatingItem = true;
						break;
					}
				}

			//Add to address list.
				if (!RepeatingItem)
					AddrList.push_back(&DNSServerDataIter);
				RepeatingItem = false;
			}
		}
	}

//IPv4
	if (Parameter.RequestMode_Network == REQUEST_MODE_BOTH || Parameter.RequestMode_Network == REQUEST_MODE_IPV4 || //IPv4
		(Parameter.RequestMode_Network == REQUEST_MODE_IPV6 && Parameter.Target_Server_IPv6.AddressData.Storage.ss_family == 0)) //Non-IPv6
	{
	//Main
		if (Parameter.Target_Server_IPv4.AddressData.Storage.ss_family > 0)
			AddrList.push_back(&Parameter.Target_Server_IPv4);

	//Alternate
		if (Parameter.Target_Server_Alternate_IPv4.AddressData.Storage.ss_family > 0)
		{
		//Check repeating items.
			for (const auto &DNSServerDataIter:AddrList)
			{
				if (DNSServerDataIter->AddressData.Storage.ss_family == Parameter.Target_Server_Alternate_IPv4.AddressData.Storage.ss_family && 
					DNSServerDataIter->AddressData.IPv4.sin_addr.s_addr == Parameter.Target_Server_Alternate_IPv4.AddressData.IPv4.sin_addr.s_addr)
				{
					RepeatingItem = true;
					break;
				}
			}

		//Add to address list.
			if (!RepeatingItem)
				AddrList.push_back(&Parameter.Target_Server_Alternate_IPv4);
			RepeatingItem = false;
		}

	//Multiple list(IPv4)
		if (Parameter.Target_Server_IPv4_Multiple != nullptr)
		{
			for (auto &DNSServerDataIter:*Parameter.Target_Server_IPv4_Multiple)
			{
			//Check repeating items.
				for (const auto &DNSServerDataInnerIter:AddrList)
				{
					if (DNSServerDataInnerIter->AddressData.Storage.ss_family == DNSServerDataIter.AddressData.Storage.ss_family && 
						DNSServerDataInnerIter->AddressData.IPv4.sin_addr.s_addr == DNSServerDataIter.AddressData.IPv4.sin_addr.s_addr)
					{
						RepeatingItem = true;
						break;
					}
				}

			//Add to address list.
				if (!RepeatingItem)
					AddrList.push_back(&DNSServerDataIter);
				RepeatingItem = false;
			}
		}
	}

//Initialization(Part 2)
	uint8_t Addr[ADDRESS_STRING_MAXSIZE] = {0};
	std::string AddrString;
	FilterRules.clear();
	FilterRules.append("(src host ");
	ssize_t Result = 0;

//List all target addresses.
	RepeatingItem = false;
	for (const auto &DNSServerDataIter:AddrList)
	{
		if (DNSServerDataIter->AddressData.Storage.ss_family == AF_INET6)
		{
			if (RepeatingItem)
				AddrString.append(" or ");
			RepeatingItem = true;

			if (!BinaryToAddressString(AF_INET6, &DNSServerDataIter->AddressData.IPv6.sin6_addr, Addr, ADDRESS_STRING_MAXSIZE, &Result))
			{
				PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"IPv6 address format error", Result, nullptr, 0);
				return false;
			}

			AddrString.append((const char *)Addr);
			memset(Addr, 0, ADDRESS_STRING_MAXSIZE);
		}
		else if (DNSServerDataIter->AddressData.Storage.ss_family == AF_INET)
		{
			if (RepeatingItem)
				AddrString.append(" or ");
			RepeatingItem = true;

			if (!BinaryToAddressString(AF_INET, &DNSServerDataIter->AddressData.IPv4.sin_addr, Addr, ADDRESS_STRING_MAXSIZE, &Result))
			{
				PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"IPv4 address format error", Result, nullptr, 0);
				return false;
			}

			AddrString.append((const char *)Addr);
			memset(Addr, 0, ADDRESS_STRING_MAXSIZE);
		}
	}

//End of address list
	FilterRules.append(AddrString);
	FilterRules.append(") or (pppoes and src host ");
	FilterRules.append(AddrString);
	FilterRules.append(")");

	return true;
}

//Capture process
bool CaptureModule(
	const pcap_if *pDrive, 
	const bool IsCaptureList)
{
	std::string CaptureDevice;

//Devices name, addresses and type check
	if (pDrive == nullptr)
		return false;
#if defined(PLATFORM_WIN)
	else if (pDrive->name == nullptr || pDrive->addresses == nullptr || pDrive->addresses->netmask == nullptr || pDrive->flags == PCAP_IF_LOOPBACK)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	else if (pDrive->name == nullptr || pDrive->addresses == nullptr || pDrive->flags == PCAP_IF_LOOPBACK)
#endif
		goto SkipDevices;

//Pcap devices blacklist check
	if (pDrive->description != nullptr)
	{
		CaptureDevice.append(pDrive->description);
		CaseConvert(CaptureDevice, false);
		for (const auto &CaptureIter:*Parameter.PcapDevicesBlacklist)
		{
			if (CaptureDevice.find(CaptureIter) != std::string::npos)
				goto SkipDevices;
		}
	}

//Mark capture name.
	CaptureDevice.clear();
	CaptureDevice.append(pDrive->name);
	CaseConvert(CaptureDevice, false);
	for (const auto &CaptureIter:*Parameter.PcapDevicesBlacklist)
	{
		if (CaptureDevice.find(CaptureIter) != std::string::npos)
			goto SkipDevices;
	}

//Jump here to skip this device.
	goto DevicesNotSkip;

SkipDevices:
	if (IsCaptureList && pDrive->next != nullptr)
	{
		std::thread CaptureThread(std::bind(CaptureModule, pDrive->next, true));
		CaptureThread.detach();
	}

	return true;

//Jump here to keep this device.
DevicesNotSkip:

//Initialization(Part 1)
	std::shared_ptr<uint8_t> Buffer(new uint8_t[LARGE_PACKET_MAXSIZE + PADDING_RESERVED_BYTES]());
	memset(Buffer.get(), 0, LARGE_PACKET_MAXSIZE + PADDING_RESERVED_BYTES);
	pcap_t *DeviceHandle = nullptr;
	CaptureDevice.clear();
	CaptureDevice.append(pDrive->name);
	CaptureDevice.shrink_to_fit();

//Open device
#if defined(PLATFORM_WIN)
	if ((DeviceHandle = pcap_open(pDrive->name, LARGE_PACKET_MAXSIZE, 0, (int)Parameter.PcapReadingTimeout, nullptr, (char *)Buffer.get())) == nullptr)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	if ((DeviceHandle = pcap_open_live(pDrive->name, LARGE_PACKET_MAXSIZE, 0, (int)Parameter.PcapReadingTimeout, (char *)Buffer.get())) == nullptr)
#endif
	{
		std::wstring Message;
		if (MBSToWCSString(Buffer.get(), PCAP_ERRBUF_SIZE, Message))
			PrintError(LOG_LEVEL_3, LOG_ERROR_PCAP, Message.c_str(), 0, nullptr, 0);
		else 
			PrintError(LOG_LEVEL_2, LOG_ERROR_SYSTEM, L"Convert multiple byte or wide char string error", 0, nullptr, 0);

		return false;
	}

//Check device type.
	uint16_t DeviceType = 0;
	if (pcap_datalink(DeviceHandle) == DLT_EN10MB || //Ethernet II(Standard)
		pcap_datalink(DeviceHandle) == DLT_PPP_ETHER || //PPPoE
		pcap_datalink(DeviceHandle) == DLT_EN3MB) //Ethernet II(Experiment)
	{
		DeviceType = DLT_EN10MB;
	}
	else if (pcap_datalink(DeviceHandle) == DLT_APPLE_IP_OVER_IEEE1394) //Apple IEEE 1394
	{
		DeviceType = DLT_APPLE_IP_OVER_IEEE1394;
	}
	else {
		pcap_close(DeviceHandle);
		return false;
	}

//Compile the string into a filter program.
	bpf_program BPF_Code;
	memset(&BPF_Code, 0, sizeof(BPF_Code));
#if defined(PLATFORM_WIN)
	if (pcap_compile(DeviceHandle, &BPF_Code, PcapFilterRules.c_str(), PCAP_COMPILE_OPTIMIZE, 0) == PCAP_ERROR)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	if (pcap_compile(DeviceHandle, &BPF_Code, PcapFilterRules.c_str(), PCAP_COMPILE_OPTIMIZE, PCAP_NETMASK_UNKNOWN) == PCAP_ERROR)
#endif
	{
		std::wstring Message;
		if (MBSToWCSString((const uint8_t *)pcap_geterr(DeviceHandle), PCAP_ERRBUF_SIZE, Message))
			PrintError(LOG_LEVEL_3, LOG_ERROR_PCAP, Message.c_str(), 0, nullptr, 0);
		else 
			PrintError(LOG_LEVEL_2, LOG_ERROR_SYSTEM, L"Convert multiple byte or wide char string error", 0, nullptr, 0);

		pcap_close(DeviceHandle);
		return false;
	}

//Specify a filter program.
	if (pcap_setfilter(DeviceHandle, &BPF_Code) == PCAP_ERROR)
	{
		std::wstring Message;
		if (MBSToWCSString((const uint8_t *)pcap_geterr(DeviceHandle), PCAP_ERRBUF_SIZE, Message))
			PrintError(LOG_LEVEL_3, LOG_ERROR_PCAP, Message.c_str(), 0, nullptr, 0);
		else 
			PrintError(LOG_LEVEL_2, LOG_ERROR_SYSTEM, L"Convert multiple byte or wide char string error", 0, nullptr, 0);

		pcap_freecode(&BPF_Code);
		pcap_close(DeviceHandle);
		return false;
	}

//Start captures with other devices.
	PcapRunningList.push_back(CaptureDevice);
	if (IsCaptureList && pDrive->next != nullptr)
	{
		std::thread CaptureThread(std::bind(CaptureModule, pDrive->next, IsCaptureList));
		CaptureThread.detach();
	}

//Initialization(Part 2)
	CAPTURE_HANDLER_PARAM ParamList;
	memset(&ParamList, 0, sizeof(ParamList));
	ParamList.DeviceType = DeviceType;
	ParamList.Buffer = Buffer.get();
	ParamList.BufferSize = LARGE_PACKET_MAXSIZE + PADDING_RESERVED_BYTES;
	ssize_t Result = 0;
	std::unique_lock<std::mutex> CaptureMutex(CaptureLock, std::defer_lock);

//Start monitor.
	for (;;)
	{
		Result = pcap_loop(DeviceHandle, PCAP_LOOP_INFINITY, CaptureHandler, (unsigned char *)&ParamList);
		if (Result < 0)
		{
		//Delete this capture from devices list.
			CaptureMutex.lock();
			for (auto CaptureIter = PcapRunningList.begin();CaptureIter != PcapRunningList.end();)
			{
				if (*CaptureIter == CaptureDevice)
					CaptureIter = PcapRunningList.erase(CaptureIter);
				else 
					++CaptureIter;
			}
			CaptureMutex.unlock();

		//Exit this capture thread.
			pcap_freecode(&BPF_Code);
			pcap_close(DeviceHandle);
			return false;
		}
		else {
			Sleep(Parameter.FileRefreshTime);
			continue;
		}
	}

//Monitor terminated
	pcap_freecode(&BPF_Code);
	pcap_close(DeviceHandle);
	PrintError(LOG_LEVEL_2, LOG_ERROR_SYSTEM, L"Capture module Monitor terminated", 0, nullptr, 0);
	return true;
}

//Handler of WinPcap/LibPcap loop function
void CaptureHandler(
	uint8_t *Param, 
	const pcap_pkthdr *PacketHeader, 
	const uint8_t *PacketData)
{
//Initialization
	auto ParamList = (PCAPTURE_HANDLER_PARAM)Param;
	memset(ParamList->Buffer, 0, LARGE_PACKET_MAXSIZE + PADDING_RESERVED_BYTES);
	size_t Length = PacketHeader->caplen;
	uint16_t Protocol = 0;

//OSI Layer 2
	if (ParamList->DeviceType == DLT_EN10MB) //Ethernet II
	{
		if (Length <= sizeof(eth_hdr))
			return;
		memcpy_s(ParamList->Buffer, LARGE_PACKET_MAXSIZE, PacketData + sizeof(eth_hdr), Length - sizeof(eth_hdr));
		Protocol = ((peth_hdr)PacketData)->Type;
		Length -= sizeof(eth_hdr);
	}
	else if (ParamList->DeviceType == DLT_APPLE_IP_OVER_IEEE1394) //Apple IEEE 1394
	{
		if (Length <= sizeof(ieee_1394_hdr))
			return;
		memcpy_s(ParamList->Buffer, LARGE_PACKET_MAXSIZE, PacketData + sizeof(ieee_1394_hdr), Length - sizeof(ieee_1394_hdr));
		Protocol = ((pieee_1394_hdr)PacketData)->Type;
		Length -= sizeof(ieee_1394_hdr);
	}
	else {
		return;
	}

//Virtual Bridged LAN(VLAN, IEEE 802.1Q)
	if (ntohs(Protocol) == OSI_L2_VLAN)
	{
		if (Length > sizeof(ieee_8021q_hdr))
		{
			Protocol = ((pieee_8021q_hdr)ParamList->Buffer)->Type;
			memmove_s(ParamList->Buffer, LARGE_PACKET_MAXSIZE, ParamList->Buffer + sizeof(ieee_8021q_hdr), Length - sizeof(ieee_8021q_hdr));
			Length -= sizeof(ieee_8021q_hdr);
		}
		else {
			return;
		}
	}

//PPP(Such as ADSL, a part of organization networks)
	if (ntohs(Protocol) == OSI_L2_PPPS)
	{
		if (Length > sizeof(ppp_hdr))
		{
			Protocol = ((pppp_hdr)ParamList->Buffer)->Protocol;
			memmove_s(ParamList->Buffer, LARGE_PACKET_MAXSIZE, ParamList->Buffer + sizeof(ppp_hdr), Length - sizeof(ppp_hdr));
			Length -= sizeof(ppp_hdr);
		}
		else {
			return;
		}
	}

//LAN, WLAN and IEEE 802.1X, some Mobile Communications Standard/MCS drives which disguise as a LAN
	if (((ntohs(Protocol) == OSI_L2_IPV6 || ntohs(Protocol) == PPP_IPV6) && Length > sizeof(ipv6_hdr)) || //IPv6
		((ntohs(Protocol) == OSI_L2_IPV4 || ntohs(Protocol) == PPP_IPV4) && Length > sizeof(ipv4_hdr))) //IPv4
			CaptureNetworkLayer(ntohs(Protocol), ParamList->Buffer, Length, ParamList->BufferSize);

	return;
}

//Network Layer(Internet Protocol/IP) process
bool CaptureNetworkLayer(
	const uint16_t Protocol, 
	const uint8_t *Buffer, 
	const size_t Length, 
	const size_t BufferSize)
{
//Initialization
	PDNS_SERVER_DATA PacketSource = nullptr;

//IPv6
	if ((Protocol == PPP_IPV6 || Protocol == OSI_L2_IPV6) && 
		Parameter.DirectRequest != REQUEST_MODE_DIRECT_BOTH && Parameter.DirectRequest != REQUEST_MODE_DIRECT_IPV6)
	{
		auto IPv6_Header = (pipv6_hdr)Buffer;

	//Validate IPv6 header length.
		if (ntohs(IPv6_Header->PayloadLength) > Length - sizeof(ipv6_hdr))
			return false;

	//Mark source of packet.
		if (memcmp(&IPv6_Header->Source, &Parameter.Target_Server_IPv6.AddressData.IPv6.sin6_addr, sizeof(IPv6_Header->Source)) == 0)
		{
			PacketSource = &Parameter.Target_Server_IPv6;
		}
		else if (memcmp(&IPv6_Header->Source, &Parameter.Target_Server_Alternate_IPv6.AddressData.IPv6.sin6_addr, sizeof(IPv6_Header->Source)) == 0)
		{
			PacketSource = &Parameter.Target_Server_Alternate_IPv6;
		}
		else if (Parameter.Target_Server_IPv6_Multiple != nullptr)
		{
			for (auto &DNSServerDataIter:*Parameter.Target_Server_IPv6_Multiple)
			{
				if (memcmp(&IPv6_Header->Source, &DNSServerDataIter.AddressData.IPv6.sin6_addr, sizeof(IPv6_Header->Source)) == 0)
				{
					PacketSource = &DNSServerDataIter;
					break;
				}
			}

			if (PacketSource == nullptr)
				return false;
		}
		else {
			return false;
		}

	//Get Hop Limits from IPv6 DNS server.
	//ICMPv6
		if (Parameter.ICMP_Speed > 0 && IPv6_Header->NextHeader == IPPROTO_ICMPV6 && ntohs(IPv6_Header->PayloadLength) >= sizeof(icmpv6_hdr))
		{
		//Validate ICMPv6 checksum.
			if (GetChecksum_ICMPv6(Buffer, ntohs(IPv6_Header->PayloadLength), IPv6_Header->Destination, IPv6_Header->Source) != CHECKSUM_SUCCESS)
				return false;

		//ICMPv6 check
			if (CaptureCheck_ICMP(AF_INET6, Buffer + sizeof(ipv6_hdr), ntohs(IPv6_Header->PayloadLength)))
				PacketSource->HopLimitData_Mark.HopLimit = IPv6_Header->HopLimit;

			return true;
		}

	//TCP
		if (Parameter.HeaderCheck_TCP && IPv6_Header->NextHeader == IPPROTO_TCP && ntohs(IPv6_Header->PayloadLength) >= sizeof(tcp_hdr))
		{
		//Validate TCP checksum.
			if (GetChecksum_TCP_UDP(AF_INET6, IPPROTO_TCP, Buffer, ntohs(IPv6_Header->PayloadLength)) != CHECKSUM_SUCCESS)
				return false;

		//Packet check
			if (CaptureCheck_TCP(Buffer + sizeof(ipv6_hdr)))
				PacketSource->HopLimitData_Mark.HopLimit = IPv6_Header->HopLimit;

			return true;
		}

	//UDP
		if (IPv6_Header->NextHeader == IPPROTO_UDP && ntohs(IPv6_Header->PayloadLength) >= sizeof(udp_hdr) + DNS_PACKET_MINSIZE)
		{
		//Validate UDP checksum.
			if (GetChecksum_TCP_UDP(AF_INET6, IPPROTO_UDP, Buffer, ntohs(IPv6_Header->PayloadLength)) != CHECKSUM_SUCCESS)
				return false;

		//Port check
			auto UDP_Header = (pudp_hdr)(Buffer + sizeof(ipv6_hdr));
			if (UDP_Header->SrcPort == PacketSource->AddressData.IPv6.sin6_port)
			{
			//Domain Test and DNS Options check and get Hop Limit from Domain Test.
				auto IsMarkHopLimit = false;
				auto DataLength = CheckResponseData(
					REQUEST_PROCESS_UDP_NORMAL, 
					(uint8_t *)(Buffer + sizeof(ipv6_hdr) + sizeof(udp_hdr)), 
					ntohs(IPv6_Header->PayloadLength) - sizeof(udp_hdr), 
					BufferSize, 
					&IsMarkHopLimit);
				if (DataLength < DNS_PACKET_MINSIZE)
					return false;
				else if (IsMarkHopLimit)
					PacketSource->HopLimitData_Mark.HopLimit = IPv6_Header->HopLimit;

			//DNSCurve encryption packet check
			#if defined(ENABLE_LIBSODIUM)
				if (Parameter.IsDNSCurve && 
				//Main(IPv6)
					((DNSCurveParameter.DNSCurve_Target_Server_IPv6.AddressData.Storage.ss_family > 0 && 
					DNSCurveParameter.DNSCurve_Target_Server_IPv6.ReceiveMagicNumber != nullptr && 
					sodium_memcmp(Buffer + sizeof(ipv6_hdr) + sizeof(udp_hdr), DNSCurveParameter.DNSCurve_Target_Server_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN) == 0) || 
				//Alternate(IPv6)
					(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.AddressData.Storage.ss_family > 0 && 
					DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber != nullptr && 
					sodium_memcmp(Buffer + sizeof(ipv6_hdr) + sizeof(udp_hdr), DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN) == 0)))
						return false;
			#endif

			//Hop Limit must not a ramdom value.
				if ((PacketSource->HopLimitData_Assign.HopLimit > 0 && 
					(size_t)IPv6_Header->HopLimit + (size_t)Parameter.HopLimitFluctuation > (size_t)PacketSource->HopLimitData_Assign.HopLimit && 
					(size_t)IPv6_Header->HopLimit < (size_t)PacketSource->HopLimitData_Assign.HopLimit + (size_t)Parameter.HopLimitFluctuation) || 
					(PacketSource->HopLimitData_Assign.HopLimit == 0 && 
					(size_t)IPv6_Header->HopLimit + (size_t)Parameter.HopLimitFluctuation > (size_t)PacketSource->HopLimitData_Mark.HopLimit && 
					(size_t)IPv6_Header->HopLimit < (size_t)PacketSource->HopLimitData_Mark.HopLimit + (size_t)Parameter.HopLimitFluctuation))
				{
					MatchPortToSend(AF_INET6, Buffer + sizeof(ipv6_hdr) + sizeof(udp_hdr), DataLength, BufferSize, UDP_Header->DstPort);
					return true;
				}
			}
		}
	}
//IPv4
	else if ((Protocol == PPP_IPV4 || Protocol == OSI_L2_IPV4) && 
		Parameter.DirectRequest != REQUEST_MODE_DIRECT_BOTH && Parameter.DirectRequest != REQUEST_MODE_DIRECT_IPV4)
	{
		auto IPv4_Header = (pipv4_hdr)Buffer;

	//Validate IPv4 header.
		if (ntohs(IPv4_Header->Length) <= IPv4_Header->IHL * IPV4_IHL_BYTES_TIMES || ntohs(IPv4_Header->Length) > Length || 
			GetChecksum((uint16_t *)Buffer, sizeof(ipv4_hdr)) != CHECKSUM_SUCCESS)
				return false;

	//Mark source of packet.
		if (IPv4_Header->Source.s_addr == Parameter.Target_Server_IPv4.AddressData.IPv4.sin_addr.s_addr)
		{
			PacketSource = &Parameter.Target_Server_IPv4;
		}
		else if (IPv4_Header->Source.s_addr == Parameter.Target_Server_Alternate_IPv4.AddressData.IPv4.sin_addr.s_addr)
		{
			PacketSource = &Parameter.Target_Server_Alternate_IPv4;
		}
		else if (Parameter.Target_Server_IPv4_Multiple != nullptr)
		{
			for (auto &DNSServerDataIter:*Parameter.Target_Server_IPv4_Multiple)
			{
				if (IPv4_Header->Source.s_addr == DNSServerDataIter.AddressData.IPv4.sin_addr.s_addr)
				{
					PacketSource = &DNSServerDataIter;
					break;
				}
			}

			if (PacketSource == nullptr)
				return false;
		}
		else {
			return false;
		}

	//IPv4 options check
		if (Parameter.HeaderCheck_IPv4)
		{
		//No standard header length and header ID check
			if (IPv4_Header->IHL > IPV4_STANDARD_IHL || IPv4_Header->ID == 0)
				PacketSource->HopLimitData_Mark.TTL = IPv4_Header->TTL;

		//ECN and DCSP(TOS bits) and Flags should not be set.
			if (IPv4_Header->ECN_DSCP > 0 || IPv4_Header->Flags > 0)
				return false;
		}

	//Get TTL from IPv4 DNS server.
	//ICMP
		if (Parameter.ICMP_Speed > 0 && IPv4_Header->Protocol == IPPROTO_ICMP && ntohs(IPv4_Header->Length) >= IPv4_Header->IHL * IPV4_IHL_BYTES_TIMES + sizeof(icmp_hdr))
		{
		//Validate ICMP checksum.
			if (GetChecksum((uint16_t *)(Buffer + IPv4_Header->IHL * IPV4_IHL_BYTES_TIMES), ntohs(IPv4_Header->Length) - IPv4_Header->IHL * IPV4_IHL_BYTES_TIMES) != CHECKSUM_SUCCESS)
				return false;

		//ICMP Check
			if (CaptureCheck_ICMP(AF_INET, Buffer + IPv4_Header->IHL * IPV4_IHL_BYTES_TIMES, ntohs(IPv4_Header->Length) - IPv4_Header->IHL * IPV4_IHL_BYTES_TIMES))
				PacketSource->HopLimitData_Mark.TTL = IPv4_Header->TTL;

			return true;
		}

	//TCP
		if (Parameter.HeaderCheck_TCP && IPv4_Header->Protocol == IPPROTO_TCP && ntohs(IPv4_Header->Length) >= IPv4_Header->IHL * IPV4_IHL_BYTES_TIMES + sizeof(tcp_hdr))
		{
		//Validate TCP checksum.
			if (GetChecksum_TCP_UDP(AF_INET, IPPROTO_TCP, Buffer, ntohs(IPv4_Header->Length) - IPv4_Header->IHL * IPV4_IHL_BYTES_TIMES) != CHECKSUM_SUCCESS)
				return false;

		//Packet check
			if (CaptureCheck_TCP(Buffer + IPv4_Header->IHL * IPV4_IHL_BYTES_TIMES))
				PacketSource->HopLimitData_Mark.TTL = IPv4_Header->TTL;

			return true;
		}

	//UDP
		if (IPv4_Header->Protocol == IPPROTO_UDP && ntohs(IPv4_Header->Length) >= IPv4_Header->IHL * IPV4_IHL_BYTES_TIMES + sizeof(udp_hdr) + DNS_PACKET_MINSIZE)
		{
		//Validate UDP checksum.
			if (GetChecksum_TCP_UDP(AF_INET, IPPROTO_UDP, Buffer, ntohs(IPv4_Header->Length) - IPv4_Header->IHL * IPV4_IHL_BYTES_TIMES) != CHECKSUM_SUCCESS)
				return false;

		//Port check
			auto UDP_Header = (pudp_hdr)(Buffer + IPv4_Header->IHL * IPV4_IHL_BYTES_TIMES);
			if (UDP_Header->SrcPort == PacketSource->AddressData.IPv4.sin_port)
			{
			//Domain Test and DNS Options check and get TTL from Domain Test.
				auto IsMarkHopLimit = false;
				auto DataLength = CheckResponseData(
					REQUEST_PROCESS_UDP_NORMAL, 
					(uint8_t *)(Buffer + IPv4_Header->IHL * IPV4_IHL_BYTES_TIMES + sizeof(udp_hdr)), 
					ntohs(IPv4_Header->Length) - IPv4_Header->IHL * IPV4_IHL_BYTES_TIMES - sizeof(udp_hdr), 
					BufferSize, 
					&IsMarkHopLimit);
				if (DataLength < DNS_PACKET_MINSIZE)
					return false;
				else if (IsMarkHopLimit)
					PacketSource->HopLimitData_Mark.TTL = IPv4_Header->TTL;

			//DNSCurve encryption packet check
			#if defined(ENABLE_LIBSODIUM)
				if (Parameter.IsDNSCurve && 
				//Main(IPv4)
					((DNSCurveParameter.DNSCurve_Target_Server_IPv4.AddressData.Storage.ss_family > 0 && 
					DNSCurveParameter.DNSCurve_Target_Server_IPv4.ReceiveMagicNumber != nullptr &&  
					sodium_memcmp(Buffer + IPv4_Header->IHL * IPV4_IHL_BYTES_TIMES + sizeof(udp_hdr), DNSCurveParameter.DNSCurve_Target_Server_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN) == 0) || 
				//Alternate(IPv4)
					(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.AddressData.Storage.ss_family > 0 && 
					DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber != nullptr && 
					sodium_memcmp(Buffer + IPv4_Header->IHL * IPV4_IHL_BYTES_TIMES + sizeof(udp_hdr), DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN) == 0)))
						return false;
			#endif

			//TTL must not a ramdom value.
				if ((PacketSource->HopLimitData_Assign.TTL > 0 && 
					(size_t)IPv4_Header->TTL + (size_t)Parameter.HopLimitFluctuation > (size_t)PacketSource->HopLimitData_Assign.TTL && 
					(size_t)IPv4_Header->TTL < (size_t)PacketSource->HopLimitData_Assign.TTL + (size_t)Parameter.HopLimitFluctuation) || 
					(PacketSource->HopLimitData_Assign.TTL == 0 && 
					(size_t)IPv4_Header->TTL + (size_t)Parameter.HopLimitFluctuation > (size_t)PacketSource->HopLimitData_Mark.TTL && 
					(size_t)IPv4_Header->TTL < (size_t)PacketSource->HopLimitData_Mark.TTL + (size_t)Parameter.HopLimitFluctuation))
				{
					MatchPortToSend(AF_INET, Buffer + IPv4_Header->IHL * IPV4_IHL_BYTES_TIMES + sizeof(udp_hdr), DataLength, BufferSize, UDP_Header->DstPort);
					return true;
				}
			}
		}
	}
	else {
		return false;
	}

	return true;
}

//ICMP header options check
bool CaptureCheck_ICMP(
	const uint16_t Protocol, 
	const uint8_t *Buffer, 
	const size_t Length)
{
//ICMPv6
	if (Protocol == AF_INET6)
	{
		if (((picmpv6_hdr)Buffer)->Type == ICMPV6_TYPE_REPLY && ((picmpv6_hdr)Buffer)->Code == ICMPV6_CODE_REPLY && //ICMPv6 echo reply
			((picmpv6_hdr)Buffer)->ID == Parameter.ICMP_ID) //Validate ICMP packet.
				return true;
	}
//ICMP
	else if (Protocol == AF_INET)
	{
		if (((picmp_hdr)Buffer)->Type == ICMP_TYPE_ECHO && ((picmp_hdr)Buffer)->Code == ICMP_CODE_ECHO && //ICMP echo reply
		//Validate ICMP packet
			((picmp_hdr)Buffer)->ID == Parameter.ICMP_ID && 
			Parameter.ICMP_PaddingData != nullptr && Length == sizeof(icmp_hdr) + Parameter.ICMP_PaddingLength && 
			memcmp(Parameter.ICMP_PaddingData, Buffer + sizeof(icmp_hdr), Parameter.ICMP_PaddingLength) == 0) //Validate ICMP additional data.
				return true;
	}

	return false;
}

//TCP header options check
bool CaptureCheck_TCP(
	const uint8_t *Buffer)
{
	if (
	//CWR bit is set.
		(ntohs(((ptcp_hdr)Buffer)->HeaderLength_Flags) & TCP_GET_BIT_CWR) > 0 || 
	//ECE bit is set.
		(ntohs(((ptcp_hdr)Buffer)->HeaderLength_Flags) & TCP_GET_BIT_ECE) > 0 || 
	//SYN and ACK bits are set, PSH bit is not set and header options are not empty.
		((ntohs(((ptcp_hdr)Buffer)->HeaderLength_Flags) & TCP_GET_BIT_IHL) >> 12U > TCP_STANDARD_IHL && 
		(ntohs(((ptcp_hdr)Buffer)->HeaderLength_Flags) & TCP_GET_BIT_FLAG) == TCP_STATUS_SYN_ACK) || 
		((ntohs(((ptcp_hdr)Buffer)->HeaderLength_Flags) & TCP_GET_BIT_IHL) >> 12U == TCP_STANDARD_IHL && 
	//ACK bit is set and header options are empty.
		((ntohs(((ptcp_hdr)Buffer)->HeaderLength_Flags) & TCP_GET_BIT_FLAG) == TCP_STATUS_ACK || 
	//PSH and ACK bits are set, header options are empty.
		(ntohs(((ptcp_hdr)Buffer)->HeaderLength_Flags) & TCP_GET_BIT_FLAG) == TCP_STATUS_PSH_ACK || 
	//FIN and ACK bits are set and header options are empty.
		(ntohs(((ptcp_hdr)Buffer)->HeaderLength_Flags) & TCP_GET_BIT_FLAG) == TCP_STATUS_FIN_ACK || 
	//RST bit is set, PSH and ACK bits are not set, Window size is zero and header options are empty.
		((ntohs(((ptcp_hdr)Buffer)->HeaderLength_Flags) & TCP_GET_BIT_FLAG) == TCP_STATUS_RST && 
		((ptcp_hdr)Buffer)->Acknowledge == 0 && 
		((ptcp_hdr)Buffer)->Windows == 0))))
			return true;

	return false;
}

//Match socket information of responses and send responses to system sockets process
bool MatchPortToSend(
	const uint16_t Protocol, 
	const uint8_t *Buffer, 
	const size_t Length, 
	const size_t BufferSize, 
	const uint16_t Port)
{
//Initialization
	SOCKET_DATA SocketData_Input;
	memset(&SocketData_Input, 0, sizeof(SocketData_Input));
	uint16_t SystemProtocol = 0;
	size_t ReceiveIndex = 0;

//Match port.
	std::unique_lock<std::mutex> OutputPacketListMutex(OutputPacketListLock);
	for (auto &PortTableIter:OutputPacketList)
	{
		for (auto &SocketDataIter:PortTableIter.SocketData_Output)
		{
			if ((PortTableIter.ClearPortTime > 0 && //Do not scan expired data.
				Protocol == AF_INET6 && SocketDataIter.AddrLen == sizeof(sockaddr_in6) && SocketDataIter.SockAddr.ss_family == AF_INET6 && 
				Port == ((PSOCKADDR_IN6)&SocketDataIter.SockAddr)->sin6_port) || //IPv6
				(Protocol == AF_INET && SocketDataIter.AddrLen == sizeof(sockaddr_in) && SocketDataIter.SockAddr.ss_family == AF_INET && 
				Port == ((PSOCKADDR_IN)&SocketDataIter.SockAddr)->sin_port)) //IPv4
			{
				if (Parameter.ReceiveWaiting > 0)
				{
					++PortTableIter.ReceiveIndex;
					ReceiveIndex = PortTableIter.ReceiveIndex;

					OutputPacketListMutex.unlock();
					goto StopLoop;
				}
				else {
					SocketData_Input = PortTableIter.SocketData_Input;
					SystemProtocol = PortTableIter.Protocol_Network;
					PortTableIter.ClearPortTime = 0;

				//Clear item in global list.
					memset(&PortTableIter.SocketData_Input, 0, sizeof(PortTableIter.SocketData_Input));
					goto ClearOutputPacketListData;
				}
			}
		}
	}

	goto ClearOutputPacketListData;

//Jump here to stop loop, wait receiving and match port again.
StopLoop:
	Sleep(Parameter.ReceiveWaiting);
	OutputPacketListMutex.lock();
	for (auto &PortTableIter:OutputPacketList)
	{
		for (auto &SocketDataIter:PortTableIter.SocketData_Output)
		{
			if (PortTableIter.ClearPortTime > 0 && //Do not scan expired data.
				((Protocol == AF_INET6 && SocketDataIter.AddrLen == sizeof(sockaddr_in6) && SocketDataIter.SockAddr.ss_family == AF_INET6 && 
				Port == ((PSOCKADDR_IN6)&SocketDataIter.SockAddr)->sin6_port) || //IPv6
				(Protocol == AF_INET && SocketDataIter.AddrLen == sizeof(sockaddr_in) && SocketDataIter.SockAddr.ss_family == AF_INET && 
				Port == ((PSOCKADDR_IN)&SocketDataIter.SockAddr)->sin_port))) //IPv4
			{
				if (PortTableIter.ReceiveIndex == ReceiveIndex)
				{
					SocketData_Input = PortTableIter.SocketData_Input;
					SystemProtocol = PortTableIter.Protocol_Network;
					PortTableIter.ClearPortTime = 0;

				//Clear item in global list.
					memset(&PortTableIter.SocketData_Input, 0, sizeof(PortTableIter.SocketData_Input));
					goto ClearOutputPacketListData;
				}
				else {
					return false;
				}
			}
		}
	}

//Jump here to stop loop and clear expired data.
ClearOutputPacketListData:
	while (!OutputPacketList.empty() && OutputPacketList.front().ClearPortTime <= GetCurrentSystemTime())
	{
	//Mark timeout.
		if (OutputPacketList.front().ClearPortTime > 0)
		{
			if (OutputPacketList.front().Protocol_Network == AF_INET6)
			{
				if (OutputPacketList.front().Protocol_Transport == IPPROTO_TCP)
					++AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_MAIN_TCP_IPV6];
				else if (OutputPacketList.front().Protocol_Transport == IPPROTO_UDP)
					++AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_MAIN_UDP_IPV6];
			}
			else if (OutputPacketList.front().Protocol_Network == AF_INET)
			{
				if (OutputPacketList.front().Protocol_Transport == IPPROTO_TCP)
					++AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_MAIN_TCP_IPV4];
				else if (OutputPacketList.front().Protocol_Transport == IPPROTO_UDP)
					++AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_MAIN_UDP_IPV4];
			}
		}

		OutputPacketList.pop_front();
	}
	OutputPacketListMutex.unlock();

//Drop resopnses which not in OutputPacketList.
	if (!SocketSetting(SocketData_Input.Socket, SOCKET_SETTING_INVALID_CHECK, false, nullptr) || 
		SocketData_Input.AddrLen == 0 || SocketData_Input.SockAddr.ss_family == 0 || SystemProtocol == 0)
			return false;

//Mark DNS cache.
	if (Parameter.CacheType > CACHE_TYPE_NONE)
		MarkDomainCache(Buffer, Length);

//Send to requester.
	SendToRequester(SystemProtocol, (uint8_t *)Buffer, Length, BufferSize, SocketData_Input);
	if (SystemProtocol == IPPROTO_TCP)
	{
		return true;
	}
	else if (!GlobalRunningStatus.LocalListeningSocket->empty()) //Check global sockets.
	{
		for (const auto &SocketIter:*GlobalRunningStatus.LocalListeningSocket)
		{
			if (SocketIter == SocketData_Input.Socket)
				return true;
		}
	}

	SocketSetting(SocketData_Input.Socket, SOCKET_SETTING_CLOSE, false, nullptr);
	return true;
}
#endif

// This code is part of Pcap_DNSProxy
// Pcap_DNSProxy, a local DNS server based on WinPcap and LibPcap
// Copyright (C) 2012-2017 Chengr28
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
//Capture filter initialization
	if (!CaptureFilterRulesInit(PcapFilterRules))
	{
		PcapFilterRules.clear();
		return;
	}

//Initialization
	uint8_t ErrorBuffer[PCAP_ERRBUF_SIZE]{0};
	pcap_if *CaptureDriveList = nullptr, *CaptureDriveIter = nullptr;
	std::wstring Message;
	std::string CaptureName, CaptureDescription;
	auto IsDeviceFound = true;
	std::unique_lock<std::mutex> CaptureMutex(CaptureLock, std::defer_lock);

//Capture Monitor
	for (;;)
	{
	//Open all devices.
		if (pcap_findalldevs(&CaptureDriveList, reinterpret_cast<char *>(ErrorBuffer)) < 0)
		{
			if (MBS_To_WCS_String(ErrorBuffer, PCAP_ERRBUF_SIZE, Message))
			{
				Message.append(L"\n");
				PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::PCAP, Message.c_str(), 0, nullptr, 0);
			}
			else {
				PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"Convert multiple byte or wide char string error", 0, nullptr, 0);
			}

			memset(ErrorBuffer, 0, PCAP_ERRBUF_SIZE);
			Sleep(Parameter.FileRefreshTime);
			continue;
		}
	//Permissions and available network devices check.
		else if (CaptureDriveList == nullptr)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::PCAP, L"Insufficient privileges or not any available network devices.", 0, nullptr, 0);
			Sleep(Parameter.FileRefreshTime);

			continue;
		}
	//Mark captures.
		else {
			CaptureMutex.lock();
			if (PcapRunningList.empty())
			{
				CaptureMutex.unlock();

				std::thread CaptureThread(std::bind(CaptureModule, CaptureDriveList, true));
				CaptureThread.detach();
			}
			else {
				CaptureMutex.unlock();
				CaptureDriveIter = CaptureDriveList;

			//Scan all devices.
				while (CaptureDriveIter != nullptr)
				{
					if (CaptureDriveIter->name != nullptr)
					{
					//Capture name and description initialization
						CaptureName = CaptureDriveIter->name;
						CaseConvert(CaptureName, false);
						if (CaptureDriveIter->description != nullptr && strnlen_s(CaptureDriveIter->description, PCAP_CAPTURE_STRING_MAXNUM) > 0)
						{
							CaptureDescription = CaptureDriveIter->description;
							CaseConvert(CaptureDescription, false);
						}
						else {
							CaptureDescription.clear();
						}

					//Capture device blacklist check
						IsDeviceFound = true;
						for (const auto &CaptureIter:*Parameter.PcapDevicesBlacklist)
						{
							if (CaptureName.find(CaptureIter) != std::string::npos || 
								(!CaptureDescription.empty() && CaptureDescription.find(CaptureIter) != std::string::npos))
							{
								IsDeviceFound = false;
								break;
							}
						}

					//Skip this capture.
						if (!IsDeviceFound)
						{
							CaptureDriveIter = CaptureDriveIter->next;
							continue;
						}

					//Capture monitor
						IsDeviceFound = true;
						CaptureMutex.lock();
						for (const auto &CaptureIter:PcapRunningList)
						{
							if (CaptureIter == CaptureDriveIter->name)
							{
								IsDeviceFound = false;
								break;
							}
						}
						CaptureMutex.unlock();

					//Start a capture monitor.
						if (IsDeviceFound)
						{
							std::thread CaptureThread(std::bind(CaptureModule, CaptureDriveIter, false));
							CaptureThread.detach();
						}
					}

					CaptureDriveIter = CaptureDriveIter->next;
				}
			}
		}

	//Reset parameters.
		Sleep(Parameter.FileRefreshTime);
		pcap_freealldevs(CaptureDriveList);
		CaptureDriveList = nullptr;
	}

//Monitor terminated
	PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"Capture module Monitor terminated", 0, nullptr, 0);
	return;
}

//Make filter rule of captures
//About filter rules, please visit https://www.winpcap.org/docs/docs_412/html/group__language.html.
bool CaptureFilterRulesInit(
	std::string &FilterRules)
{
//Initialization(Part 1)
	std::vector<DNS_SERVER_DATA *> AddrList;
	auto IsRepeatItem = false;

//IPv6
	if (Parameter.RequestMode_Network == REQUEST_MODE_NETWORK::BOTH || Parameter.RequestMode_Network == REQUEST_MODE_NETWORK::IPV6 || //IPv6
		(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK::IPV4 && Parameter.Target_Server_Main_IPv4.AddressData.Storage.ss_family == 0)) //Non-IPv4
	{
	//Main
		if (Parameter.Target_Server_Main_IPv6.AddressData.Storage.ss_family != 0)
			AddrList.push_back(&Parameter.Target_Server_Main_IPv6);

	//Alternate
		if (Parameter.Target_Server_Alternate_IPv6.AddressData.Storage.ss_family != 0)
		{
		//Check repeat items.
			for (const auto &DNSServerDataIter:AddrList)
			{
				if (DNSServerDataIter->AddressData.Storage.ss_family == Parameter.Target_Server_Alternate_IPv6.AddressData.Storage.ss_family && 
					memcmp(&DNSServerDataIter->AddressData.IPv6.sin6_addr, &Parameter.Target_Server_Alternate_IPv6.AddressData.IPv6.sin6_addr, sizeof(DNSServerDataIter->AddressData.IPv6.sin6_addr)) == 0)
				{
					IsRepeatItem = true;
					break;
				}
			}

		//Add to address list.
			if (!IsRepeatItem)
				AddrList.push_back(&Parameter.Target_Server_Alternate_IPv6);

			IsRepeatItem = false;
		}

	//Multiple list(IPv6)
		if (Parameter.Target_Server_IPv6_Multiple != nullptr)
		{
			for (auto &DNSServerDataIter:*Parameter.Target_Server_IPv6_Multiple)
			{
			//Check repeat items.
				for (const auto &DNSServerDataInnerIter:AddrList)
				{
					if (DNSServerDataInnerIter->AddressData.Storage.ss_family == DNSServerDataIter.AddressData.Storage.ss_family && 
						memcmp(&DNSServerDataInnerIter->AddressData.IPv6.sin6_addr, &DNSServerDataIter.AddressData.IPv6.sin6_addr, sizeof(DNSServerDataInnerIter->AddressData.IPv6.sin6_addr)) == 0)
					{
						IsRepeatItem = true;
						break;
					}
				}

			//Add to address list.
				if (!IsRepeatItem)
					AddrList.push_back(&DNSServerDataIter);

				IsRepeatItem = false;
			}
		}
	}

//IPv4
	if (Parameter.RequestMode_Network == REQUEST_MODE_NETWORK::BOTH || Parameter.RequestMode_Network == REQUEST_MODE_NETWORK::IPV4 || //IPv4
		(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK::IPV6 && Parameter.Target_Server_Main_IPv6.AddressData.Storage.ss_family == 0)) //Non-IPv6
	{
	//Main
		if (Parameter.Target_Server_Main_IPv4.AddressData.Storage.ss_family != 0)
			AddrList.push_back(&Parameter.Target_Server_Main_IPv4);

	//Alternate
		if (Parameter.Target_Server_Alternate_IPv4.AddressData.Storage.ss_family != 0)
		{
		//Check repeat items.
			for (const auto &DNSServerDataIter:AddrList)
			{
				if (DNSServerDataIter->AddressData.Storage.ss_family == Parameter.Target_Server_Alternate_IPv4.AddressData.Storage.ss_family && 
					DNSServerDataIter->AddressData.IPv4.sin_addr.s_addr == Parameter.Target_Server_Alternate_IPv4.AddressData.IPv4.sin_addr.s_addr)
				{
					IsRepeatItem = true;
					break;
				}
			}

		//Add to address list.
			if (!IsRepeatItem)
				AddrList.push_back(&Parameter.Target_Server_Alternate_IPv4);

			IsRepeatItem = false;
		}

	//Multiple list(IPv4)
		if (Parameter.Target_Server_IPv4_Multiple != nullptr)
		{
			for (auto &DNSServerDataIter:*Parameter.Target_Server_IPv4_Multiple)
			{
			//Check repeat items.
				for (const auto &DNSServerDataInnerIter:AddrList)
				{
					if (DNSServerDataInnerIter->AddressData.Storage.ss_family == DNSServerDataIter.AddressData.Storage.ss_family && 
						DNSServerDataInnerIter->AddressData.IPv4.sin_addr.s_addr == DNSServerDataIter.AddressData.IPv4.sin_addr.s_addr)
					{
						IsRepeatItem = true;
						break;
					}
				}

			//Add to address list.
				if (!IsRepeatItem)
					AddrList.push_back(&DNSServerDataIter);

				IsRepeatItem = false;
			}
		}
	}

//Address list check
	if (AddrList.empty())
		return false;

//Initialization(Part 2)
	uint8_t AddrBuffer[ADDRESS_STRING_MAXSIZE]{0};
	std::string AddrString;
	FilterRules.clear();
	FilterRules.append("(src host ");
	ssize_t Result = 0;

//List all target addresses.
	IsRepeatItem = false;
	for (const auto &DNSServerDataIter:AddrList)
	{
		if (DNSServerDataIter->AddressData.Storage.ss_family == AF_INET6)
		{
		//Add joiner.
			if (IsRepeatItem)
				AddrString.append(" or ");
			IsRepeatItem = true;

		//Convert binary to address string.
			if (!BinaryToAddressString(AF_INET6, &DNSServerDataIter->AddressData.IPv6.sin6_addr, AddrBuffer, ADDRESS_STRING_MAXSIZE, &Result))
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv6 address format error", Result, nullptr, 0);
				return false;
			}

		//Add assress string to end.
			AddrString.append(reinterpret_cast<const char *>(AddrBuffer));
			memset(AddrBuffer, 0, ADDRESS_STRING_MAXSIZE);
		}
		else if (DNSServerDataIter->AddressData.Storage.ss_family == AF_INET)
		{
		//Add joiner.
			if (IsRepeatItem)
				AddrString.append(" or ");
			IsRepeatItem = true;

		//Convert binary to address string.
			if (!BinaryToAddressString(AF_INET, &DNSServerDataIter->AddressData.IPv4.sin_addr, AddrBuffer, ADDRESS_STRING_MAXSIZE, &Result))
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv4 address format error", Result, nullptr, 0);
				return false;
			}

		//Add assress string to end.
			AddrString.append(reinterpret_cast<const char *>(AddrBuffer));
			memset(AddrBuffer, 0, ADDRESS_STRING_MAXSIZE);
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
	const pcap_if * const DriveInterface, 
	const bool IsCaptureList)
{
//Devices name, addresses and type check
	if (DriveInterface == nullptr)
	{
		return false;
	}
#if defined(PLATFORM_WIN)
	else if (DriveInterface->name == nullptr || DriveInterface->addresses == nullptr || DriveInterface->addresses->netmask == nullptr || 
		DriveInterface->flags == PCAP_IF_LOOPBACK)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	else if (DriveInterface->name == nullptr || DriveInterface->addresses == nullptr || DriveInterface->flags == PCAP_IF_LOOPBACK)
#endif
	{
		if (IsCaptureList && DriveInterface->next != nullptr)
		{
			std::thread CaptureThread(std::bind(CaptureModule, DriveInterface->next, true));
			CaptureThread.detach();
		}

		return true;
	}

//Initialization
	CAPTURE_DEVICE_TABLE DeviceTable;

//Pcap device blacklist check
	if (IsCaptureList)
	{
	//Capture name and description initialization
		*DeviceTable.DeviceName = DriveInterface->name;
		CaseConvert(*DeviceTable.DeviceName, false);
		std::string CaptureDescription;
		if (DriveInterface->description != nullptr && strnlen_s(DriveInterface->description, PCAP_CAPTURE_STRING_MAXNUM) > 0)
		{
			CaptureDescription = DriveInterface->description;
			CaseConvert(CaptureDescription, false);
		}

	//Check process.
		for (const auto &CaptureIter:*Parameter.PcapDevicesBlacklist)
		{
			if (DeviceTable.DeviceName->find(CaptureIter) != std::string::npos || 
				(!CaptureDescription.empty() && CaptureDescription.find(CaptureIter) != std::string::npos))
			{
				if (DriveInterface->next != nullptr)
				{
					std::thread CaptureThread(std::bind(CaptureModule, DriveInterface->next, true));
					CaptureThread.detach();
				}

				return true;
			}
		}
	}

//Initialization(Part 1)
	std::unique_ptr<uint8_t[]> Buffer(new uint8_t[Parameter.LargeBufferSize + PADDING_RESERVED_BYTES]());
	memset(Buffer.get(), 0, Parameter.LargeBufferSize + PADDING_RESERVED_BYTES);
	*DeviceTable.DeviceName = DriveInterface->name;
	DeviceTable.DeviceName->shrink_to_fit();

//Open device
#if defined(PLATFORM_WIN)
	DeviceTable.DeviceHandle = pcap_open(DriveInterface->name, static_cast<int>(Parameter.LargeBufferSize), 0, static_cast<int>(Parameter.PcapReadingTimeout), nullptr, reinterpret_cast<char *>(Buffer.get()));
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	DeviceTable.DeviceHandle = pcap_open_live(DriveInterface->name, static_cast<int>(Parameter.LargeBufferSize), 0, static_cast<int>(Parameter.PcapReadingTimeout), reinterpret_cast<char *>(Buffer.get()));
#endif
	if (DeviceTable.DeviceHandle == nullptr)
	{
		std::wstring Message;
		if (MBS_To_WCS_String(Buffer.get(), PCAP_ERRBUF_SIZE, Message))
		{
			Message.append(L"\n");
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::PCAP, Message.c_str(), 0, nullptr, 0);
		}
		else {
			PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"Convert multiple byte or wide char string error", 0, nullptr, 0);
		}

		return false;
	}

//Check device type.
	DeviceTable.DeviceType = pcap_datalink(DeviceTable.DeviceHandle);
	if (DeviceTable.DeviceType == DLT_EN10MB || //Ethernet II(Standard)
		DeviceTable.DeviceType == DLT_PPP_ETHER || //PPP over Ethernet/PPPoE
		DeviceTable.DeviceType == DLT_EN3MB || //Ethernet II(Experiment)
		DeviceTable.DeviceType == DLT_APPLE_IP_OVER_IEEE1394) //Apple IEEE 1394
	{
		if (DeviceTable.DeviceType == DLT_PPP_ETHER || DeviceTable.DeviceType == DLT_EN3MB)
			DeviceTable.DeviceType = DLT_EN10MB;
	}
	else {
		return false;
	}

//Compile the string into a filter program.
#if defined(PLATFORM_WIN)
	if (pcap_compile(DeviceTable.DeviceHandle, &DeviceTable.BPF_Code, PcapFilterRules.c_str(), PCAP_COMPILE_OPTIMIZE, 0) == PCAP_ERROR)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	if (pcap_compile(DeviceTable.DeviceHandle, &DeviceTable.BPF_Code, PcapFilterRules.c_str(), PCAP_COMPILE_OPTIMIZE, PCAP_NETMASK_UNKNOWN) == PCAP_ERROR)
#endif
	{
		std::wstring Message;
		if (MBS_To_WCS_String(reinterpret_cast<const uint8_t *>(pcap_geterr(DeviceTable.DeviceHandle)), PCAP_ERRBUF_SIZE, Message))
		{
			Message.append(L"\n");
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::PCAP, Message.c_str(), 0, nullptr, 0);
		}
		else {
			PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"Convert multiple byte or wide char string error", 0, nullptr, 0);
		}

		return false;
	}

//Specify a filter program.
	if (pcap_setfilter(DeviceTable.DeviceHandle, &DeviceTable.BPF_Code) == PCAP_ERROR)
	{
		std::wstring Message;
		if (MBS_To_WCS_String(reinterpret_cast<const uint8_t *>(pcap_geterr(DeviceTable.DeviceHandle)), PCAP_ERRBUF_SIZE, Message))
		{
			Message.append(L"\n");
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::PCAP, Message.c_str(), 0, nullptr, 0);
		}
		else {
			PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"Convert multiple byte or wide char string error", 0, nullptr, 0);
		}

		return false;
	}

//Start capture with other devices.
	std::unique_lock<std::mutex> CaptureMutex(CaptureLock);
	PcapRunningList.push_back(*DeviceTable.DeviceName);
	CaptureMutex.unlock();
	if (IsCaptureList && DriveInterface->next != nullptr)
	{
		std::thread CaptureThread(std::bind(CaptureModule, DriveInterface->next, true));
		CaptureThread.detach();
	}

//Initialization(Part 2)
	CAPTURE_HANDLER_PARAM ParamList;
	memset(&ParamList, 0, sizeof(ParamList));
	ParamList.DeviceType = DeviceTable.DeviceType;
	ParamList.Buffer = Buffer.get();
	ParamList.BufferSize = Parameter.LargeBufferSize;

//Start Pcap Monitor.
	for (;;)
	{
		ssize_t Result = pcap_loop(DeviceTable.DeviceHandle, PCAP_LOOP_INFINITY, CaptureHandler, reinterpret_cast<unsigned char *>(&ParamList));
		if (Result < 0)
		{
		//Delete this capture from device list.
			CaptureMutex.lock();
			for (auto CaptureIter = PcapRunningList.begin();CaptureIter != PcapRunningList.end();)
			{
				if (*CaptureIter == *DeviceTable.DeviceName)
					CaptureIter = PcapRunningList.erase(CaptureIter);
				else 
					++CaptureIter;
			}

			return false;
		}
		else {
			Sleep(Parameter.FileRefreshTime);
		}
	}

//Monitor terminated
	PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"Capture module Monitor terminated", 0, nullptr, 0);
	return true;
}

//Handler of WinPcap/LibPcap loop function
void CaptureHandler(
	uint8_t * const ProcParameter, 
	const pcap_pkthdr * const PacketHeader, 
	const uint8_t * const PacketData)
{
//Initialization
	const auto ParamList = reinterpret_cast<CAPTURE_HANDLER_PARAM *>(ProcParameter);
	memset(ParamList->Buffer, 0, Parameter.LargeBufferSize);
	size_t Length = PacketHeader->caplen;
	uint16_t Protocol = 0;

//OSI Layer 2
	if (ParamList->DeviceType == DLT_EN10MB) //Ethernet II
	{
		if (Length <= sizeof(eth_hdr))
		{
			return;
		}
		else {
			memcpy_s(ParamList->Buffer, Parameter.LargeBufferSize, PacketData + sizeof(eth_hdr), Length - sizeof(eth_hdr));
			Protocol = (reinterpret_cast<const eth_hdr *>(PacketData))->Type;
			Length -= sizeof(eth_hdr);
		}
	}
	else if (ParamList->DeviceType == DLT_APPLE_IP_OVER_IEEE1394) //Apple IEEE 1394
	{
		if (Length <= sizeof(ieee_1394_hdr))
		{
			return;
		}
		else {
			memcpy_s(ParamList->Buffer, Parameter.LargeBufferSize, PacketData + sizeof(ieee_1394_hdr), Length - sizeof(ieee_1394_hdr));
			Protocol = (reinterpret_cast<const ieee_1394_hdr *>(PacketData))->Type;
			Length -= sizeof(ieee_1394_hdr);
		}
	}
	else {
		return;
	}

//Virtual Bridged LAN(VLAN, IEEE 802.1Q)
	if (ntohs(Protocol) == OSI_L2_VLAN)
	{
		if (Length <= sizeof(ieee_8021q_hdr))
		{
			return;
		}
		else {
			Protocol = (reinterpret_cast<ieee_8021q_hdr *>(ParamList->Buffer))->Type;
			memmove_s(ParamList->Buffer, Parameter.LargeBufferSize, ParamList->Buffer + sizeof(ieee_8021q_hdr), Length - sizeof(ieee_8021q_hdr));
			Length -= sizeof(ieee_8021q_hdr);
		}
	}

//PPP(Such as ADSL, a part of organization networks)
	if (ntohs(Protocol) == OSI_L2_PPPS)
	{
		if (Length <= sizeof(ppp_hdr))
		{
			return;
		}
		else {
			Protocol = (reinterpret_cast<ppp_hdr *>(ParamList->Buffer))->Protocol;
			memmove_s(ParamList->Buffer, Parameter.LargeBufferSize, ParamList->Buffer + sizeof(ppp_hdr), Length - sizeof(ppp_hdr));
			Length -= sizeof(ppp_hdr);
		}
	}

//LAN, WLAN and IEEE 802.1X, some Mobile Communications Standard/MCS devices which disguise as a LAN
	if (((ntohs(Protocol) == OSI_L2_IPV6 || ntohs(Protocol) == PPP_IPV6) && Length > sizeof(ipv6_hdr)) || //IPv6
		((ntohs(Protocol) == OSI_L2_IPV4 || ntohs(Protocol) == PPP_IPV4) && Length > sizeof(ipv4_hdr))) //IPv4
			CaptureNetworkLayer(ntohs(Protocol), ParamList->Buffer, Length, ParamList->BufferSize);

	return;
}

//Network Layer(Internet Protocol/IP) process
bool CaptureNetworkLayer(
	const uint16_t Protocol, 
	const uint8_t * const Buffer, 
	const size_t Length, 
	const size_t BufferSize)
{
//Initialization
	DNS_SERVER_DATA *PacketSource = nullptr;

//IPv6
	if ((Protocol == PPP_IPV6 || Protocol == OSI_L2_IPV6) && 
		Parameter.DirectRequest != REQUEST_MODE_DIRECT::BOTH && Parameter.DirectRequest != REQUEST_MODE_DIRECT::IPV6)
	{
		const auto IPv6_Header = reinterpret_cast<const ipv6_hdr *>(Buffer);

	//Validate IPv6 header length.
		if (ntohs(IPv6_Header->PayloadLength) + sizeof(ipv6_hdr) > Length)
			return false;

	//Mark source of packet.
		if (memcmp(&IPv6_Header->Source, &Parameter.Target_Server_Main_IPv6.AddressData.IPv6.sin6_addr, sizeof(IPv6_Header->Source)) == 0)
		{
			PacketSource = &Parameter.Target_Server_Main_IPv6;
		}
		else if (memcmp(&IPv6_Header->Source, &Parameter.Target_Server_Alternate_IPv6.AddressData.IPv6.sin6_addr, sizeof(IPv6_Header->Source)) == 0)
		{
			PacketSource = &Parameter.Target_Server_Alternate_IPv6;
		}
		else if (Parameter.Target_Server_IPv6_Multiple != nullptr)
		{
			for (const auto &DNSServerDataIter:*Parameter.Target_Server_IPv6_Multiple)
			{
				if (memcmp(&IPv6_Header->Source, &DNSServerDataIter.AddressData.IPv6.sin6_addr, sizeof(IPv6_Header->Source)) == 0)
				{
					PacketSource = const_cast<DNS_SERVER_DATA *>(&DNSServerDataIter);
					break;
				}
			}

		//Source of packet pointer check.
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
			else if (CaptureCheck_ICMP(AF_INET6, Buffer + sizeof(ipv6_hdr), ntohs(IPv6_Header->PayloadLength)))
				PacketSource->ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_Mark = IPv6_Header->HopLimit;
			else 
				return true;
		}

	//TCP
		if (Parameter.PacketCheck_TCP && IPv6_Header->NextHeader == IPPROTO_TCP && ntohs(IPv6_Header->PayloadLength) >= sizeof(tcp_hdr))
		{
		//Validate TCP checksum.
			if (GetChecksum_TCP_UDP(AF_INET6, IPPROTO_TCP, Buffer, ntohs(IPv6_Header->PayloadLength)) != CHECKSUM_SUCCESS)
				return false;
		//TCP packet check
			else if (CaptureCheck_TCP(Buffer + sizeof(ipv6_hdr)))
				PacketSource->ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_Mark = IPv6_Header->HopLimit;
			else 
				return true;
		}

	//UDP
		if (IPv6_Header->NextHeader == IPPROTO_UDP && ntohs(IPv6_Header->PayloadLength) >= sizeof(udp_hdr) + DNS_PACKET_MINSIZE)
		{
		//Validate UDP checksum.
			if (GetChecksum_TCP_UDP(AF_INET6, IPPROTO_UDP, Buffer, ntohs(IPv6_Header->PayloadLength)) != CHECKSUM_SUCCESS)
				return false;

		//Port check
			const auto UDP_Header = reinterpret_cast<const udp_hdr *>(Buffer + sizeof(ipv6_hdr));
			if (UDP_Header->SourcePort == PacketSource->AddressData.IPv6.sin6_port)
			{
			//Response check
				const auto DataLength = CheckResponseData(
					REQUEST_PROCESS_TYPE::UDP_NORMAL, 
					const_cast<uint8_t *>(Buffer + sizeof(ipv6_hdr) + sizeof(udp_hdr)), 
					ntohs(IPv6_Header->PayloadLength) - sizeof(udp_hdr), 
					BufferSize);
				if (DataLength < DNS_PACKET_MINSIZE)
					return false;

			//DNSCurve encryption packet check
			#if defined(ENABLE_LIBSODIUM)
				if (Parameter.IsDNSCurve && 
				//Main(IPv6)
					((DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.AddressData.Storage.ss_family != 0 && 
					DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber != nullptr && 
					sodium_memcmp(Buffer + sizeof(ipv6_hdr) + sizeof(udp_hdr), DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN) == 0) || 
				//Alternate(IPv6)
					(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.AddressData.Storage.ss_family != 0 && 
					DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber != nullptr && 
					sodium_memcmp(Buffer + sizeof(ipv6_hdr) + sizeof(udp_hdr), DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN) == 0)))
						return false;
			#endif

			//DNS packet check
				if (Parameter.PacketCheck_DNS)
				{
				//DNS header options and data check
					auto IsMarkStatus = false;
					if (CaptureCheck_DNS(Buffer + sizeof(ipv6_hdr) + sizeof(udp_hdr), IsMarkStatus))
					{
						PacketSource->ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_Mark = IPv6_Header->HopLimit;

					//Mark packet status.
						if (IsMarkStatus)
						{
							CaptureCheck_PacketStatus(Buffer, sizeof(ipv6_hdr) + sizeof(udp_hdr), AF_INET6, true, PacketSource);
							PacketSource->ServerPacketStatus.IsMarkSign = true;
						}
					}

				//Packet status check
					if (!IsMarkStatus && PacketSource->ServerPacketStatus.IsMarkSign && 
						!CaptureCheck_PacketStatus(Buffer, sizeof(ipv6_hdr) + sizeof(udp_hdr), AF_INET6, false, PacketSource))
							return false;
				}

			//Match port in global list.
			//Hop Limits must not a ramdom value.
				if ((PacketSource->ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_Assign > 0 && 
					static_cast<size_t>(IPv6_Header->HopLimit) + static_cast<size_t>(Parameter.HopLimitsFluctuation) > static_cast<size_t>(PacketSource->ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_Assign) && 
					static_cast<size_t>(IPv6_Header->HopLimit) < static_cast<size_t>(PacketSource->ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_Assign) + static_cast<size_t>(Parameter.HopLimitsFluctuation)) || 
					(PacketSource->ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_Assign == 0 && 
					static_cast<size_t>(IPv6_Header->HopLimit) + static_cast<size_t>(Parameter.HopLimitsFluctuation) > static_cast<size_t>(PacketSource->ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_Mark) && 
					static_cast<size_t>(IPv6_Header->HopLimit) < static_cast<size_t>(PacketSource->ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_Mark) + static_cast<size_t>(Parameter.HopLimitsFluctuation)))
				{
					MatchPortToSend(AF_INET6, Buffer + sizeof(ipv6_hdr) + sizeof(udp_hdr), DataLength, BufferSize, UDP_Header->DestinationPort);
					return true;
				}
			}
		}
	}
//IPv4
	else if ((Protocol == PPP_IPV4 || Protocol == OSI_L2_IPV4) && 
		Parameter.DirectRequest != REQUEST_MODE_DIRECT::BOTH && Parameter.DirectRequest != REQUEST_MODE_DIRECT::IPV4)
	{
		const auto IPv4_Header = reinterpret_cast<const ipv4_hdr *>(Buffer);

	//Validate IPv4 header.
		if (ntohs(IPv4_Header->Length) <= IPv4_Header->IHL * IPV4_IHL_BYTES_TIMES || ntohs(IPv4_Header->Length) > Length || 
			GetChecksum(reinterpret_cast<const uint16_t *>(Buffer), sizeof(ipv4_hdr)) != CHECKSUM_SUCCESS)
				return false;

	//Mark source of packet.
		if (IPv4_Header->Source.s_addr == Parameter.Target_Server_Main_IPv4.AddressData.IPv4.sin_addr.s_addr)
		{
			PacketSource = &Parameter.Target_Server_Main_IPv4;
		}
		else if (IPv4_Header->Source.s_addr == Parameter.Target_Server_Alternate_IPv4.AddressData.IPv4.sin_addr.s_addr)
		{
			PacketSource = &Parameter.Target_Server_Alternate_IPv4;
		}
		else if (Parameter.Target_Server_IPv4_Multiple != nullptr)
		{
			for (const auto &DNSServerDataIter:*Parameter.Target_Server_IPv4_Multiple)
			{
				if (IPv4_Header->Source.s_addr == DNSServerDataIter.AddressData.IPv4.sin_addr.s_addr)
				{
					PacketSource = const_cast<DNS_SERVER_DATA *>(&DNSServerDataIter);
					break;
				}
			}

		//Source of packet pointer check.
			if (PacketSource == nullptr)
				return false;
		}
		else {
			return false;
		}

	//Get TTL from IPv4 DNS server.
	//ICMP
		if (Parameter.ICMP_Speed > 0 && IPv4_Header->Protocol == IPPROTO_ICMP && 
			ntohs(IPv4_Header->Length) >= IPv4_Header->IHL * IPV4_IHL_BYTES_TIMES + sizeof(icmp_hdr))
		{
		//Validate ICMP checksum.
			if (GetChecksum(reinterpret_cast<const uint16_t *>(Buffer + IPv4_Header->IHL * IPV4_IHL_BYTES_TIMES), ntohs(IPv4_Header->Length) - IPv4_Header->IHL * IPV4_IHL_BYTES_TIMES) != CHECKSUM_SUCCESS)
				return false;
		//ICMP Check
			else if (CaptureCheck_ICMP(AF_INET, Buffer + IPv4_Header->IHL * IPV4_IHL_BYTES_TIMES, ntohs(IPv4_Header->Length) - IPv4_Header->IHL * IPV4_IHL_BYTES_TIMES))
				PacketSource->ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_Mark = IPv4_Header->TTL;
			else 
				return true;
		}

	//TCP
		if (Parameter.PacketCheck_TCP && IPv4_Header->Protocol == IPPROTO_TCP && ntohs(IPv4_Header->Length) >= IPv4_Header->IHL * IPV4_IHL_BYTES_TIMES + sizeof(tcp_hdr))
		{
		//Validate TCP checksum.
			if (GetChecksum_TCP_UDP(AF_INET, IPPROTO_TCP, Buffer, ntohs(IPv4_Header->Length) - IPv4_Header->IHL * IPV4_IHL_BYTES_TIMES) != CHECKSUM_SUCCESS)
				return false;
		//Packet check
			else if (CaptureCheck_TCP(Buffer + IPv4_Header->IHL * IPV4_IHL_BYTES_TIMES))
				PacketSource->ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_Mark = IPv4_Header->TTL;
			else 
				return true;
		}

	//UDP
		if (IPv4_Header->Protocol == IPPROTO_UDP && ntohs(IPv4_Header->Length) >= IPv4_Header->IHL * IPV4_IHL_BYTES_TIMES + sizeof(udp_hdr) + DNS_PACKET_MINSIZE)
		{
		//Validate UDP checksum.
			if (GetChecksum_TCP_UDP(AF_INET, IPPROTO_UDP, Buffer, ntohs(IPv4_Header->Length) - IPv4_Header->IHL * IPV4_IHL_BYTES_TIMES) != CHECKSUM_SUCCESS)
				return false;

		//Port check
			const auto UDP_Header = reinterpret_cast<const udp_hdr *>(Buffer + IPv4_Header->IHL * IPV4_IHL_BYTES_TIMES);
			if (UDP_Header->SourcePort == PacketSource->AddressData.IPv4.sin_port)
			{
			//Response check
				const auto DataLength = CheckResponseData(
					REQUEST_PROCESS_TYPE::UDP_NORMAL, 
					const_cast<uint8_t *>(Buffer + IPv4_Header->IHL * IPV4_IHL_BYTES_TIMES + sizeof(udp_hdr)), 
					ntohs(IPv4_Header->Length) - IPv4_Header->IHL * IPV4_IHL_BYTES_TIMES - sizeof(udp_hdr), 
					BufferSize);
				if (DataLength < DNS_PACKET_MINSIZE)
					return false;

			//DNSCurve encryption packet check
			#if defined(ENABLE_LIBSODIUM)
				if (Parameter.IsDNSCurve && 
				//Main(IPv4)
					((DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.AddressData.Storage.ss_family != 0 && 
					DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber != nullptr && 
					sodium_memcmp(Buffer + IPv4_Header->IHL * IPV4_IHL_BYTES_TIMES + sizeof(udp_hdr), DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN) == 0) || 
				//Alternate(IPv4)
					(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.AddressData.Storage.ss_family != 0 && 
					DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber != nullptr && 
					sodium_memcmp(Buffer + IPv4_Header->IHL * IPV4_IHL_BYTES_TIMES + sizeof(udp_hdr), DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN) == 0)))
						return false;
			#endif

			//DNS packet check
				if (Parameter.PacketCheck_DNS)
				{
				//DNS header options and data check
					auto IsMarkStatus = false;
					if (CaptureCheck_DNS(Buffer + IPv4_Header->IHL * IPV4_IHL_BYTES_TIMES + sizeof(udp_hdr), IsMarkStatus))
					{
						PacketSource->ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_Mark = IPv4_Header->TTL;

					//Mark packet status.
						if (IsMarkStatus)
						{
							CaptureCheck_PacketStatus(Buffer, IPv4_Header->IHL * IPV4_IHL_BYTES_TIMES + sizeof(udp_hdr), AF_INET, true, PacketSource);
							PacketSource->ServerPacketStatus.IsMarkSign = true;
						}
					}

				//Packet status check
					if (!IsMarkStatus && PacketSource->ServerPacketStatus.IsMarkSign && 
						!CaptureCheck_PacketStatus(Buffer, IPv4_Header->IHL * IPV4_IHL_BYTES_TIMES + sizeof(udp_hdr), AF_INET, false, PacketSource))
							return false;
				}

			//Match port in global list.
			//TTL must not a ramdom value.
				if ((PacketSource->ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_Assign > 0 && 
					static_cast<size_t>(IPv4_Header->TTL) + static_cast<size_t>(Parameter.HopLimitsFluctuation) > static_cast<size_t>(PacketSource->ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_Assign) && 
					static_cast<size_t>(IPv4_Header->TTL) < static_cast<size_t>(PacketSource->ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_Assign) + static_cast<size_t>(Parameter.HopLimitsFluctuation)) || 
					(PacketSource->ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_Assign == 0 && 
					static_cast<size_t>(IPv4_Header->TTL) + static_cast<size_t>(Parameter.HopLimitsFluctuation) > static_cast<size_t>(PacketSource->ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_Mark) && 
					static_cast<size_t>(IPv4_Header->TTL) < static_cast<size_t>(PacketSource->ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_Mark) + static_cast<size_t>(Parameter.HopLimitsFluctuation)))
				{
					MatchPortToSend(AF_INET, Buffer + IPv4_Header->IHL * IPV4_IHL_BYTES_TIMES + sizeof(udp_hdr), DataLength, BufferSize, UDP_Header->DestinationPort);
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
	const uint8_t * const Buffer, 
	const size_t Length)
{
//ICMPv6
	if ((Protocol == AF_INET6 && 
	//ICMPv6 echo reply
		(reinterpret_cast<const icmpv6_hdr *>(Buffer))->Type == ICMPV6_TYPE_REPLY && (reinterpret_cast<const icmpv6_hdr *>(Buffer))->Code == ICMPV6_CODE_REPLY && 
	//Validate ICMPv6 ID.
		(reinterpret_cast<const icmpv6_hdr *>(Buffer))->ID == Parameter.ICMP_ID) || 
//ICMP
		(Protocol == AF_INET && 
	//ICMP echo reply
		(reinterpret_cast<const icmp_hdr *>(Buffer))->Type == ICMP_TYPE_ECHO && (reinterpret_cast<const icmpv6_hdr *>(Buffer))->Code == ICMP_CODE_ECHO && 
	//Validate ICMP ID.
		(reinterpret_cast<const icmp_hdr *>(Buffer))->ID == Parameter.ICMP_ID && 
	//Validate ICMP additional data.
		Parameter.ICMP_PaddingData != nullptr && Length == sizeof(icmp_hdr) + Parameter.ICMP_PaddingLength && 
		memcmp(Parameter.ICMP_PaddingData, Buffer + sizeof(icmp_hdr), Parameter.ICMP_PaddingLength) == 0))
			return true;

	return false;
}

//TCP header options check
bool CaptureCheck_TCP(
	const uint8_t * const Buffer)
{
	if (
	//CWR bit is set.
		(ntohs((reinterpret_cast<const tcp_hdr *>(Buffer))->HeaderLength_Flags) & TCP_GET_BIT_CWR) > 0 || 
	//ECE bit is set.
		(ntohs((reinterpret_cast<const tcp_hdr *>(Buffer))->HeaderLength_Flags) & TCP_GET_BIT_ECE) > 0 || 
	//SYN and ACK bits are set, PSH bit is not set, header options are not empty but it must not only MSS option.
		((ntohs((reinterpret_cast<const tcp_hdr *>(Buffer))->HeaderLength_Flags) & TCP_GET_BIT_IHL) >> 12U > TCP_STANDARD_IHL + sizeof(uint8_t) && 
		(ntohs((reinterpret_cast<const tcp_hdr *>(Buffer))->HeaderLength_Flags) & TCP_GET_BIT_FLAG) == TCP_STATUS_SYN_ACK) || 
	//Standard IHL
		((ntohs((reinterpret_cast<const tcp_hdr *>(Buffer))->HeaderLength_Flags) & TCP_GET_BIT_IHL) >> 12U == TCP_STANDARD_IHL && 
	//ACK bit is set and header options are empty.
		((ntohs((reinterpret_cast<const tcp_hdr *>(Buffer))->HeaderLength_Flags) & TCP_GET_BIT_FLAG) == TCP_STATUS_ACK || 
	//PSH and ACK bits are set, header options are empty.
		(ntohs((reinterpret_cast<const tcp_hdr *>(Buffer))->HeaderLength_Flags) & TCP_GET_BIT_FLAG) == TCP_STATUS_PSH_ACK || 
	//FIN and ACK bits are set and header options are empty.
		(ntohs((reinterpret_cast<const tcp_hdr *>(Buffer))->HeaderLength_Flags) & TCP_GET_BIT_FLAG) == TCP_STATUS_FIN_ACK || 
	//RST bit is set, PSH and ACK bits are not set, Window Size is zero and header options are empty.
		((ntohs((reinterpret_cast<const tcp_hdr *>(Buffer))->HeaderLength_Flags) & TCP_GET_BIT_FLAG) == TCP_STATUS_RST && 
		(reinterpret_cast<const tcp_hdr *>(Buffer))->Acknowledge == 0 && (reinterpret_cast<const tcp_hdr *>(Buffer))->Windows == 0))))
			return true;

	return false;
}

//DNS header options and data check
bool CaptureCheck_DNS(
	const uint8_t * const Buffer, 
	bool &IsMarkStatus)
{
//Domain Test part
	if (Parameter.DomainTest_Speed > 0 && Parameter.DomainTest_Data != nullptr && 
		reinterpret_cast<const dns_hdr *>(Buffer)->ID == Parameter.DomainTest_ID && 
		reinterpret_cast<const dns_hdr *>(Buffer)->Question > 0)
	{
		std::string Domain;
		PacketQueryToString(Buffer + sizeof(dns_hdr), Domain);
		if (Domain == reinterpret_cast<const char *>(Parameter.DomainTest_Data))
		{
			IsMarkStatus = true;
			return true;
		}
	}
//More than zero Authority record
	else if (reinterpret_cast<const dns_hdr *>(Buffer)->Authority > 0)
	{
	//No Such Name
		if ((ntohs(reinterpret_cast<const dns_hdr *>(Buffer)->Flags) & DNS_GET_BIT_RCODE) == DNS_RCODE_NXDOMAIN)
			IsMarkStatus = true;

		return true;
	}
//DNS header check
	else if (
	//Less than or more than one Answer record
	//Some ISP will return fake responses with more than one Answer record.
//		ntohs(reinterpret_cast<const dns_hdr *>(Buffer)->Answer) != U16_NUM_ONE || 
	//No any Answer records
		reinterpret_cast<const dns_hdr *>(Buffer)->Answer == 0 || 
	//More than one Additional record
		ntohs(reinterpret_cast<const dns_hdr *>(Buffer)->Additional) > U16_NUM_ONE)
	{
		return true;
	}

	return false;
}

//Mark and check server packet status
bool CaptureCheck_PacketStatus(
	const uint8_t * const Buffer, 
	const size_t DNS_DataOffset, 
	const uint16_t Protocol, 
	const bool IsMarkStatus, 
	DNS_SERVER_DATA * const PacketSource)
{
//Mark packet status.
	if (IsMarkStatus)
	{
	//Application layer
		if (DNS_DataOffset != 0)
			PacketSource->ServerPacketStatus.ApplicationLayerStatus.DNS_Header_Flags = htons((ntohs(reinterpret_cast<const dns_hdr *>(Buffer + DNS_DataOffset)->Flags) & (~DNS_GET_BIT_AA)) & (~DNS_GET_BIT_RCODE));

	//Network layer
	//IPv6
		if (Protocol == AF_INET6)
		{
			PacketSource->ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.VersionTrafficFlow = reinterpret_cast<const ipv6_hdr *>(Buffer)->VersionTrafficFlow;
		}
	//IPv4
		else if (Protocol == AF_INET)
		{
			PacketSource->ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.IHL = reinterpret_cast<const ipv4_hdr *>(Buffer)->IHL;
			PacketSource->ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.DSCP_ECN = reinterpret_cast<const ipv4_hdr *>(Buffer)->DSCP_ECN;
			PacketSource->ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.ID = reinterpret_cast<const ipv4_hdr *>(Buffer)->ID;
			PacketSource->ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.Flags = reinterpret_cast<const ipv4_hdr *>(Buffer)->Flags;
		}
		else {
			return false;
		}
	}
//Check packet status.
	else {
	//Application layer
		if (DNS_DataOffset != 0 && PacketSource->ServerPacketStatus.ApplicationLayerStatus.DNS_Header_Flags != htons((ntohs(reinterpret_cast<const dns_hdr *>(Buffer + DNS_DataOffset)->Flags) & (~DNS_GET_BIT_AA)) & (~DNS_GET_BIT_RCODE)))
			return false;

	//Network layer
	//IPv6
		if (Protocol == AF_INET6)
		{
			if (PacketSource->ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.VersionTrafficFlow != reinterpret_cast<const ipv6_hdr *>(Buffer)->VersionTrafficFlow)
				return false;
		}
	//IPv4
		else if (Protocol == AF_INET)
		{
			if (PacketSource->ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.IHL != reinterpret_cast<const ipv4_hdr *>(Buffer)->IHL || 
				PacketSource->ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.DSCP_ECN != reinterpret_cast<const ipv4_hdr *>(Buffer)->DSCP_ECN || 
				PacketSource->ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.Flags != reinterpret_cast<const ipv4_hdr *>(Buffer)->Flags || 
				(PacketSource->ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.ID == 0 && reinterpret_cast<const ipv4_hdr *>(Buffer)->ID > 0) || 
				(PacketSource->ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.ID > 0 && reinterpret_cast<const ipv4_hdr *>(Buffer)->ID == 0))
					return false;
		}
		else {
			return false;
		}
	}

	return true;
}

//Match socket information of responses and send responses to system sockets process
bool MatchPortToSend(
	const uint16_t Protocol, 
	const uint8_t * const Buffer, 
	const size_t Length, 
	const size_t BufferSize, 
	const uint16_t Port)
{
//Initialization
	SOCKET_DATA SocketData_Input;
	memset(&SocketData_Input, 0, sizeof(SocketData_Input));
	SocketData_Input.Socket = INVALID_SOCKET;
	uint16_t SystemProtocol = 0;
	size_t ReceiveIndex = 0;

//Match port.
	std::unique_lock<std::mutex> OutputPacketListMutex(OutputPacketListLock);
	for (auto &PortTableIter:OutputPacketList)
	{
		for (const auto &SocketDataIter:PortTableIter.SocketData_Output)
		{
			if ((PortTableIter.ClearPortTime > 0 && //Do not scan expired data.
				Protocol == AF_INET6 && SocketDataIter.AddrLen == sizeof(sockaddr_in6) && SocketDataIter.SockAddr.ss_family == AF_INET6 && 
				Port == (reinterpret_cast<const sockaddr_in6 *>(&SocketDataIter.SockAddr))->sin6_port) || //IPv6
				(Protocol == AF_INET && SocketDataIter.AddrLen == sizeof(sockaddr_in) && SocketDataIter.SockAddr.ss_family == AF_INET && 
				Port == (reinterpret_cast<const sockaddr_in *>(&SocketDataIter.SockAddr))->sin_port)) //IPv4
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
					PortTableIter.SocketData_Input.Socket = INVALID_SOCKET;
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
		for (const auto &SocketDataIter:PortTableIter.SocketData_Output)
		{
			if (PortTableIter.ClearPortTime > 0 && //Do not scan expired data.
				((Protocol == AF_INET6 && SocketDataIter.AddrLen == sizeof(sockaddr_in6) && SocketDataIter.SockAddr.ss_family == AF_INET6 && 
				Port == (reinterpret_cast<const sockaddr_in6 *>(&SocketDataIter.SockAddr))->sin6_port) || //IPv6
				(Protocol == AF_INET && SocketDataIter.AddrLen == sizeof(sockaddr_in) && SocketDataIter.SockAddr.ss_family == AF_INET && 
				Port == (reinterpret_cast<const sockaddr_in *>(&SocketDataIter.SockAddr))->sin_port))) //IPv4
			{
				if (PortTableIter.ReceiveIndex == ReceiveIndex)
				{
					SocketData_Input = PortTableIter.SocketData_Input;
					SystemProtocol = PortTableIter.Protocol_Network;
					PortTableIter.ClearPortTime = 0;

				//Clear item in global list.
					memset(&PortTableIter.SocketData_Input, 0, sizeof(PortTableIter.SocketData_Input));
					PortTableIter.SocketData_Input.Socket = INVALID_SOCKET;
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
					++AlternateSwapList.TimeoutTimes[ALTERNATE_SWAP_TYPE_MAIN_TCP_IPV6];
				else if (OutputPacketList.front().Protocol_Transport == IPPROTO_UDP)
					++AlternateSwapList.TimeoutTimes[ALTERNATE_SWAP_TYPE_MAIN_UDP_IPV6];
			}
			else if (OutputPacketList.front().Protocol_Network == AF_INET)
			{
				if (OutputPacketList.front().Protocol_Transport == IPPROTO_TCP)
					++AlternateSwapList.TimeoutTimes[ALTERNATE_SWAP_TYPE_MAIN_TCP_IPV4];
				else if (OutputPacketList.front().Protocol_Transport == IPPROTO_UDP)
					++AlternateSwapList.TimeoutTimes[ALTERNATE_SWAP_TYPE_MAIN_UDP_IPV4];
			}
		}

		OutputPacketList.pop_front();
	}

	OutputPacketListMutex.unlock();

//Drop resopnses which are not in OutputPacketList.
	if (SocketData_Input.AddrLen == 0 || SocketData_Input.SockAddr.ss_family == 0 || SystemProtocol == 0 || 
		!SocketSetting(SocketData_Input.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
			return false;

//Mark DNS cache.
	if (Parameter.DNS_CacheType != DNS_CACHE_TYPE::NONE)
		MarkDomainCache(Buffer, Length, &SocketData_Input);

//Send to requester.
	SendToRequester(SystemProtocol, const_cast<uint8_t *>(Buffer), Length, BufferSize, SocketData_Input);
	if (SystemProtocol == IPPROTO_TCP)
	{
		return true;
	}
//Check global sockets.
	else if (!GlobalRunningStatus.LocalListeningSocket->empty())
	{
		for (const auto &SocketIter:*GlobalRunningStatus.LocalListeningSocket)
		{
			if (SocketIter == SocketData_Input.Socket)
				return true;
		}
	}

	SocketSetting(SocketData_Input.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
	return true;
}
#endif

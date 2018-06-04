// This code is part of Pcap_DNSProxy
// Pcap_DNSProxy, a local DNS server based on WinPcap and LibPcap
// Copyright (C) 2012-2018 Chengr28
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


#include "DNSCurveRequest.h"

/* DNSCurve(DNSCrypt) Protocol version 2

Client -> Server:
*  8 bytes: Magic query bytes
* 32 bytes: The client's DNSCurve public key (crypto_box_PUBLICKEYBYTES)
* 12 bytes: A client-selected nonce for this packet (crypto_box_NONCEBYTES / 2)
* 16 bytes: Poly1305 MAC (crypto_box_ZEROBYTES - crypto_box_BOXZEROBYTES)
* Variable encryption data ..

Server -> Client:
*  8 bytes: The string "r6fnvWJ8" (DNSCRYPT_MAGIC_RESPONSE)
* 12 bytes: The client's nonce (crypto_box_NONCEBYTES / 2)
* 12 bytes: A server-selected nonce extension (crypto_box_NONCEBYTES / 2)
* 16 bytes: Poly1305 MAC (crypto_box_ZEROBYTES - crypto_box_BOXZEROBYTES)
* Variable encryption data ..

Using TCP protocol:
* 2 bytes: DNSCurve(DNSCrypt) data payload length
* Variable original DNSCurve(DNSCrypt) data ..

*/

#if defined(ENABLE_LIBSODIUM)
//DNSCurve initialization
void DNSCurveInit(
	void)
{
//DNSCurve signature request TCP Mode
	if (DNSCurveParameter.DNSCurveProtocol_Transport == REQUEST_MODE_TRANSPORT::FORCE_TCP || DNSCurveParameter.DNSCurveProtocol_Transport == REQUEST_MODE_TRANSPORT::TCP)
	{
	//Main(IPv6)
		if (DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.AddressData.Storage.ss_family != 0 && 
			(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_NETWORK::BOTH || //Auto select
			DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_NETWORK::IPV6) && //IPv6
			((!DNSCurveParameter.IsClientEphemeralKey && sodium_is_zero(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) != 0) || 
			(DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES)) || 
			CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
		{
			std::thread DNSCurve_TCP_SignatureRequestThread(std::bind(DNSCurve_TCP_SignatureRequest, static_cast<uint16_t>(AF_INET6), false));
			DNSCurve_TCP_SignatureRequestThread.detach();
		}

	//Main(IPv4)
		if (DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.AddressData.Storage.ss_family != 0 && 
			(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_NETWORK::BOTH || //Auto select
			DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_NETWORK::IPV4) && //IPv4
			((!DNSCurveParameter.IsClientEphemeralKey && sodium_is_zero(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) != 0) || 
			(DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES)) || 
			CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
		{
			std::thread DNSCurve_TCP_SignatureRequestThread(std::bind(DNSCurve_TCP_SignatureRequest, static_cast<uint16_t>(AF_INET), false));
			DNSCurve_TCP_SignatureRequestThread.detach();
		}

	//Alternate(IPv6)
		if (DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.AddressData.Storage.ss_family != 0 && 
			(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_NETWORK::BOTH || //Auto select
			DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_NETWORK::IPV6) && //IPv6
			((!DNSCurveParameter.IsClientEphemeralKey && sodium_is_zero(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) != 0) || 
			(DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES)) || 
			CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
		{
			std::thread DNSCurve_TCP_SignatureRequestThread(std::bind(DNSCurve_TCP_SignatureRequest, static_cast<uint16_t>(AF_INET6), true));
			DNSCurve_TCP_SignatureRequestThread.detach();
		}

	//Alternate(IPv4)
		if (DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.AddressData.Storage.ss_family != 0 && 
			(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_NETWORK::BOTH || //Auto select
			DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_NETWORK::IPV4) && //IPv4
			((!DNSCurveParameter.IsClientEphemeralKey && sodium_is_zero(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) != 0) || 
			(DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES)) || 
			CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
		{
			std::thread DNSCurve_TCP_SignatureRequestThread(std::bind(DNSCurve_TCP_SignatureRequest, static_cast<uint16_t>(AF_INET), true));
			DNSCurve_TCP_SignatureRequestThread.detach();
		}
	}

//Force protocol(TCP).
	if (DNSCurveParameter.DNSCurveProtocol_Transport == REQUEST_MODE_TRANSPORT::FORCE_TCP)
		return;

//DNSCurve signature request UDP Mode
//Main(IPv6)
	if (DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.AddressData.Storage.ss_family != 0 && 
		(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_NETWORK::BOTH || //Auto select
		DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_NETWORK::IPV6) && //IPv6
		((!DNSCurveParameter.IsClientEphemeralKey && sodium_is_zero(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) != 0) || 
		(DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES)) || 
		CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
	{
		std::thread DNSCurve_UDP_SignatureRequestThread(std::bind(DNSCurve_UDP_SignatureRequest, static_cast<uint16_t>(AF_INET6), false));
		DNSCurve_UDP_SignatureRequestThread.detach();
	}

//Main(IPv4)
	if (DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.AddressData.Storage.ss_family != 0 && 
		(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_NETWORK::BOTH || //IPv4
		DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_NETWORK::IPV4) && //Auto select
		((!DNSCurveParameter.IsClientEphemeralKey && sodium_is_zero(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) != 0) || 
		(DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES)) || 
		CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
	{
		std::thread DNSCurve_UDP_SignatureRequestThread(std::bind(DNSCurve_UDP_SignatureRequest, static_cast<uint16_t>(AF_INET), false));
		DNSCurve_UDP_SignatureRequestThread.detach();
	}

//Alternate(IPv6)
	if (DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.AddressData.Storage.ss_family != 0 && 
		(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_NETWORK::BOTH || //Auto select
		DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_NETWORK::IPV6) && //IPv6
		((!DNSCurveParameter.IsClientEphemeralKey && sodium_is_zero(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) != 0) || 
		(DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES)) || 
		CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
	{
		std::thread DNSCurve_UDP_SignatureRequestThread(std::bind(DNSCurve_UDP_SignatureRequest, static_cast<uint16_t>(AF_INET6), true));
		DNSCurve_UDP_SignatureRequestThread.detach();
	}

//Alternate(IPv4)
	if (DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.AddressData.Storage.ss_family != 0 && 
		(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_NETWORK::BOTH || //Auto select
		DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_NETWORK::IPV4) && //IPv4
		((!DNSCurveParameter.IsClientEphemeralKey && sodium_is_zero(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) != 0) || 
		(DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES)) || 
		CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
	{
		std::thread DNSCurve_UDP_SignatureRequestThread(std::bind(DNSCurve_UDP_SignatureRequest, static_cast<uint16_t>(AF_INET), true));
		DNSCurve_UDP_SignatureRequestThread.detach();
	}

	return;
}

//Send TCP request to get Signature Data of servers
bool DNSCurve_TCP_SignatureRequest(
	const uint16_t Protocol, 
	const bool IsAlternate)
{
//Initialization
	const auto SendBuffer = std::make_unique<uint8_t[]>(PACKET_NORMAL_MAXSIZE + MEMORY_RESERVED_BYTES);
	const auto RecvBuffer = std::make_unique<uint8_t[]>(Parameter.LargeBufferSize + MEMORY_RESERVED_BYTES);
	memset(SendBuffer.get(), 0, PACKET_NORMAL_MAXSIZE + MEMORY_RESERVED_BYTES);
	memset(RecvBuffer.get(), 0, Parameter.LargeBufferSize + MEMORY_RESERVED_BYTES);
	std::vector<SOCKET_DATA> TCPSocketDataList(1U);
	memset(&TCPSocketDataList.front(), 0, sizeof(TCPSocketDataList.front()));
	TCPSocketDataList.front().Socket = INVALID_SOCKET;

//Make packet data(Part 1).
	auto DataLength = sizeof(dns_tcp_hdr);
	const auto DNS_TCP_Header = reinterpret_cast<dns_tcp_hdr *>(SendBuffer.get());
#if defined(ENABLE_PCAP)
	DNS_TCP_Header->ID = Parameter.DomainTest_ID;
#else
#if defined(PLATFORM_WIN)
	DNS_TCP_Header->ID = htons(static_cast<uint16_t>(GetCurrentProcessId())); //Default DNS ID is current thread ID.
#elif defined(PLATFORM_LINUX)
	DNS_TCP_Header->ID = htons(static_cast<uint16_t>(pthread_self())); //Default DNS ID is current thread ID.
#elif defined(PLATFORM_MACOS)
	DNS_TCP_Header->ID = htons(*reinterpret_cast<uint16_t *>(pthread_self())); //Default DNS ID is current thread ID.
#endif
#endif
	DNS_TCP_Header->Flags = htons(DNS_FLAG_REQUEST_STANDARD);
	DNS_TCP_Header->Question = htons(UINT16_NUM_ONE);
	if (Protocol == AF_INET6)
	{
		if (IsAlternate)
			DataLength += StringToPacketQuery(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ProviderName, SendBuffer.get() + DataLength);
		else //Main
			DataLength += StringToPacketQuery(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ProviderName, SendBuffer.get() + DataLength);
	}
	else if (Protocol == AF_INET)
	{
		if (IsAlternate)
			DataLength += StringToPacketQuery(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ProviderName, SendBuffer.get() + DataLength);
		else //Main
			DataLength += StringToPacketQuery(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ProviderName, SendBuffer.get() + DataLength);
	}
	else {
		return false;
	}
	reinterpret_cast<dns_qry *>(SendBuffer.get() + DataLength)->Type = htons(DNS_TYPE_TEXT);
	reinterpret_cast<dns_qry *>(SendBuffer.get() + DataLength)->Classes = htons(DNS_CLASS_INTERNET);
	DataLength += sizeof(dns_qry);

//EDNS Label
	DataLength = Add_EDNS_LabelToPacket(SendBuffer.get() + sizeof(uint16_t), DataLength - sizeof(uint16_t), PACKET_NORMAL_MAXSIZE, nullptr);
	DataLength += sizeof(uint16_t);

//Add length of request packet.
	DNS_TCP_Header->Length = htons(static_cast<uint16_t>(DataLength - sizeof(DNS_TCP_Header->Length)));

//Socket initialization(Part 1)
	std::wstring Message;
	size_t TotalSleepTime = 0;
	ssize_t RecvLen = 0;
	auto FileModifiedTime = GlobalRunningStatus.ConfigFileModifiedTime;
	auto ServerType = DNSCURVE_SERVER_TYPE::NONE;
	const auto PacketTarget = DNSCurveSelectSignatureTargetSocket(Protocol, IsAlternate, ServerType, TCPSocketDataList);
	if (PacketTarget == nullptr)
	{
		SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
		PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"DNSCurve TCP Signature Request module Monitor terminated", 0, nullptr, 0);

		return false;
	}

//Send request.
	for (;;)
	{
	//Sleep time controller
		if (TotalSleepTime > 0)
		{
		//Configuration files have been changed.
			if (FileModifiedTime != GlobalRunningStatus.ConfigFileModifiedTime)
			{
				FileModifiedTime = GlobalRunningStatus.ConfigFileModifiedTime;
				TotalSleepTime = 0;
			}
		//Interval time is not enough.
			else if (TotalSleepTime < DNSCurveParameter.KeyRecheckTime)
			{
				TotalSleepTime += Parameter.FileRefreshTime;

				Sleep(Parameter.FileRefreshTime);
				continue;
			}
		//Interval time is enough, next recheck time.
			else {
				TotalSleepTime = 0;
			}
		}

	//Socket initialization(Part 2)
		if (Protocol == AF_INET6)
			TCPSocketDataList.front().Socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
		else if (Protocol == AF_INET)
			TCPSocketDataList.front().Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		else 
			goto JumpTo_Restart;
		if (!SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr) || 
			!SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::TCP_FAST_OPEN, true, nullptr) || 
			!SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr) || 
			(Protocol == AF_INET6 && !SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV6, true, nullptr)) || 
			(Protocol == AF_INET && (!SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV4, true, nullptr)))) // || 
//			!SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::DO_NOT_FRAGMENT, true, nullptr))))
				goto JumpTo_Restart;

	//Socket selecting
		RecvLen = SocketSelectingOnce(REQUEST_PROCESS_TYPE::DNSCURVE_SIGN, IPPROTO_TCP, TCPSocketDataList, nullptr, SendBuffer.get(), DataLength, RecvBuffer.get(), Parameter.LargeBufferSize, nullptr, nullptr);
		if (RecvLen < static_cast<ssize_t>(DNS_PACKET_MINSIZE))
		{
			goto JumpTo_Restart;
		}
		else {
		//Check signature.
			if (!DNSCruveGetSignatureData(RecvBuffer.get() + DNS_PACKET_RR_LOCATE(RecvBuffer.get()), ServerType) || 
				CheckEmptyBuffer(PacketTarget->ServerFingerprint, crypto_box_PUBLICKEYBYTES) || 
				CheckEmptyBuffer(PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
					goto JumpTo_Restart;
		}

	//Wait for sending again.
		TotalSleepTime += Parameter.FileRefreshTime;
		continue;

	//Jump here to restart.
	JumpTo_Restart:
		SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

	//Print error log.
		DNSCurvePrintLog(ServerType, Message);
		if (!Message.empty())
		{
			Message.append(L"TCP get signature data error");
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::DNSCURVE, Message.c_str(), 0, nullptr, 0);
		}
		else {
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::DNSCURVE, L"TCP get signature data error", 0, nullptr, 0);
		}

	//Send request again.
		memset(RecvBuffer.get(), 0, Parameter.LargeBufferSize);
		if (!Parameter.AlternateMultipleRequest)
		{
			if (ServerType == DNSCURVE_SERVER_TYPE::MAIN_IPV6)
				++AlternateSwapList.TimeoutTimes[ALTERNATE_SWAP_TYPE_DNSCURVE_TCP_IPV6];
			else if (ServerType == DNSCURVE_SERVER_TYPE::MAIN_IPV4)
				++AlternateSwapList.TimeoutTimes[ALTERNATE_SWAP_TYPE_DNSCURVE_TCP_IPV4];
		}

		Sleep(SENDING_INTERVAL_TIME);
	}

	SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
	PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"DNSCurve TCP Signature Request module Monitor terminated", 0, nullptr, 0);
	return true;
}

//Send UDP request to get Signature Data of servers
bool DNSCurve_UDP_SignatureRequest(
	const uint16_t Protocol, 
	const bool IsAlternate)
{
//Initialization
	const auto SendBuffer = std::make_unique<uint8_t[]>(PACKET_NORMAL_MAXSIZE + MEMORY_RESERVED_BYTES);
	const auto RecvBuffer = std::make_unique<uint8_t[]>(PACKET_NORMAL_MAXSIZE + MEMORY_RESERVED_BYTES);
	memset(SendBuffer.get(), 0, PACKET_NORMAL_MAXSIZE + MEMORY_RESERVED_BYTES);
	memset(RecvBuffer.get(), 0, PACKET_NORMAL_MAXSIZE + MEMORY_RESERVED_BYTES);
	std::vector<SOCKET_DATA> UDPSocketDataList(1U);
	memset(&UDPSocketDataList.front(), 0, sizeof(UDPSocketDataList.front()));
	UDPSocketDataList.front().Socket = INVALID_SOCKET;

//Make packet data(Part 1).
	const auto DNS_Header = reinterpret_cast<dns_hdr *>(SendBuffer.get());
	auto DataLength = sizeof(dns_hdr);
#if defined(ENABLE_PCAP)
	DNS_Header->ID = Parameter.DomainTest_ID;
#else
#if defined(PLATFORM_WIN)
	DNS_Header->ID = htons(static_cast<uint16_t>(GetCurrentProcessId())); //Default DNS ID is current thread ID.
#elif defined(PLATFORM_LINUX)
	DNS_Header->ID = htons(static_cast<uint16_t>(pthread_self())); //Default DNS ID is current thread ID.
#elif defined(PLATFORM_MACOS)
	DNS_Header->ID = htons(*reinterpret_cast<uint16_t *>(pthread_self())); //Default DNS ID is current thread ID.
#endif
#endif
	DNS_Header->Flags = htons(DNS_FLAG_REQUEST_STANDARD);
	DNS_Header->Question = htons(UINT16_NUM_ONE);
	if (Protocol == AF_INET6)
	{
		if (IsAlternate)
			DataLength += StringToPacketQuery(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ProviderName, SendBuffer.get() + DataLength);
		else //Main
			DataLength += StringToPacketQuery(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ProviderName, SendBuffer.get() + DataLength);
	}
	else if (Protocol == AF_INET)
	{
		if (IsAlternate)
			DataLength += StringToPacketQuery(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ProviderName, SendBuffer.get() + DataLength);
		else //Main
			DataLength += StringToPacketQuery(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ProviderName, SendBuffer.get() + DataLength);
	}
	else {
		return false;
	}
	reinterpret_cast<dns_qry *>(SendBuffer.get() + DataLength)->Type = htons(DNS_TYPE_TEXT);
	reinterpret_cast<dns_qry *>(SendBuffer.get() + DataLength)->Classes = htons(DNS_CLASS_INTERNET);
	DataLength += sizeof(dns_qry);

//EDNS Label
	DataLength = Add_EDNS_LabelToPacket(SendBuffer.get(), DataLength, PACKET_NORMAL_MAXSIZE, nullptr);

//Socket initialization(Part 1)
	std::wstring Message;
	size_t TotalSleepTime = 0;
	ssize_t RecvLen = 0;
	auto FileModifiedTime = GlobalRunningStatus.ConfigFileModifiedTime;
	auto ServerType = DNSCURVE_SERVER_TYPE::NONE;
	const auto PacketTarget = DNSCurveSelectSignatureTargetSocket(Protocol, IsAlternate, ServerType, UDPSocketDataList);
	if (PacketTarget == nullptr)
	{
		SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
		PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"DNSCurve UDP Signature Request module Monitor terminated", 0, nullptr, 0);

		return false;
	}

//Send request.
	for (;;)
	{
	//Sleep time controller
		if (TotalSleepTime > 0)
		{
		//Configuration files have been changed.
			if (FileModifiedTime != GlobalRunningStatus.ConfigFileModifiedTime)
			{
				FileModifiedTime = GlobalRunningStatus.ConfigFileModifiedTime;
				TotalSleepTime = 0;
			}
		//Interval time is not enough.
			else if (TotalSleepTime < DNSCurveParameter.KeyRecheckTime)
			{
				TotalSleepTime += Parameter.FileRefreshTime;

				Sleep(Parameter.FileRefreshTime);
				continue;
			}
		//Interval time is enough, next recheck time.
			else {
				TotalSleepTime = 0;
			}
		}

	//Socket initialization(Part 2)
		if (Protocol == AF_INET6)
			UDPSocketDataList.front().Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		else if (Protocol == AF_INET)
			UDPSocketDataList.front().Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		else 
			goto JumpTo_Restart;
		if (!SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr) || 
			!SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr) || 
			(Protocol == AF_INET6 && !SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV6, true, nullptr)) || 
			(Protocol == AF_INET && (!SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV4, true, nullptr) || 
			!SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::DO_NOT_FRAGMENT, true, nullptr))))
				goto JumpTo_Restart;

	//Socket selecting
		RecvLen = SocketSelectingOnce(REQUEST_PROCESS_TYPE::DNSCURVE_SIGN, IPPROTO_UDP, UDPSocketDataList, nullptr, SendBuffer.get(), DataLength, RecvBuffer.get(), PACKET_NORMAL_MAXSIZE, nullptr, nullptr);
		if (RecvLen < static_cast<ssize_t>(DNS_PACKET_MINSIZE))
		{
			goto JumpTo_Restart;
		}
		else {
		//Check signature.
			if (!DNSCruveGetSignatureData(RecvBuffer.get() + DNS_PACKET_RR_LOCATE(RecvBuffer.get()), ServerType) || 
				CheckEmptyBuffer(PacketTarget->ServerFingerprint, crypto_box_PUBLICKEYBYTES) || 
				CheckEmptyBuffer(PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
					goto JumpTo_Restart;
		}

	//Wait for sending again.
		TotalSleepTime += Parameter.FileRefreshTime;
		continue;

	//Jump here to restart.
	JumpTo_Restart:
		SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

	//Print error log.
		DNSCurvePrintLog(ServerType, Message);
		if (!Message.empty())
		{
			Message.append(L"UDP get signature data error");
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::DNSCURVE, Message.c_str(), 0, nullptr, 0);
		}
		else {
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::DNSCURVE, L"UDP get signature data error", 0, nullptr, 0);
		}

	//Send request again.
		memset(RecvBuffer.get(), 0, PACKET_NORMAL_MAXSIZE + MEMORY_RESERVED_BYTES);
		if (!Parameter.AlternateMultipleRequest)
		{
			if (ServerType == DNSCURVE_SERVER_TYPE::MAIN_IPV6)
				++AlternateSwapList.TimeoutTimes[ALTERNATE_SWAP_TYPE_DNSCURVE_UDP_IPV6];
			else if (ServerType == DNSCURVE_SERVER_TYPE::MAIN_IPV4)
				++AlternateSwapList.TimeoutTimes[ALTERNATE_SWAP_TYPE_DNSCURVE_UDP_IPV4];
		}

		Sleep(SENDING_INTERVAL_TIME);
	}

	SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
	PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"DNSCurve UDP Signature Request module Monitor terminated", 0, nullptr, 0);
	return true;
}

//Transmission of DNSCurve TCP protocol
size_t DNSCurve_TCP_RequestSingle(
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize, 
	const uint16_t QueryType, 
	const SOCKET_DATA &LocalSocketData)
{
//Initialization
	std::vector<SOCKET_DATA> TCPSocketDataList(1U);
	memset(&TCPSocketDataList.front(), 0, sizeof(TCPSocketDataList.front()));
	TCPSocketDataList.front().Socket = INVALID_SOCKET;
	DNSCURVE_SOCKET_SELECTING_TABLE TCPSocketSelectingData;
	DNSCURVE_SERVER_DATA *PacketTarget = nullptr;
	bool *IsAlternate = nullptr;
	size_t *AlternateTimeoutTimes = nullptr;
	memset(OriginalRecv, 0, RecvSize);
	const auto SendBuffer = OriginalRecv;

//Socket initialization
	ssize_t RecvLen = SelectTargetSocketSingle(REQUEST_PROCESS_TYPE::DNSCURVE_MAIN, IPPROTO_TCP, QueryType, &LocalSocketData, &TCPSocketDataList.front(), &IsAlternate, &AlternateTimeoutTimes, nullptr, &TCPSocketSelectingData.ServerType, reinterpret_cast<void **>(&PacketTarget));
	if (RecvLen == EXIT_FAILURE || TCPSocketSelectingData.ServerType == DNSCURVE_SERVER_TYPE::NONE)
	{
		SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
		PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"DNSCurve TCP socket initialization error", 0, nullptr, 0);

		return EXIT_FAILURE;
	}

//Make Precomputation Key between client and server.
	uint8_t *Client_PublicKey = nullptr, *PrecomputationKey = nullptr;
	std::unique_ptr<uint8_t[]> Client_PublicKey_Buffer(nullptr);
	DNSCURVE_HEAP_BUFFER_TABLE<uint8_t> PrecomputationKeyBuffer;
	if (DNSCurveParameter.IsEncryption && DNSCurveParameter.IsClientEphemeralKey)
	{
		auto Client_PublicKey_BufferTemp = std::make_unique<uint8_t[]>(crypto_box_PUBLICKEYBYTES);
		std::swap(Client_PublicKey_Buffer, Client_PublicKey_BufferTemp);

		DNSCURVE_HEAP_BUFFER_TABLE<uint8_t> PrecomputationKeyBufferTemp(crypto_box_BEFORENMBYTES);
		PrecomputationKeyBufferTemp.Swap(PrecomputationKeyBuffer);
		Client_PublicKey = Client_PublicKey_Buffer.get();
		PrecomputationKey = PrecomputationKeyBuffer.Buffer;
		if (!DNSCurvePrecomputationKeySetting(PrecomputationKey, Client_PublicKey, PacketTarget->ServerFingerprint))
		{
			SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
			return EXIT_FAILURE;
		}
	}
	else {
		PrecomputationKey = PacketTarget->PrecomputationKey, Client_PublicKey = DNSCurveParameter.Client_PublicKey;
	}

//Socket attribute setting(Non-blocking mode)
	if (!SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr))
	{
		SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
		return EXIT_FAILURE;
	}

//Make encryption or normal packet.
	RecvLen = DNSCurvePacketEncryption(IPPROTO_TCP, PacketTarget->SendMagicNumber, Client_PublicKey, PrecomputationKey, OriginalSend, SendSize, SendBuffer, RecvSize);
	if (RecvLen < static_cast<ssize_t>(DNS_PACKET_MINSIZE))
	{
		SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
		return EXIT_FAILURE;
	}

//Socket selecting structure initialization
	std::vector<DNSCURVE_SOCKET_SELECTING_TABLE> TCPSocketSelectingDataList;
	if (DNSCurveParameter.IsEncryption) //Encryption mode
	{
		TCPSocketSelectingData.PrecomputationKey = PrecomputationKey;
		TCPSocketSelectingData.ReceiveMagicNumber = PacketTarget->ReceiveMagicNumber;
	}

	TCPSocketSelectingData.SendBuffer = SendBuffer;
	TCPSocketSelectingData.SendSize = RecvLen;
	TCPSocketSelectingData.RecvLen = 0;
	TCPSocketSelectingData.IsPacketDone = false;
	TCPSocketSelectingDataList.push_back(std::move(TCPSocketSelectingData));

//Socket selecting
	ssize_t ErrorCode = 0;
	RecvLen = SocketSelectingOnce(REQUEST_PROCESS_TYPE::DNSCURVE_MAIN, IPPROTO_TCP, TCPSocketDataList, &TCPSocketSelectingDataList, nullptr, 0, OriginalRecv, RecvSize, &ErrorCode, &LocalSocketData);
	if (ErrorCode == WSAETIMEDOUT && !Parameter.AlternateMultipleRequest) //Mark timeout.
	{
		if (TCPSocketDataList.front().AddrLen == sizeof(sockaddr_in6))
			++AlternateSwapList.TimeoutTimes[ALTERNATE_SWAP_TYPE_DNSCURVE_TCP_IPV6];
		else if (TCPSocketDataList.front().AddrLen == sizeof(sockaddr_in))
			++AlternateSwapList.TimeoutTimes[ALTERNATE_SWAP_TYPE_DNSCURVE_UDP_IPV4];
	}

//Close all sockets.
	if (SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
		SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

	return RecvLen;
}

//Transmission of DNSCurve TCP protocol(Multiple threading)
size_t DNSCurve_TCP_RequestMultiple(
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize, 
	const uint16_t QueryType, 
	const SOCKET_DATA &LocalSocketData)
{
//Key initialization
	uint8_t *PrecomputationKey = nullptr, *Alternate_PrecomputationKey = nullptr;
	DNSCURVE_HEAP_BUFFER_TABLE<uint8_t> PrecomputationKeyBuffer, Alternate_PrecomputationKeyBuffer;
	if (DNSCurveParameter.IsEncryption && DNSCurveParameter.IsClientEphemeralKey)
	{
		DNSCURVE_HEAP_BUFFER_TABLE<uint8_t> PrecomputationKeyBufferTemp(crypto_box_BEFORENMBYTES), Alternate_PrecomputationKeyBufferTemp(crypto_box_BEFORENMBYTES);

	//Main
		PrecomputationKeyBufferTemp.Swap(PrecomputationKeyBuffer);
		PrecomputationKey = PrecomputationKeyBuffer.Buffer;

	//Alternate
		Alternate_PrecomputationKeyBufferTemp.Swap(Alternate_PrecomputationKeyBuffer);
		Alternate_PrecomputationKey = Alternate_PrecomputationKeyBuffer.Buffer;
	}

//Initialization(Part 1)
	std::vector<SOCKET_DATA> TCPSocketDataList;
	std::vector<DNSCURVE_SOCKET_SELECTING_TABLE> TCPSocketSelectingDataList;
	std::unique_ptr<uint8_t[]> SendBuffer(nullptr);
	std::unique_ptr<uint8_t[]> Alternate_SendBuffer(nullptr);
	DNSCURVE_SERVER_DATA *PacketTarget = nullptr;
	size_t DataLength = 0, Alternate_DataLength = 0;
	memset(OriginalRecv, 0, RecvSize);

//Socket precomputation
	DNSCurveSocketPrecomputation(IPPROTO_TCP, OriginalSend, SendSize, RecvSize, &PrecomputationKey, &Alternate_PrecomputationKey, &PacketTarget, 
		TCPSocketDataList, TCPSocketSelectingDataList, QueryType, LocalSocketData, SendBuffer, DataLength, Alternate_SendBuffer, Alternate_DataLength);
	if (TCPSocketDataList.empty() || TCPSocketDataList.size() != TCPSocketSelectingDataList.size())
		return EXIT_FAILURE;

//Socket selecting structure initialization
	for (auto &SocketSelectingIter:TCPSocketSelectingDataList)
	{
	//Encryption mode
		if (DNSCurveParameter.IsEncryption)
		{
			DNSCurvePacketTargetSetting(SocketSelectingIter.ServerType, &PacketTarget);
			SocketSelectingIter.ReceiveMagicNumber = PacketTarget->ReceiveMagicNumber;

		//Alternate
			if (SocketSelectingIter.ServerType == DNSCURVE_SERVER_TYPE::ALTERNATE_IPV6 || SocketSelectingIter.ServerType == DNSCURVE_SERVER_TYPE::ALTERNATE_IPV4)
			{
				SocketSelectingIter.PrecomputationKey = Alternate_PrecomputationKey;
				SocketSelectingIter.SendBuffer = Alternate_SendBuffer.get();
				SocketSelectingIter.SendSize = Alternate_DataLength;
			}
		//Main
			else {
				SocketSelectingIter.PrecomputationKey = PrecomputationKey;
				SocketSelectingIter.SendBuffer = SendBuffer.get();
				SocketSelectingIter.SendSize = DataLength;
			}
		}
	//Normal mode
		else {
			SocketSelectingIter.SendBuffer = SendBuffer.get();
			SocketSelectingIter.SendSize = DataLength;
		}

		SocketSelectingIter.RecvLen = 0;
		SocketSelectingIter.IsPacketDone = false;
	}

//Socket selecting
	ssize_t ErrorCode = 0;
	const auto RecvLen = SocketSelectingOnce(REQUEST_PROCESS_TYPE::DNSCURVE_MAIN, IPPROTO_TCP, TCPSocketDataList, &TCPSocketSelectingDataList, nullptr, 0, OriginalRecv, RecvSize, &ErrorCode, &LocalSocketData);
	if (ErrorCode == WSAETIMEDOUT && !Parameter.AlternateMultipleRequest) //Mark timeout.
	{
		if (TCPSocketDataList.front().AddrLen == sizeof(sockaddr_in6))
			++AlternateSwapList.TimeoutTimes[ALTERNATE_SWAP_TYPE_DNSCURVE_UDP_IPV6];
		else if (TCPSocketDataList.front().AddrLen == sizeof(sockaddr_in))
			++AlternateSwapList.TimeoutTimes[ALTERNATE_SWAP_TYPE_DNSCURVE_UDP_IPV4];
	}

//Close all sockets.
	for (auto &SocketIter:TCPSocketDataList)
	{
		if (SocketSetting(SocketIter.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
			SocketSetting(SocketIter.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
	}

	return RecvLen;
}

//Transmission of DNSCurve UDP protocol
size_t DNSCurve_UDP_RequestSingle(
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize, 
	const uint16_t QueryType, 
	const SOCKET_DATA &LocalSocketData)
{
//Initialization
	std::vector<SOCKET_DATA> UDPSocketDataList(1U);
	memset(&UDPSocketDataList.front(), 0, sizeof(UDPSocketDataList.front()));
	UDPSocketDataList.front().Socket = INVALID_SOCKET;
	DNSCURVE_SOCKET_SELECTING_TABLE UDPSocketSelectingData;
	DNSCURVE_SERVER_DATA *PacketTarget = nullptr;
	bool *IsAlternate = nullptr;
	size_t *AlternateTimeoutTimes = nullptr;
	memset(OriginalRecv, 0, RecvSize);
	const auto SendBuffer = OriginalRecv;

//Socket initialization
	ssize_t RecvLen = SelectTargetSocketSingle(REQUEST_PROCESS_TYPE::DNSCURVE_MAIN, IPPROTO_UDP, QueryType, &LocalSocketData, &UDPSocketDataList.front(), &IsAlternate, &AlternateTimeoutTimes, nullptr, &UDPSocketSelectingData.ServerType, reinterpret_cast<void **>(&PacketTarget));
	if (RecvLen == EXIT_FAILURE || UDPSocketSelectingData.ServerType == DNSCURVE_SERVER_TYPE::NONE)
	{
		SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
		PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"DNSCurve UDP socket initialization error", 0, nullptr, 0);

		return EXIT_FAILURE;
	}

//Make Precomputation Key between client and server.
	uint8_t *Client_PublicKey = nullptr, *PrecomputationKey = nullptr;
	std::unique_ptr<uint8_t[]> Client_PublicKey_Buffer(nullptr);
	std::unique_ptr<uint8_t[]> PrecomputationKeyBuffer(nullptr);
	if (DNSCurveParameter.IsEncryption && DNSCurveParameter.IsClientEphemeralKey)
	{
		auto Client_PublicKey_BufferTemp = std::make_unique<uint8_t[]>(crypto_box_PUBLICKEYBYTES);
		auto PrecomputationKeyBufferTemp = std::make_unique<uint8_t[]>(crypto_box_BEFORENMBYTES);
		std::swap(Client_PublicKey_Buffer, Client_PublicKey_BufferTemp);
		std::swap(PrecomputationKeyBuffer, PrecomputationKeyBufferTemp);
		Client_PublicKey = Client_PublicKey_Buffer.get();
		PrecomputationKey = PrecomputationKeyBuffer.get();
		if (!DNSCurvePrecomputationKeySetting(PrecomputationKey, Client_PublicKey, PacketTarget->ServerFingerprint))
		{
			SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
			return EXIT_FAILURE;
		}
	}
	else {
		PrecomputationKey = PacketTarget->PrecomputationKey, Client_PublicKey = DNSCurveParameter.Client_PublicKey;
	}

//Socket attribute setting(Timeout) and UDP connecting
	if (!SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::TIMEOUT, true, &DNSCurveParameter.DNSCurve_SocketTimeout_Unreliable) || 
		SocketConnecting(IPPROTO_UDP, UDPSocketDataList.front().Socket, reinterpret_cast<sockaddr *>(&UDPSocketDataList.front().SockAddr), UDPSocketDataList.front().AddrLen, nullptr, 0) == EXIT_FAILURE)
	{
		SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
		return EXIT_FAILURE;
	}

//Make encryption or normal packet.
	RecvLen = DNSCurvePacketEncryption(IPPROTO_UDP, PacketTarget->SendMagicNumber, Client_PublicKey, PrecomputationKey, OriginalSend, SendSize, SendBuffer, RecvSize);
	if (RecvLen < static_cast<ssize_t>(DNS_PACKET_MINSIZE))
	{
		SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
		return EXIT_FAILURE;
	}

//Socket selecting structure initialization
	std::vector<DNSCURVE_SOCKET_SELECTING_TABLE> UDPSocketSelectingDataList;
	if (DNSCurveParameter.IsEncryption) //Encryption mode
	{
		UDPSocketSelectingData.PrecomputationKey = PrecomputationKey;
		UDPSocketSelectingData.ReceiveMagicNumber = PacketTarget->ReceiveMagicNumber;
		UDPSocketSelectingData.SendBuffer = SendBuffer;
		UDPSocketSelectingData.SendSize = RecvLen;
	}
	else { //Normal mode
		UDPSocketSelectingData.SendBuffer = const_cast<uint8_t *>(OriginalSend);
		UDPSocketSelectingData.SendSize = SendSize;
	}

	UDPSocketSelectingData.RecvLen = 0;
	UDPSocketSelectingData.IsPacketDone = false;
	UDPSocketSelectingDataList.push_back(std::move(UDPSocketSelectingData));

//Socket selecting
	ssize_t ErrorCode = 0;
	RecvLen = SocketSelectingOnce(REQUEST_PROCESS_TYPE::DNSCURVE_MAIN, IPPROTO_UDP, UDPSocketDataList, &UDPSocketSelectingDataList, nullptr, 0, OriginalRecv, RecvSize, &ErrorCode, &LocalSocketData);
	if (ErrorCode == WSAETIMEDOUT && !Parameter.AlternateMultipleRequest) //Mark timeout.
	{
		if (UDPSocketDataList.front().AddrLen == sizeof(sockaddr_in6))
			++AlternateSwapList.TimeoutTimes[ALTERNATE_SWAP_TYPE_DNSCURVE_UDP_IPV6];
		else if (UDPSocketDataList.front().AddrLen == sizeof(sockaddr_in))
			++AlternateSwapList.TimeoutTimes[ALTERNATE_SWAP_TYPE_DNSCURVE_UDP_IPV4];
	}

//Close all sockets.
	if (SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
		SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

	return RecvLen;
}

//Transmission of DNSCurve UDP protocol(Multiple threading)
size_t DNSCurve_UDP_RequestMultiple(
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize, 
	const uint16_t QueryType, 
	const SOCKET_DATA &LocalSocketData)
{
//Key initialization
	uint8_t *PrecomputationKey = nullptr, *Alternate_PrecomputationKey = nullptr;
	DNSCURVE_HEAP_BUFFER_TABLE<uint8_t> PrecomputationKeyBuffer, Alternate_PrecomputationKeyBuffer;
	if (DNSCurveParameter.IsEncryption && DNSCurveParameter.IsClientEphemeralKey)
	{
		DNSCURVE_HEAP_BUFFER_TABLE<uint8_t> PrecomputationKeyBufferTemp(crypto_box_BEFORENMBYTES), Alternate_PrecomputationKeyBufferTemp(crypto_box_BEFORENMBYTES);

	//Main
		PrecomputationKeyBufferTemp.Swap(PrecomputationKeyBuffer);
		PrecomputationKey = PrecomputationKeyBuffer.Buffer;

	//Alternate
		Alternate_PrecomputationKeyBufferTemp.Swap(Alternate_PrecomputationKeyBuffer);
		Alternate_PrecomputationKey = Alternate_PrecomputationKeyBuffer.Buffer;
	}

//Initialization(Part 1)
	std::vector<SOCKET_DATA> UDPSocketDataList;
	std::vector<DNSCURVE_SOCKET_SELECTING_TABLE> UDPSocketSelectingDataList;
	std::unique_ptr<uint8_t[]> SendBuffer(nullptr);
	std::unique_ptr<uint8_t[]> Alternate_SendBuffer(nullptr);
	DNSCURVE_SERVER_DATA *PacketTarget = nullptr;
	size_t DataLength = 0, Alternate_DataLength = 0;
	memset(OriginalRecv, 0, RecvSize);

//Socket precomputation
	DNSCurveSocketPrecomputation(IPPROTO_UDP, OriginalSend, SendSize, RecvSize, &PrecomputationKey, &Alternate_PrecomputationKey, &PacketTarget, 
		UDPSocketDataList, UDPSocketSelectingDataList, QueryType, LocalSocketData, SendBuffer, DataLength, Alternate_SendBuffer, Alternate_DataLength);
	if (UDPSocketDataList.empty() || UDPSocketDataList.size() != UDPSocketSelectingDataList.size())
		return EXIT_FAILURE;

//Socket selecting structure initialization
	for (auto &SocketSelectingIter:UDPSocketSelectingDataList)
	{
	//Encryption mode
		if (DNSCurveParameter.IsEncryption)
		{
			DNSCurvePacketTargetSetting(SocketSelectingIter.ServerType, &PacketTarget);
			SocketSelectingIter.ReceiveMagicNumber = PacketTarget->ReceiveMagicNumber;

		//Alternate
			if (SocketSelectingIter.ServerType == DNSCURVE_SERVER_TYPE::ALTERNATE_IPV6 || SocketSelectingIter.ServerType == DNSCURVE_SERVER_TYPE::ALTERNATE_IPV4)
			{
				SocketSelectingIter.PrecomputationKey = Alternate_PrecomputationKey;
				SocketSelectingIter.SendBuffer = Alternate_SendBuffer.get();
				SocketSelectingIter.SendSize = Alternate_DataLength;
			}
		//Main
			else {
				SocketSelectingIter.PrecomputationKey = PrecomputationKey;
				SocketSelectingIter.SendBuffer = SendBuffer.get();
				SocketSelectingIter.SendSize = DataLength;
			}
		}
	//Normal mode
		else {
			SocketSelectingIter.SendBuffer = const_cast<uint8_t *>(OriginalSend);
			SocketSelectingIter.SendSize = SendSize;
		}

		SocketSelectingIter.RecvLen = 0;
		SocketSelectingIter.IsPacketDone = false;
	}

//Socket selecting
	ssize_t ErrorCode = 0;
	const auto RecvLen = SocketSelectingOnce(REQUEST_PROCESS_TYPE::DNSCURVE_MAIN, IPPROTO_UDP, UDPSocketDataList, &UDPSocketSelectingDataList, nullptr, 0, OriginalRecv, RecvSize, &ErrorCode, &LocalSocketData);
	if (ErrorCode == WSAETIMEDOUT && !Parameter.AlternateMultipleRequest) //Mark timeout.
	{
		if (UDPSocketDataList.front().AddrLen == sizeof(sockaddr_in6))
			++AlternateSwapList.TimeoutTimes[ALTERNATE_SWAP_TYPE_DNSCURVE_UDP_IPV6];
		else if (UDPSocketDataList.front().AddrLen == sizeof(sockaddr_in))
			++AlternateSwapList.TimeoutTimes[ALTERNATE_SWAP_TYPE_DNSCURVE_UDP_IPV4];
	}

//Close all sockets.
	for (auto &SocketIter:UDPSocketDataList)
	{
		if (SocketSetting(SocketIter.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
			SocketSetting(SocketIter.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
	}

	return RecvLen;
}
#endif

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


#include "DNSCurveRequest.h"

/* DNSCurve/DNSCrypt Protocol version 2

Client -> Server:
*  8 bytes: Magic query bytes
* 32 bytes: The client's DNSCurve public key (crypto_box_PUBLICKEYBYTES)
* 12 bytes: A client-selected nonce for this packet (crypto_box_NONCEBYTES / 2)
* 16 bytes: Poly1305 MAC (crypto_box_ZEROBYTES - crypto_box_BOXZEROBYTES)
* Variable encryption data ...

Server -> Client:
*  8 bytes: The string r6fnvWJ8 (DNSCRYPT_MAGIC_RESPONSE)
* 12 bytes: The client's nonce (crypto_box_NONCEBYTES / 2)
* 12 bytes: A server-selected nonce extension (crypto_box_NONCEBYTES / 2)
* 16 bytes: Poly1305 MAC (crypto_box_ZEROBYTES - crypto_box_BOXZEROBYTES)
* Variable encryption data ...

Using TCP protocol:
* 2 bytes: DNSCurve/DNSCrypt data payload length
* Variable DNSCurve/DNSCrypt data ...

*/

#if defined(ENABLE_LIBSODIUM)
//DNSCurve initialization
void DNSCurveInit(
	void)
{
//Libsodium ramdom bytes initialization
	randombytes_set_implementation(&randombytes_salsa20_implementation);
	randombytes_stir();

//DNSCurve signature request TCP Mode
	if (DNSCurveParameter.DNSCurveProtocol_Transport == REQUEST_MODE_TCP)
	{
	//Main(IPv6)
		if (DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.AddressData.Storage.ss_family > 0 && 
			(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_BOTH || DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV6 || //Auto select and IPv6
			(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV4 && DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.AddressData.Storage.ss_family == 0)) && //Non-IPv4
			((!DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES)) || 
			(DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES)) || 
			CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
		{
			std::thread DNSCurveTCPSignatureRequestThread(std::bind(DNSCurveTCPSignatureRequest, AF_INET6, false));
			DNSCurveTCPSignatureRequestThread.detach();
		}

	//Main(IPv4)
		if (DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.AddressData.Storage.ss_family > 0 && 
			(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_BOTH || DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV4 || //Auto select and IPv4
			(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV6 && DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.AddressData.Storage.ss_family == 0)) && //Non-IPv6
			((!DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES)) || 
			(DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES)) || 
			CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
		{
			std::thread DNSCurveTCPSignatureRequestThread(std::bind(DNSCurveTCPSignatureRequest, AF_INET, false));
			DNSCurveTCPSignatureRequestThread.detach();
		}

	//Alternate(IPv6)
		if (DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.AddressData.Storage.ss_family > 0 && 
			(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_BOTH || DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV6 || //Auto select and IPv6
			(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV4 && DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.AddressData.Storage.ss_family == 0)) && //Non-IPv4
			((!DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES)) || 
			(DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES)) || 
			CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
		{
			std::thread DNSCurveTCPSignatureRequestThread(std::bind(DNSCurveTCPSignatureRequest, AF_INET6, true));
			DNSCurveTCPSignatureRequestThread.detach();
		}

	//Alternate(IPv4)
		if (DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.AddressData.Storage.ss_family > 0 && 
			(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_BOTH || DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV4 || //Auto select and IPv4
			(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV6 && DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.AddressData.Storage.ss_family == 0)) && //Non-IPv6
			((!DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES)) || 
			(DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES)) || 
			CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
		{
			std::thread DNSCurveTCPSignatureRequestThread(std::bind(DNSCurveTCPSignatureRequest, AF_INET, true));
			DNSCurveTCPSignatureRequestThread.detach();
		}
	}

//DNSCurve signature request UDP Mode
//Main(IPv6)
	if (DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.AddressData.Storage.ss_family > 0 && 
		(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_BOTH || DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV6 || //Auto select and IPv6
		(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV4 && DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.AddressData.Storage.ss_family == 0)) && //Non-IPv4
		((!DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES)) || 
		(DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES)) || 
		CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
	{
		std::thread DNSCurveUDPSignatureRequestThread(std::bind(DNSCurveUDPSignatureRequest, AF_INET6, false));
		DNSCurveUDPSignatureRequestThread.detach();
	}

//Main(IPv4)
	if (DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.AddressData.Storage.ss_family > 0 && 
		(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_BOTH || DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV4 || //Auto select and IPv4
		(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV6 && DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.AddressData.Storage.ss_family == 0)) && //Non-IPv6
		((!DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES)) || 
		(DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES)) || 
		CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
	{
		std::thread DNSCurveUDPSignatureRequestThread(std::bind(DNSCurveUDPSignatureRequest, AF_INET, false));
		DNSCurveUDPSignatureRequestThread.detach();
	}

//Alternate(IPv6)
	if (DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.AddressData.Storage.ss_family > 0 && 
		(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_BOTH || DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV6 || //Auto select and IPv6
		(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV4 && DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.AddressData.Storage.ss_family == 0)) && //Non-IPv4
		((!DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES)) || 
		(DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES)) || 
		CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
	{
		std::thread DNSCurveUDPSignatureRequestThread(std::bind(DNSCurveUDPSignatureRequest, AF_INET6, true));
		DNSCurveUDPSignatureRequestThread.detach();
	}

//Alternate(IPv4)
	if (DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.AddressData.Storage.ss_family > 0 && 
		(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_BOTH || DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV4 || //Auto select and IPv4
		(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV6 && DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.AddressData.Storage.ss_family == 0)) && //Non-IPv6
		((!DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES)) || 
		(DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES)) || 
		CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
	{
		std::thread DNSCurveUDPSignatureRequestThread(std::bind(DNSCurveUDPSignatureRequest, AF_INET, true));
		DNSCurveUDPSignatureRequestThread.detach();
	}

	return;
}

//Send TCP request to get Signature Data of servers
bool DNSCurveTCPSignatureRequest(
	const uint16_t Protocol, 
	const bool IsAlternate)
{
//Initialization
	std::shared_ptr<uint8_t> SendBuffer(new uint8_t[PACKET_MAXSIZE]()), RecvBuffer(new uint8_t[Parameter.LargeBufferSize]());
	sodium_memzero(SendBuffer.get(), PACKET_MAXSIZE);
	sodium_memzero(RecvBuffer.get(), Parameter.LargeBufferSize);
	std::vector<SOCKET_DATA> TCPSocketDataList(1U);
	sodium_memzero(&TCPSocketDataList.front(), sizeof(TCPSocketDataList.front()));

//Make packet data(Part 1).
	size_t DataLength = sizeof(dns_tcp_hdr);
	const auto DNS_TCP_Header = (pdns_tcp_hdr)SendBuffer.get();
#if defined(ENABLE_PCAP)
	DNS_TCP_Header->ID = Parameter.DomainTest_ID;
#else
	DNS_TCP_Header->ID = htons(U16_NUM_ONE);
#endif
	DNS_TCP_Header->Flags = htons(DNS_STANDARD);
	DNS_TCP_Header->Question = htons(U16_NUM_ONE);
	if (Protocol == AF_INET6)
	{
		if (IsAlternate)
			DataLength += CharToDNSQuery(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ProviderName, SendBuffer.get() + DataLength);
		else 
			DataLength += CharToDNSQuery(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ProviderName, SendBuffer.get() + DataLength);
	}
	else if (Protocol == AF_INET)
	{
		if (IsAlternate)
			DataLength += CharToDNSQuery(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ProviderName, SendBuffer.get() + DataLength);
		else 
			DataLength += CharToDNSQuery(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ProviderName, SendBuffer.get() + DataLength);
	}
	else {
		return false;
	}
	((pdns_qry)(SendBuffer.get() + DataLength))->Type = htons(DNS_TYPE_TEXT);
	((pdns_qry)(SendBuffer.get() + DataLength))->Classes = htons(DNS_CLASS_INTERNET);
	DataLength += sizeof(dns_qry);

//EDNS Label
	DataLength = AddEDNSLabelToAdditionalRR(SendBuffer.get() + sizeof(uint16_t), DataLength - sizeof(uint16_t), PACKET_MAXSIZE, nullptr);
	DataLength += sizeof(uint16_t);

//Add length of request packet(It must be written in header when transport with TCP protocol).
	DNS_TCP_Header->Length = htons((uint16_t)(DataLength - sizeof(uint16_t)));

//Socket initialization(Part 1)
	size_t ServerType = 0, SleepTime_SignatureRequest = 0, SpeedTime_SignatureRequest = DNSCurveParameter.KeyRecheckTime;
	PDNSCURVE_SERVER_DATA PacketTarget = DNSCurveSelectSignatureTargetSocket(Protocol, IsAlternate, ServerType, TCPSocketDataList);
	std::wstring Message;
	ssize_t RecvLen = 0;

//Send request.
	for (;;)
	{
	//Sleep time controller
		if (SleepTime_SignatureRequest > 0)
		{
			if (SpeedTime_SignatureRequest != DNSCurveParameter.KeyRecheckTime)
			{
				SpeedTime_SignatureRequest = DNSCurveParameter.KeyRecheckTime;
			}
			else if (SleepTime_SignatureRequest < SpeedTime_SignatureRequest)
			{
				SleepTime_SignatureRequest += Parameter.FileRefreshTime;

				Sleep(Parameter.FileRefreshTime);
				continue;
			}

			SleepTime_SignatureRequest = 0;
		}

	//Socket initialization(Part 2)
		if (Protocol == AF_INET6)
			TCPSocketDataList.front().Socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
		else if (Protocol == AF_INET)
			TCPSocketDataList.front().Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		else 
			goto JumpToRestart;
		if (!SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_INVALID_CHECK, true, nullptr) || 
			!SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_TCP_FAST_OPEN, true, nullptr) || 
			!SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_NON_BLOCKING_MODE, true, nullptr) || 
			(Protocol == AF_INET6 && !SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_HOP_LIMITS_IPV6, true, nullptr)) || 
			(Protocol == AF_INET && (!SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_HOP_LIMITS_IPV4, true, nullptr) || 
			!SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_DO_NOT_FRAGMENT, true, nullptr))))
				goto JumpToRestart;

	//Socket selecting
		RecvLen = SocketSelectingOnce(REQUEST_PROCESS_DNSCURVE_SIGN, IPPROTO_TCP, TCPSocketDataList, nullptr, SendBuffer.get(), DataLength, RecvBuffer.get(), Parameter.LargeBufferSize, nullptr);
		if (RecvLen < (ssize_t)DNS_PACKET_MINSIZE)
		{
			goto JumpToRestart;
		}
		else {
		//Check Signature.
			if (PacketTarget == nullptr || !DNSCruveGetSignatureData(RecvBuffer.get() + DNS_PACKET_RR_LOCATE(RecvBuffer.get()), ServerType) || 
				CheckEmptyBuffer(PacketTarget->ServerFingerprint, crypto_box_PUBLICKEYBYTES) || 
				CheckEmptyBuffer(PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
					goto JumpToRestart;
		}

	//Wait for sending again.
		SleepTime_SignatureRequest += Parameter.FileRefreshTime;
		continue;

	//Jump here to restart.
	JumpToRestart:
		SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);
		TCPSocketDataList.front().Socket = 0;

	//Print error log.
		DNSCurvePrintLog(ServerType, Message);
		if (!Message.empty())
		{
			Message.append(L"TCP get signature data error");
			PrintError(LOG_LEVEL_3, LOG_ERROR_DNSCURVE, Message.c_str(), 0, nullptr, 0);
		}

	//Send request again.
		sodium_memzero(RecvBuffer.get(), Parameter.LargeBufferSize);
		if (!Parameter.AlternateMultipleRequest)
		{
			if (ServerType == DNSCURVE_MAIN_IPV6)
				++AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_DNSCURVE_TCP_IPV6];
			else if (ServerType == DNSCURVE_MAIN_IPV4)
				++AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_DNSCURVE_TCP_IPV4];
		}

		Sleep(SENDING_INTERVAL_TIME);
	}

	SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);
	PrintError(LOG_LEVEL_2, LOG_ERROR_SYSTEM, L"DNSCurve TCP Signature Request module Monitor terminated", 0, nullptr, 0);
	return true;
}

//Send UDP request to get Signature Data of servers
bool DNSCurveUDPSignatureRequest(
	const uint16_t Protocol, 
	const bool IsAlternate)
{
//Initialization
	std::shared_ptr<uint8_t> SendBuffer(new uint8_t[PACKET_MAXSIZE]()), RecvBuffer(new uint8_t[PACKET_MAXSIZE]());
	sodium_memzero(SendBuffer.get(), PACKET_MAXSIZE);
	sodium_memzero(RecvBuffer.get(), PACKET_MAXSIZE);
	std::vector<SOCKET_DATA> UDPSocketDataList(1U);
	sodium_memzero(&UDPSocketDataList.front(), sizeof(UDPSocketDataList.front()));

//Make packet data(Part 1).
	size_t DataLength = sizeof(dns_hdr);
	const auto DNS_Header = (pdns_hdr)SendBuffer.get();
#if defined(ENABLE_PCAP)
	DNS_Header->ID = Parameter.DomainTest_ID;
#else
	DNS_Header->ID = htons(U16_NUM_ONE);
#endif
	DNS_Header->Flags = htons(DNS_STANDARD);
	DNS_Header->Question = htons(U16_NUM_ONE);
	if (Protocol == AF_INET6)
	{
		if (IsAlternate)
			DataLength += CharToDNSQuery(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ProviderName, SendBuffer.get() + DataLength);
		else 
			DataLength += CharToDNSQuery(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ProviderName, SendBuffer.get() + DataLength);
	}
	else if (Protocol == AF_INET)
	{
		if (IsAlternate)
			DataLength += CharToDNSQuery(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ProviderName, SendBuffer.get() + DataLength);
		else 
			DataLength += CharToDNSQuery(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ProviderName, SendBuffer.get() + DataLength);
	}
	else {
		return false;
	}
	((pdns_qry)(SendBuffer.get() + DataLength))->Type = htons(DNS_TYPE_TEXT);
	((pdns_qry)(SendBuffer.get() + DataLength))->Classes = htons(DNS_CLASS_INTERNET);
	DataLength += sizeof(dns_qry);

//EDNS Label
	DataLength = AddEDNSLabelToAdditionalRR(SendBuffer.get(), DataLength, PACKET_MAXSIZE, nullptr);

//Socket initialization(Part 1)
	size_t ServerType = 0, SleepTime_SignatureRequest = 0, SpeedTime_SignatureRequest = DNSCurveParameter.KeyRecheckTime;
	PDNSCURVE_SERVER_DATA PacketTarget = DNSCurveSelectSignatureTargetSocket(Protocol, IsAlternate, ServerType, UDPSocketDataList);
	std::wstring Message;
	ssize_t RecvLen = 0;

//Send request.
	for (;;)
	{
	//Sleep time controller
		if (SleepTime_SignatureRequest > 0)
		{
			if (SpeedTime_SignatureRequest != DNSCurveParameter.KeyRecheckTime)
			{
				SpeedTime_SignatureRequest = DNSCurveParameter.KeyRecheckTime;
			}
			else if (SleepTime_SignatureRequest < SpeedTime_SignatureRequest)
			{
				SleepTime_SignatureRequest += Parameter.FileRefreshTime;

				Sleep(Parameter.FileRefreshTime);
				continue;
			}

			SleepTime_SignatureRequest = 0;
		}

	//Socket initialization(Part 2)
		if (Protocol == AF_INET6)
			UDPSocketDataList.front().Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		else if (Protocol == AF_INET)
			UDPSocketDataList.front().Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		else 
			goto JumpToRestart;
		if (!SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_INVALID_CHECK, true, nullptr) || 
			!SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_NON_BLOCKING_MODE, true, nullptr) || 
			(Protocol == AF_INET6 && !SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_HOP_LIMITS_IPV6, true, nullptr)) || 
			(Protocol == AF_INET && (!SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_HOP_LIMITS_IPV4, true, nullptr) || 
			!SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_DO_NOT_FRAGMENT, true, nullptr))))
				goto JumpToRestart;

	//Socket selecting
		RecvLen = SocketSelectingOnce(REQUEST_PROCESS_DNSCURVE_SIGN, IPPROTO_UDP, UDPSocketDataList, nullptr, SendBuffer.get(), DataLength, RecvBuffer.get(), PACKET_MAXSIZE, nullptr);
		if (RecvLen < (ssize_t)DNS_PACKET_MINSIZE)
		{
			goto JumpToRestart;
		}
		else {
		//Check Signature.
			if (PacketTarget == nullptr || !DNSCruveGetSignatureData(RecvBuffer.get() + DNS_PACKET_RR_LOCATE(RecvBuffer.get()), ServerType) || 
				CheckEmptyBuffer(PacketTarget->ServerFingerprint, crypto_box_PUBLICKEYBYTES) || 
				CheckEmptyBuffer(PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
					goto JumpToRestart;
		}

	//Wait for sending again.
		SleepTime_SignatureRequest += Parameter.FileRefreshTime;
		continue;

	//Jump here to restart.
	JumpToRestart:
		SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);
		UDPSocketDataList.front().Socket = 0;

	//Print error log.
		DNSCurvePrintLog(ServerType, Message);
		if (!Message.empty())
		{
			Message.append(L"UDP get signature data error");
			PrintError(LOG_LEVEL_3, LOG_ERROR_DNSCURVE, Message.c_str(), 0, nullptr, 0);
		}

	//Send request again.
		sodium_memzero(RecvBuffer.get(), PACKET_MAXSIZE);
		if (!Parameter.AlternateMultipleRequest)
		{
			if (ServerType == DNSCURVE_MAIN_IPV6)
				++AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_DNSCURVE_UDP_IPV6];
			else if (ServerType == DNSCURVE_MAIN_IPV4)
				++AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_DNSCURVE_UDP_IPV4];
		}

		Sleep(SENDING_INTERVAL_TIME);
	}

	SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);
	PrintError(LOG_LEVEL_2, LOG_ERROR_SYSTEM, L"DNSCurve UDP Signature Request module Monitor terminated", 0, nullptr, 0);
	return true;
}

//Transmission of DNSCurve TCP protocol
size_t DNSCurveTCPRequestSingle(
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize)
{
//Initialization
	std::vector<SOCKET_DATA> TCPSocketDataList(1U);
	sodium_memzero(&TCPSocketDataList.front(), sizeof(TCPSocketDataList.front()));
	DNSCURVE_SOCKET_SELECTING_DATA TCPSocketSelectingData;
	memset(&TCPSocketSelectingData, 0, sizeof(TCPSocketSelectingData));
	PDNSCURVE_SERVER_DATA PacketTarget = nullptr;
	bool *IsAlternate = nullptr;
	size_t *AlternateTimeoutTimes = nullptr;
	sodium_memzero(OriginalRecv, RecvSize);
	const auto SendBuffer = OriginalRecv;

//Socket initialization
	TCPSocketSelectingData.ServerType = SelectTargetSocketSingle(REQUEST_PROCESS_DNSCURVE_MAIN, IPPROTO_TCP, &TCPSocketDataList.front(), (void **)&PacketTarget, &IsAlternate, &AlternateTimeoutTimes, nullptr);
	if (TCPSocketSelectingData.ServerType == EXIT_SUCCESS || TCPSocketSelectingData.ServerType == EXIT_FAILURE)
	{
		SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);
		PrintError(LOG_LEVEL_2, LOG_ERROR_NETWORK, L"DNSCurve TCP socket initialization error", 0, nullptr, 0);

		return EXIT_FAILURE;
	}

//Make Precomputation Key between client and server.
	uint8_t *Client_PublicKey = nullptr, *PrecomputationKey = nullptr;
	std::shared_ptr<uint8_t> Client_PublicKey_PTR;
	DNSCURVE_HEAP_BUFFER_TABLE<uint8_t> PrecomputationKeyPTR;
	if (DNSCurveParameter.IsEncryption && DNSCurveParameter.IsClientEphemeralKey)
	{
		std::shared_ptr<uint8_t> Client_PublicKey_PTR_Temp(new uint8_t[crypto_box_PUBLICKEYBYTES]());
		Client_PublicKey_PTR.swap(Client_PublicKey_PTR_Temp);

		DNSCURVE_HEAP_BUFFER_TABLE<uint8_t> PrecomputationKeyPTR_Temp(crypto_box_BEFORENMBYTES);
		PrecomputationKeyPTR_Temp.Swap(PrecomputationKeyPTR);
		Client_PublicKey = Client_PublicKey_PTR.get();
		PrecomputationKey = PrecomputationKeyPTR.Buffer;
		if (!DNSCurvePrecomputationKeySetting(PrecomputationKey, Client_PublicKey, PacketTarget->ServerFingerprint))
		{
			SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);
			return EXIT_FAILURE;
		}
	}
	else {
		PrecomputationKey = PacketTarget->PrecomputationKey, Client_PublicKey = DNSCurveParameter.Client_PublicKey;
	}

//Socket attribute setting(Non-blocking mode)
	if (!SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_NON_BLOCKING_MODE, true, nullptr))
	{
		SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);
		return EXIT_FAILURE;
	}

//Make encryption or normal packet.
	ssize_t RecvLen = DNSCurvePacketEncryption(IPPROTO_TCP, PacketTarget->SendMagicNumber, Client_PublicKey, PrecomputationKey, OriginalSend, SendSize, SendBuffer, RecvSize);
	if (RecvLen < (ssize_t)DNS_PACKET_MINSIZE)
	{
		SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);
		return EXIT_FAILURE;
	}

//Socket selecting structure initialization
	std::vector<DNSCURVE_SOCKET_SELECTING_DATA> TCPSocketSelectingList;
	if (DNSCurveParameter.IsEncryption) //Encryption mode
	{
		TCPSocketSelectingData.PrecomputationKey = PrecomputationKey;
		TCPSocketSelectingData.ReceiveMagicNumber = PacketTarget->ReceiveMagicNumber;
	}

	TCPSocketSelectingData.SendBuffer = SendBuffer;
	TCPSocketSelectingData.SendSize = RecvLen;
	TCPSocketSelectingData.RecvLen = 0;
	TCPSocketSelectingData.IsPacketDone = false;
	TCPSocketSelectingList.push_back(TCPSocketSelectingData);

//Socket selecting
	ssize_t ErrorCode = 0;
	RecvLen = SocketSelectingOnce(REQUEST_PROCESS_DNSCURVE_MAIN, IPPROTO_TCP, TCPSocketDataList, &TCPSocketSelectingList, nullptr, 0, OriginalRecv, RecvSize, &ErrorCode);
	if (ErrorCode == WSAETIMEDOUT && !Parameter.AlternateMultipleRequest) //Mark timeout.
	{
		if (TCPSocketDataList.front().AddrLen == sizeof(sockaddr_in6))
			++AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_DNSCURVE_TCP_IPV6];
		else if (TCPSocketDataList.front().AddrLen == sizeof(sockaddr_in))
			++AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_DNSCURVE_UDP_IPV4];
	}

	return RecvLen;
}

//Transmission of DNSCurve TCP protocol(Multiple threading)
size_t DNSCurveTCPRequestMultiple(
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize)
{
//Key initialization
	uint8_t *PrecomputationKey = nullptr, *Alternate_PrecomputationKey = nullptr;
	DNSCURVE_HEAP_BUFFER_TABLE<uint8_t> PrecomputationKeyPTR, Alternate_PrecomputationKeyPTR;
	if (DNSCurveParameter.IsEncryption && DNSCurveParameter.IsClientEphemeralKey)
	{
		DNSCURVE_HEAP_BUFFER_TABLE<uint8_t> PrecomputationKeyPTR_Temp(crypto_box_BEFORENMBYTES), Alternate_PrecomputationKeyPTR_Temp(crypto_box_BEFORENMBYTES);

	//Main
		PrecomputationKeyPTR_Temp.Swap(PrecomputationKeyPTR);
		PrecomputationKey = PrecomputationKeyPTR.Buffer;

	//Alternate
		Alternate_PrecomputationKeyPTR_Temp.Swap(Alternate_PrecomputationKeyPTR);
		Alternate_PrecomputationKey = Alternate_PrecomputationKeyPTR.Buffer;
	}

//Initialization(Part 1)
	std::vector<SOCKET_DATA> TCPSocketDataList;
	std::vector<DNSCURVE_SOCKET_SELECTING_DATA> TCPSocketSelectingList;
	std::shared_ptr<uint8_t> SendBuffer, Alternate_SendBuffer;
	PDNSCURVE_SERVER_DATA PacketTarget = nullptr;
	size_t DataLength = 0, Alternate_DataLength = 0;
	sodium_memzero(OriginalRecv, RecvSize);

//Socket precomputation
	DNSCurveSocketPrecomputation(IPPROTO_TCP, OriginalSend, SendSize, RecvSize, &PrecomputationKey, &Alternate_PrecomputationKey, &PacketTarget, 
		TCPSocketDataList, TCPSocketSelectingList, SendBuffer, DataLength, Alternate_SendBuffer, Alternate_DataLength);
	if (TCPSocketDataList.empty() || TCPSocketDataList.size() != TCPSocketSelectingList.size())
		return EXIT_FAILURE;

//Socket selecting structure initialization
	for (size_t Index = 0;Index < TCPSocketDataList.size();++Index)
	{
	//Encryption mode
		if (DNSCurveParameter.IsEncryption)
		{
			DNSCurvePacketTargetSetting(TCPSocketSelectingList.at(Index).ServerType, &PacketTarget);
			TCPSocketSelectingList.at(Index).ReceiveMagicNumber = PacketTarget->ReceiveMagicNumber;

		//Alternate
			if (TCPSocketSelectingList.at(Index).ServerType == DNSCURVE_ALTERNATE_IPV6 || TCPSocketSelectingList.at(Index).ServerType == DNSCURVE_ALTERNATE_IPV4)
			{
				TCPSocketSelectingList.at(Index).PrecomputationKey = Alternate_PrecomputationKey;
				TCPSocketSelectingList.at(Index).SendBuffer = Alternate_SendBuffer.get();
				TCPSocketSelectingList.at(Index).SendSize = Alternate_DataLength;
			}
		//Main
			else {
				TCPSocketSelectingList.at(Index).PrecomputationKey = PrecomputationKey;
				TCPSocketSelectingList.at(Index).SendBuffer = SendBuffer.get();
				TCPSocketSelectingList.at(Index).SendSize = DataLength;
			}
		}
	//Normal mode
		else {
			TCPSocketSelectingList.at(Index).SendBuffer = SendBuffer.get();
			TCPSocketSelectingList.at(Index).SendSize = DataLength;
		}

		TCPSocketSelectingList.at(Index).RecvLen = 0;
		TCPSocketSelectingList.at(Index).IsPacketDone = false;
	}

//Socket selecting
	ssize_t ErrorCode = 0;
	const ssize_t RecvLen = SocketSelectingOnce(REQUEST_PROCESS_DNSCURVE_MAIN, IPPROTO_TCP, TCPSocketDataList, &TCPSocketSelectingList, nullptr, 0, OriginalRecv, RecvSize, &ErrorCode);
	if (ErrorCode == WSAETIMEDOUT && !Parameter.AlternateMultipleRequest) //Mark timeout.
	{
		if (TCPSocketDataList.front().AddrLen == sizeof(sockaddr_in6))
			++AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_DNSCURVE_UDP_IPV6];
		else if (TCPSocketDataList.front().AddrLen == sizeof(sockaddr_in))
			++AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_DNSCURVE_UDP_IPV4];
	}

	return RecvLen;
}

//Transmission of DNSCurve UDP protocol
size_t DNSCurveUDPRequestSingle(
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize)
{
//Initialization
	std::vector<SOCKET_DATA> UDPSocketDataList(1U);
	sodium_memzero(&UDPSocketDataList.front(), sizeof(UDPSocketDataList.front()));
	DNSCURVE_SOCKET_SELECTING_DATA UDPSocketSelectingData;
	memset(&UDPSocketSelectingData, 0, sizeof(UDPSocketSelectingData));
	PDNSCURVE_SERVER_DATA PacketTarget = nullptr;
	bool *IsAlternate = nullptr;
	size_t *AlternateTimeoutTimes = nullptr;
	sodium_memzero(OriginalRecv, RecvSize);
	const auto SendBuffer = OriginalRecv;

//Socket initialization
	UDPSocketSelectingData.ServerType = SelectTargetSocketSingle(REQUEST_PROCESS_DNSCURVE_MAIN, IPPROTO_UDP, &UDPSocketDataList.front(), (void **)&PacketTarget, &IsAlternate, &AlternateTimeoutTimes, nullptr);
	if (UDPSocketSelectingData.ServerType == EXIT_SUCCESS || UDPSocketSelectingData.ServerType == EXIT_FAILURE)
	{
		SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);
		PrintError(LOG_LEVEL_2, LOG_ERROR_NETWORK, L"DNSCurve UDP socket initialization error", 0, nullptr, 0);

		return EXIT_FAILURE;
	}

//Make Precomputation Key between client and server.
	uint8_t *Client_PublicKey = nullptr, *PrecomputationKey = nullptr;
	std::shared_ptr<uint8_t> Client_PublicKey_PTR, PrecomputationKeyPTR;
	if (DNSCurveParameter.IsEncryption && DNSCurveParameter.IsClientEphemeralKey)
	{
		std::shared_ptr<uint8_t> Client_PublicKey_PTR_Temp(new uint8_t[crypto_box_PUBLICKEYBYTES]()), PrecomputationKeyPTR_Temp(new uint8_t[crypto_box_BEFORENMBYTES]());
		Client_PublicKey_PTR.swap(Client_PublicKey_PTR_Temp);
		PrecomputationKeyPTR.swap(PrecomputationKeyPTR_Temp);
		Client_PublicKey = Client_PublicKey_PTR.get();
		PrecomputationKey = PrecomputationKeyPTR.get();
		if (!DNSCurvePrecomputationKeySetting(PrecomputationKey, Client_PublicKey, PacketTarget->ServerFingerprint))
		{
			SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);
			return EXIT_FAILURE;
		}
	}
	else {
		PrecomputationKey = PacketTarget->PrecomputationKey, Client_PublicKey = DNSCurveParameter.Client_PublicKey;
	}

//Socket attribute setting(Timeout) and UDP connecting
	if (!SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_TIMEOUT, true, &DNSCurveParameter.DNSCurve_SocketTimeout_Unreliable) || 
		SocketConnecting(IPPROTO_UDP, UDPSocketDataList.front().Socket, (PSOCKADDR)&UDPSocketDataList.front().SockAddr, UDPSocketDataList.front().AddrLen, nullptr, 0) == EXIT_FAILURE)
	{
		SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);
		return EXIT_FAILURE;
	}

//Make encryption or normal packet.
	ssize_t RecvLen = DNSCurvePacketEncryption(IPPROTO_UDP, PacketTarget->SendMagicNumber, Client_PublicKey, PrecomputationKey, OriginalSend, SendSize, SendBuffer, RecvSize);
	if (RecvLen < (ssize_t)DNS_PACKET_MINSIZE)
	{
		SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);
		return EXIT_FAILURE;
	}

//Socket selecting structure initialization
	std::vector<DNSCURVE_SOCKET_SELECTING_DATA> UDPSocketSelectingList;
	if (DNSCurveParameter.IsEncryption) //Encryption mode
	{
		UDPSocketSelectingData.PrecomputationKey = PrecomputationKey;
		UDPSocketSelectingData.ReceiveMagicNumber = PacketTarget->ReceiveMagicNumber;
		UDPSocketSelectingData.SendBuffer = SendBuffer;
		UDPSocketSelectingData.SendSize = RecvLen;
	}
	else { //Normal mode
		UDPSocketSelectingData.SendBuffer = (uint8_t *)OriginalSend;
		UDPSocketSelectingData.SendSize = SendSize;
	}

	UDPSocketSelectingData.RecvLen = 0;
	UDPSocketSelectingData.IsPacketDone = false;
	UDPSocketSelectingList.push_back(UDPSocketSelectingData);

//Socket selecting
	ssize_t ErrorCode = 0;
	RecvLen = SocketSelectingOnce(REQUEST_PROCESS_DNSCURVE_MAIN, IPPROTO_UDP, UDPSocketDataList, &UDPSocketSelectingList, nullptr, 0, OriginalRecv, RecvSize, &ErrorCode);
	if (ErrorCode == WSAETIMEDOUT && !Parameter.AlternateMultipleRequest) //Mark timeout.
	{
		if (UDPSocketDataList.front().AddrLen == sizeof(sockaddr_in6))
			++AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_DNSCURVE_UDP_IPV6];
		else if (UDPSocketDataList.front().AddrLen == sizeof(sockaddr_in))
			++AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_DNSCURVE_UDP_IPV4];
	}

	return RecvLen;
}

//Transmission of DNSCurve UDP protocol(Multiple threading)
size_t DNSCurveUDPRequestMultiple(
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize)
{
//Key initialization
	uint8_t *PrecomputationKey = nullptr, *Alternate_PrecomputationKey = nullptr;
	DNSCURVE_HEAP_BUFFER_TABLE<uint8_t> PrecomputationKeyPTR, Alternate_PrecomputationKeyPTR;
	if (DNSCurveParameter.IsEncryption && DNSCurveParameter.IsClientEphemeralKey)
	{
		DNSCURVE_HEAP_BUFFER_TABLE<uint8_t> PrecomputationKeyPTR_Temp(crypto_box_BEFORENMBYTES), Alternate_PrecomputationKeyPTR_Temp(crypto_box_BEFORENMBYTES);

	//Main
		PrecomputationKeyPTR_Temp.Swap(PrecomputationKeyPTR);
		PrecomputationKey = PrecomputationKeyPTR.Buffer;

	//Alternate
		Alternate_PrecomputationKeyPTR_Temp.Swap(Alternate_PrecomputationKeyPTR);
		Alternate_PrecomputationKey = Alternate_PrecomputationKeyPTR.Buffer;
	}

//Initialization(Part 1)
	std::vector<SOCKET_DATA> UDPSocketDataList;
	std::vector<DNSCURVE_SOCKET_SELECTING_DATA> UDPSocketSelectingList;
	std::shared_ptr<uint8_t> SendBuffer, Alternate_SendBuffer;
	PDNSCURVE_SERVER_DATA PacketTarget = nullptr;
	size_t DataLength = 0, Alternate_DataLength = 0;
	sodium_memzero(OriginalRecv, RecvSize);

//Socket precomputation
	DNSCurveSocketPrecomputation(IPPROTO_UDP, OriginalSend, SendSize, RecvSize, &PrecomputationKey, &Alternate_PrecomputationKey, &PacketTarget, 
		UDPSocketDataList, UDPSocketSelectingList, SendBuffer, DataLength, Alternate_SendBuffer, Alternate_DataLength);
	if (UDPSocketDataList.empty() || UDPSocketDataList.size() != UDPSocketSelectingList.size())
		return EXIT_FAILURE;

//Socket selecting structure initialization
	for (size_t Index = 0;Index < UDPSocketDataList.size();++Index)
	{
	//Encryption mode
		if (DNSCurveParameter.IsEncryption)
		{
			DNSCurvePacketTargetSetting(UDPSocketSelectingList.at(Index).ServerType, &PacketTarget);
			UDPSocketSelectingList.at(Index).ReceiveMagicNumber = PacketTarget->ReceiveMagicNumber;

		//Alternate
			if (UDPSocketSelectingList.at(Index).ServerType == DNSCURVE_ALTERNATE_IPV6 || UDPSocketSelectingList.at(Index).ServerType == DNSCURVE_ALTERNATE_IPV4)
			{
				UDPSocketSelectingList.at(Index).PrecomputationKey = Alternate_PrecomputationKey;
				UDPSocketSelectingList.at(Index).SendBuffer = Alternate_SendBuffer.get();
				UDPSocketSelectingList.at(Index).SendSize = Alternate_DataLength;
			}
		//Main
			else {
				UDPSocketSelectingList.at(Index).PrecomputationKey = PrecomputationKey;
				UDPSocketSelectingList.at(Index).SendBuffer = SendBuffer.get();
				UDPSocketSelectingList.at(Index).SendSize = DataLength;
			}
		}
	//Normal mode
		else {
			UDPSocketSelectingList.at(Index).SendBuffer = (uint8_t *)OriginalSend;
			UDPSocketSelectingList.at(Index).SendSize = SendSize;
		}

		UDPSocketSelectingList.at(Index).RecvLen = 0;
		UDPSocketSelectingList.at(Index).IsPacketDone = false;
	}

//Socket selecting
	ssize_t ErrorCode = 0;
	const ssize_t RecvLen = SocketSelectingOnce(REQUEST_PROCESS_DNSCURVE_MAIN, IPPROTO_UDP, UDPSocketDataList, &UDPSocketSelectingList, nullptr, 0, OriginalRecv, RecvSize, &ErrorCode);
	if (ErrorCode == WSAETIMEDOUT && !Parameter.AlternateMultipleRequest) //Mark timeout.
	{
		if (UDPSocketDataList.front().AddrLen == sizeof(sockaddr_in6))
			++AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_DNSCURVE_UDP_IPV6];
		else if (UDPSocketDataList.front().AddrLen == sizeof(sockaddr_in))
			++AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_DNSCURVE_UDP_IPV4];
	}

	return RecvLen;
}
#endif

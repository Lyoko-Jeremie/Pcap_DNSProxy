// This code is part of Pcap_DNSProxy
// A local DNS server based on WinPcap and LibPcap
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


#include "DNSCurve.h"

#if defined(ENABLE_LIBSODIUM)
//DNSCurve verify keypair
bool __fastcall DNSCurveVerifyKeypair(const unsigned char *PublicKey, const unsigned char *SecretKey)
{
	std::shared_ptr<uint8_t> Test_PublicKey(new uint8_t[crypto_box_PUBLICKEYBYTES]()), Test_SecretKey(new uint8_t[crypto_box_PUBLICKEYBYTES]()), Validation(new uint8_t[crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES + crypto_box_ZEROBYTES]());
	memset(Test_PublicKey.get(), 0, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES);
	memset(Test_SecretKey.get(), 0, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES);
	memset(Validation.get(), 0, sizeof(uint8_t) * (crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES + crypto_box_ZEROBYTES));

//Keypair, Nonce and validation data
	crypto_box_curve25519xsalsa20poly1305_keypair(Test_PublicKey.get(), Test_SecretKey.get());
	uint8_t Nonce[crypto_box_NONCEBYTES] = {DNSCURVE_TEST_NONCE};
	memcpy_s(Validation.get() + crypto_box_ZEROBYTES, crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES, PublicKey, crypto_box_PUBLICKEYBYTES);

//Verify keys
	crypto_box_curve25519xsalsa20poly1305(Validation.get(), Validation.get(), crypto_box_PUBLICKEYBYTES + crypto_box_ZEROBYTES, Nonce, Test_PublicKey.get(), SecretKey);
	if (crypto_box_curve25519xsalsa20poly1305_open(
			Validation.get(), 
			Validation.get(), 
			crypto_box_PUBLICKEYBYTES + crypto_box_ZEROBYTES, 
			Nonce, PublicKey, 
			Test_SecretKey.get()) == LIBSODIUM_ERROR)
		return false;

	return true;
}

//Select socket data of DNS target(DNSCurve)
size_t __fastcall SelectTargetSocket(SOCKET_DATA *SockData, PDNSCURVE_SERVER_DATA &PacketTarget, bool *&IsAlternate, size_t *&AlternateTimeoutTimes, const uint16_t Protocol)
{
//Socket initialization
	size_t ServerType = 0;
	uint16_t SocketType = 0;
	if (Protocol == IPPROTO_TCP) //TCP
		SocketType = SOCK_STREAM;
	else //UDP
		SocketType = SOCK_DGRAM;

//IPv6
	if (DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family > 0 && 
		(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK_BOTH && Parameter.GatewayAvailable_IPv6 || //Auto select
		Parameter.RequestMode_Network == REQUEST_MODE_IPV6 || //IPv6
		Parameter.RequestMode_Network == REQUEST_MODE_IPV4 && DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family == 0)) //Non-IPv4
	{
	//TCP
		if (Protocol == IPPROTO_TCP)
		{
			IsAlternate = &AlternateSwapList.IsSwap[8U];
			AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[8U];
		}
	//UDP
		else {
			IsAlternate = &AlternateSwapList.IsSwap[10U];
			AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[10U];
		}

	//Encryption mode check
		if (DNSCurveParameter.IsEncryption)
		{
			if (CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
				CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
					*IsAlternate = true;
			if (*IsAlternate && (CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
				CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
					*IsAlternate = false;
		}

		if (*IsAlternate && DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0)
		{
			((PSOCKADDR_IN6)&SockData->SockAddr)->sin6_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
			((PSOCKADDR_IN6)&SockData->SockAddr)->sin6_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv6;
			ServerType = DNSCURVE_ALTERNATE_IPV6;
		}
		else { //Main
		//Encryption mode check
			if (DNSCurveParameter.IsEncryption && 
				(CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
				CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
					return 0;

			((PSOCKADDR_IN6)&SockData->SockAddr)->sin6_addr = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_addr;
			((PSOCKADDR_IN6)&SockData->SockAddr)->sin6_port = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_port;
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv6;
			ServerType = DNSCURVE_MAIN_IPV6;
		}

		SockData->AddrLen = sizeof(sockaddr_in6);
		SockData->SockAddr.ss_family = AF_INET6;
		SockData->Socket = socket(AF_INET6, SocketType, Protocol);
		return ServerType;
	}
//IPv4
	else if (DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family > 0 && 
		(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK_BOTH && Parameter.GatewayAvailable_IPv4 || //Auto select
		Parameter.RequestMode_Network == REQUEST_MODE_IPV4 || //IPv4
		Parameter.RequestMode_Network == REQUEST_MODE_IPV6 && DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family == 0)) //Non-IPv6
	{
	//TCP
		if (Protocol == IPPROTO_TCP)
		{
			IsAlternate = &AlternateSwapList.IsSwap[9U];
			AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[9U];
		}
	//UDP
		else {
			IsAlternate = &AlternateSwapList.IsSwap[11U];
			AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[11U];
		}

	//Encryption mode check
		if (DNSCurveParameter.IsEncryption)
		{
			if (CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
				CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
					*IsAlternate = true;
			if (*IsAlternate && (CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
				CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
					*IsAlternate = false;
		}

		if (*IsAlternate && DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0)
		{
			((PSOCKADDR_IN)&SockData->SockAddr)->sin_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
			((PSOCKADDR_IN)&SockData->SockAddr)->sin_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv4;
			ServerType = DNSCURVE_ALTERNATE_IPV4;
		}
		else { //Main
		//Encryption mode check
			if (DNSCurveParameter.IsEncryption && 
				(CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
				CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
					return 0;

			((PSOCKADDR_IN)&SockData->SockAddr)->sin_addr = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_addr;
			((PSOCKADDR_IN)&SockData->SockAddr)->sin_port = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_port;
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv4;
			ServerType = DNSCURVE_MAIN_IPV4;
		}

		SockData->AddrLen = sizeof(sockaddr_in);
		SockData->SockAddr.ss_family = AF_INET;
		SockData->Socket = socket(AF_INET, SocketType, Protocol);
		return ServerType;
	}

	return 0;
}

//Select socket data of DNS target(DNSCurve Multithreading)
bool __fastcall SelectTargetSocketMulti(bool &IsIPv6, bool *&IsAlternate, const uint16_t Protocol)
{
//IPv6
	if (DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family > 0 &&
		(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK_BOTH && Parameter.GatewayAvailable_IPv6 || //Auto select
		Parameter.RequestMode_Network == REQUEST_MODE_IPV6 || //IPv6
		Parameter.RequestMode_Network == REQUEST_MODE_IPV4 && DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family == 0)) //Non-IPv4
	{
		IsIPv6 = true;
		if (Protocol == IPPROTO_TCP) //TCP
			IsAlternate = &AlternateSwapList.IsSwap[8U];
		else //UDP
			IsAlternate = &AlternateSwapList.IsSwap[10U];
	}
//IPv4
	else if (DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family > 0 &&
		(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK_BOTH && Parameter.GatewayAvailable_IPv4 || //Auto select
		Parameter.RequestMode_Network == REQUEST_MODE_IPV4 || //IPv4
		Parameter.RequestMode_Network == REQUEST_MODE_IPV6 && DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family == 0)) //Non-IPv6
	{
		IsIPv6 = false;
		if (Protocol == IPPROTO_TCP) //TCP
			IsAlternate = &AlternateSwapList.IsSwap[9U];
		else //UDP
			IsAlternate = &AlternateSwapList.IsSwap[11U];
	}
	else {
		return false;
	}

	return true;
}

//DNSCurve initialization
void __fastcall DNSCurveInit(void)
{
//DNSCurve signature request TCP Mode
	if (DNSCurveParameter.DNSCurveMode == DNSCURVE_REQUEST_MODE_TCP)
	{
	//Main
		if (DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family > 0 && 
			(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK_BOTH || Parameter.RequestMode_Network == REQUEST_MODE_IPV6 || //Auto select and IPv6
			Parameter.RequestMode_Network == REQUEST_MODE_IPV4 && DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family > 0) && //Non-IPv4
			(CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
			CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
		{
			std::thread DNSCurveTCPSignatureRequestThread(DNSCurveTCPSignatureRequest, AF_INET6, false);
			DNSCurveTCPSignatureRequestThread.detach();
		}

		if (DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family > 0 && 
			(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK_BOTH || Parameter.RequestMode_Network == REQUEST_MODE_IPV4 || //Auto select and IPv4
			Parameter.RequestMode_Network == REQUEST_MODE_IPV6 && DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family > 0) && //Non-IPv6
			(CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
			CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
		{
			std::thread DNSCurveTCPSignatureRequestThread(DNSCurveTCPSignatureRequest, AF_INET, false);
			DNSCurveTCPSignatureRequestThread.detach();
		}

	//Alternate
		if (DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 &&
			(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK_BOTH || Parameter.RequestMode_Network == REQUEST_MODE_IPV6 || //Auto select and IPv6
			Parameter.RequestMode_Network == REQUEST_MODE_IPV4 && DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family > 0) && //Non-IPv4
			(CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
			CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
		{
			std::thread DNSCurveTCPSignatureRequestThread(DNSCurveTCPSignatureRequest, AF_INET6, true);
			DNSCurveTCPSignatureRequestThread.detach();
		}

		if (DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && 
			(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK_BOTH || Parameter.RequestMode_Network == REQUEST_MODE_IPV4 || //Auto select and IPv4
			Parameter.RequestMode_Network == REQUEST_MODE_IPV6 && DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family > 0) && //Non-IPv6
			(CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
			CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
		{
			std::thread DNSCurveTCPSignatureRequestThread(DNSCurveTCPSignatureRequest, AF_INET, true);
			DNSCurveTCPSignatureRequestThread.detach();
		}
	}

//DNSCurve signature request UDP Mode
//Main
	if (DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family > 0 && 
		(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK_BOTH || Parameter.RequestMode_Network == REQUEST_MODE_IPV6 || //Auto select and IPv6
		Parameter.RequestMode_Network == REQUEST_MODE_IPV4 && DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family > 0) && //Non-IPv4
		(CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
		CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
	{
		std::thread DNSCurveUDPSignatureRequestThread(DNSCurveUDPSignatureRequest, AF_INET6, false);
		DNSCurveUDPSignatureRequestThread.detach();
	}

	if (DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family > 0 && 
		(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK_BOTH || Parameter.RequestMode_Network == REQUEST_MODE_IPV4 || //Auto select and IPv4
		Parameter.RequestMode_Network == REQUEST_MODE_IPV6 && DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family > 0) && //Non-IPv6
		(CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
		CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
	{
		std::thread DNSCurveUDPSignatureRequestThread(DNSCurveUDPSignatureRequest, AF_INET, false);
		DNSCurveUDPSignatureRequestThread.detach();
	}

//Alternate
	if (DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && 
		(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK_BOTH || Parameter.RequestMode_Network == REQUEST_MODE_IPV6 || //Auto select and IPv6
		Parameter.RequestMode_Network == REQUEST_MODE_IPV4 && DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family > 0) && //Non-IPv4
		(CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
		CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
	{
		std::thread DNSCurveUDPSignatureRequestThread(DNSCurveUDPSignatureRequest, AF_INET6, true);
		DNSCurveUDPSignatureRequestThread.detach();
	}

	if (DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && 
		(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK_BOTH || Parameter.RequestMode_Network == REQUEST_MODE_IPV4 || //Auto select and IPv4
		Parameter.RequestMode_Network == REQUEST_MODE_IPV6 && DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family > 0) && //Non-IPv6
		(CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
		CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
	{
		std::thread DNSCurveUDPSignatureRequestThread(DNSCurveUDPSignatureRequest, AF_INET, true);
		DNSCurveUDPSignatureRequestThread.detach();
	}

	return;
}

//DNSCurve Local Signature Request
size_t DNSCurveSignatureRequest(const char *OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize)
{
//Initialization
	std::shared_ptr<sockaddr_storage> SockAddr(new sockaddr_storage());
	memset(SockAddr.get(), 0, sizeof(sockaddr_storage));
	SYSTEM_SOCKET UDPSocket = 0;
	socklen_t AddrLen = 0;

//Socket initialization
	if ((Parameter.ListenProtocol_Network == LISTEN_PROTOCOL_NETWORK_BOTH || Parameter.ListenProtocol_Network == LISTEN_PROTOCOL_IPV6) && 
		DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family > 0) //IPv6
	{
	#if defined(PLATFORM_WIN)
		((sockaddr_in6 *)SockAddr.get())->sin6_addr = in6addr_loopback;
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		((sockaddr_in6 *)SockAddr.get())->sin6_addr = *((in6_addr *)&in6addr_loopback);
	#endif
		((sockaddr_in6 *)SockAddr.get())->sin6_port = Parameter.ListenPort->front();

		AddrLen = sizeof(sockaddr_in6);
		SockAddr->ss_family = AF_INET6;
		UDPSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	}
	else if ((Parameter.ListenProtocol_Network == LISTEN_PROTOCOL_NETWORK_BOTH || Parameter.ListenProtocol_Network == LISTEN_PROTOCOL_IPV4) && 
		DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family > 0) //IPv4
	{
		((sockaddr_in *)SockAddr.get())->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		((sockaddr_in *)SockAddr.get())->sin_port = Parameter.ListenPort->front();

		AddrLen = sizeof(sockaddr_in);
		SockAddr->ss_family = AF_INET;
		UDPSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	}
	else {
		return EXIT_FAILURE;
	}

//Socket check
	if (UDPSocket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_NETWORK, L"DNSCurve Local Signature request initialization error", WSAGetLastError(), nullptr, 0);
		return EXIT_FAILURE;
	}

//Set socket timeout.
#if defined(PLATFORM_WIN)
	if (setsockopt(UDPSocket, SOL_SOCKET, SO_SNDTIMEO, (const char *)&Parameter.SocketTimeout_Unreliable, sizeof(int)) == SOCKET_ERROR || 
		setsockopt(UDPSocket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&Parameter.SocketTimeout_Unreliable, sizeof(int)) == SOCKET_ERROR)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	if (setsockopt(UDPSocket, SOL_SOCKET, SO_SNDTIMEO, (const char *)&Parameter.SocketTimeout_Unreliable, sizeof(timeval)) == SOCKET_ERROR || 
		setsockopt(UDPSocket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&Parameter.SocketTimeout_Unreliable, sizeof(timeval)) == SOCKET_ERROR)
#endif
	{
		PrintError(LOG_ERROR_NETWORK, L"Set DNSCurve Local Signature socket timeout error", WSAGetLastError(), nullptr, 0);
		closesocket(UDPSocket);

		return EXIT_FAILURE;
	}

//UDP connecting
	if (connect(UDPSocket, (PSOCKADDR)SockAddr.get(), AddrLen) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_NETWORK, L"DNSCurve Local Signature request initialization error", WSAGetLastError(), nullptr, 0);
		closesocket(UDPSocket);

		return EXIT_FAILURE;
	}

//Send requesting.
	if (send(UDPSocket, OriginalSend, (int)SendSize, 0) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_NETWORK, L"DNSCurve Local Signature request error", WSAGetLastError(), nullptr, 0);
		shutdown(UDPSocket, SD_BOTH);
		closesocket(UDPSocket);

		return EXIT_FAILURE;
	}

//Receive result.
	SSIZE_T RecvLen = recv(UDPSocket, OriginalRecv, (int)RecvSize, 0);
	shutdown(UDPSocket, SD_BOTH);
	closesocket(UDPSocket);
	if (RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE)
		return RecvLen;

	memset(OriginalRecv, 0, RecvSize);
	return EXIT_FAILURE;
}

//Send TCP request to get Signature Data of servers
bool __fastcall DNSCurveTCPSignatureRequest(const uint16_t Protocol, const bool IsAlternate)
{
//Initialization
	std::shared_ptr<char> SendBuffer(new char[PACKET_MAXSIZE]()), RecvBuffer(new char[LARGE_PACKET_MAXSIZE]());
	memset(SendBuffer.get(), 0, PACKET_MAXSIZE);
	memset(RecvBuffer.get(), 0, LARGE_PACKET_MAXSIZE);
	std::shared_ptr<sockaddr_storage> SockAddr(new sockaddr_storage());
	memset(SockAddr.get(), 0, sizeof(sockaddr_storage));
	SYSTEM_SOCKET TCPSocket = 0;

//Packet
	size_t DataLength = sizeof(dns_tcp_hdr);
	auto DNS_TCP_Header = (pdns_tcp_hdr)SendBuffer.get();
#if defined(ENABLE_PCAP)
	DNS_TCP_Header->ID = Parameter.DomainTest_ID;
#endif
	DNS_TCP_Header->Flags = htons(DNS_STANDARD);
	DNS_TCP_Header->Questions = htons(U16_NUM_ONE);

//Socket initialization
	if (Protocol == AF_INET6) //IPv6
	{
		if (IsAlternate)
			DataLength += CharToDNSQuery(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ProviderName, SendBuffer.get() + DataLength);
		else 
			DataLength += CharToDNSQuery(DNSCurveParameter.DNSCurveTarget.IPv6.ProviderName, SendBuffer.get() + DataLength);
	}
	else { //IPv4
		if (IsAlternate)
			DataLength += CharToDNSQuery(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ProviderName, SendBuffer.get() + DataLength);
		else 
			DataLength += CharToDNSQuery(DNSCurveParameter.DNSCurveTarget.IPv4.ProviderName, SendBuffer.get() + DataLength);
	}

	auto DNS_Query = (pdns_qry)(SendBuffer.get() + DataLength);
	DNS_Query->Type = htons(DNS_RECORD_TXT);
	DNS_Query->Classes = htons(DNS_CLASS_IN);
	DataLength += sizeof(dns_qry);

//EDNS Label
	DNS_TCP_Header->Additional = htons(U16_NUM_ONE);
	auto DNS_Record_OPT = (pdns_record_opt)(SendBuffer.get() + DataLength);
	DNS_Record_OPT->Type = htons(DNS_RECORD_OPT);
	DNS_Record_OPT->UDPPayloadSize = htons(EDNS_PACKET_MINSIZE);
	DataLength += sizeof(dns_record_opt);

	DNS_TCP_Header->Length = htons((uint16_t)(DataLength - sizeof(uint16_t)));
//Socket initialization
	socklen_t AddrLen = 0;
	size_t ServerType = 0;
	PDNSCURVE_SERVER_DATA PacketTarget = nullptr;
	if (Protocol == AF_INET6) //IPv6
	{
		if (IsAlternate)
		{
			((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
			((PSOCKADDR_IN6)SockAddr.get())->sin6_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv6;
			ServerType = DNSCURVE_ALTERNATE_IPV6;
		}
		else { //Main
			((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_addr;
			((PSOCKADDR_IN6)SockAddr.get())->sin6_port = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_port;
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv6;
			ServerType = DNSCURVE_MAIN_IPV6;
		}

		AddrLen = sizeof(sockaddr_in6);
		SockAddr->ss_family = AF_INET6;
		TCPSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	}
	else { //IPv4
		if (IsAlternate)
		{
			((PSOCKADDR_IN)SockAddr.get())->sin_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
			((PSOCKADDR_IN)SockAddr.get())->sin_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv4;
			ServerType = DNSCURVE_ALTERNATE_IPV4;
		}
		else { //Main
			((PSOCKADDR_IN)SockAddr.get())->sin_addr = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_addr;
			((PSOCKADDR_IN)SockAddr.get())->sin_port = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_port;
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv4;
			ServerType = DNSCURVE_MAIN_IPV4;
		}

		AddrLen = sizeof(sockaddr_in);
		SockAddr->ss_family = AF_INET;
		TCPSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	}

//Requesting
	std::shared_ptr<fd_set> ReadFDS(new fd_set()), WriteFDS(new fd_set());
	memset(ReadFDS.get(), 0, sizeof(fd_set));
	memset(WriteFDS.get(), 0, sizeof(fd_set));
#if defined(PLATFORM_WIN)
	ULONG SocketMode = 1U;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	int Flags = 0;
#endif
	std::shared_ptr<timeval> Timeout(new timeval());
	memset(Timeout.get(), 0, sizeof(timeval));
	SSIZE_T SelectResult = 0, RecvLen = 0;
	uint16_t PDULen = 0;

	for (;;)
	{
	//Socket check
		if (TCPSocket == INVALID_SOCKET)
		{
			PrintError(LOG_ERROR_NETWORK, L"DNSCurve TCP sockets initialization error", WSAGetLastError(), nullptr, 0);
			goto JumpToRestart;
		}

	//Set Non-blocking Mode.
	#if defined(PLATFORM_WIN)
		if (ioctlsocket(TCPSocket, FIONBIO, &SocketMode) == SOCKET_ERROR)
		{
			PrintError(LOG_ERROR_NETWORK, L"Set TCP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
			goto JumpToRestart;
		}
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		Flags = fcntl(TCPSocket, F_GETFL, 0);
		fcntl(TCPSocket, F_SETFL, Flags|O_NONBLOCK);
	#endif

	//Connect to server.
		if (connect(TCPSocket, (PSOCKADDR)SockAddr.get(), AddrLen) == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK)
		{
			if (ServerType == DNSCURVE_MAIN_IPV6)
				PrintError(LOG_ERROR_DNSCURVE, L"IPv6 Main Server TCP get signature data error", 0, nullptr, 0);
			else if (ServerType == DNSCURVE_MAIN_IPV4)
				PrintError(LOG_ERROR_DNSCURVE, L"IPv4 Main Server TCP get signature data error", 0, nullptr, 0);
			else if (ServerType == DNSCURVE_ALTERNATE_IPV6)
				PrintError(LOG_ERROR_DNSCURVE, L"IPv6 Alternate Server TCP get signature data error", 0, nullptr, 0);
			else if (ServerType == DNSCURVE_ALTERNATE_IPV4)
				PrintError(LOG_ERROR_DNSCURVE, L"IPv4 Alternate Server TCP get signature data error", 0, nullptr, 0);

			goto JumpToRestart;
		}

	//Send request and receive result.
		FD_ZERO(WriteFDS.get());
		FD_SET(TCPSocket, WriteFDS.get());
		SelectResult = 0, RecvLen = 0, PDULen = 0;
		for (size_t LoopLimits = 0;LoopLimits < LOOP_MAX_TIMES;++LoopLimits)
		{
			Sleep(LOOP_INTERVAL_TIME);

		//Reset parameters.
		#if defined(PLATFORM_WIN)
			Timeout->tv_sec = Parameter.SocketTimeout_Reliable / SECOND_TO_MILLISECOND;
			Timeout->tv_usec = Parameter.SocketTimeout_Reliable % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			Timeout->tv_sec = Parameter.SocketTimeout_Reliable.tv_sec;
			Timeout->tv_usec = Parameter.SocketTimeout_Reliable.tv_usec;
		#endif
			FD_ZERO(ReadFDS.get());
			FD_SET(TCPSocket, ReadFDS.get());

		//Wait for system calling.
		#if defined(PLATFORM_WIN)
			SelectResult = select(0, ReadFDS.get(), WriteFDS.get(), nullptr, Timeout.get());
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			SelectResult = select(TCPSocket + 1U, ReadFDS.get(), WriteFDS.get(), nullptr, Timeout.get());
		#endif
			if (SelectResult > 0)
			{
			//Receive.
				if (FD_ISSET(TCPSocket, ReadFDS.get()))
				{
					RecvLen = recv(TCPSocket, RecvBuffer.get(), LARGE_PACKET_MAXSIZE, 0);

				//TCP segment of a reassembled PDU
					if (RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
					{
						if (RecvLen > 0 && htons(((uint16_t *)RecvBuffer.get())[0]) >= DNS_PACKET_MINSIZE && htons(((uint16_t *)RecvBuffer.get())[0]) < LARGE_PACKET_MAXSIZE)
						{
							PDULen = htons(((uint16_t *)RecvBuffer.get())[0]);
							memset(RecvBuffer.get(), 0, LARGE_PACKET_MAXSIZE);
							continue;
						}
					//Invalid packet.
						else {
							if (ServerType == DNSCURVE_MAIN_IPV6)
								PrintError(LOG_ERROR_DNSCURVE, L"IPv6 Main Server TCP get signature data error", 0, nullptr, 0);
							else if (ServerType == DNSCURVE_MAIN_IPV4)
								PrintError(LOG_ERROR_DNSCURVE, L"IPv4 Main Server TCP get signature data error", 0, nullptr, 0);
							else if (ServerType == DNSCURVE_ALTERNATE_IPV6)
								PrintError(LOG_ERROR_DNSCURVE, L"IPv6 Alternate Server TCP get signature data error", 0, nullptr, 0);
							else if (ServerType == DNSCURVE_ALTERNATE_IPV4)
								PrintError(LOG_ERROR_DNSCURVE, L"IPv4 Alternate Server TCP get signature data error", 0, nullptr, 0);

							goto JumpToRestart;
						}
					}
					else {
					//Length check.
						if (RecvLen < (SSIZE_T)PDULen)
						{
							if (ServerType == DNSCURVE_MAIN_IPV6)
								PrintError(LOG_ERROR_DNSCURVE, L"IPv6 Main Server TCP get signature data error", 0, nullptr, 0);
							else if (ServerType == DNSCURVE_MAIN_IPV4)
								PrintError(LOG_ERROR_DNSCURVE, L"IPv4 Main Server TCP get signature data error", 0, nullptr, 0);
							else if (ServerType == DNSCURVE_ALTERNATE_IPV6)
								PrintError(LOG_ERROR_DNSCURVE, L"IPv6 Alternate Server TCP get signature data error", 0, nullptr, 0);
							else if (ServerType == DNSCURVE_ALTERNATE_IPV4)
								PrintError(LOG_ERROR_DNSCURVE, L"IPv4 Alternate Server TCP get signature data error", 0, nullptr, 0);

							goto JumpToRestart;
						}
					//Receive again.
						else if (PDULen > 0)
						{
						//Jump to normal receive process.
							if (PDULen >= (SSIZE_T)DNS_PACKET_MINSIZE)
							{
								shutdown(TCPSocket, SD_BOTH);
								closesocket(TCPSocket);
								RecvLen = PDULen;

								goto JumpFromPDU;
							}

							if (ServerType == DNSCURVE_MAIN_IPV6)
								PrintError(LOG_ERROR_DNSCURVE, L"IPv6 Main Server TCP get signature data error", 0, nullptr, 0);
							else if (ServerType == DNSCURVE_MAIN_IPV4)
								PrintError(LOG_ERROR_DNSCURVE, L"IPv4 Main Server TCP get signature data error", 0, nullptr, 0);
							else if (ServerType == DNSCURVE_ALTERNATE_IPV6)
								PrintError(LOG_ERROR_DNSCURVE, L"IPv6 Alternate Server TCP get signature data error", 0, nullptr, 0);
							else if (ServerType == DNSCURVE_ALTERNATE_IPV4)
								PrintError(LOG_ERROR_DNSCURVE, L"IPv4 Alternate Server TCP get signature data error", 0, nullptr, 0);

							goto JumpToRestart;
						}
					//First receive.
						else {
						//Length check
							if (RecvLen < (SSIZE_T)ntohs(((uint16_t *)RecvBuffer.get())[0]))
							{
								if (ServerType == DNSCURVE_MAIN_IPV6)
									PrintError(LOG_ERROR_DNSCURVE, L"IPv6 Main Server TCP get signature data error", 0, nullptr, 0);
								else if (ServerType == DNSCURVE_MAIN_IPV4)
									PrintError(LOG_ERROR_DNSCURVE, L"IPv4 Main Server TCP get signature data error", 0, nullptr, 0);
								else if (ServerType == DNSCURVE_ALTERNATE_IPV6)
									PrintError(LOG_ERROR_DNSCURVE, L"IPv6 Alternate Server TCP get signature data error", 0, nullptr, 0);
								else if (ServerType == DNSCURVE_ALTERNATE_IPV4)
									PrintError(LOG_ERROR_DNSCURVE, L"IPv4 Alternate Server TCP get signature data error", 0, nullptr, 0);
								
								goto JumpToRestart;
							}
							else {
								shutdown(TCPSocket, SD_BOTH);
								closesocket(TCPSocket);

								RecvLen = ntohs(((uint16_t *)RecvBuffer.get())[0]);
								if (RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE && RecvLen < (SSIZE_T)LARGE_PACKET_MAXSIZE)
								{
									memmove_s(RecvBuffer.get(), LARGE_PACKET_MAXSIZE, RecvBuffer.get() + sizeof(uint16_t), RecvLen);

								//Jump here when TCP segment of a reassembled PDU.
									JumpFromPDU: 

								//Check Signature.
									if (PacketTarget == nullptr || 
										!DNSCruveGetSignatureData(RecvBuffer.get() + DNS_PACKET_RR_LOCATE(RecvBuffer.get()), ServerType) || 
										CheckEmptyBuffer(PacketTarget->ServerFingerprint, crypto_box_PUBLICKEYBYTES) || 
										CheckEmptyBuffer(PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
									{
										if (ServerType == DNSCURVE_MAIN_IPV6)
											PrintError(LOG_ERROR_DNSCURVE, L"IPv6 Main Server TCP get signature data error", 0, nullptr, 0);
										else if (ServerType == DNSCURVE_MAIN_IPV4)
											PrintError(LOG_ERROR_DNSCURVE, L"IPv4 Main Server TCP get signature data error", 0, nullptr, 0);
										else if (ServerType == DNSCURVE_ALTERNATE_IPV6)
											PrintError(LOG_ERROR_DNSCURVE, L"IPv6 Alternate Server TCP get signature data error", 0, nullptr, 0);
										else if (ServerType == DNSCURVE_ALTERNATE_IPV4)
											PrintError(LOG_ERROR_DNSCURVE, L"IPv4 Alternate Server TCP get signature data error", 0, nullptr, 0);

										goto JumpToRestart;
									}

									break;
								}
							//Length check
								else {
									if (ServerType == DNSCURVE_MAIN_IPV6)
										PrintError(LOG_ERROR_DNSCURVE, L"IPv6 Main Server TCP get signature data error", 0, nullptr, 0);
									else if (ServerType == DNSCURVE_MAIN_IPV4)
										PrintError(LOG_ERROR_DNSCURVE, L"IPv4 Main Server TCP get signature data error", 0, nullptr, 0);
									else if (ServerType == DNSCURVE_ALTERNATE_IPV6)
										PrintError(LOG_ERROR_DNSCURVE, L"IPv6 Alternate Server TCP get signature data error", 0, nullptr, 0);
									else if (ServerType == DNSCURVE_ALTERNATE_IPV4)
										PrintError(LOG_ERROR_DNSCURVE, L"IPv4 Alternate Server TCP get signature data error", 0, nullptr, 0);

									goto JumpToRestart;
								}
							}
						}
					}
				}

			//Send.
				if (FD_ISSET(TCPSocket, WriteFDS.get()))
				{
					send(TCPSocket, SendBuffer.get(), (int)DataLength, 0);
					FD_ZERO(WriteFDS.get());
				}
			}
		//Timeout or SOCKET_ERROR
			else {
				if (ServerType == DNSCURVE_MAIN_IPV6)
					PrintError(LOG_ERROR_DNSCURVE, L"IPv6 Main Server TCP get signature data error", 0, nullptr, 0);
				else if (ServerType == DNSCURVE_MAIN_IPV4)
					PrintError(LOG_ERROR_DNSCURVE, L"IPv4 Main Server TCP get signature data error", 0, nullptr, 0);
				else if (ServerType == DNSCURVE_ALTERNATE_IPV6)
					PrintError(LOG_ERROR_DNSCURVE, L"IPv6 Alternate Server TCP get signature data error", 0, nullptr, 0);
				else if (ServerType == DNSCURVE_ALTERNATE_IPV4)
					PrintError(LOG_ERROR_DNSCURVE, L"IPv4 Alternate Server TCP get signature data error", 0, nullptr, 0);

				goto JumpToRestart;
			}
		}

		Sleep(DNSCurveParameter.KeyRecheckTime);
		continue;

	//Restart.
		JumpToRestart: 
		shutdown(TCPSocket, SD_BOTH);
		closesocket(TCPSocket);
		TCPSocket = socket(Protocol, SOCK_STREAM, IPPROTO_TCP);
		memset(RecvBuffer.get(), 0, LARGE_PACKET_MAXSIZE);

		if (ServerType == DNSCURVE_MAIN_IPV6)
			++AlternateSwapList.TimeoutTimes[8U];
		else if (ServerType == DNSCURVE_MAIN_IPV4)
			++AlternateSwapList.TimeoutTimes[9U];

		Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
	}

	shutdown(TCPSocket, SD_BOTH);
	closesocket(TCPSocket);
	return true;
}

//Send UDP request to get Signature Data of servers
bool __fastcall DNSCurveUDPSignatureRequest(const uint16_t Protocol, const bool IsAlternate)
{
//Initialization
	std::shared_ptr<char> SendBuffer(new char[PACKET_MAXSIZE]()), RecvBuffer(new char[PACKET_MAXSIZE]());
	memset(SendBuffer.get(), 0, PACKET_MAXSIZE);
	memset(RecvBuffer.get(), 0, PACKET_MAXSIZE);
	std::shared_ptr<sockaddr_storage> SockAddr(new sockaddr_storage());
	memset(SockAddr.get(), 0, sizeof(sockaddr_storage));
	SYSTEM_SOCKET UDPSocket = 0;

//Packet
	size_t DataLength = sizeof(dns_hdr);
	auto DNS_Header = (pdns_hdr)SendBuffer.get();
#if defined(ENABLE_PCAP)
	DNS_Header->ID = Parameter.DomainTest_ID;
#endif
	DNS_Header->Flags = htons(DNS_STANDARD);
	DNS_Header->Questions = htons(U16_NUM_ONE);

//Socket initialization
	if (Protocol == AF_INET6) //IPv6
	{
		if (IsAlternate)
			DataLength += CharToDNSQuery(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ProviderName, SendBuffer.get() + DataLength);
		else 
			DataLength += CharToDNSQuery(DNSCurveParameter.DNSCurveTarget.IPv6.ProviderName, SendBuffer.get() + DataLength);
	}
	else { //IPv4
		if (IsAlternate)
			DataLength += CharToDNSQuery(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ProviderName, SendBuffer.get() + DataLength);
		else 
			DataLength += CharToDNSQuery(DNSCurveParameter.DNSCurveTarget.IPv4.ProviderName, SendBuffer.get() + DataLength);
	}

	auto DNS_Query = (pdns_qry)(SendBuffer.get() + DataLength);
	DNS_Query->Type = htons(DNS_RECORD_TXT);
	DNS_Query->Classes = htons(DNS_CLASS_IN);
	DataLength += sizeof(dns_qry);

//EDNS Label
	DNS_Header->Additional = htons(U16_NUM_ONE);
	auto DNS_Record_OPT = (pdns_record_opt)(SendBuffer.get() + DataLength);
	DNS_Record_OPT->Type = htons(DNS_RECORD_OPT);
	DNS_Record_OPT->UDPPayloadSize = htons(EDNS_PACKET_MINSIZE);
	DataLength += sizeof(dns_record_opt);

//Socket initialization
	socklen_t AddrLen = 0;
	size_t ServerType = 0;
	PDNSCURVE_SERVER_DATA PacketTarget = nullptr;
	if (Protocol == AF_INET6) //IPv6
	{
		if (IsAlternate)
		{
			((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
			((PSOCKADDR_IN6)SockAddr.get())->sin6_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv6;
			ServerType = DNSCURVE_ALTERNATE_IPV6;
		}
		else { //Main
			((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_addr;
			((PSOCKADDR_IN6)SockAddr.get())->sin6_port = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_port;
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv6;
			ServerType = DNSCURVE_MAIN_IPV6;
		}

		SockAddr->ss_family = AF_INET6;
		AddrLen = sizeof(sockaddr_in6);
		UDPSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	}
	else { //IPv4
		if (IsAlternate)
		{
			((PSOCKADDR_IN)SockAddr.get())->sin_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
			((PSOCKADDR_IN)SockAddr.get())->sin_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv4;
			ServerType = DNSCURVE_ALTERNATE_IPV4;
		}
		else { //Main
			((PSOCKADDR_IN)SockAddr.get())->sin_addr = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_addr;
			((PSOCKADDR_IN)SockAddr.get())->sin_port = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_port;
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv4;
			ServerType = DNSCURVE_MAIN_IPV4;
		}

		AddrLen = sizeof(sockaddr_in);
		SockAddr->ss_family = AF_INET;
		UDPSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	}

//Send requesting.
	SSIZE_T RecvLen = 0;
	for (;;)
	{
	//Socket check
		if (UDPSocket == INVALID_SOCKET)
		{
			PrintError(LOG_ERROR_NETWORK, L"DNSCurve UDP sockets initialization error", WSAGetLastError(), nullptr, 0);
			goto JumpToRestart;
		}

	//Set socket timeout.
	#if defined(PLATFORM_WIN)
		if (setsockopt(UDPSocket, SOL_SOCKET, SO_SNDTIMEO, (const char *)&Parameter.SocketTimeout_Unreliable, sizeof(int)) == SOCKET_ERROR || 
			setsockopt(UDPSocket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&Parameter.SocketTimeout_Unreliable, sizeof(int)) == SOCKET_ERROR)
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		if (setsockopt(UDPSocket, SOL_SOCKET, SO_SNDTIMEO, (const char *)&Parameter.SocketTimeout_Unreliable, sizeof(timeval)) == SOCKET_ERROR || 
			setsockopt(UDPSocket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&Parameter.SocketTimeout_Unreliable, sizeof(timeval)) == SOCKET_ERROR)
	#endif
		{
			PrintError(LOG_ERROR_NETWORK, L"Set UDP socket timeout error", WSAGetLastError(), nullptr, 0);
			goto JumpToRestart;
		}

	//Requesting
		if (sendto(UDPSocket, SendBuffer.get(), (int)DataLength, 0, (PSOCKADDR)SockAddr.get(), AddrLen) == SOCKET_ERROR)
		{
			if (ServerType == DNSCURVE_MAIN_IPV6)
				PrintError(LOG_ERROR_DNSCURVE, L"IPv6 Main Server UDP get signature data error", 0, nullptr, 0);
			else if (ServerType == DNSCURVE_MAIN_IPV4)
				PrintError(LOG_ERROR_DNSCURVE, L"IPv4 Main Server UDP get signature data error", 0, nullptr, 0);
			else if (ServerType == DNSCURVE_ALTERNATE_IPV6)
				PrintError(LOG_ERROR_DNSCURVE, L"IPv6 Alternate Server UDP get signature data error", 0, nullptr, 0);
			else if (ServerType == DNSCURVE_ALTERNATE_IPV4)
				PrintError(LOG_ERROR_DNSCURVE, L"IPv4 Alternate Server UDP get signature data error", 0, nullptr, 0);

			goto JumpToRestart;
		}
		else {
			RecvLen = recvfrom(UDPSocket, RecvBuffer.get(), PACKET_MAXSIZE, 0, (PSOCKADDR)SockAddr.get(), &AddrLen);
			if (RecvLen >= (SSIZE_T)(DNS_PACKET_MINSIZE + sizeof(dns_record_txt) + DNSCRYPT_TXT_RECORDS_LEN))
			{
			//Check Signature.
				if (PacketTarget == nullptr || 
					!DNSCruveGetSignatureData(RecvBuffer.get() + DNS_PACKET_RR_LOCATE(RecvBuffer.get()), ServerType) || 
					CheckEmptyBuffer(PacketTarget->ServerFingerprint, crypto_box_PUBLICKEYBYTES) || 
					CheckEmptyBuffer(PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					if (ServerType == DNSCURVE_MAIN_IPV6)
						PrintError(LOG_ERROR_DNSCURVE, L"IPv6 Main Server UDP get signature data error", 0, nullptr, 0);
					else if (ServerType == DNSCURVE_MAIN_IPV4)
						PrintError(LOG_ERROR_DNSCURVE, L"IPv4 Main Server UDP get signature data error", 0, nullptr, 0);
					else if (ServerType == DNSCURVE_ALTERNATE_IPV6)
						PrintError(LOG_ERROR_DNSCURVE, L"IPv6 Alternate Server UDP get signature data error", 0, nullptr, 0);
					else if (ServerType == DNSCURVE_ALTERNATE_IPV4)
						PrintError(LOG_ERROR_DNSCURVE, L"IPv4 Alternate Server UDP get signature data error", 0, nullptr, 0);

					goto JumpToRestart;
				}

				memset(RecvBuffer.get(), 0, PACKET_MAXSIZE);
			}
			else {
				memset(RecvBuffer.get(), 0, PACKET_MAXSIZE);
				if (DNSCurveSignatureRequest(SendBuffer.get(), (int)DataLength, RecvBuffer.get(), PACKET_MAXSIZE) >= DNS_PACKET_MINSIZE + sizeof(dns_record_txt) + DNSCRYPT_TXT_RECORDS_LEN)
				{
				//Check Signature.
					if (PacketTarget != nullptr || 
						!DNSCruveGetSignatureData(RecvBuffer.get() + DNS_PACKET_RR_LOCATE(RecvBuffer.get()), ServerType) || 
						CheckEmptyBuffer(PacketTarget->ServerFingerprint, crypto_box_PUBLICKEYBYTES) || 
						CheckEmptyBuffer(PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
					{
						if (ServerType == DNSCURVE_MAIN_IPV6)
							PrintError(LOG_ERROR_DNSCURVE, L"IPv6 Main Server UDP get signature data error", 0, nullptr, 0);
						else if (ServerType == DNSCURVE_MAIN_IPV4)
							PrintError(LOG_ERROR_DNSCURVE, L"IPv4 Main Server UDP get signature data error", 0, nullptr, 0);
						else if (ServerType == DNSCURVE_ALTERNATE_IPV6)
							PrintError(LOG_ERROR_DNSCURVE, L"IPv6 Alternate Server UDP get signature data error", 0, nullptr, 0);
						else if (ServerType == DNSCURVE_ALTERNATE_IPV4)
							PrintError(LOG_ERROR_DNSCURVE, L"IPv4 Alternate Server UDP get signature data error", 0, nullptr, 0);

						goto JumpToRestart;
					}

					memset(RecvBuffer.get(), 0, PACKET_MAXSIZE);
				}
				else {
					if (ServerType == DNSCURVE_MAIN_IPV6)
						PrintError(LOG_ERROR_DNSCURVE, L"IPv6 Main Server UDP get signature data error", 0, nullptr, 0);
					else if (ServerType == DNSCURVE_MAIN_IPV4)
						PrintError(LOG_ERROR_DNSCURVE, L"IPv4 Main Server UDP get signature data error", 0, nullptr, 0);
					else if (ServerType == DNSCURVE_ALTERNATE_IPV6)
						PrintError(LOG_ERROR_DNSCURVE, L"IPv6 Alternate Server UDP get signature data error", 0, nullptr, 0);
					else if (ServerType == DNSCURVE_ALTERNATE_IPV4)
						PrintError(LOG_ERROR_DNSCURVE, L"IPv4 Alternate Server UDP get signature data error", 0, nullptr, 0);

					goto JumpToRestart;
				}
			}
		}

		Sleep(DNSCurveParameter.KeyRecheckTime);
		continue;

	//Restart.
		JumpToRestart:
		shutdown(UDPSocket, SD_BOTH);
		closesocket(UDPSocket);
		UDPSocket = socket(Protocol, SOCK_DGRAM, IPPROTO_UDP);
		memset(RecvBuffer.get(), 0, PACKET_MAXSIZE);

		if (ServerType == DNSCURVE_MAIN_IPV6)
			++AlternateSwapList.TimeoutTimes[10U];
		else if (ServerType == DNSCURVE_MAIN_IPV4)
			++AlternateSwapList.TimeoutTimes[11U];

		Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
	}

	shutdown(UDPSocket, SD_BOTH);
	closesocket(UDPSocket);
	return true;
}

//Get Signature Data of server from packets
bool __fastcall DNSCruveGetSignatureData(const char *Buffer, const size_t ServerType)
{
	auto DNS_Record_TXT = (pdns_record_txt)Buffer;
	if (DNS_Record_TXT->Name == htons(DNS_POINTER_QUERY) && 
		DNS_Record_TXT->Length == htons(DNS_Record_TXT->TXT_Length + 1U) && DNS_Record_TXT->TXT_Length == DNSCRYPT_TXT_RECORDS_LEN)
	{
		auto DNSCurve_TXT_Header = (pdnscurve_txt_hdr)(Buffer + sizeof(dns_record_txt));
		if (memcmp(&DNSCurve_TXT_Header->CertMagicNumber, DNSCRYPT_CERT_MAGIC, sizeof(uint16_t)) == 0 && 
			DNSCurve_TXT_Header->MajorVersion == htons(DNSCURVE_VERSION_MAJOR) && DNSCurve_TXT_Header->MinorVersion == DNSCURVE_VERSION_MINOR)
		{
			ULONGLONG SignatureLength = 0;

		//Get Send Magic Number, Server Fingerprint and Precomputation Key.
			PDNSCURVE_SERVER_DATA PacketTarget = nullptr;
			switch (ServerType)
			{
				case DNSCURVE_ALTERNATE_IPV6:
				{
					PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv6;
				}break;
				case DNSCURVE_MAIN_IPV6:
				{
					PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv6;
				}break;
				case DNSCURVE_ALTERNATE_IPV4:
				{
					PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv4;
				}break;
				case DNSCURVE_MAIN_IPV4:
				{
					PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv4;
				}break;
				default:
				{
					return false;
				}
			}

		//Check Signature.
			std::shared_ptr<char> DeBuffer(new char[PACKET_MAXSIZE]());
			memset(DeBuffer.get(), 0, PACKET_MAXSIZE);
			if (PacketTarget == nullptr || 
				crypto_sign_ed25519_open((PUINT8)DeBuffer.get(), &SignatureLength, (PUINT8)(Buffer + sizeof(dns_record_txt) + sizeof(dnscurve_txt_hdr)), DNS_Record_TXT->TXT_Length - sizeof(dnscurve_txt_hdr), PacketTarget->ServerPublicKey) == LIBSODIUM_ERROR)
			{
				if (ServerType == DNSCURVE_MAIN_IPV6)
					PrintError(LOG_ERROR_DNSCURVE, L"IPv6 Main Server Fingerprint signature validation error", 0, nullptr, 0);
				else if (ServerType == DNSCURVE_MAIN_IPV4)
					PrintError(LOG_ERROR_DNSCURVE, L"IPv4 Main Server Fingerprint signature validation error", 0, nullptr, 0);
				else if (ServerType == DNSCURVE_ALTERNATE_IPV6)
					PrintError(LOG_ERROR_DNSCURVE, L"IPv6 Alternate Server Fingerprint signature validation error", 0, nullptr, 0);
				else if (ServerType == DNSCURVE_ALTERNATE_IPV4)
					PrintError(LOG_ERROR_DNSCURVE, L"IPv4 Alternate Server Fingerprint signature validation error", 0, nullptr, 0);

				return false;
			}

			auto SignatureData = (pdnscurve_txt_signature)DeBuffer.get();
		//Signature available time check
			if (SignatureData != nullptr && PacketTarget->ServerFingerprint != nullptr && 
				time(nullptr) >= (time_t)ntohl(SignatureData->CertTime_Begin) && time(nullptr) <= (time_t)ntohl(SignatureData->CertTime_End))
			{
				memcpy_s(PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, SignatureData->MagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
				memcpy_s(PacketTarget->ServerFingerprint, crypto_box_PUBLICKEYBYTES, SignatureData->PublicKey, crypto_box_PUBLICKEYBYTES);
				crypto_box_curve25519xsalsa20poly1305_beforenm(
					PacketTarget->PrecomputationKey,
					PacketTarget->ServerFingerprint,
					DNSCurveParameter.Client_SecretKey);

				return true;
			}
			else {
				if (ServerType == DNSCURVE_MAIN_IPV6)
					PrintError(LOG_ERROR_DNSCURVE, L"IPv6 Main Server Fingerprint signature validation error", 0, nullptr, 0);
				else if (ServerType == DNSCURVE_MAIN_IPV4)
					PrintError(LOG_ERROR_DNSCURVE, L"IPv4 Main Server Fingerprint signature validation error", 0, nullptr, 0);
				else if (ServerType == DNSCURVE_ALTERNATE_IPV6)
					PrintError(LOG_ERROR_DNSCURVE, L"IPv6 Alternate Server Fingerprint signature validation error", 0, nullptr, 0);
				else if (ServerType == DNSCURVE_ALTERNATE_IPV4)
					PrintError(LOG_ERROR_DNSCURVE, L"IPv4 Alternate Server Fingerprint signature validation error", 0, nullptr, 0);
			}
		}
	}

	return false;
}

//Transmission of DNSCurve TCP protocol
size_t __fastcall DNSCurveTCPRequest(const char *OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize)
{
//Initialization
	std::shared_ptr<SOCKET_DATA> TCPSockData(new SOCKET_DATA());
	memset(TCPSockData.get(), 0, sizeof(SOCKET_DATA));
	PDNSCURVE_SERVER_DATA PacketTarget = nullptr;
	bool *IsAlternate = nullptr;
	size_t *AlternateTimeoutTimes = nullptr;

//Socket initialization
	if (SelectTargetSocket(TCPSockData.get(), PacketTarget, IsAlternate, AlternateTimeoutTimes, IPPROTO_TCP) == 0 || TCPSockData->Socket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_NETWORK, L"DNSCurve TCP sockets initialization error", WSAGetLastError(), nullptr, 0);
		closesocket(TCPSockData->Socket);

		return EXIT_FAILURE;
	}

//Set Non-blocking Mode.
#if defined(PLATFORM_WIN)
	ULONG SocketMode = 1U;
	if (ioctlsocket(TCPSockData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_NETWORK, L"Set TCP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
		closesocket(TCPSockData->Socket);

		return EXIT_FAILURE;
	}
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	int Flags = fcntl(TCPSockData->Socket, F_GETFL, 0);
	fcntl(TCPSockData->Socket, F_SETFL, Flags|O_NONBLOCK);
#endif

	size_t DataLength = DNSCurveParameter.DNSCurvePayloadSize;
//Encryption mode
	std::shared_ptr<uint8_t> WholeNonce;
	if (DNSCurveParameter.IsEncryption)
	{
	//Make nonce.
		std::shared_ptr<uint8_t> WholeNonceTemp(new uint8_t[crypto_box_NONCEBYTES]());
		memset(WholeNonceTemp.get(), 0, sizeof(uint8_t) * crypto_box_NONCEBYTES);
		WholeNonce.swap(WholeNonceTemp);
		WholeNonceTemp.reset();
		*(uint32_t *)WholeNonce.get() = randombytes_random();
		*(uint32_t *)(WholeNonce.get() + sizeof(uint32_t)) = randombytes_random();
		*(uint32_t *)(WholeNonce.get() + sizeof(uint32_t) * 2U) = randombytes_random();
		memset(WholeNonce.get() + crypto_box_HALF_NONCEBYTES, 0, crypto_box_HALF_NONCEBYTES);

	//Make a crypto box.
		std::shared_ptr<char> Buffer(new char[DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES)]());
		memset(Buffer.get(), 0, DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES));
		memcpy_s(Buffer.get() + crypto_box_ZEROBYTES, DNSCurveParameter.DNSCurvePayloadSize, OriginalSend, SendSize);
		Buffer.get()[crypto_box_ZEROBYTES + SendSize] = '\x80';

	//Make packet.
		if (PacketTarget == nullptr || 
			crypto_box_curve25519xsalsa20poly1305_afternm(
			(PUCHAR)OriginalRecv + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES - crypto_box_BOXZEROBYTES, 
			(PUCHAR)Buffer.get(), 
			DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES), 
			WholeNonce.get(), 
			PacketTarget->PrecomputationKey) != 0)
		{
			closesocket(TCPSockData->Socket);
			memset(OriginalRecv, 0, RecvSize);

			return EXIT_FAILURE;
		}

		Buffer.reset();
		memcpy_s(OriginalRecv + sizeof(uint16_t), RecvSize - sizeof(uint16_t), PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
		memcpy_s(OriginalRecv + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN, RecvSize - sizeof(uint16_t) - DNSCURVE_MAGIC_QUERY_LEN, DNSCurveParameter.Client_PublicKey, crypto_box_PUBLICKEYBYTES);
		memcpy_s(OriginalRecv + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES, RecvSize - sizeof(uint16_t) - DNSCURVE_MAGIC_QUERY_LEN - crypto_box_PUBLICKEYBYTES, WholeNonce.get(), crypto_box_HALF_NONCEBYTES);
		*(uint16_t *)OriginalRecv = htons((uint16_t)(DNSCurveParameter.DNSCurvePayloadSize - sizeof(uint16_t)));
		memset(WholeNonce.get(), 0, crypto_box_NONCEBYTES);
	}
//Normal mode
	else {
		memcpy_s(OriginalRecv + sizeof(uint16_t), RecvSize - sizeof(uint16_t), OriginalSend, SendSize);
		auto BufferLength = (uint16_t *)OriginalRecv;
		*BufferLength = htons((uint16_t)SendSize);
		DataLength = sizeof(uint16_t) + SendSize;
	}

//Connect to server.
	if (connect(TCPSockData->Socket, (PSOCKADDR)&TCPSockData->SockAddr, TCPSockData->AddrLen) == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK)
	{
		if (IsAlternate != nullptr && !*IsAlternate && WSAGetLastError() == WSAETIMEDOUT)
		{
			closesocket(TCPSockData->Socket);
			if (AlternateTimeoutTimes != nullptr)
				++(*AlternateTimeoutTimes);

			return WSAETIMEDOUT;
		}
		else {
			closesocket(TCPSockData->Socket);
			return EXIT_FAILURE;
		}
	}

//Requesting
	std::shared_ptr<fd_set> ReadFDS(new fd_set()), WriteFDS(new fd_set());
	std::shared_ptr<timeval> Timeout(new timeval());
	memset(ReadFDS.get(), 0, sizeof(fd_set));
	memset(WriteFDS.get(), 0, sizeof(fd_set));
	memset(Timeout.get(), 0, sizeof(timeval));
	FD_ZERO(WriteFDS.get());
	FD_SET(TCPSockData->Socket, WriteFDS.get());
	SSIZE_T SelectResult = 0, RecvLen = 0;
	uint16_t PDULen = 0;

	for (size_t LoopLimits = 0;LoopLimits < LOOP_MAX_TIMES;++LoopLimits)
	{
		Sleep(LOOP_INTERVAL_TIME);

	//Reset parameters.
	#if defined(PLATFORM_WIN)
		Timeout->tv_sec = Parameter.SocketTimeout_Reliable / SECOND_TO_MILLISECOND;
		Timeout->tv_usec = Parameter.SocketTimeout_Reliable % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		Timeout->tv_sec = Parameter.SocketTimeout_Reliable.tv_sec;
		Timeout->tv_usec = Parameter.SocketTimeout_Reliable.tv_usec;
	#endif
		FD_ZERO(ReadFDS.get());
		FD_SET(TCPSockData->Socket, ReadFDS.get());

	//Wait for system calling.
	#if defined(PLATFORM_WIN)
		SelectResult = select(0, ReadFDS.get(), WriteFDS.get(), nullptr, Timeout.get());
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		SelectResult = select(TCPSockData->Socket + 1U, ReadFDS.get(), WriteFDS.get(), nullptr, Timeout.get());
	#endif
		if (SelectResult > 0)
		{
		//Receive.
			if (FD_ISSET(TCPSockData->Socket, ReadFDS.get()))
			{
				RecvLen = recv(TCPSockData->Socket, OriginalRecv, (int)RecvSize, 0);

			//TCP segment of a reassembled PDU
				if (RecvLen > 0 && RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
				{
					if (htons(((uint16_t *)OriginalRecv)[0]) >= DNS_PACKET_MINSIZE && htons(((uint16_t *)OriginalRecv)[0]) < RecvSize)
					{
						PDULen = htons(((uint16_t *)OriginalRecv)[0]);
						memset(OriginalRecv, 0, RecvSize);
						continue;
					}
				//Invalid packet.
					else {
						break;
					}
				}
				else {
				//Length check.
					if (RecvLen < (SSIZE_T)PDULen)
					{
						break;
					}
				//Receive again.
					else if (PDULen > 0)
					{
						shutdown(TCPSockData->Socket, SD_BOTH);
						closesocket(TCPSockData->Socket);

					//Jump to normal receive process.
						if (PDULen >= DNS_PACKET_MINSIZE)
						{
							RecvLen = PDULen;
							goto JumpFromPDU;
						}

						memset(OriginalRecv, 0, RecvSize);
						return EXIT_FAILURE;
					}
				//First receive.
					else {
					//Length check
						if (RecvLen < (SSIZE_T)ntohs(((uint16_t *)OriginalRecv)[0]))
						{
							break;
						}
						else {
							shutdown(TCPSockData->Socket, SD_BOTH);
							closesocket(TCPSockData->Socket);

							RecvLen = ntohs(((uint16_t *)OriginalRecv)[0]);
							if (RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE && RecvLen < (SSIZE_T)RecvSize)
							{
								memmove_s(OriginalRecv, RecvSize, OriginalRecv + sizeof(uint16_t), RecvLen);

							//Encryption mode
								if (DNSCurveParameter.IsEncryption)
								{
									if (memcmp(OriginalRecv, PacketTarget->ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN) != 0)
									{
										memset(OriginalRecv, 0, RecvSize);
										return EXIT_FAILURE;
									}

								//Copy whole nonce.
									memcpy_s(WholeNonce.get(), crypto_box_NONCEBYTES, OriginalRecv + DNSCURVE_MAGIC_QUERY_LEN, crypto_box_NONCEBYTES);

								//Open crypto box.
									memset(OriginalRecv, 0, DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);
									memmove_s(OriginalRecv + crypto_box_BOXZEROBYTES, RecvSize - crypto_box_BOXZEROBYTES, OriginalRecv + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
									if (crypto_box_curve25519xsalsa20poly1305_open_afternm(
										(PUCHAR)OriginalRecv, 
										(PUCHAR)OriginalRecv, 
										RecvLen + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES),
										WholeNonce.get(), 
										PacketTarget->PrecomputationKey) != 0)
									{
										memset(OriginalRecv, 0, RecvSize);
										return EXIT_FAILURE;
									}
									memmove_s(OriginalRecv, RecvSize, OriginalRecv + crypto_box_ZEROBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
									memset(OriginalRecv + RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES), 0, RecvSize - (RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES)));
									for (SSIZE_T Index = RecvLen - (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);Index >= (SSIZE_T)DNS_PACKET_MINSIZE;--Index)
									{
										if ((UCHAR)OriginalRecv[Index] == 0x80)
										{
											RecvLen = Index;
											break;
										}
									}
								}

							//Jump here when TCP segment of a reassembled PDU.
								JumpFromPDU: 

							//Responses question and answers check
								if ((Parameter.DNSDataCheck || Parameter.BlacklistCheck) && CheckResponseData(OriginalRecv, RecvLen, false) == EXIT_FAILURE)
								{
									memset(OriginalRecv, 0, RecvSize);
									return EXIT_FAILURE;
								}

							//Mark DNS Cache.
								if (Parameter.CacheType > 0)
									MarkDomainCache(OriginalRecv, RecvLen);

								return RecvLen;
							}
						//Length check
							else {
								break;
							}
						}
					}
				}
			}

		//Send.
			if (FD_ISSET(TCPSockData->Socket, WriteFDS.get()))
			{
				send(TCPSockData->Socket, OriginalRecv, (int)DataLength, 0);
				memset(OriginalRecv, 0, RecvSize);
				FD_ZERO(WriteFDS.get());
			}
		}
	//Timeout
		else if (SelectResult == 0)
		{
			shutdown(TCPSockData->Socket, SD_BOTH);
			closesocket(TCPSockData->Socket);
			memset(OriginalRecv, 0, RecvSize);
			if (AlternateTimeoutTimes != nullptr)
				++(*AlternateTimeoutTimes);

			return WSAETIMEDOUT;
		}
	//SOCKET_ERROR
		else {
			break;
		}
	}

	shutdown(TCPSockData->Socket, SD_BOTH);
	closesocket(TCPSockData->Socket);
	memset(OriginalRecv, 0, RecvSize);
	return EXIT_FAILURE;
}

//Transmission of DNSCurve TCP protocol(Multithreading)
size_t __fastcall DNSCurveTCPRequestMulti(const char *OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize)
{
//Initialization
	std::vector<SOCKET_DATA> TCPSocketDataList;
	std::vector<size_t> ServerTypeList;
	std::shared_ptr<char> SendBuffer, Alternate_SendBuffer;
	std::shared_ptr<uint8_t> WholeNonce, Alternate_WholeNonce;

//Normal mode
	size_t DataLength = DNSCurveParameter.DNSCurvePayloadSize;
	if (!DNSCurveParameter.IsEncryption)
	{
		std::shared_ptr<char> SendBufferTemp(new char[sizeof(uint16_t) + SendSize]());
		memset(SendBufferTemp.get(), 0, sizeof(uint16_t) + SendSize);
		SendBuffer.swap(SendBufferTemp);
		SendBufferTemp.reset();
		memcpy_s(SendBuffer.get(), sizeof(uint16_t) + SendSize, OriginalSend, SendSize);

	//Add length of request packet(It must be written in header when transpot with TCP protocol).
		DataLength = AddLengthDataToDNSHeader(SendBuffer.get(), SendSize, sizeof(uint16_t) + SendSize);
		if (DataLength == EXIT_FAILURE)
			return EXIT_FAILURE;
	}

//Socket initialization
	auto IsIPv6 = false;
	bool *IsAlternate = nullptr;
	if (!SelectTargetSocketMulti(IsIPv6, IsAlternate, IPPROTO_TCP))
		return EXIT_FAILURE;

	std::shared_ptr<SOCKET_DATA> TCPSocketData(new SOCKET_DATA());
	memset(TCPSocketData.get(), 0, sizeof(SOCKET_DATA));
	PDNSCURVE_SERVER_DATA PacketTarget = nullptr;
#if defined(PLATFORM_WIN)
	ULONG SocketMode = 1U;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	int Flags = 0;
#endif

	//Main
	if (!*IsAlternate)
	{
	//Set target.
		if (IsIPv6) //IPv6
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv6;
		else //IPv4
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv4;

	//Encryption mode check
		if (DNSCurveParameter.IsEncryption && 
			(CheckEmptyBuffer(PacketTarget->PrecomputationKey, crypto_box_BEFORENMBYTES) || 
			CheckEmptyBuffer(PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
				goto SkipMain;

		for (size_t Index = 0;Index < Parameter.MultiRequestTimes;++Index)
		{
			TCPSocketData->SockAddr = PacketTarget->AddressData.Storage;
			if (IsIPv6) //IPv6
				TCPSocketData->Socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
			else //IPv4
				TCPSocketData->Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

		//Socket check
			if (TCPSocketData->Socket == INVALID_SOCKET)
			{
				PrintError(LOG_ERROR_NETWORK, L"DNSCurve TCP request initialization error", WSAGetLastError(), nullptr, 0);
				for (auto &SocketDataIter:TCPSocketDataList)
					closesocket(SocketDataIter.Socket);

				goto SkipMain;
			}

		//Set Non-blocking Mode.
		#if defined(PLATFORM_WIN)
			else if (ioctlsocket(TCPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
			{
				PrintError(LOG_ERROR_NETWORK, L"Set TCP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
				closesocket(TCPSocketData->Socket);
				for (auto &SocketDataIter:TCPSocketDataList)
					closesocket(SocketDataIter.Socket);

				goto SkipMain;
			}
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			Flags = fcntl(TCPSocketData->Socket, F_GETFL, 0);
			fcntl(TCPSocketData->Socket, F_SETFL, Flags|O_NONBLOCK);
		#endif

			if (IsIPv6) //IPv6
			{
				TCPSocketData->AddrLen = sizeof(sockaddr_in6);
				ServerTypeList.push_back(DNSCURVE_MAIN_IPV6);
			}
			else { //IPv4
				TCPSocketData->AddrLen = sizeof(sockaddr_in);
				ServerTypeList.push_back(DNSCURVE_MAIN_IPV4);
			}

			TCPSocketDataList.push_back(*TCPSocketData);
			memset(TCPSocketData.get(), 0, sizeof(SOCKET_DATA));
		}

	//Encryption mode
		if (DNSCurveParameter.IsEncryption)
		{
			std::shared_ptr<char> SendBufferTemp(new char[RecvSize]());
			memset(SendBufferTemp.get(), 0, RecvSize);
			SendBuffer.swap(SendBufferTemp);
			SendBufferTemp.reset();
			std::shared_ptr<uint8_t> WholeNonceTemp(new uint8_t[crypto_box_NONCEBYTES]());
			memset(WholeNonceTemp.get(), 0, sizeof(uint8_t) * crypto_box_NONCEBYTES);
			WholeNonce.swap(WholeNonceTemp);
			WholeNonceTemp.reset();

		//Make nonce.
			*(uint32_t *)WholeNonce.get() = randombytes_random();
			*(uint32_t *)(WholeNonce.get() + sizeof(uint32_t)) = randombytes_random();
			*(uint32_t *)(WholeNonce.get() + sizeof(uint32_t) * 2U) = randombytes_random();
			memset(WholeNonce.get() + crypto_box_HALF_NONCEBYTES, 0, crypto_box_HALF_NONCEBYTES);

		//Make a crypto box.
			std::shared_ptr<char> Buffer(new char[DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES)]());
			memset(Buffer.get(), 0, DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES));
			memcpy_s(Buffer.get() + crypto_box_ZEROBYTES, RecvSize - crypto_box_ZEROBYTES, OriginalSend, SendSize);
			Buffer.get()[crypto_box_ZEROBYTES + SendSize] = '\x80';

			if (crypto_box_curve25519xsalsa20poly1305_afternm(
				(PUCHAR)SendBuffer.get() + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES - crypto_box_BOXZEROBYTES,
				(PUCHAR)Buffer.get(),
				DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES),
				WholeNonce.get(),
				PacketTarget->PrecomputationKey) != 0)
			{
				for (auto &SocketDataIter:TCPSocketDataList)
					closesocket(SocketDataIter.Socket);
				
				goto SkipMain;
			}

			Buffer.reset();
			memcpy_s(SendBuffer.get() + sizeof(uint16_t), RecvSize - sizeof(uint16_t), PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
			memcpy_s(SendBuffer.get() + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN, RecvSize - sizeof(uint16_t) - DNSCURVE_MAGIC_QUERY_LEN, DNSCurveParameter.Client_PublicKey, crypto_box_PUBLICKEYBYTES);
			memcpy_s(SendBuffer.get() + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES, RecvSize - sizeof(uint16_t) - DNSCURVE_MAGIC_QUERY_LEN - crypto_box_PUBLICKEYBYTES, WholeNonce.get(), crypto_box_HALF_NONCEBYTES);
			*(uint16_t *)SendBuffer.get() = htons((uint16_t)(DNSCurveParameter.DNSCurvePayloadSize - sizeof(uint16_t)));
			memset(WholeNonce.get(), 0, crypto_box_NONCEBYTES);
		}
	}
	SkipMain: 

	//Set target.
	if (IsIPv6) //IPv6
		PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv6;
	else //IPv4
		PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv4;

	//Alternate
	if (PacketTarget->AddressData.Storage.ss_family > 0 && (*IsAlternate || Parameter.AlternateMultiRequest))
	{
	//Encryption mode check
		if (DNSCurveParameter.IsEncryption && 
			(CheckEmptyBuffer(PacketTarget->PrecomputationKey, crypto_box_BEFORENMBYTES) || 
			CheckEmptyBuffer(PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
		{
			for (auto SocketDataIter = TCPSocketDataList.begin();SocketDataIter != TCPSocketDataList.end();++SocketDataIter)
			{
				if (memcmp(&SocketDataIter->SockAddr, PacketTarget, sizeof(sockaddr_storage)) == 0)
					SocketDataIter = TCPSocketDataList.erase(SocketDataIter);
				if (SocketDataIter + 1U == TCPSocketDataList.end())
					break;
			}

			goto SkipAlternate;
		}

		for (size_t Index = 0;Index < Parameter.MultiRequestTimes;++Index)
		{
			TCPSocketData->SockAddr = PacketTarget->AddressData.Storage;
			if (IsIPv6) //IPv6
				TCPSocketData->Socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
			else //IPv4
				TCPSocketData->Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

		//Socket check
			if (TCPSocketData->Socket == INVALID_SOCKET)
			{
				PrintError(LOG_ERROR_NETWORK, L"DNSCurve TCP request initialization error", WSAGetLastError(), nullptr, 0);
				for (auto SocketDataIter = TCPSocketDataList.begin();SocketDataIter != TCPSocketDataList.end();++SocketDataIter)
				{
					if (memcmp(&SocketDataIter->SockAddr, PacketTarget, sizeof(sockaddr_storage)) == 0)
						SocketDataIter = TCPSocketDataList.erase(SocketDataIter);
					if (SocketDataIter + 1U == TCPSocketDataList.end())
						break;
				}

				goto SkipAlternate;
			}

		//Set Non-blocking Mode.
		#if defined(PLATFORM_WIN)
			else if (ioctlsocket(TCPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
			{
				PrintError(LOG_ERROR_NETWORK, L"Set TCP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
				closesocket(TCPSocketData->Socket);
				for (auto SocketDataIter = TCPSocketDataList.begin();SocketDataIter != TCPSocketDataList.end();++SocketDataIter)
				{
					if (memcmp(&SocketDataIter->SockAddr, PacketTarget, sizeof(sockaddr_storage)) == 0)
						SocketDataIter = TCPSocketDataList.erase(SocketDataIter);
					if (SocketDataIter + 1U == TCPSocketDataList.end())
						break;
				}

				goto SkipAlternate;
			}
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			Flags = fcntl(TCPSocketData->Socket, F_GETFL, 0);
			fcntl(TCPSocketData->Socket, F_SETFL, Flags|O_NONBLOCK);
		#endif

			if (IsIPv6) //IPv6
			{
				TCPSocketData->AddrLen = sizeof(sockaddr_in6);
				ServerTypeList.push_back(DNSCURVE_ALTERNATE_IPV6);
			}
			else { //IPv4
				TCPSocketData->AddrLen = sizeof(sockaddr_in);
				ServerTypeList.push_back(DNSCURVE_ALTERNATE_IPV4);
			}
			TCPSocketDataList.push_back(*TCPSocketData);
			memset(TCPSocketData.get(), 0, sizeof(SOCKET_DATA));
		}

	//Encryption mode
		if (DNSCurveParameter.IsEncryption)
		{
			std::shared_ptr<char> SendBufferTemp(new char[RecvSize]());
			memset(SendBufferTemp.get(), 0, RecvSize);
			Alternate_SendBuffer.swap(SendBufferTemp);
			SendBufferTemp.reset();
			std::shared_ptr<uint8_t> WholeNonceTemp(new uint8_t[crypto_box_NONCEBYTES]());
			memset(WholeNonceTemp.get(), 0, sizeof(uint8_t) * crypto_box_NONCEBYTES);
			WholeNonce.swap(WholeNonceTemp);
			WholeNonceTemp.reset();

		//Make nonce.
			*(uint32_t *)WholeNonce.get() = randombytes_random();
			*(uint32_t *)(WholeNonce.get() + sizeof(uint32_t)) = randombytes_random();
			*(uint32_t *)(WholeNonce.get() + sizeof(uint32_t) * 2U) = randombytes_random();
			memset(WholeNonce.get() + crypto_box_HALF_NONCEBYTES, 0, crypto_box_HALF_NONCEBYTES);

		//Make a crypto box.
			std::shared_ptr<char> Buffer(new char[DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES)]());
			memset(Buffer.get(), 0, DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES));
			memcpy_s(Buffer.get() + crypto_box_ZEROBYTES, RecvSize - crypto_box_ZEROBYTES, OriginalSend, SendSize);
			Buffer.get()[crypto_box_ZEROBYTES + SendSize] = '\x80';

			if (crypto_box_curve25519xsalsa20poly1305_afternm(
				(PUCHAR)Alternate_SendBuffer.get() + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES - crypto_box_BOXZEROBYTES,
				(PUCHAR)Buffer.get(),
				DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES),
				WholeNonce.get(),
				PacketTarget->PrecomputationKey) != 0)
			{
				for (auto SocketDataIter = TCPSocketDataList.begin();SocketDataIter != TCPSocketDataList.end();++SocketDataIter)
				{
					if (memcmp(&SocketDataIter->SockAddr, PacketTarget, sizeof(sockaddr_storage)) == 0)
						SocketDataIter = TCPSocketDataList.erase(SocketDataIter);
					if (SocketDataIter + 1U == TCPSocketDataList.end())
						break;
				}

				goto SkipAlternate;
			}

			Buffer.reset();
			memcpy_s(Alternate_SendBuffer.get() + sizeof(uint16_t), RecvSize - sizeof(uint16_t), PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
			memcpy_s(Alternate_SendBuffer.get() + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN, RecvSize - sizeof(uint16_t) - DNSCURVE_MAGIC_QUERY_LEN, DNSCurveParameter.Client_PublicKey, crypto_box_PUBLICKEYBYTES);
			memcpy_s(Alternate_SendBuffer.get() + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES, RecvSize - sizeof(uint16_t) - DNSCURVE_MAGIC_QUERY_LEN - crypto_box_PUBLICKEYBYTES, WholeNonce.get(), crypto_box_HALF_NONCEBYTES);
			*(uint16_t *)Alternate_SendBuffer.get() = htons((uint16_t)(DNSCurveParameter.DNSCurvePayloadSize - sizeof(uint16_t)));
			memset(WholeNonce.get(), 0, crypto_box_NONCEBYTES);
		}
	}
	SkipAlternate: 
	if (TCPSocketDataList.empty())
		return EXIT_FAILURE;

//Connect to servers.
	for (auto SocketDataIter = TCPSocketDataList.begin();SocketDataIter != TCPSocketDataList.end();)
	{
		if (connect(SocketDataIter->Socket, (PSOCKADDR)&SocketDataIter->SockAddr, SocketDataIter->AddrLen) == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK)
		{
			closesocket(SocketDataIter->Socket);
			SocketDataIter = TCPSocketDataList.erase(SocketDataIter);
			if (SocketDataIter == TCPSocketDataList.end())
				goto StopLoop;
		}
		else {
			++SocketDataIter;
		}
	}
	StopLoop: 
	if (TCPSocketDataList.empty())
		return EXIT_FAILURE;

//Send request and receive result.
	std::shared_ptr<fd_set> ReadFDS(new fd_set()), WriteFDS(new fd_set());
	std::shared_ptr<timeval> Timeout(new timeval());
	memset(ReadFDS.get(), 0, sizeof(fd_set));
	memset(WriteFDS.get(), 0, sizeof(fd_set));
	memset(Timeout.get(), 0, sizeof(timeval));
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	SOCKET MaxSocket = 0;
#endif
	FD_ZERO(WriteFDS.get());

	for (auto &SocketDataIter:TCPSocketDataList)
	{
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		if (SocketDataIter.Socket > MaxSocket)
			MaxSocket = SocketDataIter.Socket;
	#endif
		FD_SET(SocketDataIter.Socket, WriteFDS.get());
	}
	SSIZE_T SelectResult = 0, RecvLen = 0;
	std::vector<uint16_t> PDULenList(TCPSocketDataList.size(), 0);
	for (size_t LoopLimits = 0;LoopLimits < LOOP_MAX_TIMES;++LoopLimits)
	{
		Sleep(LOOP_INTERVAL_TIME);

	//Reset parameters.
	#if defined(PLATFORM_WIN)
		Timeout->tv_sec = Parameter.SocketTimeout_Reliable / SECOND_TO_MILLISECOND;
		Timeout->tv_usec = Parameter.SocketTimeout_Reliable % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		Timeout->tv_sec = Parameter.SocketTimeout_Reliable.tv_sec;
		Timeout->tv_usec = Parameter.SocketTimeout_Reliable.tv_usec;
	#endif
		FD_ZERO(ReadFDS.get());
		for (auto &SocketDataIter:TCPSocketDataList)
		{
			if (SocketDataIter.Socket > 0)
			{
				FD_SET(SocketDataIter.Socket, ReadFDS.get());
			}
		}

	//Wait for system calling.
	#if defined(PLATFORM_WIN)
		SelectResult = select(0, ReadFDS.get(), WriteFDS.get(), nullptr, Timeout.get());
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		SelectResult = select(MaxSocket + 1U, ReadFDS.get(), WriteFDS.get(), nullptr, Timeout.get());
	#endif
		if (SelectResult > 0)
		{
		//Receive.
			for (size_t Index = 0;Index < TCPSocketDataList.size();++Index)
			{
				if (FD_ISSET(TCPSocketDataList.at(Index).Socket, ReadFDS.get()))
				{
					RecvLen = recv(TCPSocketDataList.at(Index).Socket, OriginalRecv, (int)RecvSize, 0);

				//TCP segment of a reassembled PDU
					if (RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
					{
						if (RecvLen > 0 && htons(((uint16_t *)OriginalRecv)[0]) >= DNS_PACKET_MINSIZE && htons(((uint16_t *)OriginalRecv)[0]) < RecvSize)
						{
							PDULenList.at(Index) = htons(((uint16_t *)OriginalRecv)[0]);
							memset(OriginalRecv, 0, RecvSize);
							continue;
						}
					//Invalid packet.
						else {
							shutdown(TCPSocketDataList.at(Index).Socket, SD_BOTH);
							closesocket(TCPSocketDataList.at(Index).Socket);
							TCPSocketDataList.at(Index).Socket = 0;
							break;
						}
					}
					else {
					//Length check.
						if (RecvLen < (SSIZE_T)PDULenList.at(Index))
						{
							shutdown(TCPSocketDataList.at(Index).Socket, SD_BOTH);
							closesocket(TCPSocketDataList.at(Index).Socket);
							TCPSocketDataList.at(Index).Socket = 0;
							break;
						}
					//Receive again.
						else if (PDULenList.at(Index) > 0)
						{
						//Encryption mode
							if (DNSCurveParameter.IsEncryption)
							{
							//Jump to normal receive process.
								if (PDULenList.at(Index) >= DNS_PACKET_MINSIZE)
								{
									RecvLen = PDULenList.at(Index);
									goto JumpFromPDU;
								}

								memset(OriginalRecv, 0, RecvSize);
								continue;
							}
						}
					//First receive.
						else {
						//Length check
							if (RecvLen < (SSIZE_T)ntohs(((uint16_t *)OriginalRecv)[0]))
							{
								shutdown(TCPSocketDataList.at(Index).Socket, SD_BOTH);
								closesocket(TCPSocketDataList.at(Index).Socket);
								TCPSocketDataList.at(Index).Socket = 0;
								break;
							}
							else {
								RecvLen = ntohs(((uint16_t *)OriginalRecv)[0]);
								if (RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE && RecvLen < (SSIZE_T)RecvSize)
								{
									memmove_s(OriginalRecv, RecvSize, OriginalRecv + sizeof(uint16_t), RecvLen);

								//Jump here when TCP segment of a reassembled PDU.
									JumpFromPDU: 

								//Encryption mode
									if (DNSCurveParameter.IsEncryption)
									{
									//Check receive magic number.
										if (ServerTypeList.back() != ServerTypeList.front() && Index > 0 && Index >= TCPSocketDataList.size() / 2U)
										{
											if (ServerTypeList.back() == DNSCURVE_ALTERNATE_IPV6)
												PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv6;
											else if (ServerTypeList.back() == DNSCURVE_MAIN_IPV6)
												PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv6;
											else if (ServerTypeList.back() == DNSCURVE_ALTERNATE_IPV4)
												PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv4;
											else if (ServerTypeList.back() == DNSCURVE_MAIN_IPV4)
												PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv4;
										}
										else {
											if (ServerTypeList.front() == DNSCURVE_ALTERNATE_IPV6)
												PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv6;
											else if (ServerTypeList.front() == DNSCURVE_MAIN_IPV6)
												PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv6;
											else if (ServerTypeList.front() == DNSCURVE_ALTERNATE_IPV4)
												PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv4;
											else if (ServerTypeList.front() == DNSCURVE_MAIN_IPV4)
												PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv4;
										}
										if (memcmp(OriginalRecv, PacketTarget->ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN) != 0)
										{
											memset(OriginalRecv, 0, RecvSize);
											continue;
										}

									//Copy whole nonce.
										memcpy_s(WholeNonce.get(), crypto_box_NONCEBYTES, OriginalRecv + DNSCURVE_MAGIC_QUERY_LEN, crypto_box_NONCEBYTES);

									//Open crypto box.
										memset(OriginalRecv, 0, DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);
										memmove_s(OriginalRecv + crypto_box_BOXZEROBYTES, RecvSize - crypto_box_BOXZEROBYTES, OriginalRecv + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
										if (crypto_box_curve25519xsalsa20poly1305_open_afternm(
											(PUCHAR)OriginalRecv,
											(PUCHAR)OriginalRecv,
											RecvLen + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES),
											WholeNonce.get(),
											PacketTarget->PrecomputationKey) != 0)
										{
											memset(OriginalRecv, 0, RecvSize);
											continue;
										}
										memmove_s(OriginalRecv, RecvSize, OriginalRecv + crypto_box_ZEROBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
										memset(OriginalRecv + RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES), 0, RecvSize - (RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES)));
										for (SSIZE_T InnerIndex = RecvLen - (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);InnerIndex >= (SSIZE_T)DNS_PACKET_MINSIZE;--InnerIndex)
										{
											if ((UCHAR)OriginalRecv[InnerIndex] == 0x80)
											{
												RecvLen = InnerIndex;
												break;
											}
										}
									}

								//Hosts Only Extended check
									if ((Parameter.DNSDataCheck || Parameter.BlacklistCheck) && CheckResponseData(OriginalRecv, RecvLen, false) == EXIT_FAILURE)
									{
										memset(OriginalRecv, 0, RecvSize);
										continue;
									}

								//Close sockets and remove response length of TCP requesting.
									for (auto &SocketDataIter:TCPSocketDataList)
									{
										if (SocketDataIter.Socket > 0)
										{
											shutdown(SocketDataIter.Socket, SD_BOTH);
											closesocket(SocketDataIter.Socket);
										}
									}

								//Mark DNS Cache.
									if (Parameter.CacheType > 0)
										MarkDomainCache(OriginalRecv, RecvLen);

									return RecvLen;
								}
							//Length check
								else {
									shutdown(TCPSocketDataList.at(Index).Socket, SD_BOTH);
									closesocket(TCPSocketDataList.at(Index).Socket);
									TCPSocketDataList.at(Index).Socket = 0;
									break;
								}
							}
						}
					}
				}
			}

		//Send.
			size_t Alternate = 0;
			for (auto &SocketDataIter:TCPSocketDataList)
			{
				if (FD_ISSET(SocketDataIter.Socket, WriteFDS.get()))
				{
				//Encryption mode
					if (DNSCurveParameter.IsEncryption)
					{
						if (Alternate > 0 && Alternate >= TCPSocketDataList.size() / 2U && Alternate_SendBuffer)
							send(SocketDataIter.Socket, Alternate_SendBuffer.get(), (int)DNSCurveParameter.DNSCurvePayloadSize, 0);
						else 
							send(SocketDataIter.Socket, SendBuffer.get(), (int)DNSCurveParameter.DNSCurvePayloadSize, 0);
					}
				//Normal mode
					else {
						send(SocketDataIter.Socket, SendBuffer.get(), (int)DataLength, 0);
					}

					++Alternate;
				}
			}

			FD_ZERO(WriteFDS.get());
		}
	//Timeout
		else if (SelectResult == 0)
		{
			memset(OriginalRecv, 0, RecvSize);
			++AlternateSwapList.TimeoutTimes[8U];
			++AlternateSwapList.TimeoutTimes[9U];

		//Close all sockets.
			for (auto &SocketDataIter:TCPSocketDataList)
			{
				if (SocketDataIter.Socket > 0)
				{
					shutdown(SocketDataIter.Socket, SD_BOTH);
					closesocket(SocketDataIter.Socket);
				}
			}

			return WSAETIMEDOUT;
		}
	//SOCKET_ERROR
		else {
			break;
		}
	}

//Close all sockets.
	for (auto &SocketDataIter:TCPSocketDataList)
	{
		if (SocketDataIter.Socket > 0)
		{
			shutdown(SocketDataIter.Socket, SD_BOTH);
			closesocket(SocketDataIter.Socket);
		}
	}

	memset(OriginalRecv, 0, RecvSize);
	return EXIT_FAILURE;
}

//Transmission of DNSCurve UDP protocol
size_t __fastcall DNSCurveUDPRequest(const char *OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize)
{
//Initialization
	std::shared_ptr<SOCKET_DATA> UDPSockData(new SOCKET_DATA());
	memset(UDPSockData.get(), 0, sizeof(SOCKET_DATA));
	PDNSCURVE_SERVER_DATA PacketTarget = nullptr;
	bool *IsAlternate = nullptr;
	size_t *AlternateTimeoutTimes = nullptr;

//Socket initialization
	if (SelectTargetSocket(UDPSockData.get(), PacketTarget, IsAlternate, AlternateTimeoutTimes, IPPROTO_UDP) == 0 || UDPSockData->Socket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_NETWORK, L"DNSCurve UDP sockets initialization error", WSAGetLastError(), nullptr, 0);
		closesocket(UDPSockData->Socket);

		return EXIT_FAILURE;
	}

//Set socket timeout.
#if defined(PLATFORM_WIN)
	if (setsockopt(UDPSockData->Socket, SOL_SOCKET, SO_SNDTIMEO, (const char *)&Parameter.SocketTimeout_Unreliable, sizeof(int)) == SOCKET_ERROR || 
		setsockopt(UDPSockData->Socket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&Parameter.SocketTimeout_Unreliable, sizeof(int)) == SOCKET_ERROR)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	if (setsockopt(UDPSockData->Socket, SOL_SOCKET, SO_SNDTIMEO, (const char *)&Parameter.SocketTimeout_Unreliable, sizeof(timeval)) == SOCKET_ERROR || 
		setsockopt(UDPSockData->Socket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&Parameter.SocketTimeout_Unreliable, sizeof(timeval)) == SOCKET_ERROR)
#endif
	{
		PrintError(LOG_ERROR_NETWORK, L"Set UDP socket timeout error", WSAGetLastError(), nullptr, 0);
		closesocket(UDPSockData->Socket);

		return EXIT_FAILURE;
	}

//UDP connecting
	if (connect(UDPSockData->Socket, (PSOCKADDR)&UDPSockData->SockAddr, UDPSockData->AddrLen) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_NETWORK, L"DNSCurve UDP sockets initialization error", WSAGetLastError(), nullptr, 0);
		closesocket(UDPSockData->Socket);

		return EXIT_FAILURE;
	}

//Encryption mode
	std::shared_ptr<uint8_t> WholeNonce;
	if (DNSCurveParameter.IsEncryption)
	{
	//Make nonce.
		std::shared_ptr<uint8_t> WholeNonceTemp(new uint8_t[crypto_box_NONCEBYTES]());
		memset(WholeNonceTemp.get(), 0, sizeof(uint8_t) * crypto_box_NONCEBYTES);
		WholeNonce.swap(WholeNonceTemp);
		WholeNonceTemp.reset();
		*(uint32_t *)WholeNonce.get() = randombytes_random();
		*(uint32_t *)(WholeNonce.get() + sizeof(uint32_t)) = randombytes_random();
		*(uint32_t *)(WholeNonce.get() + sizeof(uint32_t) * 2U) = randombytes_random();
		memset(WholeNonce.get() + crypto_box_HALF_NONCEBYTES, 0, crypto_box_HALF_NONCEBYTES);

	//Make a crypto box.
		std::shared_ptr<char> Buffer(new char[DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES)]());
		memset(Buffer.get(), 0, DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES));
		memcpy_s(Buffer.get() + crypto_box_ZEROBYTES, DNSCurveParameter.DNSCurvePayloadSize - crypto_box_ZEROBYTES, OriginalSend, SendSize);
		Buffer.get()[crypto_box_ZEROBYTES + SendSize] = '\x80';

	//Make packet.
		if (crypto_box_curve25519xsalsa20poly1305_afternm(
			(PUCHAR)OriginalRecv + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES - crypto_box_BOXZEROBYTES, 
			(PUCHAR)Buffer.get(), 
			DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES), 
			WholeNonce.get(), 
			PacketTarget->PrecomputationKey) != 0)
		{
			closesocket(UDPSockData->Socket);
			memset(OriginalRecv, 0, RecvSize);

			return EXIT_FAILURE;
		}

		Buffer.reset();
		memcpy_s(OriginalRecv, RecvSize, PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
		memcpy_s(OriginalRecv + DNSCURVE_MAGIC_QUERY_LEN, RecvSize - DNSCURVE_MAGIC_QUERY_LEN, DNSCurveParameter.Client_PublicKey, crypto_box_PUBLICKEYBYTES);
		memcpy_s(OriginalRecv + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES, RecvSize - DNSCURVE_MAGIC_QUERY_LEN - crypto_box_PUBLICKEYBYTES, WholeNonce.get(), crypto_box_HALF_NONCEBYTES);
		memset(WholeNonce.get(), 0, crypto_box_NONCEBYTES);

//Send requesting.
		if (send(UDPSockData->Socket, OriginalRecv, (int)DNSCurveParameter.DNSCurvePayloadSize, 0) == SOCKET_ERROR)
		{
			PrintError(LOG_ERROR_NETWORK, L"DNSCurve UDP request error", WSAGetLastError(), nullptr, 0);
			shutdown(UDPSockData->Socket, SD_BOTH);
			closesocket(UDPSockData->Socket);

			return EXIT_FAILURE;
		}

		memset(OriginalRecv, 0, RecvSize);
	}
//Normal mode
	else {
		WholeNonce.reset();
		if (send(UDPSockData->Socket, OriginalSend, (int)SendSize, 0) == SOCKET_ERROR)
		{
			PrintError(LOG_ERROR_NETWORK, L"DNSCurve UDP request error", WSAGetLastError(), nullptr, 0);
			shutdown(UDPSockData->Socket, SD_BOTH);
			closesocket(UDPSockData->Socket);

			return EXIT_FAILURE;
		}
	}

//Receive result.
	SSIZE_T RecvLen = recv(UDPSockData->Socket, OriginalRecv, (int)RecvSize, 0);
	if (DNSCurveParameter.IsEncryption && RecvLen < (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES + DNS_PACKET_MINSIZE) || 
		RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
	{
		if (WSAGetLastError() == WSAETIMEDOUT)
		{
			shutdown(UDPSockData->Socket, SD_BOTH);
			closesocket(UDPSockData->Socket);
			if (AlternateTimeoutTimes != nullptr)
				++(*AlternateTimeoutTimes);

			return WSAETIMEDOUT;
		}
		else {
			shutdown(UDPSockData->Socket, SD_BOTH);
			closesocket(UDPSockData->Socket);
			return EXIT_FAILURE;
		}
	}

	shutdown(UDPSockData->Socket, SD_BOTH);
	closesocket(UDPSockData->Socket);
//Encryption mode
	if (DNSCurveParameter.IsEncryption)
	{
		memset(OriginalRecv + RecvLen, 0, RecvSize - RecvLen);
		if (memcmp(OriginalRecv, PacketTarget->ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN) != 0)
		{
			memset(OriginalRecv, 0, RecvSize);
			return EXIT_FAILURE;
		}

	//Copy whole nonce.
		memcpy_s(WholeNonce.get(), crypto_box_NONCEBYTES, OriginalRecv + DNSCURVE_MAGIC_QUERY_LEN, crypto_box_NONCEBYTES);

	//Open crypto box.
		memset(OriginalRecv, 0, DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);
		memmove_s(OriginalRecv + crypto_box_BOXZEROBYTES, RecvSize - crypto_box_BOXZEROBYTES, OriginalRecv + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
		if (crypto_box_curve25519xsalsa20poly1305_open_afternm(
			(PUCHAR)OriginalRecv,
			(PUCHAR)OriginalRecv,
			RecvLen + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES),
			WholeNonce.get(),
			PacketTarget->PrecomputationKey) != 0)
		{
			memset(OriginalRecv, 0, RecvSize);
			return EXIT_FAILURE;
		}
		memmove_s(OriginalRecv, RecvSize, OriginalRecv + crypto_box_ZEROBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
		memset(OriginalRecv + RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES), 0, RecvSize - (RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES)));
		for (SSIZE_T Index = RecvLen - (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);Index >= (SSIZE_T)DNS_PACKET_MINSIZE;--Index)
		{
			if ((UCHAR)OriginalRecv[Index] == 0x80)
			{
				RecvLen = Index;
				break;
			}
		}

	//Responses question and answers check
		if ((Parameter.DNSDataCheck || Parameter.BlacklistCheck) && CheckResponseData(OriginalRecv, RecvLen, false) == EXIT_FAILURE)
		{
			memset(OriginalRecv, 0, RecvSize);
			return EXIT_FAILURE;
		}

	//Mark DNS Cache.
		if (Parameter.CacheType > 0)
			MarkDomainCache(OriginalRecv, RecvLen);

		return RecvLen;
	}
//Normal mode
	else {
	//Responses question and answers check
		if ((Parameter.DNSDataCheck || Parameter.BlacklistCheck) && CheckResponseData(OriginalRecv, RecvLen, false) == EXIT_FAILURE)
		{
			memset(OriginalRecv, 0, RecvSize);
			return EXIT_FAILURE;
		}

	//Mark DNS Cache.
		if (Parameter.CacheType > 0)
			MarkDomainCache(OriginalRecv, RecvLen);

		return RecvLen;
	}

	memset(OriginalRecv, 0, RecvSize);
	return EXIT_FAILURE;
}

//Transmission of DNSCurve UDP protocol(Multithreading)
size_t __fastcall DNSCurveUDPRequestMulti(const char *OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize)
{
//Initialization
	std::vector<SOCKET_DATA> UDPSocketDataList;
	std::vector<size_t> ServerTypeList;
	std::shared_ptr<char> SendBuffer, Alternate_SendBuffer;
	std::shared_ptr<uint8_t> WholeNonce, Alternate_WholeNonce;

//Socket initialization
	auto IsIPv6 = false;
	bool *IsAlternate = nullptr;
	if (!SelectTargetSocketMulti(IsIPv6, IsAlternate, IPPROTO_UDP))
		return EXIT_FAILURE;

	std::shared_ptr<SOCKET_DATA> UDPSocketData(new SOCKET_DATA());
	memset(UDPSocketData.get(), 0, sizeof(SOCKET_DATA));
#if defined(PLATFORM_WIN)
	ULONG SocketMode = 1U;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	int Flags = 0;
#endif
	PDNSCURVE_SERVER_DATA PacketTarget = nullptr;

//Main
	if (!*IsAlternate)
	{
	//Set target.
		if (IsIPv6) //IPv6
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv6;
		else //IPv4
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv4;

	//Encryption mode check
		if (DNSCurveParameter.IsEncryption && 
			(CheckEmptyBuffer(PacketTarget->PrecomputationKey, crypto_box_BEFORENMBYTES) || 
			CheckEmptyBuffer(PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
				goto SkipMain;

		UDPSocketData->SockAddr = PacketTarget->AddressData.Storage;
		if (IsIPv6) //IPv6
			UDPSocketData->Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		else //IPv4
			UDPSocketData->Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	//Socket check
		if (UDPSocketData->Socket == INVALID_SOCKET)
		{
			PrintError(LOG_ERROR_NETWORK, L"Complete UDP request initialization error", WSAGetLastError(), nullptr, 0);
			goto SkipMain;
		}

	//Set Non-blocking Mode.
	#if defined(PLATFORM_WIN)
		else if (ioctlsocket(UDPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
		{
			PrintError(LOG_ERROR_NETWORK, L"Set UDP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
			closesocket(UDPSocketData->Socket);

			goto SkipMain;
		}
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		Flags = fcntl(UDPSocketData->Socket, F_GETFL, 0);
		fcntl(UDPSocketData->Socket, F_SETFL, Flags|O_NONBLOCK);
	#endif

		if (IsIPv6) //IPv6
		{
			UDPSocketData->AddrLen = sizeof(sockaddr_in6);
			ServerTypeList.push_back(DNSCURVE_MAIN_IPV6);
		}
		else { //IPv4
			UDPSocketData->AddrLen = sizeof(sockaddr_in);
			ServerTypeList.push_back(DNSCURVE_MAIN_IPV4);
		}

		UDPSocketDataList.push_back(*UDPSocketData);
		memset(UDPSocketData.get(), 0, sizeof(SOCKET_DATA));

	//Encryption mode
		if (DNSCurveParameter.IsEncryption)
		{
			std::shared_ptr<char> SendBufferTemp(new char[RecvSize]());
			memset(SendBufferTemp.get(), 0, RecvSize);
			SendBuffer.swap(SendBufferTemp);
			SendBufferTemp.reset();
			std::shared_ptr<uint8_t> WholeNonceTemp(new uint8_t[crypto_box_NONCEBYTES]());
			memset(WholeNonceTemp.get(), 0, sizeof(uint8_t) * crypto_box_NONCEBYTES);
			WholeNonce.swap(WholeNonceTemp);
			WholeNonceTemp.reset();

		//Make nonce.
			*(uint32_t *)WholeNonce.get() = randombytes_random();
			*(uint32_t *)(WholeNonce.get() + sizeof(uint32_t)) = randombytes_random();
			*(uint32_t *)(WholeNonce.get() + sizeof(uint32_t) * 2U) = randombytes_random();
			memset(WholeNonce.get() + crypto_box_HALF_NONCEBYTES, 0, crypto_box_HALF_NONCEBYTES);

		//Make a crypto box.
			std::shared_ptr<char> Buffer(new char[DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES)]());
			memset(Buffer.get(), 0, DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES));
			memcpy_s(Buffer.get() + crypto_box_ZEROBYTES, RecvSize - crypto_box_ZEROBYTES, OriginalSend, SendSize);
			Buffer.get()[crypto_box_ZEROBYTES + SendSize] = '\x80';

			if (crypto_box_curve25519xsalsa20poly1305_afternm(
				(PUCHAR)SendBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES - crypto_box_BOXZEROBYTES,
				(PUCHAR)Buffer.get(),
				DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES),
				WholeNonce.get(),
				PacketTarget->PrecomputationKey) != 0)
			{
				for (auto &SocketDataIter:UDPSocketDataList)
					closesocket(SocketDataIter.Socket);
				
				goto SkipMain;
			}

			Buffer.reset();
			memcpy_s(SendBuffer.get(), RecvSize, PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
			memcpy_s(SendBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN, RecvSize - DNSCURVE_MAGIC_QUERY_LEN, DNSCurveParameter.Client_PublicKey, crypto_box_PUBLICKEYBYTES);
			memcpy_s(SendBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES, RecvSize - DNSCURVE_MAGIC_QUERY_LEN - crypto_box_PUBLICKEYBYTES, WholeNonce.get(), crypto_box_HALF_NONCEBYTES);
			memset(WholeNonce.get(), 0, crypto_box_NONCEBYTES);
		}
	}
	SkipMain: 

	if (IsIPv6) //IPv6
		PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv6;
	else //IPv4
		PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv4;

//Alternate
	if (PacketTarget->AddressData.Storage.ss_family > 0 && (*IsAlternate || Parameter.AlternateMultiRequest))
	{
	//Encryption mode check
		if (DNSCurveParameter.IsEncryption && 
			(CheckEmptyBuffer(PacketTarget->PrecomputationKey, crypto_box_BEFORENMBYTES) || 
			CheckEmptyBuffer(PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
		{
			for (auto SocketDataIter = UDPSocketDataList.begin();SocketDataIter != UDPSocketDataList.end();++SocketDataIter)
			{
				if (memcmp(&SocketDataIter->SockAddr, PacketTarget, sizeof(sockaddr_storage)) == 0)
					SocketDataIter = UDPSocketDataList.erase(SocketDataIter);
				if (SocketDataIter + 1U == UDPSocketDataList.end())
					break;
			}

			goto SkipAlternate;
		}

		UDPSocketData->SockAddr = PacketTarget->AddressData.Storage;
		if (IsIPv6) //IPv6
			UDPSocketData->Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		else //IPv4
			UDPSocketData->Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	//Socket check
		if (UDPSocketData->Socket == INVALID_SOCKET)
		{
			PrintError(LOG_ERROR_NETWORK, L"Complete UDP request initialization error", WSAGetLastError(), nullptr, 0);
			for (auto SocketDataIter = UDPSocketDataList.begin();SocketDataIter != UDPSocketDataList.end();++SocketDataIter)
			{
				if (memcmp(&SocketDataIter->SockAddr, PacketTarget, sizeof(sockaddr_storage)) == 0)
					SocketDataIter = UDPSocketDataList.erase(SocketDataIter);
				if (SocketDataIter + 1U == UDPSocketDataList.end())
					break;
			}

			goto SkipAlternate;
		}

	//Set Non-blocking Mode.
	#if defined(PLATFORM_WIN)
		else if (ioctlsocket(UDPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
		{
			PrintError(LOG_ERROR_NETWORK, L"Set UDP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
			for (auto SocketDataIter = UDPSocketDataList.begin();SocketDataIter != UDPSocketDataList.end();++SocketDataIter)
			{
				if (memcmp(&SocketDataIter->SockAddr, PacketTarget, sizeof(sockaddr_storage)) == 0)
					SocketDataIter = UDPSocketDataList.erase(SocketDataIter);
				if (SocketDataIter + 1U == UDPSocketDataList.end())
					break;
			}

			goto SkipAlternate;
		}
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		Flags = fcntl(UDPSocketData->Socket, F_GETFL, 0);
		fcntl(UDPSocketData->Socket, F_SETFL, Flags|O_NONBLOCK);
	#endif

		if (IsIPv6) //IPv6
		{
			UDPSocketData->AddrLen = sizeof(sockaddr_in6);
			ServerTypeList.push_back(DNSCURVE_ALTERNATE_IPV6);
		}
		else { //IPv4
			UDPSocketData->AddrLen = sizeof(sockaddr_in);
			ServerTypeList.push_back(DNSCURVE_ALTERNATE_IPV4);
		}
		UDPSocketDataList.push_back(*UDPSocketData);
		memset(UDPSocketData.get(), 0, sizeof(SOCKET_DATA));

	//Encryption mode
		if (DNSCurveParameter.IsEncryption)
		{
			std::shared_ptr<char> SendBufferTemp(new char[RecvSize]());
			memset(SendBufferTemp.get(), 0, RecvSize);
			Alternate_SendBuffer.swap(SendBufferTemp);
			SendBufferTemp.reset();
			std::shared_ptr<uint8_t> WholeNonceTemp(new uint8_t[crypto_box_NONCEBYTES]());
			memset(WholeNonceTemp.get(), 0, sizeof(uint8_t) * crypto_box_NONCEBYTES);
			Alternate_WholeNonce.swap(WholeNonceTemp);
			WholeNonceTemp.reset();

		//Make nonce.
			*(uint32_t *)Alternate_WholeNonce.get() = randombytes_random();
			*(uint32_t *)(Alternate_WholeNonce.get() + sizeof(uint32_t)) = randombytes_random();
			*(uint32_t *)(Alternate_WholeNonce.get() + sizeof(uint32_t) * 2U) = randombytes_random();
			memset(Alternate_WholeNonce.get() + crypto_box_HALF_NONCEBYTES, 0, crypto_box_HALF_NONCEBYTES);

		//Make a crypto box.
			std::shared_ptr<char> Buffer(new char[DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES)]());
			memset(Buffer.get(), 0, DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES));
			memcpy_s(Buffer.get() + crypto_box_ZEROBYTES, RecvSize - crypto_box_ZEROBYTES, OriginalSend, SendSize);
			Buffer.get()[crypto_box_ZEROBYTES + SendSize] = '\x80';

			if (crypto_box_curve25519xsalsa20poly1305_afternm(
				(PUCHAR)Alternate_SendBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES - crypto_box_BOXZEROBYTES,
				(PUCHAR)Buffer.get(),
				DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES),
				Alternate_WholeNonce.get(),
				PacketTarget->PrecomputationKey) != 0)
			{
				for (auto SocketDataIter = UDPSocketDataList.begin();SocketDataIter != UDPSocketDataList.end();++SocketDataIter)
				{
					if (memcmp(&SocketDataIter->SockAddr, PacketTarget, sizeof(sockaddr_storage)) == 0)
						SocketDataIter = UDPSocketDataList.erase(SocketDataIter);
					if (SocketDataIter + 1U == UDPSocketDataList.end())
						break;
				}

				goto SkipAlternate;
			}

			Buffer.reset();
			memcpy_s(Alternate_SendBuffer.get(), RecvSize, PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
			memcpy_s(Alternate_SendBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN, RecvSize - DNSCURVE_MAGIC_QUERY_LEN, DNSCurveParameter.Client_PublicKey, crypto_box_PUBLICKEYBYTES);
			memcpy_s(Alternate_SendBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES, RecvSize - DNSCURVE_MAGIC_QUERY_LEN - crypto_box_PUBLICKEYBYTES, Alternate_WholeNonce.get(), crypto_box_HALF_NONCEBYTES);
			memset(Alternate_WholeNonce.get(), 0, crypto_box_NONCEBYTES);
		}
	}
	SkipAlternate: 
	if (UDPSocketDataList.empty())
		return EXIT_FAILURE;

//Send request and receive result.
	std::shared_ptr<fd_set> ReadFDS(new fd_set()), WriteFDS(new fd_set());
	std::shared_ptr<timeval> Timeout(new timeval());
	memset(Timeout.get(), 0, sizeof(timeval));
	memset(ReadFDS.get(), 0, sizeof(fd_set));
	memset(WriteFDS.get(), 0, sizeof(fd_set));
	memset(Timeout.get(), 0, sizeof(timeval));
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	SOCKET MaxSocket = 0;
#endif
	FD_ZERO(WriteFDS.get());
	for (auto &SocketDataIter:UDPSocketDataList)
	{
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		if (SocketDataIter.Socket > MaxSocket)
			MaxSocket = SocketDataIter.Socket;
	#endif
		FD_SET(SocketDataIter.Socket, WriteFDS.get());
	}
	SSIZE_T SelectResult = 0, RecvLen = 0;
	size_t Index = 0;
	for (size_t LoopLimits = 0;LoopLimits < LOOP_MAX_TIMES;++LoopLimits)
	{
		Sleep(LOOP_INTERVAL_TIME);

	//Reset parameters.
	#if defined(PLATFORM_WIN)
		Timeout->tv_sec = Parameter.SocketTimeout_Unreliable / SECOND_TO_MILLISECOND;
		Timeout->tv_usec = Parameter.SocketTimeout_Unreliable % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		Timeout->tv_sec = Parameter.SocketTimeout_Unreliable.tv_sec;
		Timeout->tv_usec = Parameter.SocketTimeout_Unreliable.tv_usec;
	#endif
		FD_ZERO(ReadFDS.get());
		for (auto &SocketDataIter:UDPSocketDataList)
		{
			if (SocketDataIter.Socket > 0)
			{
				FD_SET(SocketDataIter.Socket, ReadFDS.get());
			}
		}

	//Wait for system calling.
	#if defined(PLATFORM_WIN)
		SelectResult = select(0, ReadFDS.get(), WriteFDS.get(), nullptr, Timeout.get());
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		SelectResult = select(MaxSocket + 1U, ReadFDS.get(), WriteFDS.get(), nullptr, Timeout.get());
	#endif
		if (SelectResult > 0)
		{
			auto InnerIsAlternate = false;

		//Receive.
			for (Index = 0;Index < UDPSocketDataList.size();++Index)
			{
				if (FD_ISSET(UDPSocketDataList.at(Index).Socket, ReadFDS.get()))
				{
					RecvLen = recvfrom(UDPSocketDataList.at(Index).Socket, OriginalRecv, (int)RecvSize, 0, (PSOCKADDR)&UDPSocketDataList.at(Index).SockAddr, &UDPSocketDataList.at(Index).AddrLen);
					if (DNSCurveParameter.IsEncryption && RecvLen < (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES + DNS_PACKET_MINSIZE) || 
						RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
					{
						if (RecvLen > 0)
						{
							memset(OriginalRecv, 0, RecvSize);
							continue;
						}
						else {
							shutdown(UDPSocketDataList.at(Index).Socket, SD_BOTH);
							closesocket(UDPSocketDataList.at(Index).Socket);
							UDPSocketDataList.at(Index).Socket = 0;
							break;
						}
					}
					
				//Encryption mode
					if (DNSCurveParameter.IsEncryption)
					{
					//Check receive magic number.
						if (InnerIsAlternate)
						{
							if (ServerTypeList.back() == DNSCURVE_ALTERNATE_IPV6)
								PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv6;
							else if (ServerTypeList.back() == DNSCURVE_MAIN_IPV6)
								PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv6;
							else if (ServerTypeList.back() == DNSCURVE_ALTERNATE_IPV4)
								PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv4;
							else if (ServerTypeList.back() == DNSCURVE_MAIN_IPV4)
								PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv4;
						}
						else {
							if (ServerTypeList.front() == DNSCURVE_ALTERNATE_IPV6)
								PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv6;
							else if (ServerTypeList.front() == DNSCURVE_MAIN_IPV6)
								PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv6;
							else if (ServerTypeList.front() == DNSCURVE_ALTERNATE_IPV4)
								PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv4;
							else if (ServerTypeList.front() == DNSCURVE_MAIN_IPV4)
								PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv4;
						}
						if (memcmp(OriginalRecv, PacketTarget->ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN) != 0)
						{
							memset(OriginalRecv, 0, RecvSize);
							shutdown(UDPSocketDataList.at(Index).Socket, SD_BOTH);
							closesocket(UDPSocketDataList.at(Index).Socket);
							UDPSocketDataList.at(Index).Socket = 0;

							continue;
						}

					//Copy whole nonce.
						memcpy_s(WholeNonce.get(), crypto_box_NONCEBYTES, OriginalRecv + DNSCURVE_MAGIC_QUERY_LEN, crypto_box_NONCEBYTES);

					//Open crypto box.
						memset(OriginalRecv, 0, DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);
						memmove_s(OriginalRecv + crypto_box_BOXZEROBYTES, RecvSize - crypto_box_BOXZEROBYTES, OriginalRecv + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
						if (crypto_box_curve25519xsalsa20poly1305_open_afternm(
							(PUCHAR)OriginalRecv,
							(PUCHAR)OriginalRecv,
							RecvLen + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES),
							WholeNonce.get(),
							PacketTarget->PrecomputationKey) != 0)
						{
							memset(OriginalRecv, 0, RecvSize);
							shutdown(UDPSocketDataList.at(Index).Socket, SD_BOTH);
							closesocket(UDPSocketDataList.at(Index).Socket);
							UDPSocketDataList.at(Index).Socket = 0;

							continue;
						}
						memmove_s(OriginalRecv, RecvSize, OriginalRecv + crypto_box_ZEROBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
						memset(OriginalRecv + RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES), 0, RecvSize - (RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES)));
						for (SSIZE_T InnerIndex = RecvLen - (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);InnerIndex >= (SSIZE_T)DNS_PACKET_MINSIZE;--InnerIndex)
						{
							if ((UCHAR)OriginalRecv[InnerIndex] == 0x80)
							{
								RecvLen = InnerIndex;
								break;
							}
						}

					//Responses question and answers check
						if ((Parameter.DNSDataCheck || Parameter.BlacklistCheck) && CheckResponseData(OriginalRecv, RecvLen, false) == EXIT_FAILURE)
						{
							memset(OriginalRecv, 0, RecvSize);
							shutdown(UDPSocketDataList.at(Index).Socket, SD_BOTH);
							closesocket(UDPSocketDataList.at(Index).Socket);
							UDPSocketDataList.at(Index).Socket = 0;

							continue;
						}

					//Close all sockets.
						for (auto &SocketDataIter:UDPSocketDataList)
						{
							if (SocketDataIter.Socket > 0)
							{
								shutdown(SocketDataIter.Socket, SD_BOTH);
								closesocket(SocketDataIter.Socket);
							}
						}

					//Mark DNS Cache.
						if (Parameter.CacheType > 0)
							MarkDomainCache(OriginalRecv, RecvLen);

						return RecvLen;
					}
				//Normal mode
					else {
						for (auto &SocketDataIter:UDPSocketDataList)
						{
							if (SocketDataIter.Socket > 0)
							{
								shutdown(SocketDataIter.Socket, SD_BOTH);
								closesocket(SocketDataIter.Socket);
							}
						}

					//Hosts Only Extended check
						if ((Parameter.DNSDataCheck || Parameter.BlacklistCheck) && CheckResponseData(OriginalRecv, RecvLen, false) == EXIT_FAILURE)
						{
							memset(OriginalRecv, 0, RecvSize);
							continue;
						}

					//Mark DNS Cache.
						if (Parameter.CacheType > 0)
							MarkDomainCache(OriginalRecv, RecvLen);

					//Close all sockets.
						for (auto &SocketDataIter:UDPSocketDataList)
						{
							if (SocketDataIter.Socket > 0)
							{
								shutdown(SocketDataIter.Socket, SD_BOTH);
								closesocket(SocketDataIter.Socket);
							}
						}

						return RecvLen;
					}
				}

				InnerIsAlternate = true;
			}

		//Send.
			InnerIsAlternate = false;
			for (auto &SocketDataIter:UDPSocketDataList)
			{
				if (FD_ISSET(SocketDataIter.Socket, WriteFDS.get()))
				{
				//Encryption mode
					if (DNSCurveParameter.IsEncryption)
					{
						if (InnerIsAlternate && Alternate_SendBuffer)
						{
							for (size_t InnerIndex = 0;InnerIndex < Parameter.MultiRequestTimes;++InnerIndex)
								sendto(SocketDataIter.Socket, Alternate_SendBuffer.get(), (int)DNSCurveParameter.DNSCurvePayloadSize, 0, (PSOCKADDR)&SocketDataIter.SockAddr, SocketDataIter.AddrLen);
						}
						else {
							for (size_t InnerIndex = 0;InnerIndex < Parameter.MultiRequestTimes;++InnerIndex)
								sendto(SocketDataIter.Socket, SendBuffer.get(), (int)DNSCurveParameter.DNSCurvePayloadSize, 0, (PSOCKADDR)&SocketDataIter.SockAddr, SocketDataIter.AddrLen);
							InnerIsAlternate = true;
						}
					}
				//Normal mode
					else {
						for (size_t InnerIndex = 0;InnerIndex < Parameter.MultiRequestTimes;++InnerIndex)
							sendto(SocketDataIter.Socket, OriginalSend, (int)SendSize, 0, (PSOCKADDR)&SocketDataIter.SockAddr, SocketDataIter.AddrLen);
					}
				}
			}

			FD_ZERO(WriteFDS.get());
		}
	//Timeout
		else if (SelectResult == 0)
		{
			memset(OriginalRecv, 0, RecvSize);
			++AlternateSwapList.TimeoutTimes[10U];
			++AlternateSwapList.TimeoutTimes[11U];

		//Close all sockets.
			for (auto &SocketDataIter:UDPSocketDataList)
			{
				if (SocketDataIter.Socket > 0)
				{
					shutdown(SocketDataIter.Socket, SD_BOTH);
					closesocket(SocketDataIter.Socket);
				}
			}

			return WSAETIMEDOUT;
		}
	//SOCKET_ERROR
		else {
			break;
		}
	}

//Close all sockets.
	for (auto &SocketDataIter:UDPSocketDataList)
	{
		if (SocketDataIter.Socket > 0)
		{
			shutdown(SocketDataIter.Socket, SD_BOTH);
			closesocket(SocketDataIter.Socket);
		}
	}

	memset(OriginalRecv, 0, RecvSize);
	return EXIT_FAILURE;
}
#endif

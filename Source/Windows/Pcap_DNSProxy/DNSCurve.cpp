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


#include "DNSCurve.h"

//DNSCurve verify keypair
bool __fastcall VerifyKeypair(const PUINT8 PublicKey, const PUINT8 SecretKey)
{
	std::shared_ptr<uint8_t> Test_PublicKey(new uint8_t[crypto_box_PUBLICKEYBYTES]()), Test_SecretKey(new uint8_t[crypto_box_PUBLICKEYBYTES]()), Validation(new uint8_t[crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES + crypto_box_ZEROBYTES]());
	memset(Test_PublicKey.get(), 0, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES);
	memset(Test_SecretKey.get(), 0, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES);
	memset(Validation.get(), 0, sizeof(uint8_t) * (crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES + crypto_box_ZEROBYTES));

//Keypair, Nonce and validation data
	crypto_box_curve25519xsalsa20poly1305_keypair(Test_PublicKey.get(), Test_SecretKey.get());
	uint8_t Nonce[crypto_box_NONCEBYTES] = {DNSCURVE_TEST_NONCE};
//	memcpy(Validation.get() + crypto_box_ZEROBYTES, PublicKey, crypto_box_PUBLICKEYBYTES);
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

//DNSCurve initialization
size_t __fastcall DNSCurveInit(void)
{
//DNSCurve signature request TCP Mode
	if (DNSCurveParameter.DNSCurveMode == DNSCURVE_REQUEST_TCPMODE)
	{
	//Main
		if (DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family > 0 && 
			(CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
			CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
		{
			std::thread DNSCurveTCPSignatureRequestThread(DNSCurveTCPSignatureRequest, AF_INET6, false);
			DNSCurveTCPSignatureRequestThread.detach();
		}
		
		if (DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family > 0 && 
			(CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
			CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
		{
			std::thread DNSCurveTCPSignatureRequestThread(DNSCurveTCPSignatureRequest, AF_INET, false);
			DNSCurveTCPSignatureRequestThread.detach();
		}

	//Alternate
		if (DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && 
			(CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
			CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
		{
			std::thread DNSCurveTCPSignatureRequestThread(DNSCurveTCPSignatureRequest, AF_INET6, true);
			DNSCurveTCPSignatureRequestThread.detach();
		}
		
		if (DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && 
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
		(CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
		CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
	{
		std::thread DNSCurveUDPSignatureRequestThread(DNSCurveUDPSignatureRequest, AF_INET6, false);
		DNSCurveUDPSignatureRequestThread.detach();
	}
		
	if (DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family > 0 && 
		(CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
		CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
	{
		std::thread DNSCurveUDPSignatureRequestThread(DNSCurveUDPSignatureRequest, AF_INET, false);
		DNSCurveUDPSignatureRequestThread.detach();
	}

//Alternate
	if (DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && 
		(CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
		CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
	{
		std::thread DNSCurveUDPSignatureRequestThread(DNSCurveUDPSignatureRequest, AF_INET6, true);
		DNSCurveUDPSignatureRequestThread.detach();
	}
		
	if (DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && 
		(CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
		CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
	{
		std::thread DNSCurveUDPSignatureRequestThread(DNSCurveUDPSignatureRequest, AF_INET, true);
		DNSCurveUDPSignatureRequestThread.detach();
	}

	return EXIT_SUCCESS;
}

//DNSCurve Local Signature Request
size_t LocalSignatureRequest(const PSTR OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize)
{
//Initialization
	std::shared_ptr<sockaddr_storage> SockAddr(new sockaddr_storage());
	memset(SockAddr.get(), 0, sizeof(sockaddr_storage));
	SYSTEM_SOCKET UDPSocket = 0;
	int AddrLen = 0;

//Socket initialization
	if (Parameter.GatewayAvailable_IPv6 && DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family > 0) //IPv6
	{
		((sockaddr_in6 *)SockAddr.get())->sin6_addr = in6addr_loopback;
		((sockaddr_in6 *)SockAddr.get())->sin6_port = Parameter.ListenPort->front();

		AddrLen = sizeof(sockaddr_in6);
		SockAddr->ss_family = AF_INET6;
		UDPSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	}
	else if (Parameter.GatewayAvailable_IPv4 && DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family > 0) //IPv4
	{
		((sockaddr_in *)SockAddr.get())->sin_addr.S_un.S_addr = htonl(INADDR_LOOPBACK);
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
		PrintError(LOG_ERROR_WINSOCK, L"DNSCurve Local Signature request initialization error", WSAGetLastError(), nullptr, 0);
		return EXIT_FAILURE;
	}

//Set socket timeout.
	if (setsockopt(UDPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR || 
		setsockopt(UDPSocket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Set DNSCurve Local Signature socket timeout error", WSAGetLastError(), nullptr, 0);
		closesocket(UDPSocket);

		return EXIT_FAILURE;
	}

//Send requesting.
	if (sendto(UDPSocket, OriginalSend, (int)SendSize, 0, (PSOCKADDR)SockAddr.get(), AddrLen) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"DNSCurve Local Signature request error", WSAGetLastError(), nullptr, 0);
		shutdown(UDPSocket, SD_BOTH);
		closesocket(UDPSocket);

		return EXIT_FAILURE;
	}

//Receive result.
	SSIZE_T RecvLen = recvfrom(UDPSocket, OriginalRecv, (int)RecvSize, 0, (PSOCKADDR)SockAddr.get(), (PINT)&AddrLen);
	shutdown(UDPSocket, SD_BOTH);
	closesocket(UDPSocket);
	if (RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE)
		return RecvLen;
	
	memset(OriginalRecv, 0, RecvSize);
	return EXIT_FAILURE;
}

//Send TCP request to get Signature Data of servers
bool __fastcall DNSCurveTCPSignatureRequest(const uint16_t NetworkLayer, const bool IsAlternate)
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
	DNS_TCP_Header->ID = Parameter.DomainTestID;
	DNS_TCP_Header->Flags = htons(DNS_STANDARD);
	DNS_TCP_Header->Questions = htons(U16_NUM_ONE);
	
	if (Parameter.GatewayAvailable_IPv6 && NetworkLayer == AF_INET6) //IPv6
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

//EDNS0 Label
	DNS_TCP_Header->Additional = htons(U16_NUM_ONE);
	auto DNS_Record_OPT = (pdns_record_opt)(SendBuffer.get() + DataLength);
	DNS_Record_OPT->Type = htons(DNS_RECORD_OPT);
	DNS_Record_OPT->UDPPayloadSize = htons(EDNS0_MINSIZE);
	DataLength += sizeof(dns_record_opt);

	DNS_TCP_Header->Length = htons((uint16_t)(DataLength - sizeof(uint16_t)));
//Socket initialization
	int AddrLen = 0;
	size_t ServerType = 0;
	PDNSCURVE_SERVER_DATA PacketTarget = nullptr;
	if (NetworkLayer == AF_INET6) //IPv6
	{
		if (IsAlternate)
		{
			((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
			((PSOCKADDR_IN6)SockAddr.get())->sin6_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv6;
			ServerType = DNSCURVE_ALTERNATEIPV6;
		}
		else { //Main
			((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_addr;
			((PSOCKADDR_IN6)SockAddr.get())->sin6_port = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_port;
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv6;
			ServerType = DNSCURVE_MAINIPV6;
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
			ServerType = DNSCURVE_ALTERNATEIPV4;
		}
		else { //Main
			((PSOCKADDR_IN)SockAddr.get())->sin_addr = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_addr;
			((PSOCKADDR_IN)SockAddr.get())->sin_port = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_port;
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv4;
			ServerType = DNSCURVE_MAINIPV4;
		}

		AddrLen = sizeof(sockaddr_in);
		SockAddr->ss_family = AF_INET;
		TCPSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	}

/* Old version(2015-01-14)
	SSIZE_T RecvLen = 0;
	for (;;)
	{
	//Socket check
		if (TCPSocket == INVALID_SOCKET)
		{
			PrintError(LOG_ERROR_WINSOCK, L"DNSCurve TCP sockets initialization error", WSAGetLastError(), nullptr, 0);
			return false;
		}

	//Set socket timeout.
		if (setsockopt(TCPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.ReliableSocketTimeout, sizeof(int)) == SOCKET_ERROR || 
			setsockopt(TCPSocket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.ReliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
		{
			PrintError(LOG_ERROR_WINSOCK, L"Set TCP socket timeout error", WSAGetLastError(), nullptr, 0);
			closesocket(TCPSocket);

			return false;
		}

	//Connect to server.
		if (connect(TCPSocket, (PSOCKADDR)SockAddr.get(), AddrLen) == SOCKET_ERROR) //Connection is RESET or other errors when connecting.
		{
			closesocket(TCPSocket);
			if (NetworkLayer == AF_INET6) //IPv6
				TCPSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
			else //IPv4
				TCPSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

			Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
			continue;
		}

	//Send requesting.
		if (send(TCPSocket, SendBuffer.get(), (int)DataLength, 0) == SOCKET_ERROR)
		{
			PrintError(LOG_ERROR_DNSCURVE, L"TCP get signature data request error", WSAGetLastError(), nullptr, 0);
			closesocket(TCPSocket);

			if (NetworkLayer == AF_INET6) //IPv6
				TCPSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
			else //IPv4
				TCPSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

			Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
			continue;
		}
		else {
			RecvLen = recv(TCPSocket, RecvBuffer.get(), LARGE_PACKET_MAXSIZE, 0);
			if (RecvLen <= 0 || (SSIZE_T)htons(((uint16_t *)RecvBuffer.get())[0]) > RecvLen) //Connection is RESET or other errors(including SOCKET_ERROR) when sending or server fin the connection.
			{
				closesocket(TCPSocket);
				if (NetworkLayer == AF_INET6) //IPv6
					TCPSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
				else //IPv4
					TCPSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

				memset(RecvBuffer.get(), 0, LARGE_PACKET_MAXSIZE);
				Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
				continue;
			}
			else if (htons(((uint16_t *)RecvBuffer.get())[0]) < DNS_PACKET_MINSIZE + sizeof(dns_record_txt) + DNSCRYPT_TXT_RECORDS_LEN) //TCP segment of a reassembled PDU
			{
				uint16_t PDULen = htons(((uint16_t *)RecvBuffer.get())[0]);
				memset(RecvBuffer.get(), 0, LARGE_PACKET_MAXSIZE);
				RecvLen = recv(TCPSocket, RecvBuffer.get(), LARGE_PACKET_MAXSIZE, 0) - sizeof(uint16_t);
				if (RecvLen <= 0 || RecvLen < (SSIZE_T)PDULen) //Connection is RESET or other errors(including SOCKET_ERROR) after sending or finished, also may be a corrupted packet.
				{
					closesocket(TCPSocket);
					if (NetworkLayer == AF_INET6) //IPv6
						TCPSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
					else //IPv4
						TCPSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

					memset(RecvBuffer.get(), 0, LARGE_PACKET_MAXSIZE);
					Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
					continue;
				}
				else if (PDULen >= DNS_PACKET_MINSIZE + sizeof(dns_record_txt) + DNSCRYPT_TXT_RECORDS_LEN)
				{
				//Check result.
					PUINT8 ServerFingerprint = nullptr;
					PSTR SendMagicNumber = nullptr;
					if (ServerType == DNSCURVE_ALTERNATEIPV6)
					{
						ServerFingerprint = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ServerFingerprint;
						SendMagicNumber = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber;
					}
					else if (ServerType == DNSCURVE_MAINIPV6)
					{
						ServerFingerprint = DNSCurveParameter.DNSCurveTarget.IPv6.ServerFingerprint;
						SendMagicNumber = DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber;
					}
					else if (ServerType == DNSCURVE_ALTERNATEIPV4)
					{
						ServerFingerprint = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ServerFingerprint;
						SendMagicNumber = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.SendMagicNumber;
					}
					else if (ServerType == DNSCURVE_MAINIPV4)
					{
						ServerFingerprint = DNSCurveParameter.DNSCurveTarget.IPv4.ServerFingerprint;
						SendMagicNumber = DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber;
					}

				//Check Signature.
					if (!GetSignatureData(RecvBuffer.get() + DNS_PACKET_RR_LOCATE(RecvBuffer.get()), ServerType) || 
						CheckEmptyBuffer(ServerFingerprint, crypto_box_PUBLICKEYBYTES) || 
						CheckEmptyBuffer(SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
					{
						closesocket(TCPSocket);
						if (NetworkLayer == AF_INET6) //IPv6
							TCPSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
						else //IPv4
							TCPSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

						memset(RecvBuffer.get(), 0, LARGE_PACKET_MAXSIZE);
						Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
						continue;
					}

					memset(RecvBuffer.get(), 0, LARGE_PACKET_MAXSIZE);
				}
				else {
					closesocket(TCPSocket);
					if (NetworkLayer == AF_INET6) //IPv6
						TCPSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
					else //IPv4
						TCPSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

					memset(RecvBuffer.get(), 0, LARGE_PACKET_MAXSIZE);
					Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
					continue;
				}
			}
			else if (htons(((uint16_t *)RecvBuffer.get())[0]) >= DNS_PACKET_MINSIZE + sizeof(dns_record_txt) + DNSCRYPT_TXT_RECORDS_LEN)
			{
				RecvLen = htons(((uint16_t *)RecvBuffer.get())[0]);
				memmove(RecvBuffer.get(), RecvBuffer.get() + sizeof(uint16_t), RecvLen);

			//Check result.
				PUINT8 ServerFingerprint = nullptr;
				PSTR SendMagicNumber = nullptr;
				if (ServerType == DNSCURVE_ALTERNATEIPV6)
				{
					ServerFingerprint = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ServerFingerprint;
					SendMagicNumber = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber;
				}
				else if (ServerType == DNSCURVE_MAINIPV6)
				{
					ServerFingerprint = DNSCurveParameter.DNSCurveTarget.IPv6.ServerFingerprint;
					SendMagicNumber = DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber;
				}
				else if (ServerType == DNSCURVE_ALTERNATEIPV4)
				{
					ServerFingerprint = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ServerFingerprint;
					SendMagicNumber = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.SendMagicNumber;
					
				}
				else if (ServerType == DNSCURVE_MAINIPV4)
				{
					ServerFingerprint = DNSCurveParameter.DNSCurveTarget.IPv4.ServerFingerprint;
					SendMagicNumber = DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber;
				}

			//Check Signature.
				if (!GetSignatureData(RecvBuffer.get() + DNS_PACKET_RR_LOCATE(RecvBuffer.get()), ServerType) || 
					CheckEmptyBuffer(ServerFingerprint, crypto_box_PUBLICKEYBYTES) || 
					CheckEmptyBuffer(SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					closesocket(TCPSocket);
					if (NetworkLayer == AF_INET6) //IPv6
						TCPSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
					else //IPv4
						TCPSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

					memset(RecvBuffer.get(), 0, LARGE_PACKET_MAXSIZE);
					Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
					continue;
				}

				memset(RecvBuffer.get(), 0, LARGE_PACKET_MAXSIZE);
			}
			else {
				closesocket(TCPSocket);
				if (NetworkLayer == AF_INET6) //IPv6
					TCPSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
				else //IPv4
					TCPSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

				memset(RecvBuffer.get(), 0, LARGE_PACKET_MAXSIZE);
				Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
				continue;
			}
		}

		Sleep((DWORD)DNSCurveParameter.KeyRecheckTime);
	}
*/

	std::shared_ptr<fd_set> ReadFDS(new fd_set()), WriteFDS(new fd_set());
	memset(ReadFDS.get(), 0, sizeof(fd_set));
	memset(WriteFDS.get(), 0, sizeof(fd_set));
	ULONG SocketMode = 1U;
	timeval Timeout = {0};
	SSIZE_T SelectResult = 0, RecvLen = 0;
	uint16_t PDULen = 0;
	for (;;)
	{
	//Socket check
		if (TCPSocket == INVALID_SOCKET)
		{
			PrintError(LOG_ERROR_WINSOCK, L"DNSCurve TCP sockets initialization error", WSAGetLastError(), nullptr, 0);
			TCPSocket = socket(NetworkLayer, SOCK_STREAM, IPPROTO_TCP);

			goto JumpToRestart;
		}

	//Set Non-blocking Mode
		if (ioctlsocket(TCPSocket, FIONBIO, &SocketMode) == SOCKET_ERROR)
		{
			closesocket(TCPSocket);
			PrintError(LOG_ERROR_WINSOCK, L"Set TCP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
			TCPSocket = socket(NetworkLayer, SOCK_STREAM, IPPROTO_TCP);

			goto JumpToRestart;
		}

	//Connect to server.
		if (connect(TCPSocket, (PSOCKADDR)SockAddr.get(), AddrLen) == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK)
		{
			Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
			continue;
		}

	//Send request and receive result.
		FD_ZERO(WriteFDS.get());
		FD_SET(TCPSocket, WriteFDS.get());
		SelectResult = 0, RecvLen = 0, PDULen = 0;
		for (;;)
		{
			Sleep(LOOP_INTERVAL_TIME);

		//Reset parameters.
			Timeout.tv_sec = Parameter.ReliableSocketTimeout / SECOND_TO_MILLISECOND;
			Timeout.tv_usec = Parameter.ReliableSocketTimeout % SECOND_TO_MILLISECOND * SECOND_TO_MILLISECOND;
			FD_ZERO(ReadFDS.get());
			FD_SET(TCPSocket, ReadFDS.get());

		//Wait for system calling.
			SelectResult = select(0, ReadFDS.get(), WriteFDS.get(), nullptr, &Timeout);
			if (SelectResult > 0)
			{
			//Receive.
				if (FD_ISSET(TCPSocket, ReadFDS.get()))
				{
					RecvLen = recv(TCPSocket, RecvBuffer.get(), LARGE_PACKET_MAXSIZE, 0);

				//TCP segment of a reassembled PDU
					if (RecvLen < DNS_PACKET_MINSIZE)
					{
						if (RecvLen > 0 && htons(((uint16_t *)RecvBuffer.get())[0]) >= DNS_PACKET_MINSIZE)
						{
							PDULen = htons(((uint16_t *)RecvBuffer.get())[0]);
							memset(RecvBuffer.get(), 0, LARGE_PACKET_MAXSIZE);
							continue;
						}
					//Invalid packet.
						else {
							goto JumpToRestart;
						}
					}
					else {
					//Length check.
						if ((SSIZE_T)PDULen > RecvLen)
						{
							goto JumpToRestart;
						}
					//Receive again.
						else if (PDULen > 0)
						{
							shutdown(TCPSocket, SD_BOTH);
							closesocket(TCPSocket);

						//Jump to normal receive process.
							if (PDULen >= DNS_PACKET_MINSIZE)
							{
								RecvLen = (SSIZE_T)PDULen;
								goto JumpFromPDU;
							}

							goto JumpToRestart;
						}
					//First receive.
						else {
						//Length check
							if ((SSIZE_T)ntohs(((uint16_t *)RecvBuffer.get())[0]) > RecvLen)
							{
								goto JumpToRestart;
							}
							else {
								shutdown(TCPSocket, SD_BOTH);
								closesocket(TCPSocket);

								RecvLen = (SSIZE_T)ntohs(((uint16_t *)RecvBuffer.get())[0]);
								if (RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE)
								{
//									memmove(RecvBuffer.get(), RecvBuffer.get() + sizeof(uint16_t), RecvLen);
									memmove_s(RecvBuffer.get(), LARGE_PACKET_MAXSIZE, RecvBuffer.get() + sizeof(uint16_t), RecvLen);

								//Jump here when TCP segment of a reassembled PDU.
									JumpFromPDU: 

								//Check Signature.
									if (PacketTarget == nullptr || 
										!GetSignatureData(RecvBuffer.get() + DNS_PACKET_RR_LOCATE(RecvBuffer.get()), ServerType) || 
										CheckEmptyBuffer(PacketTarget->ServerFingerprint, crypto_box_PUBLICKEYBYTES) || 
										CheckEmptyBuffer(PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
									{
										shutdown(TCPSocket, SD_BOTH);
										closesocket(TCPSocket);
										TCPSocket = socket(NetworkLayer, SOCK_STREAM, IPPROTO_TCP);
										goto JumpToRestart;
									}

									break;
								}
							//Length check
								else {
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
				goto JumpToRestart;
			}
		}

		Sleep((DWORD)DNSCurveParameter.KeyRecheckTime);
		continue;

	//Restart.
		JumpToRestart: 
		memset(RecvBuffer.get(), 0, LARGE_PACKET_MAXSIZE);
		Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
	}

	shutdown(TCPSocket, SD_BOTH);
	closesocket(TCPSocket);
	return true;
}

//Send UDP request to get Signature Data of servers
bool __fastcall DNSCurveUDPSignatureRequest(const uint16_t NetworkLayer, const bool IsAlternate)
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
	DNS_Header->ID = Parameter.DomainTestID;
	DNS_Header->Flags = htons(DNS_STANDARD);
	DNS_Header->Questions = htons(U16_NUM_ONE);

	if (NetworkLayer == AF_INET6) //IPv6
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

//EDNS0 Label
	DNS_Header->Additional = htons(U16_NUM_ONE);
	auto DNS_Record_OPT = (pdns_record_opt)(SendBuffer.get() + DataLength);
	DNS_Record_OPT->Type = htons(DNS_RECORD_OPT);
	DNS_Record_OPT->UDPPayloadSize = htons(EDNS0_MINSIZE);
	DataLength += sizeof(dns_record_opt);

//Socket initialization
	int AddrLen = 0;
	size_t ServerType = 0;
	PDNSCURVE_SERVER_DATA PacketTarget = nullptr;
	if (NetworkLayer == AF_INET6) //IPv6
	{
		if (IsAlternate)
		{
			((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
			((PSOCKADDR_IN6)SockAddr.get())->sin6_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv6;
			ServerType = DNSCURVE_ALTERNATEIPV6;
		}
		else { //Main
			((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_addr;
			((PSOCKADDR_IN6)SockAddr.get())->sin6_port = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_port;
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv6;
			ServerType = DNSCURVE_MAINIPV6;
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
			ServerType = DNSCURVE_ALTERNATEIPV4;
		}
		else { //Main
			((PSOCKADDR_IN)SockAddr.get())->sin_addr = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_addr;
			((PSOCKADDR_IN)SockAddr.get())->sin_port = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_port;
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv4;
			ServerType = DNSCURVE_MAINIPV4;
		}

		AddrLen = sizeof(sockaddr_in);
		SockAddr->ss_family = AF_INET;
		UDPSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	}

//Socket check
	if (UDPSocket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_WINSOCK, L"DNSCurve UDP sockets initialization error", WSAGetLastError(), nullptr, 0);
		return false;
	}

//Set socket timeout.
	if (setsockopt(UDPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR || 
		setsockopt(UDPSocket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket timeout error", WSAGetLastError(), nullptr, 0);
		closesocket(UDPSocket);

		return false;
	}

//Send requesting.
	SSIZE_T RecvLen = 0;
	for (;;)
	{
		if (sendto(UDPSocket, SendBuffer.get(), (int)DataLength, 0, (PSOCKADDR)SockAddr.get(), AddrLen) == SOCKET_ERROR)
		{
			shutdown(UDPSocket, SD_BOTH);
			closesocket(UDPSocket);
			PrintError(LOG_ERROR_DNSCURVE, L"UDP get signature data request error", WSAGetLastError(), nullptr, 0);
			UDPSocket = socket(NetworkLayer, SOCK_DGRAM, IPPROTO_UDP);

		//Socket check
			if (UDPSocket == INVALID_SOCKET)
			{
				PrintError(LOG_ERROR_WINSOCK, L"DNSCurve UDP sockets initialization error", WSAGetLastError(), nullptr, 0);
				goto JumpToRestart;
			}

		//Set socket timeout.
			if (setsockopt(UDPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR || 
				setsockopt(UDPSocket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
			{
				PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket timeout error", WSAGetLastError(), nullptr, 0);
				closesocket(UDPSocket);

				goto JumpToRestart;
			}

		//Restart
			JumpToRestart: 
			memset(RecvBuffer.get(), 0, PACKET_MAXSIZE);
			Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
			continue;
		}
		else {
			RecvLen = recvfrom(UDPSocket, RecvBuffer.get(), PACKET_MAXSIZE, 0, (PSOCKADDR)SockAddr.get(), &AddrLen);
			if (RecvLen >= (SSIZE_T)(DNS_PACKET_MINSIZE + sizeof(dns_record_txt) + DNSCRYPT_TXT_RECORDS_LEN))
			{
			//Check Signature.
				if (PacketTarget == nullptr || 
					!GetSignatureData(RecvBuffer.get() + DNS_PACKET_RR_LOCATE(RecvBuffer.get()), ServerType) || 
					CheckEmptyBuffer(PacketTarget->ServerFingerprint, crypto_box_PUBLICKEYBYTES) || 
					CheckEmptyBuffer(PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					memset(RecvBuffer.get(), 0, PACKET_MAXSIZE);
					Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
					continue;
				}

				memset(RecvBuffer.get(), 0, PACKET_MAXSIZE);
			}
			else {
				memset(RecvBuffer.get(), 0, PACKET_MAXSIZE);
				if (LocalSignatureRequest(SendBuffer.get(), (int)DataLength, RecvBuffer.get(), PACKET_MAXSIZE) >= DNS_PACKET_MINSIZE + sizeof(dns_record_txt) + DNSCRYPT_TXT_RECORDS_LEN)
				{
				//Check Signature.
					if (PacketTarget != nullptr || 
						!GetSignatureData(RecvBuffer.get() + DNS_PACKET_RR_LOCATE(RecvBuffer.get()), ServerType) || 
						CheckEmptyBuffer(PacketTarget->ServerFingerprint, crypto_box_PUBLICKEYBYTES) || 
						CheckEmptyBuffer(PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
					{
						memset(RecvBuffer.get(), 0, PACKET_MAXSIZE);
						Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
						continue;
					}

					memset(RecvBuffer.get(), 0, PACKET_MAXSIZE);
				}
				else {
					memset(RecvBuffer.get(), 0, PACKET_MAXSIZE);
					Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
					continue;
				}
			}
		}

		Sleep((DWORD)DNSCurveParameter.KeyRecheckTime);
	}

	shutdown(UDPSocket, SD_BOTH);
	closesocket(UDPSocket);
	return true;
}

//Get Signature Data of server form packets
bool __fastcall GetSignatureData(const PSTR Buffer, const size_t ServerType)
{
	auto DNS_Record_TXT = (pdns_record_txt)Buffer;
	if (DNS_Record_TXT->Name == htons(DNS_QUERY_PTR) && 
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
				case DNSCURVE_ALTERNATEIPV6:
				{
					PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv6;
				}break;
				case DNSCURVE_MAINIPV6:
				{
					PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv6;
				}break;
				case DNSCURVE_ALTERNATEIPV4:
				{
					PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv4;
				}break;
				case DNSCURVE_MAINIPV4:
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
				if (ServerType == DNSCURVE_MAINIPV6)
					PrintError(LOG_ERROR_DNSCURVE, L"IPv6 Main Server Fingerprint signature validation error", 0, nullptr, 0);
				else if (ServerType == DNSCURVE_MAINIPV4)
					PrintError(LOG_ERROR_DNSCURVE, L"IPv4 Main Server Fingerprint signature validation error", 0, nullptr, 0);
				else if (ServerType == DNSCURVE_ALTERNATEIPV6)
					PrintError(LOG_ERROR_DNSCURVE, L"IPv6 Alternate Server Fingerprint signature validation error", 0, nullptr, 0);
				else if (ServerType == DNSCURVE_ALTERNATEIPV4)
					PrintError(LOG_ERROR_DNSCURVE, L"IPv4 Alternate Server Fingerprint signature validation error", 0, nullptr, 0);

				return false;
			}

			auto SignatureData = (pdnscurve_txt_signature)DeBuffer.get();
		//Check available(time) Signature.
			if (SignatureData != nullptr && PacketTarget->ServerFingerprint != nullptr && 
				time(nullptr) >= (time_t)ntohl(SignatureData->CertTime_Begin) && time(nullptr) <= (time_t)ntohl(SignatureData->CertTime_End))
			{
//				memcpy(PacketTarget->SendMagicNumber, SignatureData->MagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
				memcpy_s(PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, SignatureData->MagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
//				memcpy(PacketTarget->ServerFingerprint, SignatureData->PublicKey, crypto_box_PUBLICKEYBYTES);
				memcpy_s(PacketTarget->ServerFingerprint, crypto_box_PUBLICKEYBYTES, SignatureData->PublicKey, crypto_box_PUBLICKEYBYTES);
				crypto_box_curve25519xsalsa20poly1305_beforenm(
					PacketTarget->PrecomputationKey,
					PacketTarget->ServerFingerprint,
					DNSCurveParameter.Client_SecretKey);

				return true;
			}
			else {
				if (ServerType == DNSCURVE_MAINIPV6)
					PrintError(LOG_ERROR_DNSCURVE, L"IPv6 Main Server Fingerprint signature validation error", 0, nullptr, 0);
				else if (ServerType == DNSCURVE_MAINIPV4)
					PrintError(LOG_ERROR_DNSCURVE, L"IPv4 Main Server Fingerprint signature is not available", 0, nullptr, 0);
				else if (ServerType == DNSCURVE_ALTERNATEIPV6)
					PrintError(LOG_ERROR_DNSCURVE, L"IPv6 Alternate Server Fingerprint signature is not available", 0, nullptr, 0);
				else if (ServerType == DNSCURVE_ALTERNATEIPV4)
					PrintError(LOG_ERROR_DNSCURVE, L"IPv4 Alternate Server Fingerprint signature is not available", 0, nullptr, 0);
			}
		}
	}

	return false;
}

//Transmission of DNSCurve TCP protocol
size_t __fastcall DNSCurveTCPRequest(const PSTR OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize /* , const bool IsAlternate */ )
{
//Initialization
	std::shared_ptr<sockaddr_storage> SockAddr(new sockaddr_storage());
	memset(SockAddr.get(), 0, sizeof(sockaddr_storage));
	SYSTEM_SOCKET TCPSocket = 0;
	int AddrLen = 0;
	size_t ServerType = 0;

//Socket initialization
	bool *IsAlternate = nullptr;
	size_t *AlternateTimeoutTimes = nullptr;
	PDNSCURVE_SERVER_DATA PacketTarget = nullptr;
	if (Parameter.GatewayAvailable_IPv6 && DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family > 0) //IPv6
	{
		IsAlternate = &AlternateSwapList.IsSwap[8U];
		AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[8U];
		if (*IsAlternate && DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0)
		{
		//Encryption mode check
			if (DNSCurveParameter.IsEncryption && 
				(CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
				CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
					return EXIT_FAILURE;

			((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
			((PSOCKADDR_IN6)SockAddr.get())->sin6_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv6;
			ServerType = DNSCURVE_ALTERNATEIPV6;
		}
		else { //Main
		//Encryption mode check
			if (DNSCurveParameter.IsEncryption && 
				(CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
				CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
					return EXIT_FAILURE;

			((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_addr;
			((PSOCKADDR_IN6)SockAddr.get())->sin6_port = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_port;
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv6;
			ServerType = DNSCURVE_MAINIPV6;
		}

		AddrLen = sizeof(sockaddr_in6);
		SockAddr->ss_family = AF_INET6;
		TCPSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	}
	else if (Parameter.GatewayAvailable_IPv4 && DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family > 0) //IPv4
	{
		IsAlternate = &AlternateSwapList.IsSwap[9U];
		AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[9U];
		if (*IsAlternate && DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0)
		{
		//Encryption mode check
			if (DNSCurveParameter.IsEncryption && 
				(CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
				CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
					return EXIT_FAILURE;

			((PSOCKADDR_IN)SockAddr.get())->sin_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
			((PSOCKADDR_IN)SockAddr.get())->sin_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv4;
			ServerType = DNSCURVE_ALTERNATEIPV4;
		}
		else { //Main
		//Encryption mode check
			if (DNSCurveParameter.IsEncryption && 
				(CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
				CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
					return EXIT_FAILURE;

			((PSOCKADDR_IN)SockAddr.get())->sin_addr = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_addr;
			((PSOCKADDR_IN)SockAddr.get())->sin_port = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_port;
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv4;
			ServerType = DNSCURVE_MAINIPV4;
		}

		AddrLen = sizeof(sockaddr_in);
		SockAddr->ss_family = AF_INET;
		TCPSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	}
	else {
		return EXIT_FAILURE;
	}

//Socket check
	if (TCPSocket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_WINSOCK, L"DNSCurve TCP sockets initialization error", WSAGetLastError(), nullptr, 0);
		return EXIT_FAILURE;
	}

//Set Non-blocking Mode
	ULONG SocketMode = 1U;
	if (ioctlsocket(TCPSocket, FIONBIO, &SocketMode) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Set TCP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
		closesocket(TCPSocket);

		return EXIT_FAILURE;
	}

/* Old version(2015-01-14)
//Set socket timeout.
	if (setsockopt(TCPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.ReliableSocketTimeout, sizeof(int)) == SOCKET_ERROR || 
		setsockopt(TCPSocket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.ReliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Set TCP socket timeout error", WSAGetLastError(), nullptr, 0);
		closesocket(TCPSocket);

		return EXIT_FAILURE;
	}
*/

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
//		memcpy(Buffer.get() + crypto_box_ZEROBYTES, OriginalSend, SendSize);
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
			closesocket(TCPSocket);
			memset(OriginalRecv, 0, RecvSize);

			return EXIT_FAILURE;
		}

		Buffer.reset();
//		memcpy(OriginalRecv + sizeof(uint16_t), PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
		memcpy_s(OriginalRecv + sizeof(uint16_t), RecvSize - sizeof(uint16_t), PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
//		memcpy(OriginalRecv + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN, DNSCurveParameter.Client_PublicKey, crypto_box_PUBLICKEYBYTES);
		memcpy_s(OriginalRecv + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN, RecvSize - sizeof(uint16_t) - DNSCURVE_MAGIC_QUERY_LEN, DNSCurveParameter.Client_PublicKey, crypto_box_PUBLICKEYBYTES);
//		memcpy(OriginalRecv + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES, WholeNonce.get(), crypto_box_HALF_NONCEBYTES);
		memcpy_s(OriginalRecv + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES, RecvSize - sizeof(uint16_t) - DNSCURVE_MAGIC_QUERY_LEN - crypto_box_PUBLICKEYBYTES, WholeNonce.get(), crypto_box_HALF_NONCEBYTES);
		*(uint16_t *)OriginalRecv = htons((uint16_t)(DNSCurveParameter.DNSCurvePayloadSize - sizeof(uint16_t)));
		memset(WholeNonce.get(), 0, crypto_box_NONCEBYTES);
	}
//Normal mode
	else {
//		memcpy(OriginalRecv + sizeof(uint16_t), OriginalSend, SendSize);
		memcpy_s(OriginalRecv + sizeof(uint16_t), RecvSize - sizeof(uint16_t), OriginalSend, SendSize);
		auto BufferLength = (uint16_t *)OriginalRecv;
		*BufferLength = htons((uint16_t)SendSize);
		DataLength = sizeof(uint16_t) + SendSize;
	}

//Connect to server.
	if (connect(TCPSocket, (PSOCKADDR)SockAddr.get(), AddrLen) == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK)
	{
		if (IsAlternate != nullptr && !*IsAlternate && WSAGetLastError() == WSAETIMEDOUT)
		{
			closesocket(TCPSocket);
			if (AlternateTimeoutTimes != nullptr)
				(*AlternateTimeoutTimes)++;

			return WSAETIMEDOUT;
		}
		else {
			closesocket(TCPSocket);
			return EXIT_FAILURE;
		}
	}

/* Old version(2015-01-14)
//Receive result.
	SSIZE_T RecvLen = recv(TCPSocket, OriginalRecv, (int)RecvSize, 0);
	if (!IsAlternate && WSAGetLastError() == WSAETIMEDOUT)
	{
		closesocket(TCPSocket);
		return WSAETIMEDOUT;
	}

	//Encryption mode
	if (DNSCurveParameter.IsEncryption)
	{
		closesocket(TCPSocket);
		if (RecvLen >= (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES + DNS_PACKET_MINSIZE))
		{
			if (RecvLen >= (SSIZE_T)ntohs(((uint16_t *)OriginalRecv)[0]))
			{
				RecvLen = ntohs(((uint16_t *)OriginalRecv)[0]);
				memmove(OriginalRecv, OriginalRecv + sizeof(uint16_t), RecvLen);
			}
			else {
				memset(OriginalRecv, 0, RecvSize);
				return EXIT_FAILURE;
			}

		//Check receive magic number.
			PSTR ReceiveMagicNumber = nullptr;
			PUINT8 PrecomputationKey = nullptr;
			if (ServerType == DNSCURVE_ALTERNATEIPV6)
			{
				ReceiveMagicNumber = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ReceiveMagicNumber;
				PrecomputationKey = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey;
			}
			else if (ServerType == DNSCURVE_MAINIPV6)
			{
				ReceiveMagicNumber = DNSCurveParameter.DNSCurveTarget.IPv6.ReceiveMagicNumber;
				PrecomputationKey = DNSCurveParameter.DNSCurveTarget.IPv6.PrecomputationKey;
			}
			else if (ServerType == DNSCURVE_ALTERNATEIPV4)
			{
				ReceiveMagicNumber = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ReceiveMagicNumber;
				PrecomputationKey = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.PrecomputationKey;
			}
			else if (ServerType == DNSCURVE_MAINIPV4)
			{
				ReceiveMagicNumber = DNSCurveParameter.DNSCurveTarget.IPv4.ReceiveMagicNumber;
				PrecomputationKey = DNSCurveParameter.DNSCurveTarget.IPv4.PrecomputationKey;
			}
			if (memcmp(OriginalRecv, ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN) != 0)
			{
				memset(OriginalRecv, 0, RecvSize);
				return EXIT_FAILURE;
			}

		//Copy whole nonce.
			memcpy(WholeNonce.get(), OriginalRecv + DNSCURVE_MAGIC_QUERY_LEN, crypto_box_NONCEBYTES);

		//Open crypto box.
			memset(OriginalRecv, 0, DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);
			memmove(OriginalRecv + crypto_box_BOXZEROBYTES, OriginalRecv + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
			if (crypto_box_curve25519xsalsa20poly1305_open_afternm(
				(PUCHAR)OriginalRecv,
				(PUCHAR)OriginalRecv,
				RecvLen + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES),
				WholeNonce.get(),
				PrecomputationKey) != 0)
			{
				memset(OriginalRecv, 0, RecvSize);
				return EXIT_FAILURE;
			}
			memmove(OriginalRecv, OriginalRecv + crypto_box_ZEROBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
			memset(OriginalRecv + RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES), 0, RecvSize - (RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES)));
			for (SSIZE_T Index = RecvLen - (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);Index >= (SSIZE_T)DNS_PACKET_MINSIZE;Index--)
			{
				if ((UCHAR)OriginalRecv[Index] == 0x80)
				{
					RecvLen = Index;
					break;
				}
			}

		//Responses question and answers check
			if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckResponseData(OriginalRecv + sizeof(uint16_t), RecvLen, nullptr))
			{
				memset(OriginalRecv, 0, RecvSize);
				return EXIT_FAILURE;
			}

		//Mark DNS Cache.
			if (Parameter.CacheType > 0)
				MarkDomainCache(OriginalRecv, RecvLen);

			return RecvLen;
		}
	}
//Normal mode
	else {
		if (RecvLen > 0 && (SSIZE_T)htons(((uint16_t *)OriginalRecv)[0]) <= RecvLen)
		{
			if (htons(((uint16_t *)OriginalRecv)[0]) >= DNS_PACKET_MINSIZE)
			{
				closesocket(TCPSocket);
				RecvLen = htons(((uint16_t *)OriginalRecv)[0]);
				memmove(OriginalRecv, OriginalRecv + sizeof(uint16_t), RecvLen);

			//Responses question and answers check
				if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckResponseData(OriginalRecv, RecvLen, nullptr))
				{
					memset(OriginalRecv, 0, RecvSize);
					return EXIT_FAILURE;
				}

			//Mark DNS Cache.
				if (Parameter.CacheType > 0)
					MarkDomainCache(OriginalRecv, RecvLen);

				return RecvLen;
			}
			else { //TCP segment of a reassembled PDU or incorrect packets
				uint16_t PDULen = htons(((uint16_t *)OriginalRecv)[0]);
				memset(OriginalRecv, 0, RecvSize);
				RecvLen = recv(TCPSocket, OriginalRecv, (int)RecvSize, 0);
				if (PDULen >= DNS_PACKET_MINSIZE && PDULen <= RecvSize)
				{
					closesocket(TCPSocket);

				//Responses question and answers check
					if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckResponseData(OriginalRecv, RecvLen, nullptr))
					{
						memset(OriginalRecv, 0, RecvSize);
						return EXIT_FAILURE;
					}

				//Mark DNS Cache.
					if (Parameter.CacheType > 0)
						MarkDomainCache(OriginalRecv, RecvLen);

					return RecvLen;
				}
			}
		}
	}
*/

//Send request and receive result.
	std::shared_ptr<fd_set> ReadFDS(new fd_set()), WriteFDS(new fd_set());
	memset(ReadFDS.get(), 0, sizeof(fd_set));
	memset(WriteFDS.get(), 0, sizeof(fd_set));
	timeval Timeout = {0};
	FD_ZERO(WriteFDS.get());
	FD_SET(TCPSocket, WriteFDS.get());
	SSIZE_T SelectResult = 0, RecvLen = 0;
	uint16_t PDULen = 0;
	for (;;)
	{
		Sleep(LOOP_INTERVAL_TIME);

	//Reset parameters.
		Timeout.tv_sec = Parameter.ReliableSocketTimeout / SECOND_TO_MILLISECOND;
		Timeout.tv_usec = Parameter.ReliableSocketTimeout % SECOND_TO_MILLISECOND * SECOND_TO_MILLISECOND;
		FD_ZERO(ReadFDS.get());
		FD_SET(TCPSocket, ReadFDS.get());

	//Wait for system calling.
		SelectResult = select(0, ReadFDS.get(), WriteFDS.get(), nullptr, &Timeout);
		if (SelectResult > 0)
		{
		//Receive.
			if (FD_ISSET(TCPSocket, ReadFDS.get()))
			{
				RecvLen = recv(TCPSocket, OriginalRecv, (int)RecvSize, 0);

			//TCP segment of a reassembled PDU
				if (RecvLen > 0 && RecvLen < DNS_PACKET_MINSIZE)
				{
					if (htons(((uint16_t *)OriginalRecv)[0]) >= DNS_PACKET_MINSIZE)
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
					if ((SSIZE_T)PDULen > RecvLen)
					{
						break;
					}
				//Receive again.
					else if (PDULen > 0)
					{
						shutdown(TCPSocket, SD_BOTH);
						closesocket(TCPSocket);

					//Jump to normal receive process.
						if (PDULen >= DNS_PACKET_MINSIZE)
						{
							RecvLen = (SSIZE_T)PDULen;
							goto JumpFromPDU;
						}

						memset(OriginalRecv, 0, RecvSize);
						return EXIT_FAILURE;
					}
				//First receive.
					else {
					//Length check
						if ((SSIZE_T)ntohs(((uint16_t *)OriginalRecv)[0]) > RecvLen)
						{
							break;
						}
						else {
							shutdown(TCPSocket, SD_BOTH);
							closesocket(TCPSocket);

							RecvLen = (SSIZE_T)ntohs(((uint16_t *)OriginalRecv)[0]);
//							memmove(OriginalRecv, OriginalRecv + sizeof(uint16_t), RecvLen);
							memmove_s(OriginalRecv, RecvSize, OriginalRecv + sizeof(uint16_t), RecvLen);
							if (RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE)
							{
							//Encryption mode
								if (DNSCurveParameter.IsEncryption)
								{
									if (memcmp(OriginalRecv, PacketTarget->ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN) != 0)
									{
										memset(OriginalRecv, 0, RecvSize);
										return EXIT_FAILURE;
									}

								//Copy whole nonce.
//									memcpy(WholeNonce.get(), OriginalRecv + DNSCURVE_MAGIC_QUERY_LEN, crypto_box_NONCEBYTES);
									memcpy_s(WholeNonce.get(), crypto_box_NONCEBYTES, OriginalRecv + DNSCURVE_MAGIC_QUERY_LEN, crypto_box_NONCEBYTES);

								//Open crypto box.
									memset(OriginalRecv, 0, DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);
//									memmove(OriginalRecv + crypto_box_BOXZEROBYTES, OriginalRecv + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
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
//									memmove(OriginalRecv, OriginalRecv + crypto_box_ZEROBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
									memmove_s(OriginalRecv, RecvSize, OriginalRecv + crypto_box_ZEROBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
									memset(OriginalRecv + RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES), 0, RecvSize - (RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES)));
									for (SSIZE_T Index = RecvLen - (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);Index >= (SSIZE_T)DNS_PACKET_MINSIZE;Index--)
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
								if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckResponseData(OriginalRecv, RecvLen, false, nullptr))
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
			if (FD_ISSET(TCPSocket, WriteFDS.get()))
			{
				send(TCPSocket, OriginalRecv, (int)DataLength, 0);
				memset(OriginalRecv, 0, RecvSize);
				FD_ZERO(WriteFDS.get());
			}
		}
	//Timeout
		else if (SelectResult == 0)
		{
			shutdown(TCPSocket, SD_BOTH);
			closesocket(TCPSocket);
			memset(OriginalRecv, 0, RecvSize);
			if (AlternateTimeoutTimes != nullptr)
				(*AlternateTimeoutTimes)++;

			return WSAETIMEDOUT;
		}
	//SOCKET_ERROR
		else {
			break;
		}
	}

	shutdown(TCPSocket, SD_BOTH);
	closesocket(TCPSocket);
	memset(OriginalRecv, 0, RecvSize);
	return EXIT_FAILURE;
}

/* Old version(2015-01-13)
//Transmission of DNSCurve TCP protocol(Multithreading)
size_t __fastcall DNSCurveTCPRequestMulti(DNSCURVE_REQUEST_MULTITHREAD_PARAMETER &DNSCurveTCPRequestParameter, std::mutex &Mutex)
{
//Initialization
	std::shared_ptr<sockaddr_storage> SockAddr(new sockaddr_storage());
	SYSTEM_SOCKET TCPSocket = 0;
	int AddrLen = 0;

//Socket initialization
	if (DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family > 0 && //IPv6
		DNSCurveTCPRequestParameter.TargetData.AddrLen == sizeof(sockaddr_in6) || DNSCurveTCPRequestParameter.TargetData.AddrLen == sizeof(sockaddr_in) && DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family == 0)
	{
		if (DNSCurveTCPRequestParameter.Alternate && DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0)
		{
			if (DNSCurveTCPRequestParameter.Encryption)
			{
				if (!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) && 
					!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
					((PSOCKADDR_IN6)SockAddr.get())->sin6_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
			else {
				((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)SockAddr.get())->sin6_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
			}
		}
		else if (DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family > 0) //Main
		{
			if (DNSCurveTCPRequestParameter.Encryption)
			{
				if (!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) && 
					!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_addr;
					((PSOCKADDR_IN6)SockAddr.get())->sin6_port = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
			else {
				((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)SockAddr.get())->sin6_port = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_port;
			}
		}
		else {
			return EXIT_FAILURE;
		}

		SockAddr->ss_family = AF_INET6;
		TCPSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
		AddrLen = sizeof(sockaddr_in6);
	}
	else if (DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0) //IPv4
	{
		if (DNSCurveTCPRequestParameter.Alternate && DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0)
		{
		//Encryption mode
			if (DNSCurveTCPRequestParameter.Encryption)
			{
				if (!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) && 
					!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					((PSOCKADDR_IN)SockAddr.get())->sin_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
					((PSOCKADDR_IN)SockAddr.get())->sin_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
		//Normal mode
			else {
				((PSOCKADDR_IN)SockAddr.get())->sin_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)SockAddr.get())->sin_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
			}
		}
		else if (DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family > 0) //Main
		{
		//Encryption mode
			if (DNSCurveTCPRequestParameter.Encryption)
			{
				if (!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) && 
					!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					((PSOCKADDR_IN)SockAddr.get())->sin_addr = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_addr;
					((PSOCKADDR_IN)SockAddr.get())->sin_port = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
		//Normal mode
			else {
				((PSOCKADDR_IN)SockAddr.get())->sin_addr = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)SockAddr.get())->sin_port = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_port;
			}
		}
		else {
			return EXIT_FAILURE;
		}

		SockAddr->ss_family = AF_INET;
		TCPSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		AddrLen = sizeof(sockaddr_in);
	}
	else {
		return EXIT_FAILURE;
	}

//Socket check
	if (TCPSocket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_WINSOCK, L"DNSCurve sockets initialization error", WSAGetLastError(), nullptr, 0);
		return EXIT_FAILURE;
	}

//Set socket timeout.
	if (setsockopt(TCPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.ReliableSocketTimeout, sizeof(int)) == SOCKET_ERROR || 
		setsockopt(TCPSocket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.ReliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket timeout error", WSAGetLastError(), nullptr, 0);
		closesocket(TCPSocket);

		return EXIT_FAILURE;
	}

	std::shared_ptr<char> RecvBuffer(new char[DNSCurveTCPRequestParameter.RecvSize]());
//Encryption mode
	std::shared_ptr<uint8_t> WholeNonce;
	if (DNSCurveTCPRequestParameter.Encryption)
	{
	//Make nonce.
		std::shared_ptr<uint8_t> WholeNonceTemp(new uint8_t[crypto_box_NONCEBYTES]());
		WholeNonce.swap(WholeNonceTemp);
		WholeNonceTemp.reset();
		*(uint32_t *)WholeNonce.get() = randombytes_random();
		*(uint32_t *)(WholeNonce.get() + sizeof(uint32_t)) = randombytes_random();
		*(uint32_t *)(WholeNonce.get() + sizeof(uint32_t) * 2U) = randombytes_random();
		memset(WholeNonce.get() + crypto_box_HALF_NONCEBYTES, 0, crypto_box_HALF_NONCEBYTES);

	//Make a crypto box.
		std::shared_ptr<char> Buffer(new char[DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES)]());
		memcpy(Buffer.get() + crypto_box_ZEROBYTES, DNSCurveTCPRequestParameter.Send, DNSCurveTCPRequestParameter.SendSize);
		Buffer.get()[crypto_box_ZEROBYTES + DNSCurveTCPRequestParameter.SendSize] = '\x80';

		if (AddrLen == sizeof(sockaddr_in6)) //IPv6
		{
			if (DNSCurveTCPRequestParameter.Alternate)
			{
				if (crypto_box_curve25519xsalsa20poly1305_afternm(
						(PUCHAR)RecvBuffer.get() + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES - crypto_box_BOXZEROBYTES, 
						(PUCHAR)Buffer.get(), 
						DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES), 
						WholeNonce.get(), 
						DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey) != 0)
				{
					closesocket(TCPSocket);
					return EXIT_FAILURE;
				}

			//Packet(A part)
				memcpy(RecvBuffer.get() + sizeof(uint16_t), DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
			}
			else { //Main
				if (crypto_box_curve25519xsalsa20poly1305_afternm(
						(PUCHAR)RecvBuffer.get() + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES - crypto_box_BOXZEROBYTES, 
						(PUCHAR)Buffer.get(), 
						DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES), 
						WholeNonce.get(), 
						DNSCurveParameter.DNSCurveTarget.IPv6.PrecomputationKey) != 0)
				{
					closesocket(TCPSocket);
					return EXIT_FAILURE;
				}

			//Packet(A part)
				memcpy(RecvBuffer.get() + sizeof(uint16_t), DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
			}
		}
		else { //IPv4
			if (DNSCurveTCPRequestParameter.Alternate)
			{
				if (crypto_box_curve25519xsalsa20poly1305_afternm(
						(PUCHAR)RecvBuffer.get() + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES - crypto_box_BOXZEROBYTES, 
						(PUCHAR)Buffer.get(), 
						DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES), 
						WholeNonce.get(), 
						DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.PrecomputationKey) != 0)
				{
					closesocket(TCPSocket);
					return EXIT_FAILURE;
				}

			//Packet(A part)
				memcpy(RecvBuffer.get() + sizeof(uint16_t), DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
			}
			else { //Main
				if (crypto_box_curve25519xsalsa20poly1305_afternm(
						(PUCHAR)RecvBuffer.get() + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES - crypto_box_BOXZEROBYTES, 
						(PUCHAR)Buffer.get(), 
						DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES), 
						WholeNonce.get(), 
						DNSCurveParameter.DNSCurveTarget.IPv4.PrecomputationKey) != 0)
				{
					closesocket(TCPSocket);
					return EXIT_FAILURE;
				}

			//Packet(A part)
				memcpy(RecvBuffer.get() + sizeof(uint16_t), DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
			}
		}

		//Packet(B part)
		Buffer.reset();
		memcpy(RecvBuffer.get() + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN, DNSCurveParameter.Client_PublicKey, crypto_box_PUBLICKEYBYTES);
		memcpy(RecvBuffer.get() + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES, WholeNonce.get(), crypto_box_HALF_NONCEBYTES);
		*(uint16_t *)RecvBuffer.get() = htons((uint16_t)(DNSCurveParameter.DNSCurvePayloadSize - sizeof(uint16_t)));
		memset(WholeNonce.get(), 0, crypto_box_NONCEBYTES);

	//Connect to server.
		if (connect(TCPSocket, (PSOCKADDR)SockAddr.get(), AddrLen) == SOCKET_ERROR) //Connection is RESET or other errors when connecting.
		{
			if (!DNSCurveTCPRequestParameter.Alternate && WSAGetLastError() == WSAETIMEDOUT)
			{
				closesocket(TCPSocket);

				std::unique_lock<std::mutex> DNSCurveMutex(Mutex);
				DNSCurveTCPRequestParameter.ReturnValue = WSAETIMEDOUT;
				return WSAETIMEDOUT;
			}
			else {
				closesocket(TCPSocket);
				return EXIT_FAILURE;
			}
		}

	//Send requesting.
		if (send(TCPSocket, RecvBuffer.get(), (int)DNSCurveParameter.DNSCurvePayloadSize, 0) == SOCKET_ERROR)
		{
			PrintError(LOG_ERROR_WINSOCK, L"DNSCurve TCP request error", WSAGetLastError(), nullptr, 0);
			closesocket(TCPSocket);

			if (!DNSCurveTCPRequestParameter.Alternate && WSAGetLastError() == WSAETIMEDOUT)
			{
				std::unique_lock<std::mutex> DNSCurveMutex(Mutex);
				DNSCurveTCPRequestParameter.ReturnValue = WSAETIMEDOUT;
				return WSAETIMEDOUT;
			}
			else {
				return EXIT_FAILURE;
			}
		}

		memset(RecvBuffer.get(), 0, DNSCurveTCPRequestParameter.RecvSize);
	}
//Normal mode
	else {
		std::shared_ptr<char> Buffer(new char[sizeof(uint16_t) + DNSCurveTCPRequestParameter.SendSize]());
		memcpy(Buffer.get() + sizeof(uint16_t), DNSCurveTCPRequestParameter.Send, DNSCurveTCPRequestParameter.SendSize);
		auto BufferLength = (uint16_t *)Buffer.get();
		*BufferLength = htons((uint16_t)DNSCurveTCPRequestParameter.SendSize);

	//Connect to server.
		if (connect(TCPSocket, (PSOCKADDR)SockAddr.get(), AddrLen) == SOCKET_ERROR) //Connection is RESET or other errors when connecting.
		{
			if (!DNSCurveTCPRequestParameter.Alternate && WSAGetLastError() == WSAETIMEDOUT)
			{
				closesocket(TCPSocket);

				std::unique_lock<std::mutex> DNSCurveMutex(Mutex);
				DNSCurveTCPRequestParameter.ReturnValue = WSAETIMEDOUT;
				return WSAETIMEDOUT;
			}
			else {
				closesocket(TCPSocket);
				return EXIT_FAILURE;
			}
		}

	//Send requesting.
		if (send(TCPSocket, Buffer.get(), (int)(sizeof(uint16_t) + DNSCurveTCPRequestParameter.SendSize), 0) == SOCKET_ERROR)
		{
			PrintError(LOG_ERROR_WINSOCK, L"DNSCurve TCP request error", WSAGetLastError(), nullptr, 0);
			if (!DNSCurveTCPRequestParameter.Alternate && WSAGetLastError() == WSAETIMEDOUT)
			{
				closesocket(TCPSocket);

				std::unique_lock<std::mutex> DNSCurveMutex(Mutex);
				DNSCurveTCPRequestParameter.ReturnValue = WSAETIMEDOUT;
				return WSAETIMEDOUT;
			}
			else {
				closesocket(TCPSocket);
				return EXIT_FAILURE;
			}
		}
	}

//Receive result.
	SSIZE_T RecvLen = recv(TCPSocket, RecvBuffer.get(), (int)DNSCurveTCPRequestParameter.RecvSize, 0);
	if (!DNSCurveTCPRequestParameter.Alternate && WSAGetLastError() == WSAETIMEDOUT)
	{
		closesocket(TCPSocket);

		std::unique_lock<std::mutex> DNSCurveMutex(Mutex);
		DNSCurveTCPRequestParameter.ReturnValue = WSAETIMEDOUT;
		return WSAETIMEDOUT;
	}

	//Encryption mode
	if (DNSCurveTCPRequestParameter.Encryption)
	{
		closesocket(TCPSocket);
		if (RecvLen >= (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES + DNS_PACKET_MINSIZE))
		{
			if (RecvLen >= (SSIZE_T)ntohs(((uint16_t *)RecvBuffer.get())[0]))
			{
				RecvLen = ntohs(((uint16_t *)RecvBuffer.get())[0]);
				memmove(RecvBuffer.get(), RecvBuffer.get() + sizeof(uint16_t), RecvLen);
				memset(RecvBuffer.get() + RecvLen, 0, DNSCurveTCPRequestParameter.RecvSize - RecvLen);
			}
			else {
				return EXIT_FAILURE;
			}

		//Check receive magic number.
			if (AddrLen == sizeof(sockaddr_in6)) //IPv6
			{
				if (DNSCurveTCPRequestParameter.Alternate)
				{
					if (memcmp(RecvBuffer.get(), DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN) != 0)
						return EXIT_FAILURE;

				//Copy whole nonce.
					memcpy(WholeNonce.get(), RecvBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN, crypto_box_NONCEBYTES);

				//Open crypto box.
					memset(RecvBuffer.get(), 0, DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);
					memmove(RecvBuffer.get() + crypto_box_BOXZEROBYTES, RecvBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
					if (crypto_box_curve25519xsalsa20poly1305_open_afternm(
							(PUCHAR)RecvBuffer.get(), 
							(PUCHAR)RecvBuffer.get(), 
							RecvLen + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES), 
							WholeNonce.get(), 
							DNSCurveParameter.DNSCurveTarget.IPv6.PrecomputationKey) != 0)
						return EXIT_FAILURE;
					memmove(RecvBuffer.get(), RecvBuffer.get() + crypto_box_ZEROBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
					for (SSIZE_T Index = RecvLen - (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);Index >= (SSIZE_T)DNS_PACKET_MINSIZE;Index--)
					{
						if ((UCHAR)RecvBuffer.get()[Index] == 0x80)
						{
							RecvLen = Index;
							break;
						}
					}

				//Responses question and answers check
					if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckResponseData(RecvBuffer.get(), RecvLen, nullptr))
						return EXIT_FAILURE;

				//Send back.
					std::unique_lock<std::mutex> DNSCurveMutex(Mutex);
					if (CheckEmptyBuffer(DNSCurveTCPRequestParameter.Recv, DNSCurveTCPRequestParameter.RecvSize) && (DNSCurveTCPRequestParameter.ReturnValue == 0 || DNSCurveTCPRequestParameter.ReturnValue == WSAETIMEDOUT))
					{
						memcpy(DNSCurveTCPRequestParameter.Recv, RecvBuffer.get(), RecvLen);
						DNSCurveTCPRequestParameter.ReturnValue = RecvLen;
						DNSCurveMutex.unlock();

					//Mark DNS Cache.
						if (Parameter.CacheType > 0)
							MarkDomainCache(RecvBuffer.get(), RecvLen);

						return RecvLen;
					}
					else {
						return EXIT_SUCCESS;
					}
				}
				else { //Main
					if (memcmp(RecvBuffer.get(), DNSCurveParameter.DNSCurveTarget.IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN) != 0)
						return EXIT_FAILURE;

				//Copy whole nonce.
					memcpy(WholeNonce.get(), RecvBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN, crypto_box_NONCEBYTES);

				//Open crypto box.
					memset(RecvBuffer.get(), 0, DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);
					memmove(RecvBuffer.get() + crypto_box_BOXZEROBYTES, RecvBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
					if (crypto_box_curve25519xsalsa20poly1305_open_afternm(
							(PUCHAR)RecvBuffer.get(), 
							(PUCHAR)RecvBuffer.get(), 
							RecvLen + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES), 
							WholeNonce.get(), 
							DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey) != 0)
						return EXIT_FAILURE;
					memmove(RecvBuffer.get(), RecvBuffer.get() + crypto_box_ZEROBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
					for (SSIZE_T Index = RecvLen - (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);Index >= (SSIZE_T)DNS_PACKET_MINSIZE;Index--)
					{
						if ((UCHAR)RecvBuffer.get()[Index] == 0x80)
						{
							RecvLen = Index;
							break;
						}
					}

				//Responses question and answers check
					if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckResponseData(RecvBuffer.get(), RecvLen, nullptr))
						return EXIT_FAILURE;

				//Send back.
					std::unique_lock<std::mutex> DNSCurveMutex(Mutex);
					if (CheckEmptyBuffer(DNSCurveTCPRequestParameter.Recv, DNSCurveTCPRequestParameter.RecvSize) && (DNSCurveTCPRequestParameter.ReturnValue == 0 || DNSCurveTCPRequestParameter.ReturnValue == WSAETIMEDOUT))
					{
						memcpy(DNSCurveTCPRequestParameter.Recv, RecvBuffer.get(), RecvLen);
						DNSCurveTCPRequestParameter.ReturnValue = RecvLen;
						DNSCurveMutex.unlock();

					//Mark DNS Cache.
						if (Parameter.CacheType > 0)
							MarkDomainCache(RecvBuffer.get(), RecvLen);

						return RecvLen;
					}
					else {
						return EXIT_SUCCESS;
					}
				}
			}
			else { //IPv4
				if (DNSCurveTCPRequestParameter.Alternate)
				{
					if (memcmp(RecvBuffer.get(), DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN) != 0)
						return EXIT_FAILURE;

				//Copy whole nonce.
					memcpy(WholeNonce.get(), RecvBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN, crypto_box_NONCEBYTES);

				//Open crypto box.
					memset(RecvBuffer.get(), 0, DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);
					memmove(RecvBuffer.get() + crypto_box_BOXZEROBYTES, RecvBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
					if (crypto_box_curve25519xsalsa20poly1305_open_afternm(
							(PUCHAR)RecvBuffer.get(), 
							(PUCHAR)RecvBuffer.get(), 
							RecvLen + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES), 
							WholeNonce.get(), 
							DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.PrecomputationKey) != 0)
						return EXIT_FAILURE;
					memmove(RecvBuffer.get(), RecvBuffer.get() + crypto_box_ZEROBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
					for (SSIZE_T Index = RecvLen - (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);Index >= (SSIZE_T)DNS_PACKET_MINSIZE;Index--)
					{
						if ((UCHAR)RecvBuffer.get()[Index] == 0x80)
						{
							RecvLen = Index;
							break;
						}
					}

				//Responses question and answers check
					if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckResponseData(RecvBuffer.get(), RecvLen, nullptr))
						return EXIT_FAILURE;

				//Send back.
					std::unique_lock<std::mutex> DNSCurveMutex(Mutex);
					if (CheckEmptyBuffer(DNSCurveTCPRequestParameter.Recv, DNSCurveTCPRequestParameter.RecvSize) && (DNSCurveTCPRequestParameter.ReturnValue == 0 || DNSCurveTCPRequestParameter.ReturnValue == WSAETIMEDOUT))
					{
						memcpy(DNSCurveTCPRequestParameter.Recv, RecvBuffer.get(), RecvLen);
						DNSCurveTCPRequestParameter.ReturnValue = RecvLen;
						DNSCurveMutex.unlock();

					//Mark DNS Cache.
						if (Parameter.CacheType > 0)
							MarkDomainCache(RecvBuffer.get(), RecvLen);

						return RecvLen;
					}
					else {
						return EXIT_SUCCESS;
					}
				}
				else { //Main
					if (memcmp(RecvBuffer.get(), DNSCurveParameter.DNSCurveTarget.IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN) != 0)
						return EXIT_FAILURE;

				//Copy whole nonce.
					memcpy(WholeNonce.get(), RecvBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN, crypto_box_NONCEBYTES);

				//Open crypto box.
					memset(RecvBuffer.get(), 0, DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);
					memmove(RecvBuffer.get() + crypto_box_BOXZEROBYTES, RecvBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
					if (crypto_box_curve25519xsalsa20poly1305_open_afternm(
							(PUCHAR)RecvBuffer.get(), 
							(PUCHAR)RecvBuffer.get(), 
							RecvLen + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES), 
							WholeNonce.get(), 
							DNSCurveParameter.DNSCurveTarget.IPv4.PrecomputationKey) != 0)
						return EXIT_FAILURE;
					memmove(RecvBuffer.get(), RecvBuffer.get() + crypto_box_ZEROBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
					for (SSIZE_T Index = RecvLen - (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);Index >= (SSIZE_T)DNS_PACKET_MINSIZE;Index--)
					{
						if ((UCHAR)RecvBuffer.get()[Index] == 0x80)
						{
							RecvLen = Index;
							break;
						}
					}

				//Responses question and answers check
					if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckResponseData(RecvBuffer.get(), RecvLen, nullptr))
						return EXIT_FAILURE;

				//Send back.
					std::unique_lock<std::mutex> DNSCurveMutex(Mutex);
					if (CheckEmptyBuffer(DNSCurveTCPRequestParameter.Recv, DNSCurveTCPRequestParameter.RecvSize) && (DNSCurveTCPRequestParameter.ReturnValue == 0 || DNSCurveTCPRequestParameter.ReturnValue == WSAETIMEDOUT))
					{
						memcpy(DNSCurveTCPRequestParameter.Recv, RecvBuffer.get(), RecvLen);
						DNSCurveTCPRequestParameter.ReturnValue = RecvLen;
						DNSCurveMutex.unlock();

					//Mark DNS Cache.
						if (Parameter.CacheType > 0)
							MarkDomainCache(RecvBuffer.get(), RecvLen);

						return RecvLen;
					}
					else {
						return EXIT_SUCCESS;
					}
				}
			}
		}
	}
//Normal mode
	else {
		if (RecvLen > 0 && (SSIZE_T)htons(((uint16_t *)RecvBuffer.get())[0]) <= RecvLen)
		{
			if (htons(((uint16_t *)RecvBuffer.get())[0]) >= DNS_PACKET_MINSIZE)
			{
				closesocket(TCPSocket);
				RecvLen = htons(((uint16_t *)RecvBuffer.get())[0]);

			//Responses question and answers check
				if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckResponseData(RecvBuffer.get(), RecvLen, nullptr))
					return EXIT_FAILURE;

			//Send back.
				std::unique_lock<std::mutex> DNSCurveMutex(Mutex);
				if (CheckEmptyBuffer(DNSCurveTCPRequestParameter.Recv, DNSCurveTCPRequestParameter.RecvSize) && (DNSCurveTCPRequestParameter.ReturnValue == 0 || DNSCurveTCPRequestParameter.ReturnValue == WSAETIMEDOUT))
				{
					memcpy(DNSCurveTCPRequestParameter.Recv, RecvBuffer.get(), RecvLen);
					DNSCurveTCPRequestParameter.ReturnValue = RecvLen;
					DNSCurveMutex.unlock();

				//Mark DNS Cache.
					if (Parameter.CacheType > 0)
						MarkDomainCache(RecvBuffer.get(), RecvLen);

					return RecvLen;
				}
				else {
					return EXIT_SUCCESS;
				}
			}
			else { //TCP segment of a reassembled PDU or incorrect packets
				uint16_t PDULen = htons(((uint16_t *)RecvBuffer.get())[0]);
				memset(RecvBuffer.get(), 0, DNSCurveTCPRequestParameter.RecvSize);
				RecvLen = recv(TCPSocket, RecvBuffer.get(), (int)DNSCurveTCPRequestParameter.RecvSize, 0);
				if (PDULen >= DNS_PACKET_MINSIZE && PDULen <= DNSCurveTCPRequestParameter.RecvSize)
				{
					closesocket(TCPSocket);

				//Responses question and answers check
					if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckResponseData(RecvBuffer.get(), RecvLen, nullptr))
						return EXIT_FAILURE;

				//Send back.
					std::unique_lock<std::mutex> DNSCurveMutex(Mutex);
					if (CheckEmptyBuffer(DNSCurveTCPRequestParameter.Recv, DNSCurveTCPRequestParameter.RecvSize) && (DNSCurveTCPRequestParameter.ReturnValue == 0 || DNSCurveTCPRequestParameter.ReturnValue == WSAETIMEDOUT))
					{
						memcpy(DNSCurveTCPRequestParameter.Recv, RecvBuffer.get(), RecvLen);
						DNSCurveTCPRequestParameter.ReturnValue = RecvLen;
						DNSCurveMutex.unlock();

					//Mark DNS Cache.
						if (Parameter.CacheType > 0)
							MarkDomainCache(RecvBuffer.get(), RecvLen);

						return RecvLen;
					}
					else {
						return EXIT_SUCCESS;
					}
				}
			}
		}
	}

	closesocket(TCPSocket);
	return EXIT_FAILURE;
}
*/

//Transmission of DNSCurve TCP protocol(Multithreading)
size_t __fastcall DNSCurveTCPRequestMulti(const PSTR OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize /* , const bool IsAlternate */ )
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
//		memcpy(SendBuffer.get(), OriginalSend, SendSize);
		memcpy_s(SendBuffer.get(), sizeof(uint16_t) + SendSize, OriginalSend, SendSize);

	//Add length of request packet(It must be written in header when transpot with TCP protocol).
		DataLength = AddLengthToTCPDNSHeader(SendBuffer.get(), SendSize, sizeof(uint16_t) + SendSize);
		if (DataLength == EXIT_FAILURE)
			return EXIT_FAILURE;
	}

//Socket initialization
	auto IsIPv6 = false;
	auto IsAlternate = false;
	if (Parameter.GatewayAvailable_IPv6 && DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family > 0) //IPv6
	{
/* Old version(2015-02-26)
	{
		std::shared_ptr<SOCKET_DATA> TCPSocketData(new SOCKET_DATA());
		ULONG SocketMode = 1U;

	//Main
		if (!IsAlternate)
		{
		//Encryption mode check
			if (DNSCurveParameter.IsEncryption && 
				(CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
				CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
					return EXIT_FAILURE;

			for (size_t Index = 0;Index < Parameter.MultiRequestTimes;Index++)
			{
				TCPSocketData->SockAddr = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage;
				TCPSocketData->Socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
			//Socket check
				if (TCPSocketData->Socket == INVALID_SOCKET)
				{
					PrintError(LOG_ERROR_WINSOCK, L"DNSCurve TCP request initialization error", WSAGetLastError(), nullptr, 0);
					return EXIT_FAILURE;
				}
			//Set Non-blocking Mode
				else if (ioctlsocket(TCPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
				{
					PrintError(LOG_ERROR_WINSOCK, L"Set TCP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
					closesocket(TCPSocketData->Socket);

					return EXIT_FAILURE;
				}

				TCPSocketData->AddrLen = sizeof(sockaddr_in6);
				TCPSocketDataList.push_back(*TCPSocketData);
				memset(TCPSocketData.get(), 0, sizeof(SOCKET_DATA));
			}
			ServerTypeList.push_back(DNSCURVE_MAINIPV6);

		//Encryption mode
			if (DNSCurveParameter.IsEncryption)
			{
				std::shared_ptr<char> SendBufferTemp(new char[RecvSize]());
				SendBuffer.swap(SendBufferTemp);
				SendBufferTemp.reset();
				std::shared_ptr<uint8_t> WholeNonceTemp(new uint8_t[crypto_box_NONCEBYTES]());
				WholeNonce.swap(WholeNonceTemp);
				WholeNonceTemp.reset();

			//Make nonce.
				*(uint32_t *)WholeNonce.get() = randombytes_random();
				*(uint32_t *)(WholeNonce.get() + sizeof(uint32_t)) = randombytes_random();
				*(uint32_t *)(WholeNonce.get() + sizeof(uint32_t) * 2U) = randombytes_random();
				memset(WholeNonce.get() + crypto_box_HALF_NONCEBYTES, 0, crypto_box_HALF_NONCEBYTES);

			//Make a crypto box.
				std::shared_ptr<char> Buffer(new char[DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES)]());
//				memcpy(Buffer.get() + crypto_box_ZEROBYTES, OriginalSend, SendSize);
				memcpy_s(Buffer.get() + crypto_box_ZEROBYTES, DNSCurveParameter.DNSCurvePayloadSize, OriginalSend, SendSize);
				Buffer.get()[crypto_box_ZEROBYTES + SendSize] = '\x80';

				if (crypto_box_curve25519xsalsa20poly1305_afternm(
					(PUCHAR)SendBuffer.get() + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES - crypto_box_BOXZEROBYTES,
					(PUCHAR)Buffer.get(), 
					DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES),
					WholeNonce.get(), 
					DNSCurveParameter.DNSCurveTarget.IPv6.PrecomputationKey) != 0)
				{
					for (auto SocketDataIter:TCPSocketDataList)
						closesocket(SocketDataIter.Socket);
					return EXIT_FAILURE;
				}

				Buffer.reset();
//				memcpy(SendBuffer.get() + sizeof(uint16_t), DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
				memcpy_s(SendBuffer.get() + sizeof(uint16_t), RecvSize - sizeof(uint16_t), DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
//				memcpy(SendBuffer.get() + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN, DNSCurveParameter.Client_PublicKey, crypto_box_PUBLICKEYBYTES);
				memcpy_s(SendBuffer.get() + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN, RecvSize - sizeof(uint16_t) - DNSCURVE_MAGIC_QUERY_LEN, DNSCurveParameter.Client_PublicKey, crypto_box_PUBLICKEYBYTES);
//				memcpy(SendBuffer.get() + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES, WholeNonce.get(), crypto_box_HALF_NONCEBYTES);
				memcpy_s(SendBuffer.get() + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES, RecvSize - sizeof(uint16_t) - DNSCURVE_MAGIC_QUERY_LEN - crypto_box_PUBLICKEYBYTES, WholeNonce.get(), crypto_box_HALF_NONCEBYTES);
				*(uint16_t *)SendBuffer.get() = htons((uint16_t)(DNSCurveParameter.DNSCurvePayloadSize - sizeof(uint16_t)));
				memset(WholeNonce.get(), 0, crypto_box_NONCEBYTES);
			}
		}

	//Alternate
		if (DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && (IsAlternate || Parameter.AlternateMultiRequest))
		{
		//Encryption mode check
			if (DNSCurveParameter.IsEncryption && 
				(CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
				CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
					return EXIT_FAILURE;

			for (size_t Index = 0;Index < Parameter.MultiRequestTimes;Index++)
			{
				TCPSocketData->SockAddr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage;
				TCPSocketData->Socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
			//Socket check
				if (TCPSocketData->Socket == INVALID_SOCKET)
				{
					PrintError(LOG_ERROR_WINSOCK, L"DNSCurve TCP request initialization error", WSAGetLastError(), nullptr, 0);
					return EXIT_FAILURE;
				}
			//Set Non-blocking Mode
				else if (ioctlsocket(TCPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
				{
					PrintError(LOG_ERROR_WINSOCK, L"Set TCP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
					closesocket(TCPSocketData->Socket);

					return EXIT_FAILURE;
				}

				TCPSocketData->AddrLen = sizeof(sockaddr_in6);
				TCPSocketDataList.push_back(*TCPSocketData);
				memset(TCPSocketData.get(), 0, sizeof(SOCKET_DATA));
			}
			ServerTypeList.push_back(DNSCURVE_ALTERNATEIPV6);

		//Encryption mode
			if (DNSCurveParameter.IsEncryption)
			{
				std::shared_ptr<char> SendBufferTemp(new char[RecvSize]());
				SendBuffer.swap(SendBufferTemp);
				SendBufferTemp.reset();
				std::shared_ptr<uint8_t> WholeNonceTemp(new uint8_t[crypto_box_NONCEBYTES]());
				WholeNonce.swap(WholeNonceTemp);
				WholeNonceTemp.reset();

			//Make nonce.
				*(uint32_t *)WholeNonce.get() = randombytes_random();
				*(uint32_t *)(WholeNonce.get() + sizeof(uint32_t)) = randombytes_random();
				*(uint32_t *)(WholeNonce.get() + sizeof(uint32_t) * 2U) = randombytes_random();
				memset(WholeNonce.get() + crypto_box_HALF_NONCEBYTES, 0, crypto_box_HALF_NONCEBYTES);

			//Make a crypto box.
				std::shared_ptr<char> Buffer(new char[DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES)]());
//				memcpy(Buffer.get() + crypto_box_ZEROBYTES, OriginalSend, SendSize);
				memcpy_s(Buffer.get() + crypto_box_ZEROBYTES, DNSCurveParameter.DNSCurvePayloadSize - crypto_box_ZEROBYTES, OriginalSend, SendSize);
				Buffer.get()[crypto_box_ZEROBYTES + SendSize] = '\x80';

				if (crypto_box_curve25519xsalsa20poly1305_afternm(
					(PUCHAR)SendBuffer.get() + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES - crypto_box_BOXZEROBYTES,
					(PUCHAR)Buffer.get(), 
					DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES),
					WholeNonce.get(), 
					DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey) != 0)
				{
					for (auto SocketDataIter:TCPSocketDataList)
						closesocket(SocketDataIter.Socket);
					return EXIT_FAILURE;
				}

				Buffer.reset();
//				memcpy(SendBuffer.get() + sizeof(uint16_t), DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
				memcpy_s(SendBuffer.get() + sizeof(uint16_t), RecvSize - sizeof(uint16_t), DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
//				memcpy(SendBuffer.get() + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN, DNSCurveParameter.Client_PublicKey, crypto_box_PUBLICKEYBYTES);
				memcpy_s(SendBuffer.get() + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN, RecvSize - sizeof(uint16_t) - DNSCURVE_MAGIC_QUERY_LEN, DNSCurveParameter.Client_PublicKey, crypto_box_PUBLICKEYBYTES);
//				memcpy(SendBuffer.get() + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES, WholeNonce.get(), crypto_box_HALF_NONCEBYTES);
				memcpy_s(SendBuffer.get() + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES, RecvSize - sizeof(uint16_t) - DNSCURVE_MAGIC_QUERY_LEN - crypto_box_PUBLICKEYBYTES, WholeNonce.get(), crypto_box_HALF_NONCEBYTES);
				*(uint16_t *)SendBuffer.get() = htons((uint16_t)(DNSCurveParameter.DNSCurvePayloadSize - sizeof(uint16_t)));
				memset(WholeNonce.get(), 0, crypto_box_NONCEBYTES);
			}
		}
	}
*/
		IsIPv6 = true;
		IsAlternate = AlternateSwapList.IsSwap[8U];
	}
	else if (Parameter.GatewayAvailable_IPv4 && DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family > 0) //IPv4
	{
		IsIPv6 = false;
		IsAlternate = AlternateSwapList.IsSwap[9U];
	}
	else {
		return EXIT_FAILURE;
	}

	std::shared_ptr<SOCKET_DATA> TCPSocketData(new SOCKET_DATA());
	memset(TCPSocketData.get(), 0, sizeof(SOCKET_DATA));
	PDNSCURVE_SERVER_DATA PacketTarget = nullptr;
	ULONG SocketMode = 1U;

	//Main
	if (!IsAlternate)
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
				return EXIT_FAILURE;

		for (size_t Index = 0;Index < Parameter.MultiRequestTimes;Index++)
		{
			TCPSocketData->SockAddr = PacketTarget->AddressData.Storage;
			if (IsIPv6) //IPv6
				TCPSocketData->Socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
			else //IPv4
				TCPSocketData->Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

		//Socket check
			if (TCPSocketData->Socket == INVALID_SOCKET)
			{
				PrintError(LOG_ERROR_WINSOCK, L"DNSCurve TCP request initialization error", WSAGetLastError(), nullptr, 0);
				for (auto SocketDataIter:TCPSocketDataList)
					closesocket(SocketDataIter.Socket);

				return EXIT_FAILURE;
			}

		//Set Non-blocking Mode
			else if (ioctlsocket(TCPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
			{
				PrintError(LOG_ERROR_WINSOCK, L"Set TCP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
				closesocket(TCPSocketData->Socket);
				for (auto SocketDataIter:TCPSocketDataList)
					closesocket(SocketDataIter.Socket);

				return EXIT_FAILURE;
			}

			if (IsIPv6) //IPv6
			{
				TCPSocketData->AddrLen = sizeof(sockaddr_in6);
				ServerTypeList.push_back(DNSCURVE_MAINIPV6);
			}
			else { //IPv4
				TCPSocketData->AddrLen = sizeof(sockaddr_in);
				ServerTypeList.push_back(DNSCURVE_MAINIPV4);
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
//			memcpy(Buffer.get() + crypto_box_ZEROBYTES, OriginalSend, SendSize);
			memcpy_s(Buffer.get() + crypto_box_ZEROBYTES, RecvSize - crypto_box_ZEROBYTES, OriginalSend, SendSize);
			Buffer.get()[crypto_box_ZEROBYTES + SendSize] = '\x80';

			if (crypto_box_curve25519xsalsa20poly1305_afternm(
				(PUCHAR)SendBuffer.get() + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES - crypto_box_BOXZEROBYTES,
				(PUCHAR)Buffer.get(),
				DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES),
				WholeNonce.get(),
				PacketTarget->PrecomputationKey) != 0)
			{
				for (auto SocketDataIter:TCPSocketDataList)
					closesocket(SocketDataIter.Socket);
				return EXIT_FAILURE;
			}

			Buffer.reset();
//			memcpy(SendBuffer.get() + sizeof(uint16_t), PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
			memcpy_s(SendBuffer.get() + sizeof(uint16_t), RecvSize - sizeof(uint16_t), PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
//			memcpy(SendBuffer.get() + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN, DNSCurveParameter.Client_PublicKey, crypto_box_PUBLICKEYBYTES);
			memcpy_s(SendBuffer.get() + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN, RecvSize - sizeof(uint16_t) - DNSCURVE_MAGIC_QUERY_LEN, DNSCurveParameter.Client_PublicKey, crypto_box_PUBLICKEYBYTES);
//			memcpy(SendBuffer.get() + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES, WholeNonce.get(), crypto_box_HALF_NONCEBYTES);
			memcpy_s(SendBuffer.get() + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES, RecvSize - sizeof(uint16_t) - DNSCURVE_MAGIC_QUERY_LEN - crypto_box_PUBLICKEYBYTES, WholeNonce.get(), crypto_box_HALF_NONCEBYTES);
			*(uint16_t *)SendBuffer.get() = htons((uint16_t)(DNSCurveParameter.DNSCurvePayloadSize - sizeof(uint16_t)));
			memset(WholeNonce.get(), 0, crypto_box_NONCEBYTES);
		}
	}

	//Set target.
	if (IsIPv6) //IPv6
		PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv6;
	else //IPv4
		PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv4;

	//Alternate
	if (PacketTarget->AddressData.Storage.ss_family > 0 && (IsAlternate || Parameter.AlternateMultiRequest))
	{
	//Encryption mode check
		if (DNSCurveParameter.IsEncryption && 
			(CheckEmptyBuffer(PacketTarget->PrecomputationKey, crypto_box_BEFORENMBYTES) || 
			CheckEmptyBuffer(PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
		{
			for (auto SocketDataIter:TCPSocketDataList)
				closesocket(SocketDataIter.Socket);

			return EXIT_FAILURE;
		}

		for (size_t Index = 0;Index < Parameter.MultiRequestTimes;Index++)
		{
			TCPSocketData->SockAddr = PacketTarget->AddressData.Storage;
			if (IsIPv6) //IPv6
				TCPSocketData->Socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
			else //IPv4
				TCPSocketData->Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

		//Socket check
			if (TCPSocketData->Socket == INVALID_SOCKET)
			{
				PrintError(LOG_ERROR_WINSOCK, L"DNSCurve TCP request initialization error", WSAGetLastError(), nullptr, 0);
				for (auto SocketDataIter:TCPSocketDataList)
					closesocket(SocketDataIter.Socket);

				return EXIT_FAILURE;
			}

		//Set Non-blocking Mode
			else if (ioctlsocket(TCPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
			{
				PrintError(LOG_ERROR_WINSOCK, L"Set TCP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
				closesocket(TCPSocketData->Socket);
				for (auto SocketDataIter:TCPSocketDataList)
					closesocket(SocketDataIter.Socket);

				return EXIT_FAILURE;
			}

			if (IsIPv6) //IPv6
			{
				TCPSocketData->AddrLen = sizeof(sockaddr_in6);
				ServerTypeList.push_back(DNSCURVE_ALTERNATEIPV6);
			}
			else { //IPv4
				TCPSocketData->AddrLen = sizeof(sockaddr_in);
				ServerTypeList.push_back(DNSCURVE_ALTERNATEIPV4);
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
//			memcpy(Buffer.get() + crypto_box_ZEROBYTES, OriginalSend, SendSize);
			memcpy_s(Buffer.get() + crypto_box_ZEROBYTES, RecvSize - crypto_box_ZEROBYTES, OriginalSend, SendSize);
			Buffer.get()[crypto_box_ZEROBYTES + SendSize] = '\x80';

			if (crypto_box_curve25519xsalsa20poly1305_afternm(
				(PUCHAR)Alternate_SendBuffer.get() + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES - crypto_box_BOXZEROBYTES,
				(PUCHAR)Buffer.get(),
				DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES),
				WholeNonce.get(),
				PacketTarget->PrecomputationKey) != 0)
			{
				for (auto SocketDataIter:TCPSocketDataList)
					closesocket(SocketDataIter.Socket);
				return EXIT_FAILURE;
			}

			Buffer.reset();
//			memcpy(Alternate_SendBuffer.get() + sizeof(uint16_t), PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
			memcpy_s(Alternate_SendBuffer.get() + sizeof(uint16_t), RecvSize - sizeof(uint16_t), PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
//			memcpy(Alternate_SendBuffer.get() + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN, DNSCurveParameter.Client_PublicKey, crypto_box_PUBLICKEYBYTES);
			memcpy_s(Alternate_SendBuffer.get() + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN, RecvSize - sizeof(uint16_t) - DNSCURVE_MAGIC_QUERY_LEN, DNSCurveParameter.Client_PublicKey, crypto_box_PUBLICKEYBYTES);
//			memcpy(Alternate_SendBuffer.get() + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES, WholeNonce.get(), crypto_box_HALF_NONCEBYTES);
			memcpy_s(Alternate_SendBuffer.get() + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES, RecvSize - sizeof(uint16_t) - DNSCURVE_MAGIC_QUERY_LEN - crypto_box_PUBLICKEYBYTES, WholeNonce.get(), crypto_box_HALF_NONCEBYTES);
			*(uint16_t *)Alternate_SendBuffer.get() = htons((uint16_t)(DNSCurveParameter.DNSCurvePayloadSize - sizeof(uint16_t)));
			memset(WholeNonce.get(), 0, crypto_box_NONCEBYTES);
		}
	}

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
			SocketDataIter++;
		}
	}
//Stop loop.
	StopLoop: 
	if (TCPSocketDataList.empty())
		return EXIT_FAILURE;

//Send request and receive result.
	std::shared_ptr<fd_set> ReadFDS(new fd_set()), WriteFDS(new fd_set());
	memset(ReadFDS.get(), 0, sizeof(fd_set));
	memset(WriteFDS.get(), 0, sizeof(fd_set));
	timeval Timeout = {0};
	FD_ZERO(WriteFDS.get());
	for (auto SocketDataIter:TCPSocketDataList)
	{
		FD_SET(SocketDataIter.Socket, WriteFDS.get());
	}
	SSIZE_T SelectResult = 0, RecvLen = 0;
	std::vector<uint16_t> PDULenList(TCPSocketDataList.size(), 0);
	for (;;)
	{
		Sleep(LOOP_INTERVAL_TIME);

	//Reset parameters.
		Timeout.tv_sec = Parameter.ReliableSocketTimeout / SECOND_TO_MILLISECOND;
		Timeout.tv_usec = Parameter.ReliableSocketTimeout % SECOND_TO_MILLISECOND * SECOND_TO_MILLISECOND;
		FD_ZERO(ReadFDS.get());
		for (auto SocketDataIter:TCPSocketDataList)
		{
			if (SocketDataIter.Socket > 0)
			{
				FD_SET(SocketDataIter.Socket, ReadFDS.get());
			}
		}

	//Wait for system calling.
		SelectResult = select(0, ReadFDS.get(), WriteFDS.get(), nullptr, &Timeout);
		if (SelectResult > 0)
		{
		//Receive.
			for (size_t Index = 0;Index < TCPSocketDataList.size();Index++)
			{
				if (FD_ISSET(TCPSocketDataList[Index].Socket, ReadFDS.get()))
				{
					RecvLen = recv(TCPSocketDataList[Index].Socket, OriginalRecv, (int)RecvSize, 0);

				//TCP segment of a reassembled PDU
					if (RecvLen < DNS_PACKET_MINSIZE)
					{
						if (RecvLen > 0 && htons(((uint16_t *)OriginalRecv)[0]) >= DNS_PACKET_MINSIZE)
						{
							PDULenList[Index] = htons(((uint16_t *)OriginalRecv)[0]);
							memset(OriginalRecv, 0, RecvSize);
							continue;
						}
					//Invalid packet.
						else {
							shutdown(TCPSocketDataList[Index].Socket, SD_BOTH);
							closesocket(TCPSocketDataList[Index].Socket);
							TCPSocketDataList[Index].Socket = 0;
							break;
						}
					}
					else {
					//Length check.
						if ((SSIZE_T)PDULenList[Index] > RecvLen)
						{
							shutdown(TCPSocketDataList[Index].Socket, SD_BOTH);
							closesocket(TCPSocketDataList[Index].Socket);
							TCPSocketDataList[Index].Socket = 0;
							break;
						}
					//Receive again.
						else if (PDULenList[Index] > 0)
						{
						//Encryption mode
							if (DNSCurveParameter.IsEncryption)
							{
							//Jump to normal receive process.
								if (PDULenList[Index] >= DNS_PACKET_MINSIZE)
								{
									RecvLen = (SSIZE_T)PDULenList[Index];
									goto JumpFromPDU;
								}

								memset(OriginalRecv, 0, RecvSize);
								continue;
							}
						}
					//First receive.
						else {
						//Length check
							if ((SSIZE_T)ntohs(((uint16_t *)OriginalRecv)[0]) > RecvLen)
							{
								shutdown(TCPSocketDataList[Index].Socket, SD_BOTH);
								closesocket(TCPSocketDataList[Index].Socket);
								TCPSocketDataList[Index].Socket = 0;
								break;
							}
							else {
								RecvLen = (SSIZE_T)ntohs(((uint16_t *)OriginalRecv)[0]);
								if (RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE)
								{
//									memmove(OriginalRecv, OriginalRecv + sizeof(uint16_t), RecvLen);
									memmove_s(OriginalRecv, RecvSize, OriginalRecv + sizeof(uint16_t), RecvLen);

								//Jump here when TCP segment of a reassembled PDU.
									JumpFromPDU: 

								//Encryption mode
									if (DNSCurveParameter.IsEncryption)
									{
									//Check receive magic number.
										if (ServerTypeList.back() != ServerTypeList.front() && Index > 0 && Index >= TCPSocketDataList.size() / 2U)
										{
											if (ServerTypeList.back() == DNSCURVE_ALTERNATEIPV6)
												PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv6;
											else if (ServerTypeList.back() == DNSCURVE_MAINIPV6)
												PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv6;
											else if (ServerTypeList.back() == DNSCURVE_ALTERNATEIPV4)
												PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv4;
											else if (ServerTypeList.back() == DNSCURVE_MAINIPV4)
												PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv4;
										}
										else {
											if (ServerTypeList.front() == DNSCURVE_ALTERNATEIPV6)
												PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv6;
											else if (ServerTypeList.front() == DNSCURVE_MAINIPV6)
												PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv6;
											else if (ServerTypeList.front() == DNSCURVE_ALTERNATEIPV4)
												PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv4;
											else if (ServerTypeList.front() == DNSCURVE_MAINIPV4)
												PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv4;
										}
										if (memcmp(OriginalRecv, PacketTarget->ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN) != 0)
										{
											memset(OriginalRecv, 0, RecvSize);
											continue;
										}

									//Copy whole nonce.
//										memcpy(WholeNonce.get(), OriginalRecv + DNSCURVE_MAGIC_QUERY_LEN, crypto_box_NONCEBYTES);
										memcpy_s(WholeNonce.get(), crypto_box_NONCEBYTES, OriginalRecv + DNSCURVE_MAGIC_QUERY_LEN, crypto_box_NONCEBYTES);

									//Open crypto box.
										memset(OriginalRecv, 0, DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);
//										memmove(OriginalRecv + crypto_box_BOXZEROBYTES, OriginalRecv + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
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
//										memmove(OriginalRecv, OriginalRecv + crypto_box_ZEROBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
										memmove_s(OriginalRecv, RecvSize, OriginalRecv + crypto_box_ZEROBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
										memset(OriginalRecv + RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES), 0, RecvSize - (RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES)));
										for (SSIZE_T InnerIndex = RecvLen - (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);InnerIndex >= (SSIZE_T)DNS_PACKET_MINSIZE;InnerIndex--)
										{
											if ((UCHAR)OriginalRecv[InnerIndex] == 0x80)
											{
												RecvLen = InnerIndex;
												break;
											}
										}
									}

								//Hosts Only Extended check
									if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckResponseData(OriginalRecv, RecvLen, false, nullptr))
									{
										memset(OriginalRecv, 0, RecvSize);
										continue;
									}

								//Close sockets and remove response length of TCP requesting.
									for (auto SocketDataIter:TCPSocketDataList)
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
									shutdown(TCPSocketDataList[Index].Socket, SD_BOTH);
									closesocket(TCPSocketDataList[Index].Socket);
									TCPSocketDataList[Index].Socket = 0;
									break;
								}
							}
						}
					}
				}
			}

		//Send.
			size_t Alternate = 0;
			for (auto SocketDataIter:TCPSocketDataList)
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

					Alternate++;
				}
			}

			FD_ZERO(WriteFDS.get());
		}
	//Timeout
		else if (SelectResult == 0)
		{
			memset(OriginalRecv, 0, RecvSize);
			AlternateSwapList.TimeoutTimes[8U]++;
			AlternateSwapList.TimeoutTimes[9U]++;

		//Close all sockets.
			for (auto SocketDataIter:TCPSocketDataList)
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
	for (auto SocketDataIter:TCPSocketDataList)
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
size_t __fastcall DNSCurveUDPRequest(const PSTR OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize /* , const bool IsAlternate */ )
{
//Initialization
	std::shared_ptr<sockaddr_storage> SockAddr(new sockaddr_storage());
	memset(SockAddr.get(), 0, sizeof(sockaddr_storage));
	SYSTEM_SOCKET UDPSocket = 0;
	int AddrLen = 0;
	PDNSCURVE_SERVER_DATA PacketTarget = nullptr;

//Socket initialization
	bool *IsAlternate = nullptr;
	size_t *AlternateTimeoutTimes = nullptr;
	if (Parameter.GatewayAvailable_IPv6 && DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family > 0) //IPv6
	{
		IsAlternate = &AlternateSwapList.IsSwap[10U];
		AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[10U];
		if (*IsAlternate && DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0)
		{
		//Encryption mode check
			if (DNSCurveParameter.IsEncryption && 
				(CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
				CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
					return EXIT_FAILURE;

			((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
			((PSOCKADDR_IN6)SockAddr.get())->sin6_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv6;
		}
		else { //Main
		//Encryption mode check
			if (DNSCurveParameter.IsEncryption && 
				(CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
				CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
					return EXIT_FAILURE;

			((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_addr;
			((PSOCKADDR_IN6)SockAddr.get())->sin6_port = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_port;
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv6;
		}

		AddrLen = sizeof(sockaddr_in6);
		SockAddr->ss_family = AF_INET6;
		UDPSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	}
	else if (Parameter.GatewayAvailable_IPv4 && DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family > 0) //IPv4
	{
		IsAlternate = &AlternateSwapList.IsSwap[11U];
		AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[11U];
		if (*IsAlternate && DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0)
		{
		//Encryption mode check
			if (DNSCurveParameter.IsEncryption && 
				(CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
				CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
					return EXIT_FAILURE;

			((PSOCKADDR_IN)SockAddr.get())->sin_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
			((PSOCKADDR_IN)SockAddr.get())->sin_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv4;
		}
		else { //Main
		//Encryption mode check
			if (DNSCurveParameter.IsEncryption && 
				(CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
				CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
					return EXIT_FAILURE;

			((PSOCKADDR_IN)SockAddr.get())->sin_addr = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_addr;
			((PSOCKADDR_IN)SockAddr.get())->sin_port = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_port;
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv4;
		}

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
		PrintError(LOG_ERROR_WINSOCK, L"DNSCurve UDP sockets initialization error", WSAGetLastError(), nullptr, 0);
		return EXIT_FAILURE;
	}

//Set socket timeout.
	if (setsockopt(UDPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR || 
		setsockopt(UDPSocket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket timeout error", WSAGetLastError(), nullptr, 0);
		closesocket(UDPSocket);

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
//		memcpy(Buffer.get() + crypto_box_ZEROBYTES, OriginalSend, SendSize);
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
			closesocket(UDPSocket);
			memset(OriginalRecv, 0, RecvSize);

			return EXIT_FAILURE;
		}

		Buffer.reset();
//		memcpy(OriginalRecv, PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
		memcpy_s(OriginalRecv, RecvSize, PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
//		memcpy(OriginalRecv + DNSCURVE_MAGIC_QUERY_LEN, DNSCurveParameter.Client_PublicKey, crypto_box_PUBLICKEYBYTES);
		memcpy_s(OriginalRecv + DNSCURVE_MAGIC_QUERY_LEN, RecvSize - DNSCURVE_MAGIC_QUERY_LEN, DNSCurveParameter.Client_PublicKey, crypto_box_PUBLICKEYBYTES);
//		memcpy(OriginalRecv + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES, WholeNonce.get(), crypto_box_HALF_NONCEBYTES);
		memcpy_s(OriginalRecv + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES, RecvSize - DNSCURVE_MAGIC_QUERY_LEN - crypto_box_PUBLICKEYBYTES, WholeNonce.get(), crypto_box_HALF_NONCEBYTES);
		memset(WholeNonce.get(), 0, crypto_box_NONCEBYTES);

//Send requesting.
		if (sendto(UDPSocket, OriginalRecv, (int)DNSCurveParameter.DNSCurvePayloadSize, 0, (PSOCKADDR)SockAddr.get(), AddrLen) == SOCKET_ERROR)
		{
			PrintError(LOG_ERROR_WINSOCK, L"DNSCurve UDP request error", WSAGetLastError(), nullptr, 0);
			shutdown(UDPSocket, SD_BOTH);
			closesocket(UDPSocket);

			return EXIT_FAILURE;
		}

		memset(OriginalRecv, 0, RecvSize);
	}
//Normal mode
	else {
		WholeNonce.reset();
		if (sendto(UDPSocket, OriginalSend, (int)SendSize, 0, (PSOCKADDR)SockAddr.get(), AddrLen) == SOCKET_ERROR)
		{
			PrintError(LOG_ERROR_WINSOCK, L"DNSCurve UDP request error", WSAGetLastError(), nullptr, 0);
			shutdown(UDPSocket, SD_BOTH);
			closesocket(UDPSocket);

			return EXIT_FAILURE;
		}
	}

//Receive result.
	SSIZE_T RecvLen = recvfrom(UDPSocket, OriginalRecv, (int)RecvSize, 0, (PSOCKADDR)SockAddr.get(), (PINT)&AddrLen);
	if (DNSCurveParameter.IsEncryption && RecvLen < (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES + DNS_PACKET_MINSIZE) || 
		RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
	{
		if (WSAGetLastError() == WSAETIMEDOUT)
		{
			shutdown(UDPSocket, SD_BOTH);
			closesocket(UDPSocket);
			if (AlternateTimeoutTimes != nullptr)
				(*AlternateTimeoutTimes)++;

			return WSAETIMEDOUT;
		}
		else {
			shutdown(UDPSocket, SD_BOTH);
			closesocket(UDPSocket);
			return EXIT_FAILURE;
		}
	}

	shutdown(UDPSocket, SD_BOTH);
	closesocket(UDPSocket);
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
//		memcpy(WholeNonce.get(), OriginalRecv + DNSCURVE_MAGIC_QUERY_LEN, crypto_box_NONCEBYTES);
		memcpy_s(WholeNonce.get(), crypto_box_NONCEBYTES, OriginalRecv + DNSCURVE_MAGIC_QUERY_LEN, crypto_box_NONCEBYTES);

	//Open crypto box.
		memset(OriginalRecv, 0, DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);
//		memmove(OriginalRecv + crypto_box_BOXZEROBYTES, OriginalRecv + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
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
//		memmove(OriginalRecv, OriginalRecv + crypto_box_ZEROBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
		memmove_s(OriginalRecv, RecvSize, OriginalRecv + crypto_box_ZEROBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
		memset(OriginalRecv + RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES), 0, RecvSize - (RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES)));
		memset(OriginalRecv + RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES), 0, RecvSize - (RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES)));
		for (SSIZE_T Index = RecvLen - (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);Index >= (SSIZE_T)DNS_PACKET_MINSIZE;Index--)
		{
			if ((UCHAR)OriginalRecv[Index] == 0x80)
			{
				RecvLen = Index;
				break;
			}
		}

	//Responses question and answers check
		if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckResponseData(OriginalRecv, RecvLen, false, nullptr))
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
		auto DNS_Header = (pdns_hdr)OriginalRecv;
		if (DNS_Header->Additional == 0 || (Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckResponseData(OriginalRecv, RecvLen, false, nullptr))
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

/* Old version(2015-01-13)
//Transmission of DNSCurve UDP protocol(Multithreading)
size_t __fastcall DNSCurveUDPRequestMulti(DNSCURVE_REQUEST_MULTITHREAD_PARAMETER &DNSCurveUDPRequestParameter, std::mutex &Mutex)
{
//Initialization
	std::shared_ptr<sockaddr_storage> SockAddr(new sockaddr_storage());
	SYSTEM_SOCKET UDPSocket = 0;
	int AddrLen = 0;

//Socket initialization
	if (DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family > 0 && //IPv6
		DNSCurveUDPRequestParameter.TargetData.AddrLen == sizeof(sockaddr_in6) || DNSCurveUDPRequestParameter.TargetData.AddrLen == sizeof(sockaddr_in) && DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family == 0)
	{
		if (DNSCurveUDPRequestParameter.Alternate && DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0)
		{
			if (DNSCurveUDPRequestParameter.Encryption)
			{
				if (!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) && 
					!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
					((PSOCKADDR_IN6)SockAddr.get())->sin6_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
			else {
				((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)SockAddr.get())->sin6_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
			}
		}
		else if (DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family > 0) //Main
		{
			if (DNSCurveUDPRequestParameter.Encryption)
			{
				if (!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) && 
					!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_addr;
					((PSOCKADDR_IN6)SockAddr.get())->sin6_port = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
			else {
				((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)SockAddr.get())->sin6_port = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_port;
			}
		}
		else {
			return EXIT_FAILURE;
		}

		SockAddr->ss_family = AF_INET6;
		UDPSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		AddrLen = sizeof(sockaddr_in6);
	}
	else if (DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family > 0) //IPv4
	{
		if (DNSCurveUDPRequestParameter.Alternate && DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0)
		{
		//Encryption mode
			if (DNSCurveUDPRequestParameter.Encryption)
			{
				if (!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) && 
					!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					((PSOCKADDR_IN)SockAddr.get())->sin_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
					((PSOCKADDR_IN)SockAddr.get())->sin_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
		//Normal mode
			else {
				((PSOCKADDR_IN)SockAddr.get())->sin_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)SockAddr.get())->sin_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
			}
		}
		else if (DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family > 0) //Main
		{
		//Encryption mode
			if (DNSCurveUDPRequestParameter.Encryption)
			{
				if (!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) && 
					!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					((PSOCKADDR_IN)SockAddr.get())->sin_addr = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_addr;
					((PSOCKADDR_IN)SockAddr.get())->sin_port = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
		//Normal mode
			else {
				((PSOCKADDR_IN)SockAddr.get())->sin_addr = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)SockAddr.get())->sin_port = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_port;
			}
		}
		else {
			return EXIT_FAILURE;
		}

		SockAddr->ss_family = AF_INET;
		UDPSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		AddrLen = sizeof(sockaddr_in);
	}

//Socket check
	if (UDPSocket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_WINSOCK, L"DNSCurve sockets initialization error", WSAGetLastError(), nullptr, 0);
		return EXIT_FAILURE;
	}

//Set socket timeout.
	if (setsockopt(UDPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR || 
		setsockopt(UDPSocket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket timeout error", WSAGetLastError(), nullptr, 0);
		closesocket(UDPSocket);

		return EXIT_FAILURE;
	}

	std::shared_ptr<char> RecvBuffer(new char[DNSCurveUDPRequestParameter.RecvSize]());
//Encryption mode
	std::shared_ptr<uint8_t> WholeNonce;
	if (DNSCurveUDPRequestParameter.Encryption)
	{
		std::shared_ptr<uint8_t> BufferTemp(new uint8_t[crypto_box_NONCEBYTES]());
		WholeNonce.swap(BufferTemp);
		BufferTemp.reset();

	//Make nonce.
		*(uint32_t *)WholeNonce.get() = randombytes_random();
		*(uint32_t *)(WholeNonce.get() + sizeof(uint32_t)) = randombytes_random();
		*(uint32_t *)(WholeNonce.get() + sizeof(uint32_t) * 2U) = randombytes_random();
		memset(WholeNonce.get() + crypto_box_HALF_NONCEBYTES, 0, crypto_box_HALF_NONCEBYTES);

	//Make a crypto box.
		std::shared_ptr<char> Buffer(new char[DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES)]());
		memcpy(Buffer.get() + crypto_box_ZEROBYTES, DNSCurveUDPRequestParameter.Send, DNSCurveUDPRequestParameter.SendSize);
		Buffer.get()[crypto_box_ZEROBYTES + DNSCurveUDPRequestParameter.SendSize] = '\x80';

		if (AddrLen == sizeof(sockaddr_in6)) //IPv6
		{
			if (DNSCurveUDPRequestParameter.Alternate)
			{
				if (crypto_box_curve25519xsalsa20poly1305_afternm(
						(PUCHAR)RecvBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES - crypto_box_BOXZEROBYTES, 
						(PUCHAR)Buffer.get(), 
						DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES), 
						WholeNonce.get(), 
						DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey) != 0)
				{
					closesocket(UDPSocket);
					return EXIT_FAILURE;
				}

			//Packet(A part)
				memcpy(RecvBuffer.get(), DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
			}
			else { //Main
				if (crypto_box_curve25519xsalsa20poly1305_afternm(
						(PUCHAR)RecvBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES - crypto_box_BOXZEROBYTES, 
						(PUCHAR)Buffer.get(), 
						DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES), 
						WholeNonce.get(), 
						DNSCurveParameter.DNSCurveTarget.IPv6.PrecomputationKey) != 0)
				{
					closesocket(UDPSocket);
					return EXIT_FAILURE;
				}

			//Packet(A part)
				memcpy(RecvBuffer.get(), DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
			}
		}
		else { //IPv4
			if (DNSCurveUDPRequestParameter.Alternate)
			{
				if (crypto_box_curve25519xsalsa20poly1305_afternm(
						(PUCHAR)RecvBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES - crypto_box_BOXZEROBYTES, 
						(PUCHAR)Buffer.get(), 
						DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES), 
						WholeNonce.get(), 
						DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.PrecomputationKey) != 0)
				{
					closesocket(UDPSocket);
					return EXIT_FAILURE;
				}

			//Packet(A part)
				memcpy(RecvBuffer.get(), DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
			}
			else { //Main
				if (crypto_box_curve25519xsalsa20poly1305_afternm(
						(PUCHAR)RecvBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES - crypto_box_BOXZEROBYTES, 
						(PUCHAR)Buffer.get(), 
						DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES),
						WholeNonce.get(), 
						DNSCurveParameter.DNSCurveTarget.IPv4.PrecomputationKey) != 0)
				{
					closesocket(UDPSocket);
					return EXIT_FAILURE;
				}

			//Packet(A part)
				memcpy(RecvBuffer.get(), DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
			}
		}

		//Packet(B part)
		Buffer.reset();
		memcpy(RecvBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN, DNSCurveParameter.Client_PublicKey, crypto_box_PUBLICKEYBYTES);
		memcpy(RecvBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES, WholeNonce.get(), crypto_box_HALF_NONCEBYTES);
		memset(WholeNonce.get(), 0, crypto_box_NONCEBYTES);

//Send requesting.
		if (sendto(UDPSocket, RecvBuffer.get(), (int)DNSCurveParameter.DNSCurvePayloadSize, 0, (PSOCKADDR)SockAddr.get(), AddrLen) == SOCKET_ERROR)
		{
			PrintError(LOG_ERROR_WINSOCK, L"DNSCurve UDP request error", WSAGetLastError(), nullptr, 0);
			closesocket(UDPSocket);

			return EXIT_FAILURE;
		}

		memset(RecvBuffer.get(), 0, DNSCurveUDPRequestParameter.RecvSize);
	}
//Normal mode
	else {
		WholeNonce.reset();
		if (sendto(UDPSocket, DNSCurveUDPRequestParameter.Send, (int)DNSCurveUDPRequestParameter.SendSize, 0, (PSOCKADDR)SockAddr.get(), AddrLen) == SOCKET_ERROR)
		{
			closesocket(UDPSocket);
			PrintError(LOG_ERROR_WINSOCK, L"DNSCurve UDP request error", WSAGetLastError(), nullptr, 0);

			return EXIT_FAILURE;
		}
	}

//Receive result.
	SSIZE_T RecvLen = recvfrom(UDPSocket, RecvBuffer.get(), (int)DNSCurveUDPRequestParameter.RecvSize, 0, (PSOCKADDR)SockAddr.get(), (PINT)&AddrLen);
	if (RecvLen < (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES + DNS_PACKET_MINSIZE))
	{
		if (WSAGetLastError() == WSAETIMEDOUT)
		{
			closesocket(UDPSocket);

			std::unique_lock<std::mutex> DNSCurveMutex(Mutex);
			DNSCurveUDPRequestParameter.ReturnValue = WSAETIMEDOUT;
			return WSAETIMEDOUT;
		}
		else {
			closesocket(UDPSocket);
			return EXIT_FAILURE;
		}
	}

	closesocket(UDPSocket);
//Encryption mode
	if (DNSCurveUDPRequestParameter.Encryption)
	{
		memset(RecvBuffer.get() + RecvLen, 0, DNSCurveUDPRequestParameter.RecvSize - RecvLen);

	//Check receive magic number.
		if (AddrLen == sizeof(sockaddr_in6)) //IPv6
		{
			if (DNSCurveUDPRequestParameter.Alternate)
			{
				if (memcmp(RecvBuffer.get(), DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN) != 0)
					return EXIT_FAILURE;

			//Copy whole nonce.
				memcpy(WholeNonce.get(), RecvBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN, crypto_box_NONCEBYTES);

			//Open crypto box.
				memset(RecvBuffer.get(), 0, DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);
				memmove(RecvBuffer.get() + crypto_box_BOXZEROBYTES, RecvBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
				if (crypto_box_curve25519xsalsa20poly1305_open_afternm(
						(PUCHAR)RecvBuffer.get(), 
						(PUCHAR)RecvBuffer.get(), 
						RecvLen + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES), 
						WholeNonce.get(), 
						DNSCurveParameter.DNSCurveTarget.IPv6.PrecomputationKey) != 0)
					return EXIT_FAILURE;
				memmove(RecvBuffer.get(), RecvBuffer.get() + crypto_box_ZEROBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
				for (SSIZE_T Index = RecvLen - (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);Index >= (SSIZE_T)DNS_PACKET_MINSIZE;Index--)
				{
					if ((UCHAR)RecvBuffer.get()[Index] == 0x80)
					{
						RecvLen = Index;
						break;
					}
				}

			//Responses question and answers check
				if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckResponseData(RecvBuffer.get(), RecvLen, nullptr))
					return EXIT_FAILURE;

			//Send back.
				std::unique_lock<std::mutex> DNSCurveMutex(Mutex);
				if (CheckEmptyBuffer(DNSCurveUDPRequestParameter.Recv, DNSCurveUDPRequestParameter.RecvSize) && DNSCurveUDPRequestParameter.ReturnValue == 0)
				{
					memcpy(DNSCurveUDPRequestParameter.Recv, RecvBuffer.get(), RecvLen);
					DNSCurveUDPRequestParameter.ReturnValue = RecvLen;
					DNSCurveMutex.unlock();
						
				//Mark DNS Cache.
					if (Parameter.CacheType > 0)
						MarkDomainCache(RecvBuffer.get(), RecvLen);
					return RecvLen;
				}
				else {
					return EXIT_SUCCESS;
				}
			}
			else { //Main
				if (memcmp(RecvBuffer.get(), DNSCurveParameter.DNSCurveTarget.IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN) != 0)
					return EXIT_FAILURE;

			//Copy whole nonce.
				memcpy(WholeNonce.get(), RecvBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN, crypto_box_NONCEBYTES);

			//Open crypto box.
				memset(RecvBuffer.get(), 0, DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);
				memmove(RecvBuffer.get() + crypto_box_BOXZEROBYTES, RecvBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
				if (crypto_box_curve25519xsalsa20poly1305_open_afternm(
						(PUCHAR)RecvBuffer.get(), 
						(PUCHAR)RecvBuffer.get(), 
						RecvLen + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES), 
						WholeNonce.get(), 
						DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey) != 0)
					return EXIT_FAILURE;
				memmove(RecvBuffer.get(), RecvBuffer.get() + crypto_box_ZEROBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
				for (SSIZE_T Index = RecvLen - (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);Index >= (SSIZE_T)DNS_PACKET_MINSIZE;Index--)
				{
					if ((UCHAR)RecvBuffer.get()[Index] == 0x80)
					{
						RecvLen = Index;
						break;
					}
				}

			//Responses question and answers check
				if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckResponseData(RecvBuffer.get(), RecvLen, nullptr))
					return EXIT_FAILURE;

			//Send back.
				std::unique_lock<std::mutex> DNSCurveMutex(Mutex);
				if (CheckEmptyBuffer(DNSCurveUDPRequestParameter.Recv, DNSCurveUDPRequestParameter.RecvSize) && DNSCurveUDPRequestParameter.ReturnValue == 0)
				{
					memcpy(DNSCurveUDPRequestParameter.Recv, RecvBuffer.get(), RecvLen);
					DNSCurveUDPRequestParameter.ReturnValue = RecvLen;
					DNSCurveMutex.unlock();
						
				//Mark DNS Cache.
					if (Parameter.CacheType > 0)
						MarkDomainCache(RecvBuffer.get(), RecvLen);
					return RecvLen;
				}
				else {
					return EXIT_SUCCESS;
				}
			}
		}
		else { //IPv4
			if (DNSCurveUDPRequestParameter.Alternate)
			{
				if (memcmp(RecvBuffer.get(), DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN) != 0)
					return EXIT_FAILURE;

			//Copy whole nonce.
				memcpy(WholeNonce.get(), RecvBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN, crypto_box_NONCEBYTES);

			//Open crypto box.
				memset(RecvBuffer.get(), 0, DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);
				memmove(RecvBuffer.get() + crypto_box_BOXZEROBYTES, RecvBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
				if (crypto_box_curve25519xsalsa20poly1305_open_afternm(
						(PUCHAR)RecvBuffer.get(), 
						(PUCHAR)RecvBuffer.get(), 
						RecvLen + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES), 
						WholeNonce.get(), DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.PrecomputationKey) != 0)
					return EXIT_FAILURE;
				memmove(RecvBuffer.get(), RecvBuffer.get() + crypto_box_ZEROBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
				for (SSIZE_T Index = RecvLen - (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);Index >= (SSIZE_T)DNS_PACKET_MINSIZE;Index--)
				{
					if ((UCHAR)RecvBuffer.get()[Index] == 0x80)
					{
						RecvLen = Index;
						break;
					}
				}

			//Responses question and answers check
				if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckResponseData(RecvBuffer.get(), RecvLen, nullptr))
					return EXIT_FAILURE;

			//Send back.
				std::unique_lock<std::mutex> DNSCurveMutex(Mutex);
				if (CheckEmptyBuffer(DNSCurveUDPRequestParameter.Recv, DNSCurveUDPRequestParameter.RecvSize) && DNSCurveUDPRequestParameter.ReturnValue == 0)
				{
					memcpy(DNSCurveUDPRequestParameter.Recv, RecvBuffer.get(), RecvLen);
					DNSCurveUDPRequestParameter.ReturnValue = RecvLen;
					DNSCurveMutex.unlock();
						
				//Mark DNS Cache.
					if (Parameter.CacheType > 0)
						MarkDomainCache(RecvBuffer.get(), RecvLen);
					return RecvLen;
				}
				else {
					return EXIT_SUCCESS;
				}
			}
			else { //Main
				if (memcmp(RecvBuffer.get(), DNSCurveParameter.DNSCurveTarget.IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN) != 0)
					return EXIT_FAILURE;

			//Copy whole nonce.
				memcpy(WholeNonce.get(), RecvBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN, crypto_box_NONCEBYTES);

			//Open crypto box.
				memset(RecvBuffer.get(), 0, DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);
				memmove(RecvBuffer.get() + crypto_box_BOXZEROBYTES, RecvBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
				if (crypto_box_curve25519xsalsa20poly1305_open_afternm(
						(PUCHAR)RecvBuffer.get(), 
						(PUCHAR)RecvBuffer.get(), 
						RecvLen + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES), 
						WholeNonce.get(), 
						DNSCurveParameter.DNSCurveTarget.IPv4.PrecomputationKey) != 0)
					return EXIT_FAILURE;
				memmove(RecvBuffer.get(), RecvBuffer.get() + crypto_box_ZEROBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
				for (SSIZE_T Index = RecvLen - (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);Index >= (SSIZE_T)DNS_PACKET_MINSIZE;Index--)
				{
					if ((UCHAR)RecvBuffer.get()[Index] == 0x80)
					{
						RecvLen = Index;
						break;
					}
				}

			//Responses question and answers check
				if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckResponseData(RecvBuffer.get(), RecvLen, nullptr))
					return EXIT_FAILURE;

			//Send back.
				std::unique_lock<std::mutex> DNSCurveMutex(Mutex);
				if (CheckEmptyBuffer(DNSCurveUDPRequestParameter.Recv, DNSCurveUDPRequestParameter.RecvSize) && DNSCurveUDPRequestParameter.ReturnValue == 0)
				{
					memcpy(DNSCurveUDPRequestParameter.Recv, RecvBuffer.get(), RecvLen);
					DNSCurveUDPRequestParameter.ReturnValue = RecvLen;
					DNSCurveMutex.unlock();
						
				//Mark DNS Cache.
					if (Parameter.CacheType > 0)
						MarkDomainCache(RecvBuffer.get(), RecvLen);
					return RecvLen;
				}
				else {
					return EXIT_SUCCESS;
				}
			}
		}
	}
	//Normal mode
	else {
	//EDNS0 Label and responses answers check
		auto DNS_Header = (pdns_hdr)RecvBuffer.get();
		if (DNS_Header->Additional == 0 || (Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckResponseData(RecvBuffer.get(), RecvLen, nullptr))
			return EXIT_FAILURE;

	//Send back.
		std::unique_lock<std::mutex> DNSCurveMutex(Mutex);
		if (CheckEmptyBuffer(DNSCurveUDPRequestParameter.Recv, DNSCurveUDPRequestParameter.RecvSize) && DNSCurveUDPRequestParameter.ReturnValue == 0)
		{
			memcpy(DNSCurveUDPRequestParameter.Recv, RecvBuffer.get(), RecvLen);
			DNSCurveUDPRequestParameter.ReturnValue = RecvLen;
			DNSCurveMutex.unlock();
						
		//Mark DNS Cache.
			if (Parameter.CacheType > 0)
				MarkDomainCache(RecvBuffer.get(), RecvLen);
			return RecvLen;
		}
		else {
			return EXIT_SUCCESS;
		}
	}

	return EXIT_FAILURE;
}
*/

//Transmission of DNSCurve UDP protocol(Multithreading)
size_t __fastcall DNSCurveUDPRequestMulti(const PSTR OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize /* , const bool IsAlternate */ )
{
//Initialization
	std::vector<SOCKET_DATA> UDPSocketDataList;
	std::vector<size_t> ServerTypeList;
	std::shared_ptr<char> SendBuffer, Alternate_SendBuffer;
	std::shared_ptr<uint8_t> WholeNonce, Alternate_WholeNonce;

//Socket initialization
	auto IsIPv6 = false;
	auto IsAlternate = false;
	if (Parameter.GatewayAvailable_IPv6 && DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family > 0) //IPv6
	{
/* Old version(2015-02-26)
	{
		std::shared_ptr<SOCKET_DATA> UDPSocketData(new SOCKET_DATA());
		ULONG SocketMode = 1U;

	//Main
		if (!IsAlternate)
		{
		//Encryption mode check
			if (DNSCurveParameter.IsEncryption && 
				(CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
				CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
					return EXIT_FAILURE;

			UDPSocketData->SockAddr = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage;
			UDPSocketData->Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		//Socket check
			if (UDPSocketData->Socket == INVALID_SOCKET)
			{
				PrintError(LOG_ERROR_WINSOCK, L"Complete UDP request initialization error", WSAGetLastError(), nullptr, 0);
				return EXIT_FAILURE;
			}
		//Set Non-blocking Mode
			else if (ioctlsocket(UDPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
			{
				PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
				closesocket(UDPSocketData->Socket);

				return EXIT_FAILURE;
			}

			UDPSocketData->AddrLen = sizeof(sockaddr_in6);
			UDPSocketDataList.push_back(*UDPSocketData);
			ServerTypeList.push_back(DNSCURVE_MAINIPV6);
			memset(UDPSocketData.get(), 0, sizeof(SOCKET_DATA));

		//Encryption mode
			if (DNSCurveParameter.IsEncryption)
			{
				std::shared_ptr<char> SendBufferTemp(new char[RecvSize]());
				SendBuffer.swap(SendBufferTemp);
				SendBufferTemp.reset();
				std::shared_ptr<uint8_t> WholeNonceTemp(new uint8_t[crypto_box_NONCEBYTES]());
				WholeNonce.swap(WholeNonceTemp);
				WholeNonceTemp.reset();

			//Make nonce.
				*(uint32_t *)WholeNonce.get() = randombytes_random();
				*(uint32_t *)(WholeNonce.get() + sizeof(uint32_t)) = randombytes_random();
				*(uint32_t *)(WholeNonce.get() + sizeof(uint32_t) * 2U) = randombytes_random();
				memset(WholeNonce.get() + crypto_box_HALF_NONCEBYTES, 0, crypto_box_HALF_NONCEBYTES);

			//Make a crypto box.
				std::shared_ptr<char> Buffer(new char[DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES)]());
//				memcpy(Buffer.get() + crypto_box_ZEROBYTES, OriginalSend, SendSize);
				memcpy_s(Buffer.get() + crypto_box_ZEROBYTES, RecvSize - crypto_box_ZEROBYTES, OriginalSend, SendSize);
				Buffer.get()[crypto_box_ZEROBYTES + SendSize] = '\x80';

				if (crypto_box_curve25519xsalsa20poly1305_afternm(
					(PUCHAR)SendBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES - crypto_box_BOXZEROBYTES, 
					(PUCHAR)Buffer.get(), 
					DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES), 
					WholeNonce.get(), 
					DNSCurveParameter.DNSCurveTarget.IPv6.PrecomputationKey) != 0)
				{
					for (auto SocketDataIter:UDPSocketDataList)
						closesocket(SocketDataIter.Socket);
					return EXIT_FAILURE;
				}

				Buffer.reset();
//				memcpy(SendBuffer.get(), DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
				memcpy_s(SendBuffer.get(), RecvSize, DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
//				memcpy(SendBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN, DNSCurveParameter.Client_PublicKey, crypto_box_PUBLICKEYBYTES);
				memcpy_s(SendBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN, RecvSize - DNSCURVE_MAGIC_QUERY_LEN, DNSCurveParameter.Client_PublicKey, crypto_box_PUBLICKEYBYTES);
//				memcpy(SendBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES, WholeNonce.get(), crypto_box_HALF_NONCEBYTES);
				memcpy_s(SendBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES, RecvSize - DNSCURVE_MAGIC_QUERY_LEN - crypto_box_PUBLICKEYBYTES, WholeNonce.get(), crypto_box_HALF_NONCEBYTES);
				memset(WholeNonce.get(), 0, crypto_box_NONCEBYTES);
			}
		}

	//Alternate
		if (DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && (IsAlternate || Parameter.AlternateMultiRequest))
		{
		//Encryption mode check
			if (DNSCurveParameter.IsEncryption && 
				(CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
				CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
					return EXIT_FAILURE;

			UDPSocketData->SockAddr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage;
			UDPSocketData->Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		//Socket check
			if (UDPSocketData->Socket == INVALID_SOCKET)
			{
				PrintError(LOG_ERROR_WINSOCK, L"Complete UDP request initialization error", WSAGetLastError(), nullptr, 0);
				return EXIT_FAILURE;
			}
		//Set Non-blocking Mode
			else if (ioctlsocket(UDPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
			{
				PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
				for (auto SocketDataIter:UDPSocketDataList)
					closesocket(SocketDataIter.Socket);

				return EXIT_FAILURE;
			}

			UDPSocketData->AddrLen = sizeof(sockaddr_in6);
			UDPSocketDataList.push_back(*UDPSocketData);
			ServerTypeList.push_back(DNSCURVE_ALTERNATEIPV6);
			memset(UDPSocketData.get(), 0, sizeof(SOCKET_DATA));
		}

	//Encryption mode
		if (DNSCurveParameter.IsEncryption)
		{
			std::shared_ptr<char> SendBufferTemp(new char[RecvSize]());
			Alternate_SendBuffer.swap(SendBufferTemp);
			SendBufferTemp.reset();
			std::shared_ptr<uint8_t> WholeNonceTemp(new uint8_t[crypto_box_NONCEBYTES]());
			Alternate_WholeNonce.swap(WholeNonceTemp);
			WholeNonceTemp.reset();

		//Make nonce.
			*(uint32_t *)Alternate_WholeNonce.get() = randombytes_random();
			*(uint32_t *)(Alternate_WholeNonce.get() + sizeof(uint32_t)) = randombytes_random();
			*(uint32_t *)(Alternate_WholeNonce.get() + sizeof(uint32_t) * 2U) = randombytes_random();
			memset(Alternate_WholeNonce.get() + crypto_box_HALF_NONCEBYTES, 0, crypto_box_HALF_NONCEBYTES);

		//Make a crypto box.
			std::shared_ptr<char> Buffer(new char[DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES)]());
//			memcpy(Buffer.get() + crypto_box_ZEROBYTES, OriginalSend, SendSize);
			memcpy_s(Buffer.get() + crypto_box_ZEROBYTES, RecvSize - crypto_box_ZEROBYTES, OriginalSend, SendSize);
			Buffer.get()[crypto_box_ZEROBYTES + SendSize] = '\x80';

			if (crypto_box_curve25519xsalsa20poly1305_afternm(
				(PUCHAR)Alternate_SendBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES - crypto_box_BOXZEROBYTES, 
				(PUCHAR)Buffer.get(), 
				DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES), 
				Alternate_WholeNonce.get(), 
				DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey) != 0)
			{
				for (auto SocketDataIter:UDPSocketDataList)
					closesocket(SocketDataIter.Socket);
				return EXIT_FAILURE;
			}

			Buffer.reset();
//			memcpy(Alternate_SendBuffer.get(), DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
			memcpy_s(Alternate_SendBuffer.get(), RecvSize, DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
//			memcpy(Alternate_SendBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN, DNSCurveParameter.Client_PublicKey, crypto_box_PUBLICKEYBYTES);
			memcpy_s(Alternate_SendBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN, RecvSize - DNSCURVE_MAGIC_QUERY_LEN, DNSCurveParameter.Client_PublicKey, crypto_box_PUBLICKEYBYTES);
//			memcpy(Alternate_SendBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES, Alternate_WholeNonce.get(), crypto_box_HALF_NONCEBYTES);
			memcpy_s(Alternate_SendBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES, RecvSize - DNSCURVE_MAGIC_QUERY_LEN - crypto_box_PUBLICKEYBYTES, Alternate_WholeNonce.get(), crypto_box_HALF_NONCEBYTES);
			memset(Alternate_WholeNonce.get(), 0, crypto_box_NONCEBYTES);
		}
	}
*/
		IsIPv6 = true;
		IsAlternate = AlternateSwapList.IsSwap[10U];
	}
	else if (Parameter.GatewayAvailable_IPv4 && DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family > 0) //IPv4
	{
		IsIPv6 = false;
		IsAlternate = AlternateSwapList.IsSwap[11U];
	}
	else {
		return EXIT_FAILURE;
	}

	std::shared_ptr<SOCKET_DATA> UDPSocketData(new SOCKET_DATA());
	memset(UDPSocketData.get(), 0, sizeof(SOCKET_DATA));
	ULONG SocketMode = 1U;
	PDNSCURVE_SERVER_DATA PacketTarget = nullptr;

	//Main
	if (!IsAlternate)
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
				return EXIT_FAILURE;

		UDPSocketData->SockAddr = PacketTarget->AddressData.Storage;
		if (IsIPv6) //IPv6
			UDPSocketData->Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		else //IPv4
			UDPSocketData->Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	//Socket check
		if (UDPSocketData->Socket == INVALID_SOCKET)
		{
			PrintError(LOG_ERROR_WINSOCK, L"Complete UDP request initialization error", WSAGetLastError(), nullptr, 0);
			return EXIT_FAILURE;
		}

	//Set Non-blocking Mode
		else if (ioctlsocket(UDPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
		{
			PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
			closesocket(UDPSocketData->Socket);

			return EXIT_FAILURE;
		}

		if (IsIPv6) //IPv6
		{
			UDPSocketData->AddrLen = sizeof(sockaddr_in6);
			ServerTypeList.push_back(DNSCURVE_MAINIPV6);
		}
		else { //IPv4
			UDPSocketData->AddrLen = sizeof(sockaddr_in);
			ServerTypeList.push_back(DNSCURVE_MAINIPV4);
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
//			memcpy(Buffer.get() + crypto_box_ZEROBYTES, OriginalSend, SendSize);
			memcpy_s(Buffer.get() + crypto_box_ZEROBYTES, RecvSize - crypto_box_ZEROBYTES, OriginalSend, SendSize);
			Buffer.get()[crypto_box_ZEROBYTES + SendSize] = '\x80';

			if (crypto_box_curve25519xsalsa20poly1305_afternm(
				(PUCHAR)SendBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES - crypto_box_BOXZEROBYTES,
				(PUCHAR)Buffer.get(),
				DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES),
				WholeNonce.get(),
				PacketTarget->PrecomputationKey) != 0)
			{
				for (auto SocketDataIter:UDPSocketDataList)
					closesocket(SocketDataIter.Socket);
				return EXIT_FAILURE;
			}

			Buffer.reset();
//			memcpy(SendBuffer.get(), PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
			memcpy_s(SendBuffer.get(), RecvSize, PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
//			memcpy(SendBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN, DNSCurveParameter.Client_PublicKey, crypto_box_PUBLICKEYBYTES);
			memcpy_s(SendBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN, RecvSize - DNSCURVE_MAGIC_QUERY_LEN, DNSCurveParameter.Client_PublicKey, crypto_box_PUBLICKEYBYTES);
//			memcpy(SendBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES, WholeNonce.get(), crypto_box_HALF_NONCEBYTES);
			memcpy_s(SendBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES, RecvSize - DNSCURVE_MAGIC_QUERY_LEN - crypto_box_PUBLICKEYBYTES, WholeNonce.get(), crypto_box_HALF_NONCEBYTES);
			memset(WholeNonce.get(), 0, crypto_box_NONCEBYTES);
		}
	}

	if (IsIPv6) //IPv6
		PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv6;
	else //IPv4
		PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv4;

	//Alternate
	if (PacketTarget->AddressData.Storage.ss_family > 0 && (IsAlternate || Parameter.AlternateMultiRequest))
	{
	//Encryption mode check
		if (DNSCurveParameter.IsEncryption && 
			(CheckEmptyBuffer(PacketTarget->PrecomputationKey, crypto_box_BEFORENMBYTES) || 
			CheckEmptyBuffer(PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
		{
			for (auto SocketDataIter:UDPSocketDataList)
				closesocket(SocketDataIter.Socket);

			return EXIT_FAILURE;
		}

		UDPSocketData->SockAddr = PacketTarget->AddressData.Storage;
		if (IsIPv6) //IPv6
			UDPSocketData->Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		else //IPv4
			UDPSocketData->Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	
	//Socket check
		if (UDPSocketData->Socket == INVALID_SOCKET)
		{
			PrintError(LOG_ERROR_WINSOCK, L"Complete UDP request initialization error", WSAGetLastError(), nullptr, 0);
			for (auto SocketDataIter:UDPSocketDataList)
				closesocket(SocketDataIter.Socket);

			return EXIT_FAILURE;
		}
	
	//Set Non-blocking Mode
		else if (ioctlsocket(UDPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
		{
			PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
			for (auto SocketDataIter:UDPSocketDataList)
				closesocket(SocketDataIter.Socket);

			return EXIT_FAILURE;
		}

		if (IsIPv6) //IPv6
		{
			UDPSocketData->AddrLen = sizeof(sockaddr_in6);
			ServerTypeList.push_back(DNSCURVE_ALTERNATEIPV6);
		}
		else { //IPv4
			UDPSocketData->AddrLen = sizeof(sockaddr_in);
			ServerTypeList.push_back(DNSCURVE_ALTERNATEIPV4);
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
//			memcpy(Buffer.get() + crypto_box_ZEROBYTES, OriginalSend, SendSize);
			memcpy_s(Buffer.get() + crypto_box_ZEROBYTES, RecvSize - crypto_box_ZEROBYTES, OriginalSend, SendSize);
			Buffer.get()[crypto_box_ZEROBYTES + SendSize] = '\x80';

			if (crypto_box_curve25519xsalsa20poly1305_afternm(
				(PUCHAR)Alternate_SendBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES - crypto_box_BOXZEROBYTES,
				(PUCHAR)Buffer.get(),
				DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES),
				Alternate_WholeNonce.get(),
				PacketTarget->PrecomputationKey) != 0)
			{
				for (auto SocketDataIter:UDPSocketDataList)
					closesocket(SocketDataIter.Socket);
				return EXIT_FAILURE;
			}

			Buffer.reset();
//			memcpy(Alternate_SendBuffer.get(), PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
			memcpy_s(Alternate_SendBuffer.get(), RecvSize, PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
//			memcpy(Alternate_SendBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN, DNSCurveParameter.Client_PublicKey, crypto_box_PUBLICKEYBYTES);
			memcpy_s(Alternate_SendBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN, RecvSize - DNSCURVE_MAGIC_QUERY_LEN, DNSCurveParameter.Client_PublicKey, crypto_box_PUBLICKEYBYTES);
//			memcpy(Alternate_SendBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES, Alternate_WholeNonce.get(), crypto_box_HALF_NONCEBYTES);
			memcpy_s(Alternate_SendBuffer.get() + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES, RecvSize - DNSCURVE_MAGIC_QUERY_LEN - crypto_box_PUBLICKEYBYTES, Alternate_WholeNonce.get(), crypto_box_HALF_NONCEBYTES);
			memset(Alternate_WholeNonce.get(), 0, crypto_box_NONCEBYTES);
		}
	}

//Send request and receive result.
	std::shared_ptr<fd_set> ReadFDS(new fd_set()), WriteFDS(new fd_set());
	memset(ReadFDS.get(), 0, sizeof(fd_set));
	memset(WriteFDS.get(), 0, sizeof(fd_set));
	timeval Timeout = {0};
	FD_ZERO(WriteFDS.get());
	for (auto SocketDataIter:UDPSocketDataList)
	{
		FD_SET(SocketDataIter.Socket, WriteFDS.get());
	}
	SSIZE_T SelectResult = 0, RecvLen = 0;
	size_t Index = 0;
	for (;;)
	{
		Sleep(LOOP_INTERVAL_TIME);

	//Reset parameters.
		Timeout.tv_sec = Parameter.UnreliableSocketTimeout / SECOND_TO_MILLISECOND;
		Timeout.tv_usec = Parameter.UnreliableSocketTimeout % SECOND_TO_MILLISECOND * SECOND_TO_MILLISECOND;
		FD_ZERO(ReadFDS.get());
		for (auto SocketDataIter:UDPSocketDataList)
		{
			if (SocketDataIter.Socket > 0)
			{
				FD_SET(SocketDataIter.Socket, ReadFDS.get());
			}
		}

	//Wait for system calling.
		SelectResult = select(0, ReadFDS.get(), WriteFDS.get(), nullptr, &Timeout);
		if (SelectResult > 0)
		{
			auto InnerIsAlternate = false;

		//Receive.
			for (Index = 0;Index < UDPSocketDataList.size();Index++)
			{
				if (FD_ISSET(UDPSocketDataList[Index].Socket, ReadFDS.get()))
				{
					RecvLen = recvfrom(UDPSocketDataList[Index].Socket, OriginalRecv, (int)RecvSize, 0, (PSOCKADDR)&UDPSocketDataList[Index].SockAddr, (PINT)&UDPSocketDataList[Index].AddrLen);
					if (DNSCurveParameter.IsEncryption && RecvLen < (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES + DNS_PACKET_MINSIZE) || 
						RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
					{
						if (RecvLen > 0)
						{
							memset(OriginalRecv, 0, RecvSize);
							continue;
						}
						else {
							shutdown(UDPSocketDataList[Index].Socket, SD_BOTH);
							closesocket(UDPSocketDataList[Index].Socket);
							UDPSocketDataList[Index].Socket = 0;
							break;
						}
					}
					
				//Encryption mode
					if (DNSCurveParameter.IsEncryption)
					{
					//Check receive magic number.
						if (InnerIsAlternate)
						{
							if (ServerTypeList.back() == DNSCURVE_ALTERNATEIPV6)
								PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv6;
							else if (ServerTypeList.back() == DNSCURVE_MAINIPV6)
								PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv6;
							else if (ServerTypeList.back() == DNSCURVE_ALTERNATEIPV4)
								PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv4;
							else if (ServerTypeList.back() == DNSCURVE_MAINIPV4)
								PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv4;
						}
						else {
							if (ServerTypeList.front() == DNSCURVE_ALTERNATEIPV6)
								PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv6;
							else if (ServerTypeList.front() == DNSCURVE_MAINIPV6)
								PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv6;
							else if (ServerTypeList.front() == DNSCURVE_ALTERNATEIPV4)
								PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv4;
							else if (ServerTypeList.front() == DNSCURVE_MAINIPV4)
								PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv4;
						}
						if (memcmp(OriginalRecv, PacketTarget->ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN) != 0)
						{
							memset(OriginalRecv, 0, RecvSize);
							shutdown(UDPSocketDataList[Index].Socket, SD_BOTH);
							closesocket(UDPSocketDataList[Index].Socket);
							UDPSocketDataList[Index].Socket = 0;

							continue;
						}

					//Copy whole nonce.
//						memcpy(WholeNonce.get(), OriginalRecv + DNSCURVE_MAGIC_QUERY_LEN, crypto_box_NONCEBYTES);
						memcpy_s(WholeNonce.get(), crypto_box_NONCEBYTES, OriginalRecv + DNSCURVE_MAGIC_QUERY_LEN, crypto_box_NONCEBYTES);

					//Open crypto box.
						memset(OriginalRecv, 0, DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);
//						memmove(OriginalRecv + crypto_box_BOXZEROBYTES, OriginalRecv + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
						memmove_s(OriginalRecv + crypto_box_BOXZEROBYTES, RecvSize - crypto_box_BOXZEROBYTES, OriginalRecv + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
						if (crypto_box_curve25519xsalsa20poly1305_open_afternm(
							(PUCHAR)OriginalRecv,
							(PUCHAR)OriginalRecv,
							RecvLen + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES),
							WholeNonce.get(),
							PacketTarget->PrecomputationKey) != 0)
						{
							memset(OriginalRecv, 0, RecvSize);
							shutdown(UDPSocketDataList[Index].Socket, SD_BOTH);
							closesocket(UDPSocketDataList[Index].Socket);
							UDPSocketDataList[Index].Socket = 0;

							continue;
						}
//						memmove(OriginalRecv, OriginalRecv + crypto_box_ZEROBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
						memmove_s(OriginalRecv, RecvSize, OriginalRecv + crypto_box_ZEROBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
						memset(OriginalRecv + RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES), 0, RecvSize - (RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES)));
						for (SSIZE_T InnerIndex = RecvLen - (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);InnerIndex >= (SSIZE_T)DNS_PACKET_MINSIZE;InnerIndex--)
						{
							if ((UCHAR)OriginalRecv[InnerIndex] == 0x80)
							{
								RecvLen = InnerIndex;
								break;
							}
						}

					//Responses question and answers check
						if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckResponseData(OriginalRecv, RecvLen, false, nullptr))
						{
							memset(OriginalRecv, 0, RecvSize);
							shutdown(UDPSocketDataList[Index].Socket, SD_BOTH);
							closesocket(UDPSocketDataList[Index].Socket);
							UDPSocketDataList[Index].Socket = 0;

							continue;
						}

					//Close all sockets.
						for (auto SocketDataIter:UDPSocketDataList)
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
						for (auto SocketDataIter:UDPSocketDataList)
						{
							if (SocketDataIter.Socket > 0)
							{
								shutdown(SocketDataIter.Socket, SD_BOTH);
								closesocket(SocketDataIter.Socket);
							}
						}

					//Hosts Only Extended check
						if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckResponseData(OriginalRecv, RecvLen, false, nullptr))
						{
							memset(OriginalRecv, 0, RecvSize);
							continue;
						}

					//Mark DNS Cache.
						if (Parameter.CacheType > 0)
							MarkDomainCache(OriginalRecv, RecvLen);

					//Close all sockets.
						for (auto SocketDataIter:UDPSocketDataList)
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
			for (auto SocketDataIter:UDPSocketDataList)
			{
				if (FD_ISSET(SocketDataIter.Socket, WriteFDS.get()))
				{
				//Encryption mode
					if (DNSCurveParameter.IsEncryption)
					{
						if (InnerIsAlternate && Alternate_SendBuffer)
						{
							for (size_t InnerIndex = 0;InnerIndex < Parameter.MultiRequestTimes;InnerIndex++)
								sendto(SocketDataIter.Socket, Alternate_SendBuffer.get(), (int)DNSCurveParameter.DNSCurvePayloadSize, 0, (PSOCKADDR)&SocketDataIter.SockAddr, SocketDataIter.AddrLen);
						}
						else {
							for (size_t InnerIndex = 0;InnerIndex < Parameter.MultiRequestTimes;InnerIndex++)
								sendto(SocketDataIter.Socket, SendBuffer.get(), (int)DNSCurveParameter.DNSCurvePayloadSize, 0, (PSOCKADDR)&SocketDataIter.SockAddr, SocketDataIter.AddrLen);
							InnerIsAlternate = true;
						}
					}
				//Normal mode
					else {
						for (size_t InnerIndex = 0;InnerIndex < Parameter.MultiRequestTimes;InnerIndex++)
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
			AlternateSwapList.TimeoutTimes[10U]++;
			AlternateSwapList.TimeoutTimes[11U]++;

		//Close all sockets.
			for (auto SocketDataIter:UDPSocketDataList)
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
	for (auto SocketDataIter:UDPSocketDataList)
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

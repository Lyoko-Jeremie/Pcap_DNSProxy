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

extern Configuration Parameter;
extern DNSCurveConfiguration DNSCurveParameter;

//DNSCurve verify keypair
bool __fastcall VerifyKeypair(const PUINT8 PublicKey, const PUINT8 SecretKey)
{
	std::shared_ptr<uint8_t> Test_PublicKey(new uint8_t[crypto_box_PUBLICKEYBYTES]()), Test_SecretKey(new uint8_t[crypto_box_PUBLICKEYBYTES]()), Validation(new uint8_t[crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES + crypto_box_ZEROBYTES]());

//Keypair, Nonce and validation data
	crypto_box_curve25519xsalsa20poly1305_keypair(Test_PublicKey.get(), Test_SecretKey.get());
	uint8_t Nonce[crypto_box_NONCEBYTES] = {DNSCURVE_TEST_NONCE};
	memcpy(Validation.get() + crypto_box_ZEROBYTES, PublicKey, crypto_box_PUBLICKEYBYTES);

//Verify keys
	crypto_box_curve25519xsalsa20poly1305(Validation.get(), Validation.get(), crypto_box_PUBLICKEYBYTES + crypto_box_ZEROBYTES, Nonce, Test_PublicKey.get(), SecretKey);
	if (crypto_box_curve25519xsalsa20poly1305_open(
			Validation.get(), 
			Validation.get(), 
			crypto_box_PUBLICKEYBYTES + crypto_box_ZEROBYTES, 
			Nonce, PublicKey, 
			Test_SecretKey.get()) == RETURN_ERROR)
		return false;
	else 
		return true;
}

//DNSCurve initialization
size_t __fastcall DNSCurveInit(void)
{
//DNSCurve signature request TCP Mode
	if (DNSCurveParameter.DNSCurveMode == DNSCURVE_REQUEST_TCPMODE)
	{
	//Main
		if (DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family != NULL && 
			(CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
			CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
		{
			std::thread DNSCurveTCPSignatureRequestThread(DNSCurveTCPSignatureRequest, AF_INET6, false);
			DNSCurveTCPSignatureRequestThread.detach();
		}
		
		if (DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family != NULL && 
			(CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
			CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
		{
			std::thread DNSCurveTCPSignatureRequestThread(DNSCurveTCPSignatureRequest, AF_INET, false);
			DNSCurveTCPSignatureRequestThread.detach();
		}

	//Alternate
		if (DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL && 
			(CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
			CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
		{
			std::thread DNSCurveTCPSignatureRequestThread(DNSCurveTCPSignatureRequest, AF_INET6, true);
			DNSCurveTCPSignatureRequestThread.detach();
		}
		
		if (DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL && 
			(CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
			CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
		{
			std::thread DNSCurveTCPSignatureRequestThread(DNSCurveTCPSignatureRequest, AF_INET, true);
			DNSCurveTCPSignatureRequestThread.detach();
		}
	}

//DNSCurve signature request UDP Mode
//Main
	if (DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family != NULL && 
		(CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
		CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
	{
		std::thread DNSCurveUDPSignatureRequestThread(DNSCurveUDPSignatureRequest, AF_INET6, false);
		DNSCurveUDPSignatureRequestThread.detach();
	}
		
	if (DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family != NULL && 
		(CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
		CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
	{
		std::thread DNSCurveUDPSignatureRequestThread(DNSCurveUDPSignatureRequest, AF_INET, false);
		DNSCurveUDPSignatureRequestThread.detach();
	}

//Alternate
	if (DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL && 
		(CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
		CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
	{
		std::thread DNSCurveUDPSignatureRequestThread(DNSCurveUDPSignatureRequest, AF_INET6, true);
		DNSCurveUDPSignatureRequestThread.detach();
	}
		
	if (DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL && 
		(CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
		CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
	{
		std::thread DNSCurveUDPSignatureRequestThread(DNSCurveUDPSignatureRequest, AF_INET, true);
		DNSCurveUDPSignatureRequestThread.detach();
	}

	return EXIT_SUCCESS;
}

//DNSCurve Local Signature Request
inline size_t LocalSignatureRequest(const PSTR Send, const size_t SendSize, PSTR Recv, const size_t RecvSize)
{
//Initialization
	SYSTEM_SOCKET UDPSocket = 0;
	sockaddr_storage SockAddr = {0};
	int AddrLen = 0;

//Socket initialization
	if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family != NULL) //IPv6
	{
		AddrLen = sizeof(sockaddr_in6);
		((sockaddr_in6 *)&SockAddr)->sin6_family = AF_INET6;
		((sockaddr_in6 *)&SockAddr)->sin6_addr = in6addr_loopback;
		((sockaddr_in6 *)&SockAddr)->sin6_port = Parameter.ListenPort;
		UDPSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	}
	else { //IPv4
		AddrLen = sizeof(sockaddr_in);
		((sockaddr_in *)&SockAddr)->sin_family = AF_INET;
		((sockaddr_in *)&SockAddr)->sin_addr.S_un.S_addr = htonl(INADDR_LOOPBACK);
		((sockaddr_in *)&SockAddr)->sin_port = Parameter.ListenPort;
		UDPSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	}

//Check socket.
	if (UDPSocket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_WINSOCK, L"DNSCurve Local Signature request initialization error", WSAGetLastError(), nullptr, NULL);
		return EXIT_FAILURE;
	}

//Set socket timeout.
/* Old version(2014-07-22)
	if (setsockopt(UDPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR || 
		setsockopt(UDPSocket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR)
*/
	if (setsockopt(UDPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR || 
		setsockopt(UDPSocket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Set DNSCurve Local Signature socket timeout error", WSAGetLastError(), nullptr, NULL);
		closesocket(UDPSocket);

		return EXIT_FAILURE;
	}

//Send request.
	if (sendto(UDPSocket, Send, (int)SendSize, NULL, (PSOCKADDR)&SockAddr, AddrLen) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"DNSCurve Local Signature request error", WSAGetLastError(), nullptr, NULL);
		closesocket(UDPSocket);

		return EXIT_FAILURE;
	}

//Receive result.
	SSIZE_T RecvLen = recvfrom(UDPSocket, Recv, (int)RecvSize, NULL, (PSOCKADDR)&SockAddr, (PINT)&AddrLen);
	closesocket(UDPSocket);
	if (RecvLen > (SSIZE_T)(sizeof(dns_hdr) + 1U + sizeof(dns_qry)))
	{
		return RecvLen;
	}
	else {
		memset(Recv, 0, RecvSize);
		return EXIT_FAILURE;
	}
}

//Send TCP request to get Signature Data of server(s)
inline bool __fastcall DNSCurveTCPSignatureRequest(const uint16_t NetworkLayer, const bool Alternate)
{
//Initialization
	std::shared_ptr<char> SendBuffer(new char[PACKET_MAXSIZE]()), RecvBuffer(new char[LARGE_PACKET_MAXSIZE]());
	sockaddr_storage SockAddr = {0};
	SYSTEM_SOCKET TCPSocket = 0;

//Packet
	size_t DataLength = sizeof(tcp_dns_hdr);
	auto ptcp_dns_hdr = (tcp_dns_hdr *)SendBuffer.get();
	ptcp_dns_hdr->ID = Parameter.DomainTestOptions.DomainTestID;
	ptcp_dns_hdr->Flags = htons(DNS_STANDARD);
	ptcp_dns_hdr->Questions = htons(U16_NUM_1);
	
	if (NetworkLayer == AF_INET6) //IPv6
	{
		if (Alternate)
			DataLength += CharToDNSQuery(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ProviderName, SendBuffer.get() + DataLength);
		else 
			DataLength += CharToDNSQuery(DNSCurveParameter.DNSCurveTarget.IPv6.ProviderName, SendBuffer.get() + DataLength);
	}
	else { //IPv4
		if (Alternate)
			DataLength += CharToDNSQuery(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ProviderName, SendBuffer.get() + DataLength);
		else 
			DataLength += CharToDNSQuery(DNSCurveParameter.DNSCurveTarget.IPv4.ProviderName, SendBuffer.get() + DataLength);
	}

	auto pdns_qry = (dns_qry *)(SendBuffer.get() + DataLength);
	pdns_qry->Type = htons(DNS_TXT_RECORDS);
	pdns_qry->Classes = htons(DNS_CLASS_IN);
	DataLength += sizeof(dns_qry);

//EDNS0 Label
	ptcp_dns_hdr->Additional = htons(U16_NUM_1);
	auto pdns_edns0_label = (dns_edns0_label *)(SendBuffer.get() + DataLength);
	pdns_edns0_label->Type = htons(DNS_EDNS0_RECORDS);
	pdns_edns0_label->UDPPayloadSize = htons(EDNS0_MINSIZE);
	DataLength += sizeof(dns_edns0_label);

	ptcp_dns_hdr->Length = htons((uint16_t)(DataLength - sizeof(uint16_t)));
//Socket initialization
	int AddrLen = 0;
	if (NetworkLayer == AF_INET6) //IPv6
	{
		AddrLen = sizeof(sockaddr_in6);
		SockAddr.ss_family = AF_INET6;
		TCPSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);

		if (Alternate)
		{
			((PSOCKADDR_IN6)&SockAddr)->sin6_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
			((PSOCKADDR_IN6)&SockAddr)->sin6_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
		}
		else { //Main
			((PSOCKADDR_IN6)&SockAddr)->sin6_addr = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_addr;
			((PSOCKADDR_IN6)&SockAddr)->sin6_port = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_port;
		}
	}
	else { //IPv4
		AddrLen = sizeof(sockaddr_in);
		SockAddr.ss_family = AF_INET;
		TCPSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

		if (Alternate)
		{
			((PSOCKADDR_IN)&SockAddr)->sin_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
			((PSOCKADDR_IN)&SockAddr)->sin_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
		}
		else { //Main
			((PSOCKADDR_IN)&SockAddr)->sin_addr = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_addr;
			((PSOCKADDR_IN)&SockAddr)->sin_port = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_port;
		}
	}

	SSIZE_T RecvLen = 0;
	while (true)
	{
	//Check socket.
		if (TCPSocket == INVALID_SOCKET)
		{
			PrintError(LOG_ERROR_WINSOCK, L"DNSCurve socket(s) initialization error", WSAGetLastError(), nullptr, NULL);
			return false;
		}

	//Set socket timeout.
/* Old version(2014-07-22)

		if (setsockopt(TCPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.ReliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR || 
			setsockopt(TCPSocket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.ReliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR)
*/
		if (setsockopt(TCPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.ReliableSocketTimeout, sizeof(int)) == SOCKET_ERROR || 
			setsockopt(TCPSocket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.ReliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
		{
			PrintError(LOG_ERROR_WINSOCK, L"Set TCP socket timeout error", WSAGetLastError(), nullptr, NULL);
			closesocket(TCPSocket);

			return false;
		}

	//Connect to server.
		if (connect(TCPSocket, (PSOCKADDR)&SockAddr, AddrLen) == SOCKET_ERROR) //Connection is RESET or other errors when connecting.
		{
			closesocket(TCPSocket);
			if (NetworkLayer == AF_INET6) //IPv6
				TCPSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
			else //IPv4
				TCPSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

			Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
			continue;
		}

	//Send request.
		if (send(TCPSocket, SendBuffer.get(), (int)DataLength, NULL) == SOCKET_ERROR)
		{
			PrintError(LOG_ERROR_DNSCURVE, L"TCP get signature data request error", WSAGetLastError(), nullptr, NULL);
			closesocket(TCPSocket);

			if (NetworkLayer == AF_INET6) //IPv6
				TCPSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
			else //IPv4
				TCPSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

			Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
			continue;
		}
		else {
			RecvLen = recv(TCPSocket, RecvBuffer.get(), LARGE_PACKET_MAXSIZE, NULL);
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
			else if (htons(((uint16_t *)RecvBuffer.get())[0]) <= sizeof(dns_hdr) + 1U + sizeof(dns_qry) + sizeof(dns_txt_record) + DNSCRYPT_TXT_RECORDS_LEN) //TCP segment of a reassembled PDU
			{
				size_t PDULen = htons(((uint16_t *)RecvBuffer.get())[0]);
				memset(RecvBuffer.get(), 0, LARGE_PACKET_MAXSIZE);
				RecvLen = recv(TCPSocket, RecvBuffer.get(), LARGE_PACKET_MAXSIZE, NULL) - sizeof(uint16_t);
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
				else if (PDULen > sizeof(dns_hdr) + 1U + sizeof(dns_qry) + sizeof(dns_txt_record) + DNSCRYPT_TXT_RECORDS_LEN)
				{
					memmove(RecvBuffer.get(), RecvBuffer.get() + sizeof(uint16_t), PDULen);

				//Check result.
					if (Alternate)
					{
						if (NetworkLayer == AF_INET6) //IPv6
						{
							if (!GetSignatureData(RecvBuffer.get() + sizeof(dns_hdr) + strlen(RecvBuffer.get() + sizeof(dns_hdr)) + 1U + sizeof(dns_qry), DNSCURVE_ALTERNATEIPV6) || 
								CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES) || 
								CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
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
						else { //IPv4
							if (!GetSignatureData(RecvBuffer.get() + sizeof(dns_hdr) + strlen(RecvBuffer.get() + sizeof(dns_hdr)) + 1U + sizeof(dns_qry), DNSCURVE_ALTERNATEIPV4) || 
								CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES) || 
								CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
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
					}
					else {
						if (NetworkLayer == AF_INET6) //IPv6
						{
							if (!GetSignatureData(RecvBuffer.get() + sizeof(dns_hdr) + strlen(RecvBuffer.get() + sizeof(dns_hdr)) + 1U + sizeof(dns_qry), DNSCURVE_MAINIPV6) || 
								CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES) || 
								CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
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
						else { //IPv4
							if (!GetSignatureData(RecvBuffer.get() + sizeof(dns_hdr) + strlen(RecvBuffer.get() + sizeof(dns_hdr)) + 1U + sizeof(dns_qry), DNSCURVE_MAINIPV4) || 
								CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES) || 
								CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
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
					}
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
			else if (htons(((uint16_t *)RecvBuffer.get())[0]) > sizeof(dns_hdr) + 1U + sizeof(dns_qry) + sizeof(dns_txt_record) + DNSCRYPT_TXT_RECORDS_LEN)
			{
				RecvLen = htons(((uint16_t *)RecvBuffer.get())[0]);
				memmove(RecvBuffer.get(), RecvBuffer.get() + sizeof(uint16_t), RecvLen);

			//Check result.
				if (Alternate)
				{
					if (NetworkLayer == AF_INET6) //IPv6
					{
						if (!GetSignatureData(RecvBuffer.get() + sizeof(dns_hdr) + strlen(RecvBuffer.get() + sizeof(dns_hdr)) + 1U + sizeof(dns_qry), DNSCURVE_ALTERNATEIPV6) || 
							CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES) || 
							CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
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
					else { //IPv4
						if (!GetSignatureData(RecvBuffer.get() + sizeof(dns_hdr) + strlen(RecvBuffer.get() + sizeof(dns_hdr)) + 1U + sizeof(dns_qry), DNSCURVE_ALTERNATEIPV4) || 
							CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES) || 
							CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
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
				}
				else {
					if (NetworkLayer == AF_INET6) //IPv6
					{
						if (!GetSignatureData(RecvBuffer.get() + sizeof(dns_hdr) + strlen(RecvBuffer.get() + sizeof(dns_hdr)) + 1U + sizeof(dns_qry), DNSCURVE_MAINIPV6) || 
							CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES) || 
							CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
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
					else { //IPv4
						if (!GetSignatureData(RecvBuffer.get() + sizeof(dns_hdr) + strlen(RecvBuffer.get() + sizeof(dns_hdr)) + 1U + sizeof(dns_qry), DNSCURVE_MAINIPV4) || 
							CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES) || 
							CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
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
				}
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

	return true;
}

//Send UDP request to get Signature Data of server(s)
inline bool __fastcall DNSCurveUDPSignatureRequest(const uint16_t NetworkLayer, const bool Alternate)
{
//Initialization
	std::shared_ptr<char> SendBuffer(new char[PACKET_MAXSIZE]()), RecvBuffer(new char[PACKET_MAXSIZE]());
	sockaddr_storage SockAddr = {0};
	SYSTEM_SOCKET UDPSocket = 0;

//Packet
	size_t DataLength = sizeof(dns_hdr);
	dns_hdr *pdns_hdr = (dns_hdr *)SendBuffer.get();
	pdns_hdr->ID = Parameter.DomainTestOptions.DomainTestID;
	pdns_hdr->Flags = htons(DNS_STANDARD);
	pdns_hdr->Questions = htons(U16_NUM_1);

	if (NetworkLayer == AF_INET6) //IPv6
	{
		if (Alternate)
			DataLength += CharToDNSQuery(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ProviderName, SendBuffer.get() + DataLength);
		else 
			DataLength += CharToDNSQuery(DNSCurveParameter.DNSCurveTarget.IPv6.ProviderName, SendBuffer.get() + DataLength);
	}
	else { //IPv4
		if (Alternate)
			DataLength += CharToDNSQuery(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ProviderName, SendBuffer.get() + DataLength);
		else 
			DataLength += CharToDNSQuery(DNSCurveParameter.DNSCurveTarget.IPv4.ProviderName, SendBuffer.get() + DataLength);
	}

	auto pdns_qry = (dns_qry *)(SendBuffer.get() + DataLength);
	pdns_qry->Type = htons(DNS_TXT_RECORDS);
	pdns_qry->Classes = htons(DNS_CLASS_IN);
	DataLength += sizeof(dns_qry);

//EDNS0 Label
	pdns_hdr->Additional = htons(U16_NUM_1);
	auto pdns_edns0_label = (dns_edns0_label *)(SendBuffer.get() + DataLength);
	pdns_edns0_label->Type = htons(DNS_EDNS0_RECORDS);
	pdns_edns0_label->UDPPayloadSize = htons(EDNS0_MINSIZE);
	DataLength += sizeof(dns_edns0_label);

//Socket initialization
	int AddrLen = 0;
	if (NetworkLayer == AF_INET6) //IPv6
	{
		if (Alternate)
		{
			((PSOCKADDR_IN6)&SockAddr)->sin6_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
			((PSOCKADDR_IN6)&SockAddr)->sin6_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
		}
		else { //Main
			((PSOCKADDR_IN6)&SockAddr)->sin6_addr = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_addr;
			((PSOCKADDR_IN6)&SockAddr)->sin6_port = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_port;
		}

		SockAddr.ss_family = AF_INET6;
		AddrLen = sizeof(sockaddr_in6);
		UDPSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	}
	else { //IPv4
		if (Alternate)
		{
			((PSOCKADDR_IN)&SockAddr)->sin_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
			((PSOCKADDR_IN)&SockAddr)->sin_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
		}
		else { //Main
			((PSOCKADDR_IN)&SockAddr)->sin_addr = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_addr;
			((PSOCKADDR_IN)&SockAddr)->sin_port = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_port;
		}

		SockAddr.ss_family = AF_INET;
		AddrLen = sizeof(sockaddr_in);
		UDPSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	}

//Check socket.
	if (UDPSocket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_WINSOCK, L"DNSCurve socket(s) initialization error", WSAGetLastError(), nullptr, NULL);
		return false;
	}

//Set socket timeout.
/* Old version(2014-07-22)
	if (setsockopt(UDPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR || 
		setsockopt(UDPSocket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR)
*/
	if (setsockopt(UDPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR || 
		setsockopt(UDPSocket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket timeout error", WSAGetLastError(), nullptr, NULL);
		closesocket(UDPSocket);

		return false;
	}

//Send request.
	SSIZE_T RecvLen = 0;
	while (true)
	{
		if (sendto(UDPSocket, SendBuffer.get(), (int)DataLength, NULL, (PSOCKADDR)&SockAddr, AddrLen) == SOCKET_ERROR)
		{
			closesocket(UDPSocket);
			PrintError(LOG_ERROR_DNSCURVE, L"UDP get signature data request error", WSAGetLastError(), nullptr, NULL);

			if (NetworkLayer == AF_INET6) //IPv6
				UDPSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
			else //IPv4
				UDPSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

		//Check socket.
			if (UDPSocket == INVALID_SOCKET)
			{
				PrintError(LOG_ERROR_WINSOCK, L"DNSCurve socket(s) initialization error", WSAGetLastError(), nullptr, NULL);
				return false;
			}

		//Set socket timeout.
/* Old version(2014-07-22)
			if (setsockopt(UDPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR || 
				setsockopt(UDPSocket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR)
*/
			if (setsockopt(UDPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR || 
				setsockopt(UDPSocket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
			{
				closesocket(UDPSocket);
				PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket timeout error", WSAGetLastError(), nullptr, NULL);

				return false;
			}

			Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
			continue;
		}
		else {
			RecvLen = recvfrom(UDPSocket, RecvBuffer.get(), PACKET_MAXSIZE, NULL, (PSOCKADDR)&SockAddr, &AddrLen);
			if (RecvLen > (SSIZE_T)(sizeof(dns_hdr) + 1U + sizeof(dns_qry) + sizeof(dns_txt_record) + DNSCRYPT_TXT_RECORDS_LEN))
			{
				//Check result.
				if (Alternate)
				{
					if (NetworkLayer == AF_INET6) //IPv6
					{
						if (!GetSignatureData(RecvBuffer.get() + sizeof(dns_hdr) + strlen(RecvBuffer.get() + sizeof(dns_hdr)) + 1U + sizeof(dns_qry), DNSCURVE_ALTERNATEIPV6) ||
							CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES) ||
							CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
						{
							memset(RecvBuffer.get(), 0, PACKET_MAXSIZE);
							Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
							continue;
						}

						memset(RecvBuffer.get(), 0, PACKET_MAXSIZE);
					}
					else { //IPv4
						if (!GetSignatureData(RecvBuffer.get() + sizeof(dns_hdr) + strlen(RecvBuffer.get() + sizeof(dns_hdr)) + 1U + sizeof(dns_qry), DNSCURVE_ALTERNATEIPV4) ||
							CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES) ||
							CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
						{
							memset(RecvBuffer.get(), 0, PACKET_MAXSIZE);
							Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
							continue;
						}

						memset(RecvBuffer.get(), 0, PACKET_MAXSIZE);
					}
				}
				else {
					if (NetworkLayer == AF_INET6) //IPv6
					{
						if (!GetSignatureData(RecvBuffer.get() + sizeof(dns_hdr) + strlen(RecvBuffer.get() + sizeof(dns_hdr)) + 1U + sizeof(dns_qry), DNSCURVE_MAINIPV6) ||
							CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES) ||
							CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
						{
							memset(RecvBuffer.get(), 0, PACKET_MAXSIZE);
							Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
							continue;
						}

						memset(RecvBuffer.get(), 0, PACKET_MAXSIZE);
					}
					else { //IPv4
						if (!GetSignatureData(RecvBuffer.get() + sizeof(dns_hdr) + strlen(RecvBuffer.get() + sizeof(dns_hdr)) + 1U + sizeof(dns_qry), DNSCURVE_MAINIPV4) ||
							CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES) ||
							CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
						{
							memset(RecvBuffer.get(), 0, PACKET_MAXSIZE);
							Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
							continue;
						}

						memset(RecvBuffer.get(), 0, PACKET_MAXSIZE);
					}
				}
			}
			else {
				memset(RecvBuffer.get(), 0, PACKET_MAXSIZE);
				if (LocalSignatureRequest(SendBuffer.get(), (int)DataLength, RecvBuffer.get(), PACKET_MAXSIZE) > sizeof(dns_hdr) + 1U + sizeof(dns_qry) + sizeof(dns_txt_record) + DNSCRYPT_TXT_RECORDS_LEN)
				{
					//Check result.
					if (Alternate)
					{
						if (NetworkLayer == AF_INET6) //IPv6
						{
							if (!GetSignatureData(RecvBuffer.get() + sizeof(dns_hdr) + strlen(RecvBuffer.get() + sizeof(dns_hdr)) + 1U + sizeof(dns_qry), DNSCURVE_ALTERNATEIPV6) ||
								CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES) ||
								CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
							{
								memset(RecvBuffer.get(), 0, PACKET_MAXSIZE);
								Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
								continue;
							}

							memset(RecvBuffer.get(), 0, PACKET_MAXSIZE);
						}
						else { //IPv4
							if (!GetSignatureData(RecvBuffer.get() + sizeof(dns_hdr) + strlen(RecvBuffer.get() + sizeof(dns_hdr)) + 1U + sizeof(dns_qry), DNSCURVE_ALTERNATEIPV4) ||
								CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES) ||
								CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
							{
								memset(RecvBuffer.get(), 0, PACKET_MAXSIZE);
								Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
								continue;
							}

							memset(RecvBuffer.get(), 0, PACKET_MAXSIZE);
						}
					}
					else {
						if (NetworkLayer == AF_INET6) //IPv6
						{
							if (!GetSignatureData(RecvBuffer.get() + sizeof(dns_hdr) + strlen(RecvBuffer.get() + sizeof(dns_hdr)) + 1U + sizeof(dns_qry), DNSCURVE_MAINIPV6) ||
								CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES) ||
								CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
							{
								memset(RecvBuffer.get(), 0, PACKET_MAXSIZE);
								Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
								continue;
							}

							memset(RecvBuffer.get(), 0, PACKET_MAXSIZE);
						}
						else { //IPv4
							if (!GetSignatureData(RecvBuffer.get() + sizeof(dns_hdr) + strlen(RecvBuffer.get() + sizeof(dns_hdr)) + 1U + sizeof(dns_qry), DNSCURVE_MAINIPV4) ||
								CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES) ||
								CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
							{
								memset(RecvBuffer.get(), 0, PACKET_MAXSIZE);
								Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
								continue;
							}

							memset(RecvBuffer.get(), 0, PACKET_MAXSIZE);
						}
					}
				}
				else {
					Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
					continue;
				}
			}
		}

		Sleep((DWORD)DNSCurveParameter.KeyRecheckTime);
	}

	return true;
}

//Get Signature Data of server form packets
bool __fastcall GetSignatureData(const PSTR Buffer, const size_t ServerType)
{
	auto pdns_txt_record = (dns_txt_record *)Buffer;
	if (pdns_txt_record->Name == htons(DNS_QUERY_PTR) &&
		pdns_txt_record->Length == htons(pdns_txt_record->TXT_Length + 1U) && pdns_txt_record->TXT_Length == DNSCRYPT_TXT_RECORDS_LEN)
	{
		auto pdnscurve_txt_hdr = (dnscurve_txt_hdr *)(Buffer + sizeof(dns_txt_record));
		if (memcmp(&pdnscurve_txt_hdr->CertMagicNumber, DNSCRYPT_CERT_MAGIC, sizeof(uint16_t)) == 0 && 
			pdnscurve_txt_hdr->MajorVersion == htons(DNSCURVE_VERSION_MAJOR) && pdnscurve_txt_hdr->MinorVersion == DNSCURVE_VERSION_MINOR)
		{
			std::shared_ptr<char> DeBuffer(new char[PACKET_MAXSIZE]());
			dnscurve_txt_signature *SignatureData = nullptr;
			ULONGLONG SignatureLength = 0;

			if (ServerType == DNSCURVE_MAINIPV6)
			{
			//Check Signature.
				if (crypto_sign_ed25519_open((PUINT8)DeBuffer.get(), &SignatureLength, (PUINT8)(Buffer + sizeof(dns_txt_record) + sizeof(dnscurve_txt_hdr)), pdns_txt_record->TXT_Length - sizeof(dnscurve_txt_hdr), DNSCurveParameter.DNSCurveTarget.IPv6.ServerPublicKey) == RETURN_ERROR)
				{
					PrintError(LOG_ERROR_DNSCURVE, L"IPv6 Main Server Fingerprint signature validation error", NULL, nullptr, NULL);
					return false;
				}

				SignatureData = (dnscurve_txt_signature *)DeBuffer.get();
			//Check available(time) Signature.
				if (time(NULL) >= (time_t)ntohl(SignatureData->CertTime_Begin) && time(NULL) <= (time_t)ntohl(SignatureData->CertTime_End))
				{
					memcpy(DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber, SignatureData->MagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
					memcpy(DNSCurveParameter.DNSCurveTarget.IPv6.ServerFingerprint, SignatureData->PublicKey, crypto_box_PUBLICKEYBYTES);
					crypto_box_curve25519xsalsa20poly1305_beforenm(
						DNSCurveParameter.DNSCurveTarget.IPv6.PrecomputationKey, 
						DNSCurveParameter.DNSCurveTarget.IPv6.ServerFingerprint, 
						DNSCurveParameter.Client_SecretKey);
					
					return true;
				}
				else {
					PrintError(LOG_ERROR_DNSCURVE, L"IPv6 Main Server Fingerprint signature is not available", NULL, nullptr, NULL);
				}
			}
			else if (ServerType == DNSCURVE_MAINIPV4)
			{
			//Check Signature.
				if (crypto_sign_ed25519_open((PUINT8)DeBuffer.get(), &SignatureLength, (PUINT8)(Buffer + sizeof(dns_txt_record) + sizeof(dnscurve_txt_hdr)), pdns_txt_record->TXT_Length - sizeof(dnscurve_txt_hdr), DNSCurveParameter.DNSCurveTarget.IPv4.ServerPublicKey) == RETURN_ERROR)
				{
					PrintError(LOG_ERROR_DNSCURVE, L"IPv4 Main Server Fingerprint signature validation error", NULL, nullptr, NULL);
					return false;
				}

				SignatureData = (dnscurve_txt_signature *)DeBuffer.get();
			//Check available(time) Signature.
				if (time(NULL) >= (time_t)ntohl(SignatureData->CertTime_Begin) && time(NULL) <= (time_t)ntohl(SignatureData->CertTime_End))
				{
					memcpy(DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber, SignatureData->MagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
					memcpy(DNSCurveParameter.DNSCurveTarget.IPv4.ServerFingerprint, SignatureData->PublicKey, crypto_box_PUBLICKEYBYTES);
					crypto_box_curve25519xsalsa20poly1305_beforenm(
						DNSCurveParameter.DNSCurveTarget.IPv4.PrecomputationKey, 
						DNSCurveParameter.DNSCurveTarget.IPv4.ServerFingerprint, 
						DNSCurveParameter.Client_SecretKey);

					return true;
				}
				else {
					PrintError(LOG_ERROR_DNSCURVE, L"IPv4 Main Server Fingerprint signature is not available", NULL, nullptr, NULL);
				}
			}
			else if (ServerType == DNSCURVE_ALTERNATEIPV6)
			{
			//Check Signature.
				if (crypto_sign_ed25519_open((PUINT8)DeBuffer.get(), &SignatureLength, (PUINT8)(Buffer + sizeof(dns_txt_record) + sizeof(dnscurve_txt_hdr)), pdns_txt_record->TXT_Length - sizeof(dnscurve_txt_hdr), DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ServerPublicKey) == RETURN_ERROR)
				{
					PrintError(LOG_ERROR_DNSCURVE, L"IPv6 Alternate Server Fingerprint signature validation error", NULL, nullptr, NULL);
					return false;
				}

				SignatureData = (dnscurve_txt_signature *)DeBuffer.get();
			//Check available(time) Signature.
				if (time(NULL) >= (time_t)ntohl(SignatureData->CertTime_Begin) && time(NULL) <= (time_t)ntohl(SignatureData->CertTime_End))
				{
					memcpy(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, SignatureData->MagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
					memcpy(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ServerFingerprint, SignatureData->PublicKey, crypto_box_PUBLICKEYBYTES);
					crypto_box_curve25519xsalsa20poly1305_beforenm(
						DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey, 
						DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ServerFingerprint, 
						DNSCurveParameter.Client_SecretKey);

					return true;
				}
				else {
					PrintError(LOG_ERROR_DNSCURVE, L"IPv6 Alternate Server Fingerprint signature is not available", NULL, nullptr, NULL);
				}
			}
			else if (ServerType == DNSCURVE_ALTERNATEIPV4)
			{
			//Check Signature.
				if (crypto_sign_ed25519_open((PUINT8)DeBuffer.get(), &SignatureLength, (PUINT8)(Buffer + sizeof(dns_txt_record) + sizeof(dnscurve_txt_hdr)), pdns_txt_record->TXT_Length - sizeof(dnscurve_txt_hdr), DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ServerPublicKey) == RETURN_ERROR)
				{
					PrintError(LOG_ERROR_DNSCURVE, L"IPv4 Alternate Server Fingerprint signature validation error", NULL, nullptr, NULL);
					return false;
				}

				SignatureData = (dnscurve_txt_signature *)DeBuffer.get();
			//Check available(time) Signature.
				if (time(NULL) >= (time_t)ntohl(SignatureData->CertTime_Begin) && time(NULL) <= (time_t)ntohl(SignatureData->CertTime_End))
				{
					memcpy(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.SendMagicNumber, SignatureData->MagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
					memcpy(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ServerFingerprint, SignatureData->PublicKey, crypto_box_PUBLICKEYBYTES);
					crypto_box_curve25519xsalsa20poly1305_beforenm(
						DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.PrecomputationKey, 
						DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ServerFingerprint, 
						DNSCurveParameter.Client_SecretKey);
					
					return true;
				}
				else {
					PrintError(LOG_ERROR_DNSCURVE, L"IPv4 Alternate Server Fingerprint signature is not available", NULL, nullptr, NULL);
				}
			}
		}
	}

	return false;
}

//Transmission of DNSCurve TCP protocol
size_t __fastcall DNSCurveTCPRequest(const PSTR Send, const size_t SendSize, PSTR Recv, const size_t RecvSize, const SOCKET_DATA TargetData, const bool Alternate, const bool Encryption)
{
//Initialization
/*	if (Encryption && (SendSize > DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES) || 
		RecvSize < DNSCurveParameter.DNSCurvePayloadSize || RecvSize < crypto_box_ZEROBYTES + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES + SendSize))
			return EXIT_FAILURE;
*/
	sockaddr_storage SockAddr = {0};
	SYSTEM_SOCKET TCPSocket = 0;
	int AddrLen = 0;

//Socket initialization
	if (DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family != NULL && //IPv6
		TargetData.AddrLen == sizeof(sockaddr_in6) || TargetData.AddrLen == sizeof(sockaddr_in) && DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family == NULL)
	{
		if (Alternate && DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL)
		{
			if (Encryption)
			{
				if (!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) &&
					!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					((PSOCKADDR_IN6)&SockAddr)->sin6_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
					((PSOCKADDR_IN6)&SockAddr)->sin6_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
			else {
				((PSOCKADDR_IN6)&SockAddr)->sin6_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&SockAddr)->sin6_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
			}
		}
		else if (DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family != NULL) //Main
		{
			if (Encryption)
			{
				if (!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) &&
					!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					((PSOCKADDR_IN6)&SockAddr)->sin6_addr = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_addr;
					((PSOCKADDR_IN6)&SockAddr)->sin6_port = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
			else {
				((PSOCKADDR_IN6)&SockAddr)->sin6_addr = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&SockAddr)->sin6_port = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_port;
			}
		}
		else {
			return EXIT_FAILURE;
		}

		SockAddr.ss_family = AF_INET6;
		TCPSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
		AddrLen = sizeof(sockaddr_in6);
	}
	else if (DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL) //IPv4
	{
		if (Alternate && DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL)
		{
		//Encryption mode
			if (Encryption)
			{
				if (!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) &&
					!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					((PSOCKADDR_IN)&SockAddr)->sin_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
					((PSOCKADDR_IN)&SockAddr)->sin_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
		//Normal mode
			else {
				((PSOCKADDR_IN)&SockAddr)->sin_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)&SockAddr)->sin_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
			}
		}
		else if (DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family != NULL) //Main
		{
		//Encryption mode
			if (Encryption)
			{
				if (!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) &&
					!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					((PSOCKADDR_IN)&SockAddr)->sin_addr = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_addr;
					((PSOCKADDR_IN)&SockAddr)->sin_port = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
		//Normal mode
			else {
				((PSOCKADDR_IN)&SockAddr)->sin_addr = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)&SockAddr)->sin_port = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_port;
			}
		}
		else {
			return EXIT_FAILURE;
		}

		SockAddr.ss_family = AF_INET;
		TCPSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		AddrLen = sizeof(sockaddr_in);
	}
	else {
		return EXIT_FAILURE;
	}

//Check socket.
	if (TCPSocket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_WINSOCK, L"DNSCurve socket(s) initialization error", WSAGetLastError(), nullptr, NULL);
		return EXIT_FAILURE;
	}

//Set socket timeout.
/* Old version(2014-07-22)
	if (setsockopt(TCPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.ReliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR || 
		setsockopt(TCPSocket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.ReliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR)
*/
	if (setsockopt(TCPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.ReliableSocketTimeout, sizeof(int)) == SOCKET_ERROR || 
		setsockopt(TCPSocket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.ReliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket timeout error", WSAGetLastError(), nullptr, NULL);
		closesocket(TCPSocket);

		return EXIT_FAILURE;
	}

//Encryption mode
	std::shared_ptr<uint8_t> WholeNonce;
	if (Encryption)
	{
		std::shared_ptr<uint8_t> BufferTemp(new uint8_t[crypto_box_NONCEBYTES]());
		WholeNonce.swap(BufferTemp);
		BufferTemp.reset();

	//Make nonce.
// Move to global initialization(2014-08-11)
//		randombytes_stir();
		*(uint32_t *)WholeNonce.get() = randombytes_random();
		*(uint32_t *)(WholeNonce.get() + sizeof(uint32_t)) = randombytes_random();
		*(uint32_t *)(WholeNonce.get() + sizeof(uint32_t) * 2U) = randombytes_random();
		memset(WholeNonce.get() + crypto_box_HALF_NONCEBYTES, 0, crypto_box_HALF_NONCEBYTES);
/*
		if (randombytes_close() != 0)
		{
			closesocket(TCPSocket);
			PrintError(LOG_ERROR_DNSCURVE, L"Ramdom module close error", NULL, nullptr, NULL);

			return EXIT_FAILURE;
		}
*/
	//Make a crypto box.
		std::shared_ptr<char> Buffer(new char[DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES)]());
		memcpy(Buffer.get() + crypto_box_ZEROBYTES, Send, SendSize);
		Buffer.get()[crypto_box_ZEROBYTES + SendSize] = '\x80';

		if (AddrLen == sizeof(sockaddr_in6)) //IPv6
		{
			if (Alternate)
			{
				if (crypto_box_curve25519xsalsa20poly1305_afternm(
						(PUCHAR)Recv + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES - crypto_box_BOXZEROBYTES, 
						(PUCHAR)Buffer.get(), 
						DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES), 
						WholeNonce.get(), 
						DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey) != 0)
				{
					closesocket(TCPSocket);
					memset(Recv, 0, RecvSize);

					return EXIT_FAILURE;
				}

			//Packet(A part)
				memcpy(Recv + sizeof(uint16_t), DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
			}
			else { //Main
				if (crypto_box_curve25519xsalsa20poly1305_afternm(
						(PUCHAR)Recv + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES - crypto_box_BOXZEROBYTES, 
						(PUCHAR)Buffer.get(), 
						DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES), 
						WholeNonce.get(),
						DNSCurveParameter.DNSCurveTarget.IPv6.PrecomputationKey) != 0)
				{
					closesocket(TCPSocket);
					memset(Recv, 0, RecvSize);

					return EXIT_FAILURE;
				}

			//Packet(A part)
				memcpy(Recv + sizeof(uint16_t), DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
			}
		}
		else { //IPv4
			if (Alternate)
			{
				if (crypto_box_curve25519xsalsa20poly1305_afternm(
						(PUCHAR)Recv + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES - crypto_box_BOXZEROBYTES, 
						(PUCHAR)Buffer.get(), 
						DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES), 
						WholeNonce.get(), 
						DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.PrecomputationKey) != 0)
				{
					closesocket(TCPSocket);
					memset(Recv, 0, RecvSize);

					return EXIT_FAILURE;
				}

			//Packet(A part)
				memcpy(Recv + sizeof(uint16_t), DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
			}
			else { //Main
				if (crypto_box_curve25519xsalsa20poly1305_afternm(
						(PUCHAR)Recv + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES - crypto_box_BOXZEROBYTES, 
						(PUCHAR)Buffer.get(), 
						DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES),
						WholeNonce.get(), 
						DNSCurveParameter.DNSCurveTarget.IPv4.PrecomputationKey) != 0)
				{
					closesocket(TCPSocket);
					memset(Recv, 0, RecvSize);

					return EXIT_FAILURE;
				}

			//Packet(A part)
				memcpy(Recv + sizeof(uint16_t), DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
			}
		}

		//Packet(B part)
		Buffer.reset();
		memcpy(Recv + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN, DNSCurveParameter.Client_PublicKey, crypto_box_PUBLICKEYBYTES);
		memcpy(Recv + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES, WholeNonce.get(), crypto_box_HALF_NONCEBYTES);
		*(uint16_t *)Recv = htons((uint16_t)(DNSCurveParameter.DNSCurvePayloadSize - sizeof(uint16_t)));
		memset(WholeNonce.get(), 0, crypto_box_NONCEBYTES);

	//Connect to server.
		if (connect(TCPSocket, (PSOCKADDR)&SockAddr, AddrLen) == SOCKET_ERROR) //Connection is RESET or other errors when connecting.
		{
			if (!Alternate && WSAGetLastError() == WSAETIMEDOUT)
			{
				closesocket(TCPSocket);
				return WSAETIMEDOUT;
			}
			else {
				closesocket(TCPSocket);
				return EXIT_FAILURE;
			}
		}

	//Send request.
		if (send(TCPSocket, Recv, (int)DNSCurveParameter.DNSCurvePayloadSize, NULL) == SOCKET_ERROR)
		{
			PrintError(LOG_ERROR_WINSOCK, L"DNSCurve TCP request error", WSAGetLastError(), nullptr, NULL);
			closesocket(TCPSocket);

			if (!Alternate && WSAGetLastError() == WSAETIMEDOUT)
				return WSAETIMEDOUT;
			else 
				return EXIT_FAILURE;
		}

		memset(Recv, 0, RecvSize);
	}
//Normal mode
	else {
		std::shared_ptr<char> Buffer(new char[sizeof(uint16_t) + SendSize]());
		memcpy(Buffer.get() + sizeof(uint16_t), Send, SendSize);
		auto BufferLength = (uint16_t *)Buffer.get();
		*BufferLength = htons((uint16_t)SendSize);

	//Connect to server.
		if (connect(TCPSocket, (PSOCKADDR)&SockAddr, AddrLen) == SOCKET_ERROR) //Connection is RESET or other errors when connecting.
		{
			if (!Alternate && WSAGetLastError() == WSAETIMEDOUT)
			{
				closesocket(TCPSocket);
				return WSAETIMEDOUT;
			}
			else {
				closesocket(TCPSocket);
				return EXIT_FAILURE;
			}
		}

	//Send request.
		if (send(TCPSocket, Buffer.get(), (int)(sizeof(uint16_t) + SendSize), NULL) == SOCKET_ERROR)
		{
			PrintError(LOG_ERROR_WINSOCK, L"DNSCurve TCP request error", WSAGetLastError(), nullptr, NULL);
			if (!Alternate && WSAGetLastError() == WSAETIMEDOUT)
			{
				closesocket(TCPSocket);
				return WSAETIMEDOUT;
			}
			else {
				closesocket(TCPSocket);
				return EXIT_FAILURE;
			}
		}
	}

//Receive result.
	SSIZE_T RecvLen = recv(TCPSocket, Recv, (int)RecvSize, NULL);
	if (!Alternate && WSAGetLastError() == WSAETIMEDOUT)
	{
		closesocket(TCPSocket);
		return WSAETIMEDOUT;
	}

	//Encryption mode
	if (Encryption)
	{
		closesocket(TCPSocket);
		if (RecvLen > (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES + sizeof(dns_hdr) + 1U + sizeof(dns_qry)))
		{
			if (RecvLen >= (SSIZE_T)ntohs(((uint16_t *)Recv)[0]))
			{
				RecvLen = ntohs(((uint16_t *)Recv)[0]);
				memmove(Recv, Recv + sizeof(uint16_t), RecvLen);
				memset(Recv + RecvLen, 0, RecvSize - RecvLen);
			}
			else {
				memset(Recv, 0, RecvSize);
				return EXIT_FAILURE;
			}

		//Check receive magic number.
			if (AddrLen == sizeof(sockaddr_in6)) //IPv6
			{
				if (Alternate)
				{
					if (memcmp(Recv, DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN) != 0)
					{
						memset(Recv, 0, RecvSize);
						return EXIT_FAILURE;
					}

				//Copy whole nonce.
					memcpy(WholeNonce.get(), Recv + DNSCURVE_MAGIC_QUERY_LEN, crypto_box_NONCEBYTES);

				//Open crypto box.
					memset(Recv, 0, DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);
					memmove(Recv + crypto_box_BOXZEROBYTES, Recv + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
					if (crypto_box_curve25519xsalsa20poly1305_open_afternm(
							(PUCHAR)Recv, 
							(PUCHAR)Recv, 
							RecvLen + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES), 
							WholeNonce.get(), 
							DNSCurveParameter.DNSCurveTarget.IPv6.PrecomputationKey) != 0)
					{
						memset(Recv, 0, RecvSize);
						return EXIT_FAILURE;
					}
					memmove(Recv, Recv + crypto_box_ZEROBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
					for (SSIZE_T Index = RecvLen - (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);Index > (SSIZE_T)(sizeof(dns_hdr) + 1U + sizeof(dns_qry));Index--)
					{
						if ((UCHAR)Recv[Index] == 0x80)
						{
							RecvLen = Index;
							break;
						}
					}

				//Responses answer(s) check
					if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckDNSLastResult(Recv + sizeof(uint16_t), RecvLen))
					{
						memset(Recv, 0, RecvSize);
						return EXIT_FAILURE;
					}

				//Mark DNS Cache
					if (Parameter.CacheType != 0)
						MarkDomainCache(Recv, RecvLen);
					return RecvLen;
				}
				else { //Main
					if (memcmp(Recv, DNSCurveParameter.DNSCurveTarget.IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN) != 0)
					{
						memset(Recv, 0, RecvSize);
						return EXIT_FAILURE;
					}

				//Copy whole nonce.
					memcpy(WholeNonce.get(), Recv + DNSCURVE_MAGIC_QUERY_LEN, crypto_box_NONCEBYTES);

				//Open crypto box.
					memset(Recv, 0, DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);
					memmove(Recv + crypto_box_BOXZEROBYTES, Recv + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
					if (crypto_box_curve25519xsalsa20poly1305_open_afternm(
							(PUCHAR)Recv, 
							(PUCHAR)Recv, 
							RecvLen + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES), 
							WholeNonce.get(), 
							DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey) != 0)
					{
						memset(Recv, 0, RecvSize);
						return EXIT_FAILURE;
					}
					memmove(Recv, Recv + crypto_box_ZEROBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
					for (SSIZE_T Index = RecvLen - (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);Index > (SSIZE_T)(sizeof(dns_hdr) + 1U + sizeof(dns_qry));Index--)
					{
						if ((UCHAR)Recv[Index] == 0x80)
						{
							RecvLen = Index;
							break;
						}
					}

				//Responses answer(s) check
					if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckDNSLastResult(Recv + sizeof(uint16_t), RecvLen))
					{
						memset(Recv, 0, RecvSize);
						return EXIT_FAILURE;
					}

				//Mark DNS Cache
					if (Parameter.CacheType != 0)
						MarkDomainCache(Recv, RecvLen);
					return RecvLen;
				}
			}
			else { //IPv4
				if (Alternate)
				{
					if (memcmp(Recv, DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN) != 0)
					{
						memset(Recv, 0, RecvSize);
						return EXIT_FAILURE;
					}

				//Copy whole nonce.
					memcpy(WholeNonce.get(), Recv + DNSCURVE_MAGIC_QUERY_LEN, crypto_box_NONCEBYTES);

				//Open crypto box.
					memset(Recv, 0, DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);
					memmove(Recv + crypto_box_BOXZEROBYTES, Recv + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
					if (crypto_box_curve25519xsalsa20poly1305_open_afternm(
							(PUCHAR)Recv, 
							(PUCHAR)Recv, 
							RecvLen + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES), 
							WholeNonce.get(), 
							DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.PrecomputationKey) != 0)
					{
						memset(Recv, 0, RecvSize);
						return EXIT_FAILURE;
					}
					memmove(Recv, Recv + crypto_box_ZEROBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
					for (SSIZE_T Index = RecvLen - (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);Index > (SSIZE_T)(sizeof(dns_hdr) + 1U + sizeof(dns_qry));Index--)
					{
						if ((UCHAR)Recv[Index] == 0x80)
						{
							RecvLen = Index;
							break;
						}
					}

				//Responses answer(s) check
					if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckDNSLastResult(Recv + sizeof(uint16_t), RecvLen))
					{
						memset(Recv, 0, RecvSize);
						return EXIT_FAILURE;
					}

				//Mark DNS Cache
					if (Parameter.CacheType != 0)
						MarkDomainCache(Recv, RecvLen);
					return RecvLen;
				}
				else { //Main
					if (memcmp(Recv, DNSCurveParameter.DNSCurveTarget.IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN) != 0)
					{
						memset(Recv, 0, RecvSize);
						return EXIT_FAILURE;
					}

				//Copy whole nonce.
					memcpy(WholeNonce.get(), Recv + DNSCURVE_MAGIC_QUERY_LEN, crypto_box_NONCEBYTES);

				//Open crypto box.
					memset(Recv, 0, DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);
					memmove(Recv + crypto_box_BOXZEROBYTES, Recv + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
					if (crypto_box_curve25519xsalsa20poly1305_open_afternm(
							(PUCHAR)Recv, 
							(PUCHAR)Recv, 
							RecvLen + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES), 
							WholeNonce.get(), 
							DNSCurveParameter.DNSCurveTarget.IPv4.PrecomputationKey) != 0)
					{
						memset(Recv, 0, RecvSize);
						return EXIT_FAILURE;
					}
					memmove(Recv, Recv + crypto_box_ZEROBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
					for (SSIZE_T Index = RecvLen - (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);Index > (SSIZE_T)(sizeof(dns_hdr) + 1U + sizeof(dns_qry));Index--)
					{
						if ((UCHAR)Recv[Index] == 0x80)
						{
							RecvLen = Index;
							break;
						}
					}

				//Responses answer(s) check
					if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckDNSLastResult(Recv + sizeof(uint16_t), RecvLen))
					{
						memset(Recv, 0, RecvSize);
						return EXIT_FAILURE;
					}

				//Mark DNS Cache
					if (Parameter.CacheType != 0)
						MarkDomainCache(Recv, RecvLen);
					return RecvLen;
				}
			}
		}
	}
//Normal mode
	else {
		if (RecvLen > 0 && (SSIZE_T)htons(((uint16_t *)Recv)[0]) <= RecvLen)
		{
			if (htons(((uint16_t *)Recv)[0]) > sizeof(dns_hdr) + 1U + sizeof(dns_qry))
			{
				closesocket(TCPSocket);
				RecvLen = htons(((uint16_t *)Recv)[0]);
				memmove(Recv, Recv + sizeof(uint16_t), RecvLen);

			//Responses answer(s) check
				if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckDNSLastResult(Recv, RecvLen))
				{
					memset(Recv, 0, RecvSize);
					return EXIT_FAILURE;
				}

			//Mark DNS Cache
				if (Parameter.CacheType != 0)
					MarkDomainCache(Recv, RecvLen);
				return RecvLen;
			}
			else { //TCP segment of a reassembled PDU or incorrect packets
				size_t PDULen = htons(((uint16_t *)Recv)[0]);
				memset(Recv, 0, RecvSize);
				RecvLen = recv(TCPSocket, Recv, (int)RecvSize, NULL);
				if (PDULen > sizeof(dns_hdr) + 1U + sizeof(dns_qry) && PDULen <= RecvSize)
				{
					closesocket(TCPSocket);

				//Responses answer(s) check
					if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckDNSLastResult(Recv, RecvLen))
					{
						memset(Recv, 0, RecvSize);
						return EXIT_FAILURE;
					}

				//Mark DNS Cache
					if (Parameter.CacheType != 0)
						MarkDomainCache(Recv, RecvLen);
					return RecvLen;
				}
			}
		}
	}

	closesocket(TCPSocket);
	memset(Recv, 0, RecvSize);
	return EXIT_FAILURE;
}

//Transmission of DNSCurve TCP protocol(Multithreading)
size_t __fastcall DNSCurveTCPRequestMulti(DNSCURVE_REQUEST_MULTITHREAD_PARAMETER &DNSCurveTCPRequestParameter, std::mutex &Mutex)
{
/*
//Initialization
	if (DNSCurveTCPRequestParameter.Encryption && (DNSCurveTCPRequestParameter.SendSize > DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES) || 
		DNSCurveTCPRequestParameter.RecvSize < DNSCurveParameter.DNSCurvePayloadSize || DNSCurveTCPRequestParameter.RecvSize < crypto_box_ZEROBYTES + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES + DNSCurveTCPRequestParameter.SendSize))
			return EXIT_FAILURE;
*/
	sockaddr_storage SockAddr = {0};
	SYSTEM_SOCKET TCPSocket = 0;
	int AddrLen = 0;

//Socket initialization
	if (DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family != NULL && //IPv6
		DNSCurveTCPRequestParameter.TargetData.AddrLen == sizeof(sockaddr_in6) || DNSCurveTCPRequestParameter.TargetData.AddrLen == sizeof(sockaddr_in) && DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family == NULL)
	{
		if (DNSCurveTCPRequestParameter.Alternate && DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL)
		{
			if (DNSCurveTCPRequestParameter.Encryption)
			{
				if (!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) &&
					!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					((PSOCKADDR_IN6)&SockAddr)->sin6_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
					((PSOCKADDR_IN6)&SockAddr)->sin6_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
			else {
				((PSOCKADDR_IN6)&SockAddr)->sin6_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&SockAddr)->sin6_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
			}
		}
		else if (DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family != NULL) //Main
		{
			if (DNSCurveTCPRequestParameter.Encryption)
			{
				if (!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) &&
					!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					((PSOCKADDR_IN6)&SockAddr)->sin6_addr = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_addr;
					((PSOCKADDR_IN6)&SockAddr)->sin6_port = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
			else {
				((PSOCKADDR_IN6)&SockAddr)->sin6_addr = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&SockAddr)->sin6_port = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_port;
			}
		}
		else {
			return EXIT_FAILURE;
		}

		SockAddr.ss_family = AF_INET6;
		TCPSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
		AddrLen = sizeof(sockaddr_in6);
	}
	else if (DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL) //IPv4
	{
		if (DNSCurveTCPRequestParameter.Alternate && DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL)
		{
		//Encryption mode
			if (DNSCurveTCPRequestParameter.Encryption)
			{
				if (!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) &&
					!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					((PSOCKADDR_IN)&SockAddr)->sin_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
					((PSOCKADDR_IN)&SockAddr)->sin_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
		//Normal mode
			else {
				((PSOCKADDR_IN)&SockAddr)->sin_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)&SockAddr)->sin_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
			}
		}
		else if (DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family != NULL) //Main
		{
		//Encryption mode
			if (DNSCurveTCPRequestParameter.Encryption)
			{
				if (!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) &&
					!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					((PSOCKADDR_IN)&SockAddr)->sin_addr = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_addr;
					((PSOCKADDR_IN)&SockAddr)->sin_port = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
		//Normal mode
			else {
				((PSOCKADDR_IN)&SockAddr)->sin_addr = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)&SockAddr)->sin_port = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_port;
			}
		}
		else {
			return EXIT_FAILURE;
		}

		SockAddr.ss_family = AF_INET;
		TCPSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		AddrLen = sizeof(sockaddr_in);
	}
	else {
		return EXIT_FAILURE;
	}

//Check socket.
	if (TCPSocket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_WINSOCK, L"DNSCurve socket(s) initialization error", WSAGetLastError(), nullptr, NULL);
		return EXIT_FAILURE;
	}

//Set socket timeout.
/* Old version(2014-07-22)
	if (setsockopt(TCPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.ReliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR || 
		setsockopt(TCPSocket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.ReliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR)
*/
	if (setsockopt(TCPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.ReliableSocketTimeout, sizeof(int)) == SOCKET_ERROR || 
		setsockopt(TCPSocket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.ReliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket timeout error", WSAGetLastError(), nullptr, NULL);
		closesocket(TCPSocket);

		return EXIT_FAILURE;
	}

	std::shared_ptr<char> RecvBuffer(new char[DNSCurveTCPRequestParameter.RecvSize]());
//Encryption mode
	std::shared_ptr<uint8_t> WholeNonce;
	if (DNSCurveTCPRequestParameter.Encryption)
	{
		std::shared_ptr<uint8_t> BufferTemp(new uint8_t[crypto_box_NONCEBYTES]());
		WholeNonce.swap(BufferTemp);
		BufferTemp.reset();

	//Make nonce.
/* Move to global initialization(2014-08-11)
		std::unique_lock<std::mutex> DNSCurveMutex(Mutex);
		randombytes_stir();
*/
		*(uint32_t *)WholeNonce.get() = randombytes_random();
		*(uint32_t *)(WholeNonce.get() + sizeof(uint32_t)) = randombytes_random();
		*(uint32_t *)(WholeNonce.get() + sizeof(uint32_t) * 2U) = randombytes_random();
		memset(WholeNonce.get() + crypto_box_HALF_NONCEBYTES, 0, crypto_box_HALF_NONCEBYTES);
/*
		if (randombytes_close() != 0)
		{
			closesocket(TCPSocket);
			PrintError(LOG_ERROR_DNSCURVE, L"Ramdom module close error", NULL, nullptr, NULL);

			return EXIT_FAILURE;
		}
		DNSCurveMutex.unlock();
*/
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
		if (connect(TCPSocket, (PSOCKADDR)&SockAddr, AddrLen) == SOCKET_ERROR) //Connection is RESET or other errors when connecting.
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

	//Send request.
		if (send(TCPSocket, RecvBuffer.get(), (int)DNSCurveParameter.DNSCurvePayloadSize, NULL) == SOCKET_ERROR)
		{
			PrintError(LOG_ERROR_WINSOCK, L"DNSCurve TCP request error", WSAGetLastError(), nullptr, NULL);
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
		if (connect(TCPSocket, (PSOCKADDR)&SockAddr, AddrLen) == SOCKET_ERROR) //Connection is RESET or other errors when connecting.
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

	//Send request.
		if (send(TCPSocket, Buffer.get(), (int)(sizeof(uint16_t) + DNSCurveTCPRequestParameter.SendSize), NULL) == SOCKET_ERROR)
		{
			PrintError(LOG_ERROR_WINSOCK, L"DNSCurve TCP request error", WSAGetLastError(), nullptr, NULL);
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
	SSIZE_T RecvLen = recv(TCPSocket, RecvBuffer.get(), (int)DNSCurveTCPRequestParameter.RecvSize, NULL);
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
		if (RecvLen > (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES + sizeof(dns_hdr) + 1U + sizeof(dns_qry)))
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
					for (SSIZE_T Index = RecvLen - (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);Index > (SSIZE_T)(sizeof(dns_hdr) + 1U + sizeof(dns_qry));Index--)
					{
						if ((UCHAR)RecvBuffer.get()[Index] == 0x80)
						{
							RecvLen = Index;
							break;
						}
					}

				//Responses answer(s) check
					if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckDNSLastResult(RecvBuffer.get() + sizeof(uint16_t), RecvLen))
						return EXIT_FAILURE;

				//Send back.
					std::unique_lock<std::mutex> DNSCurveMutex(Mutex);
					if (CheckEmptyBuffer(DNSCurveTCPRequestParameter.Recv, DNSCurveTCPRequestParameter.RecvSize) && (DNSCurveTCPRequestParameter.ReturnValue == 0 || DNSCurveTCPRequestParameter.ReturnValue == WSAETIMEDOUT))
					{
						memcpy(DNSCurveTCPRequestParameter.Recv, RecvBuffer.get(), RecvLen);
						DNSCurveTCPRequestParameter.ReturnValue = RecvLen;
						DNSCurveMutex.unlock();

					//Mark DNS Cache
						if (Parameter.CacheType != 0)
							MarkDomainCache(RecvBuffer.get(), RecvLen);

						return RecvLen;
					}
					else {
						return EXIT_FAILURE;
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
					for (SSIZE_T Index = RecvLen - (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);Index > (SSIZE_T)(sizeof(dns_hdr) + 1U + sizeof(dns_qry));Index--)
					{
						if ((UCHAR)RecvBuffer.get()[Index] == 0x80)
						{
							RecvLen = Index;
							break;
						}
					}

				//Responses answer(s) check
					if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckDNSLastResult(RecvBuffer.get() + sizeof(uint16_t), RecvLen))
						return EXIT_FAILURE;

				//Send back.
					std::unique_lock<std::mutex> DNSCurveMutex(Mutex);
					if (CheckEmptyBuffer(DNSCurveTCPRequestParameter.Recv, DNSCurveTCPRequestParameter.RecvSize) && (DNSCurveTCPRequestParameter.ReturnValue == 0 || DNSCurveTCPRequestParameter.ReturnValue == WSAETIMEDOUT))
					{
						memcpy(DNSCurveTCPRequestParameter.Recv, RecvBuffer.get(), RecvLen);
						DNSCurveTCPRequestParameter.ReturnValue = RecvLen;
						DNSCurveMutex.unlock();

					//Mark DNS Cache
						if (Parameter.CacheType != 0)
							MarkDomainCache(RecvBuffer.get(), RecvLen);

						return RecvLen;
					}
					else {
						return EXIT_FAILURE;
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
					for (SSIZE_T Index = RecvLen - (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);Index > (SSIZE_T)(sizeof(dns_hdr) + 1U + sizeof(dns_qry));Index--)
					{
						if ((UCHAR)RecvBuffer.get()[Index] == 0x80)
						{
							RecvLen = Index;
							break;
						}
					}

				//Responses answer(s) check
					if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckDNSLastResult(RecvBuffer.get() + sizeof(uint16_t), RecvLen))
						return EXIT_FAILURE;

				//Send back.
					std::unique_lock<std::mutex> DNSCurveMutex(Mutex);
					if (CheckEmptyBuffer(DNSCurveTCPRequestParameter.Recv, DNSCurveTCPRequestParameter.RecvSize) && (DNSCurveTCPRequestParameter.ReturnValue == 0 || DNSCurveTCPRequestParameter.ReturnValue == WSAETIMEDOUT))
					{
						memcpy(DNSCurveTCPRequestParameter.Recv, RecvBuffer.get(), RecvLen);
						DNSCurveTCPRequestParameter.ReturnValue = RecvLen;
						DNSCurveMutex.unlock();

					//Mark DNS Cache
						if (Parameter.CacheType != 0)
							MarkDomainCache(RecvBuffer.get(), RecvLen);

						return RecvLen;
					}
					else {
						return EXIT_FAILURE;
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
					for (SSIZE_T Index = RecvLen - (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);Index > (SSIZE_T)(sizeof(dns_hdr) + 1U + sizeof(dns_qry));Index--)
					{
						if ((UCHAR)RecvBuffer.get()[Index] == 0x80)
						{
							RecvLen = Index;
							break;
						}
					}

				//Responses answer(s) check
					if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckDNSLastResult(RecvBuffer.get() + sizeof(uint16_t), RecvLen))
						return EXIT_FAILURE;

				//Send back.
					std::unique_lock<std::mutex> DNSCurveMutex(Mutex);
					if (CheckEmptyBuffer(DNSCurveTCPRequestParameter.Recv, DNSCurveTCPRequestParameter.RecvSize) && (DNSCurveTCPRequestParameter.ReturnValue == 0 || DNSCurveTCPRequestParameter.ReturnValue == WSAETIMEDOUT))
					{
						memcpy(DNSCurveTCPRequestParameter.Recv, RecvBuffer.get(), RecvLen);
						DNSCurveTCPRequestParameter.ReturnValue = RecvLen;
						DNSCurveMutex.unlock();

					//Mark DNS Cache
						if (Parameter.CacheType != 0)
							MarkDomainCache(RecvBuffer.get(), RecvLen);

						return RecvLen;
					}
					else {
						return EXIT_FAILURE;
					}
				}
			}
		}
	}
//Normal mode
	else {
		if (RecvLen > 0 && (SSIZE_T)htons(((uint16_t *)RecvBuffer.get())[0]) <= RecvLen)
		{
			if (htons(((uint16_t *)RecvBuffer.get())[0]) > sizeof(dns_hdr) + 1U + sizeof(dns_qry))
			{
				closesocket(TCPSocket);
				RecvLen = htons(((uint16_t *)RecvBuffer.get())[0]);

			//Responses answer(s) check
				if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckDNSLastResult(RecvBuffer.get(), RecvLen))
					return EXIT_FAILURE;

			//Send back.
				std::unique_lock<std::mutex> DNSCurveMutex(Mutex);
				if (CheckEmptyBuffer(DNSCurveTCPRequestParameter.Recv, DNSCurveTCPRequestParameter.RecvSize) && (DNSCurveTCPRequestParameter.ReturnValue == 0 || DNSCurveTCPRequestParameter.ReturnValue == WSAETIMEDOUT))
				{
					memcpy(DNSCurveTCPRequestParameter.Recv, RecvBuffer.get(), RecvLen);
					DNSCurveTCPRequestParameter.ReturnValue = RecvLen;
					DNSCurveMutex.unlock();

				//Mark DNS Cache
					if (Parameter.CacheType != 0)
						MarkDomainCache(RecvBuffer.get(), RecvLen);

					return RecvLen;
				}
				else {
					return EXIT_FAILURE;
				}
			}
			else { //TCP segment of a reassembled PDU or incorrect packets
				size_t PDULen = htons(((uint16_t *)RecvBuffer.get())[0]);
				memset(RecvBuffer.get(), 0, DNSCurveTCPRequestParameter.RecvSize);
				RecvLen = recv(TCPSocket, RecvBuffer.get(), (int)DNSCurveTCPRequestParameter.RecvSize, NULL);
				if (PDULen > sizeof(dns_hdr) + 1U + sizeof(dns_qry) && PDULen <= DNSCurveTCPRequestParameter.RecvSize)
				{
					closesocket(TCPSocket);

				//Responses answer(s) check
					if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckDNSLastResult(RecvBuffer.get(), RecvLen))
						return EXIT_FAILURE;

				//Send back.
					std::unique_lock<std::mutex> DNSCurveMutex(Mutex);
					if (CheckEmptyBuffer(DNSCurveTCPRequestParameter.Recv, DNSCurveTCPRequestParameter.RecvSize) && (DNSCurveTCPRequestParameter.ReturnValue == 0 || DNSCurveTCPRequestParameter.ReturnValue == WSAETIMEDOUT))
					{
						memcpy(DNSCurveTCPRequestParameter.Recv, RecvBuffer.get(), RecvLen);
						DNSCurveTCPRequestParameter.ReturnValue = RecvLen;
						DNSCurveMutex.unlock();

					//Mark DNS Cache
						if (Parameter.CacheType != 0)
							MarkDomainCache(RecvBuffer.get(), RecvLen);

						return RecvLen;
					}
					else {
						return EXIT_FAILURE;
					}
				}
			}
		}
	}

	closesocket(TCPSocket);
	return EXIT_FAILURE;
}

//Transmission of DNSCurve UDP protocol
size_t __fastcall DNSCurveUDPRequest(const PSTR Send, const size_t SendSize, PSTR Recv, const size_t RecvSize, const SOCKET_DATA TargetData, const bool Alternate, const bool Encryption)
{
//Initialization
/*	if (Encryption && (SendSize > DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES) || 
		RecvSize < DNSCurveParameter.DNSCurvePayloadSize || RecvSize < crypto_box_ZEROBYTES + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES + SendSize))
			return EXIT_FAILURE;
*/
	sockaddr_storage SockAddr = {0};
	SYSTEM_SOCKET UDPSocket = 0;
	int AddrLen = 0;

//Socket initialization
	if (DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family != NULL && //IPv6
		TargetData.AddrLen == sizeof(sockaddr_in6) || TargetData.AddrLen == sizeof(sockaddr_in) && DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family == NULL)
	{
		if (Alternate && DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL)
		{
			if (Encryption)
			{
				if (!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) &&
					!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					((PSOCKADDR_IN6)&SockAddr)->sin6_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
					((PSOCKADDR_IN6)&SockAddr)->sin6_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
			else {
				((PSOCKADDR_IN6)&SockAddr)->sin6_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&SockAddr)->sin6_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
			}
		}
		else if (DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family != NULL) //Main
		{
			if (Encryption)
			{
				if (!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) &&
					!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					((PSOCKADDR_IN6)&SockAddr)->sin6_addr = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_addr;
					((PSOCKADDR_IN6)&SockAddr)->sin6_port = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
			else {
				((PSOCKADDR_IN6)&SockAddr)->sin6_addr = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&SockAddr)->sin6_port = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_port;
			}
		}
		else {
			return EXIT_FAILURE;
		}

		SockAddr.ss_family = AF_INET6;
		UDPSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		AddrLen = sizeof(sockaddr_in6);
	}
	else if (DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family != NULL) //IPv4
	{
		if (Alternate && DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL)
		{
		//Encryption mode
			if (Encryption)
			{
				if (!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) &&
					!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					((PSOCKADDR_IN)&SockAddr)->sin_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
					((PSOCKADDR_IN)&SockAddr)->sin_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
		//Normal mode
			else {
				((PSOCKADDR_IN)&SockAddr)->sin_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)&SockAddr)->sin_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
			}
		}
		else if (DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family != NULL) //Main
		{
		//Encryption mode
			if (Encryption)
			{
				if (!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) &&
					!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					((PSOCKADDR_IN)&SockAddr)->sin_addr = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_addr;
					((PSOCKADDR_IN)&SockAddr)->sin_port = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
		//Normal mode
			else {
				((PSOCKADDR_IN)&SockAddr)->sin_addr = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)&SockAddr)->sin_port = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_port;
			}
		}
		else {
			return EXIT_FAILURE;
		}

		SockAddr.ss_family = AF_INET;
		UDPSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		AddrLen = sizeof(sockaddr_in);
	}

//Check socket.
	if (UDPSocket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_WINSOCK, L"DNSCurve socket(s) initialization error", WSAGetLastError(), nullptr, NULL);
		return EXIT_FAILURE;
	}

//Set socket timeout.
/* Old version(2014-07-22)
	if (setsockopt(UDPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR || 
		setsockopt(UDPSocket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR)
*/
	if (setsockopt(UDPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR || 
		setsockopt(UDPSocket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket timeout error", WSAGetLastError(), nullptr, NULL);
		closesocket(UDPSocket);

		return EXIT_FAILURE;
	}

//Encryption mode
	std::shared_ptr<uint8_t> WholeNonce;
	if (Encryption)
	{
		std::shared_ptr<uint8_t> BufferTemp(new uint8_t[crypto_box_NONCEBYTES]());
		WholeNonce.swap(BufferTemp);
		BufferTemp.reset();

	//Make nonce.
// Move to global initialization(2014-08-11)
//		randombytes_stir();
		*(uint32_t *)WholeNonce.get() = randombytes_random();
		*(uint32_t *)(WholeNonce.get() + sizeof(uint32_t)) = randombytes_random();
		*(uint32_t *)(WholeNonce.get() + sizeof(uint32_t) * 2U) = randombytes_random();
		memset(WholeNonce.get() + crypto_box_HALF_NONCEBYTES, 0, crypto_box_HALF_NONCEBYTES);
/*
		if (randombytes_close() != 0)
		{
			closesocket(UDPSocket);
			PrintError(LOG_ERROR_DNSCURVE, L"Ramdom module close error", NULL, nullptr, NULL);

			return EXIT_FAILURE;
		}
*/
	//Make a crypto box.
		std::shared_ptr<char> Buffer(new char[DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES)]());
		memcpy(Buffer.get() + crypto_box_ZEROBYTES, Send, SendSize);
		Buffer.get()[crypto_box_ZEROBYTES + SendSize] = '\x80';

		if (AddrLen == sizeof(sockaddr_in6)) //IPv6
		{
			if (Alternate)
			{
				if (crypto_box_curve25519xsalsa20poly1305_afternm(
						(PUCHAR)Recv + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES - crypto_box_BOXZEROBYTES, 
						(PUCHAR)Buffer.get(), 
						DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES), 
						WholeNonce.get(), 
						DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey) != 0)
				{
					closesocket(UDPSocket);
					memset(Recv, 0, RecvSize);

					return EXIT_FAILURE;
				}

			//Packet(A part)
				memcpy(Recv, DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
			}
			else { //Main
				if (crypto_box_curve25519xsalsa20poly1305_afternm(
						(PUCHAR)Recv + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES - crypto_box_BOXZEROBYTES, 
						(PUCHAR)Buffer.get(), 
						DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES), 
						WholeNonce.get(), 
						DNSCurveParameter.DNSCurveTarget.IPv6.PrecomputationKey) != 0)
				{
					closesocket(UDPSocket);
					memset(Recv, 0, RecvSize);

					return EXIT_FAILURE;
				}

			//Packet(A part)
				memcpy(Recv, DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
			}
		}
		else { //IPv4
			if (Alternate)
			{
				if (crypto_box_curve25519xsalsa20poly1305_afternm(
						(PUCHAR)Recv + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES - crypto_box_BOXZEROBYTES, 
						(PUCHAR)Buffer.get(),
						DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES), 
						WholeNonce.get(), 
						DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.PrecomputationKey) != 0)
				{
					closesocket(UDPSocket);
					memset(Recv, 0, RecvSize);

					return EXIT_FAILURE;
				}

			//Packet(A part)
				memcpy(Recv, DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
			}
			else { //Main
				if (crypto_box_curve25519xsalsa20poly1305_afternm(
						(PUCHAR)Recv + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES - crypto_box_BOXZEROBYTES, 
						(PUCHAR)Buffer.get(), 
						DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES),
						WholeNonce.get(), 
						DNSCurveParameter.DNSCurveTarget.IPv4.PrecomputationKey) != 0)
				{
					closesocket(UDPSocket);
					memset(Recv, 0, RecvSize);

					return EXIT_FAILURE;
				}

			//Packet(A part)
				memcpy(Recv, DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
			}
		}

		//Packet(B part)
		Buffer.reset();
		memcpy(Recv + DNSCURVE_MAGIC_QUERY_LEN, DNSCurveParameter.Client_PublicKey, crypto_box_PUBLICKEYBYTES);
		memcpy(Recv + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES, WholeNonce.get(), crypto_box_HALF_NONCEBYTES);
		memset(WholeNonce.get(), 0, crypto_box_NONCEBYTES);

//Send request.
		if (sendto(UDPSocket, Recv, (int)DNSCurveParameter.DNSCurvePayloadSize, NULL, (PSOCKADDR)&SockAddr, AddrLen) == SOCKET_ERROR)
		{
			PrintError(LOG_ERROR_WINSOCK, L"DNSCurve UDP request error", WSAGetLastError(), nullptr, NULL);
			closesocket(UDPSocket);

			return EXIT_FAILURE;
		}

		memset(Recv, 0, RecvSize);
	}
//Normal mode
	else {
		WholeNonce.reset();
		if (sendto(UDPSocket, Send, (int)SendSize, NULL, (PSOCKADDR)&SockAddr, AddrLen) == SOCKET_ERROR)
		{
			PrintError(LOG_ERROR_WINSOCK, L"DNSCurve UDP request error", WSAGetLastError(), nullptr, NULL);
			closesocket(UDPSocket);

			return EXIT_FAILURE;
		}
	}

//Receive result.
	SSIZE_T RecvLen = recvfrom(UDPSocket, Recv, (int)RecvSize, NULL, (PSOCKADDR)&SockAddr, (PINT)&AddrLen);
	if (RecvLen <= (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES + sizeof(dns_hdr) + 1U + sizeof(dns_qry)))
	{
		if (WSAGetLastError() == WSAETIMEDOUT)
		{
			closesocket(UDPSocket);
			return WSAETIMEDOUT;
		}
		else {
			return EXIT_FAILURE;
		}
	}

	closesocket(UDPSocket);
//Encryption mode
	if (Encryption)
	{
		memset(Recv + RecvLen, 0, RecvSize - RecvLen);

	//Check receive magic number.
		if (AddrLen == sizeof(sockaddr_in6)) //IPv6
		{
			if (Alternate)
			{
				if (memcmp(Recv, DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN) != 0)
				{
					memset(Recv, 0, RecvSize);
					return EXIT_FAILURE;
				}

			//Copy whole nonce.
				memcpy(WholeNonce.get(), Recv + DNSCURVE_MAGIC_QUERY_LEN, crypto_box_NONCEBYTES);

			//Open crypto box.
				memset(Recv, 0, DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);
				memmove(Recv + crypto_box_BOXZEROBYTES, Recv + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
				if (crypto_box_curve25519xsalsa20poly1305_open_afternm(
						(PUCHAR)Recv, 
						(PUCHAR)Recv, 
						RecvLen + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES), 
						WholeNonce.get(), 
						DNSCurveParameter.DNSCurveTarget.IPv6.PrecomputationKey) != 0)
				{
					memset(Recv, 0, RecvSize);
					return EXIT_FAILURE;
				}
				memmove(Recv, Recv + crypto_box_ZEROBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
				for (SSIZE_T Index = RecvLen - (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);Index > (SSIZE_T)(sizeof(dns_hdr) + 1U + sizeof(dns_qry));Index--)
				{
					if ((UCHAR)Recv[Index] == 0x80)
					{
						RecvLen = Index;
						break;
					}
				}

			//Responses answer(s) check
				if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckDNSLastResult(Recv, RecvLen))
				{
					memset(Recv, 0, RecvSize);
					return EXIT_FAILURE;
				}

			//Mark DNS Cache
				if (Parameter.CacheType != 0)
					MarkDomainCache(Recv, RecvLen);
				return RecvLen;
			}
			else { //Main
				if (memcmp(Recv, DNSCurveParameter.DNSCurveTarget.IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN) != 0)
				{
					memset(Recv, 0, RecvSize);
					return EXIT_FAILURE;
				}

			//Copy whole nonce.
				memcpy(WholeNonce.get(), Recv + DNSCURVE_MAGIC_QUERY_LEN, crypto_box_NONCEBYTES);

			//Open crypto box.
				memset(Recv, 0, DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);
				memmove(Recv + crypto_box_BOXZEROBYTES, Recv + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
				if (crypto_box_curve25519xsalsa20poly1305_open_afternm(
						(PUCHAR)Recv, 
						(PUCHAR)Recv, 
						RecvLen + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES), 
						WholeNonce.get(), 
						DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey) != 0)
				{
					memset(Recv, 0, RecvSize);
					return EXIT_FAILURE;
				}
				memmove(Recv, Recv + crypto_box_ZEROBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
				for (SSIZE_T Index = RecvLen - (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);Index > (SSIZE_T)(sizeof(dns_hdr) + 1U + sizeof(dns_qry));Index--)
				{
					if ((UCHAR)Recv[Index] == 0x80)
					{
						RecvLen = Index;
						break;
					}
				}

			//Responses answer(s) check
				if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckDNSLastResult(Recv, RecvLen))
				{
					memset(Recv, 0, RecvSize);
					return EXIT_FAILURE;
				}

			//Mark DNS Cache
				if (Parameter.CacheType != 0)
					MarkDomainCache(Recv, RecvLen);
				return RecvLen;
			}
		}
		else { //IPv4
			if (Alternate)
			{
				if (memcmp(Recv, DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN) != 0)
				{
					memset(Recv, 0, RecvSize);
					return EXIT_FAILURE;
				}

			//Copy whole nonce.
				memcpy(WholeNonce.get(), Recv + DNSCURVE_MAGIC_QUERY_LEN, crypto_box_NONCEBYTES);
				
			//Open crypto box.
				memset(Recv, 0, DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);
				memmove(Recv + crypto_box_BOXZEROBYTES, Recv + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
				if (crypto_box_curve25519xsalsa20poly1305_open_afternm(
						(PUCHAR)Recv, 
						(PUCHAR)Recv, 
						RecvLen + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES), 
						WholeNonce.get(), 
						DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.PrecomputationKey) != 0)
				{
					memset(Recv, 0, RecvSize);
					return EXIT_FAILURE;
				}
				memmove(Recv, Recv + crypto_box_ZEROBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
				for (SSIZE_T Index = RecvLen - (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);Index > (SSIZE_T)(sizeof(dns_hdr) + 1U + sizeof(dns_qry));Index--)
				{
					if ((UCHAR)Recv[Index] == 0x80)
					{
						RecvLen = Index;
						break;
					}
				}

			//Responses answer(s) check
				if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckDNSLastResult(Recv, RecvLen))
				{
					memset(Recv, 0, RecvSize);
					return EXIT_FAILURE;
				}

			//Mark DNS Cache
				if (Parameter.CacheType != 0)
					MarkDomainCache(Recv, RecvLen);
				return RecvLen;
			}
			else { //Main
				if (memcmp(Recv, DNSCurveParameter.DNSCurveTarget.IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN) != 0)
				{
					memset(Recv, 0, RecvSize);
					return EXIT_FAILURE;
				}

			//Copy whole nonce.
				memcpy(WholeNonce.get(), Recv + DNSCURVE_MAGIC_QUERY_LEN, crypto_box_NONCEBYTES);

			//Open crypto box.
				memset(Recv, 0, DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);
				memmove(Recv + crypto_box_BOXZEROBYTES, Recv + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
				if (crypto_box_curve25519xsalsa20poly1305_open_afternm(
						(PUCHAR)Recv, 
						(PUCHAR)Recv, 
						RecvLen + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES), 
						WholeNonce.get(), 
						DNSCurveParameter.DNSCurveTarget.IPv4.PrecomputationKey) != 0)
				{
					memset(Recv, 0, RecvSize);
					return EXIT_FAILURE;
				}
				memmove(Recv, Recv + crypto_box_ZEROBYTES, RecvLen - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
				for (SSIZE_T Index = RecvLen - (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);Index > (SSIZE_T)(sizeof(dns_hdr) + 1U + sizeof(dns_qry));Index--)
				{
					if ((UCHAR)Recv[Index] == 0x80)
					{
						RecvLen = Index;
						break;
					}
				}

			//Responses answer(s) check
				if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckDNSLastResult(Recv, RecvLen))
				{
					memset(Recv, 0, RecvSize);
					return EXIT_FAILURE;
				}

			//Mark DNS Cache
				if (Parameter.CacheType != 0)
					MarkDomainCache(Recv, RecvLen);
				return RecvLen;
			}
		}
	}
//Normal mode
	else {
	//EDNS0 Label and responses answer(s) check
		auto pdns_hdr = (dns_hdr *)Recv;
		if (pdns_hdr->Additional == 0 || (Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckDNSLastResult(Recv, RecvLen))
		{
			memset(Recv, 0, RecvSize);
			return EXIT_FAILURE;
		}

	//Mark DNS Cache
		if (Parameter.CacheType != 0)
			MarkDomainCache(Recv, RecvLen);
		return RecvLen;
	}

	memset(Recv, 0, RecvSize);
	return EXIT_FAILURE;
}

//Transmission of DNSCurve UDP protocol(Multithreading)
size_t __fastcall DNSCurveUDPRequestMulti(DNSCURVE_REQUEST_MULTITHREAD_PARAMETER &DNSCurveUDPRequestParameter, std::mutex &Mutex)
{
//Initialization
/*	if (DNSCurveUDPRequestParameter.Encryption && (DNSCurveUDPRequestParameter.SendSize > DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES) || 
		DNSCurveUDPRequestParameter.RecvSize < DNSCurveParameter.DNSCurvePayloadSize || DNSCurveUDPRequestParameter.RecvSize < crypto_box_ZEROBYTES + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES + DNSCurveUDPRequestParameter.SendSize))
			return EXIT_FAILURE;
*/
	sockaddr_storage SockAddr = {0};
	SYSTEM_SOCKET UDPSocket = 0;
	int AddrLen = 0;

//Socket initialization
	if (DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family != NULL && //IPv6
		DNSCurveUDPRequestParameter.TargetData.AddrLen == sizeof(sockaddr_in6) || DNSCurveUDPRequestParameter.TargetData.AddrLen == sizeof(sockaddr_in) && DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family == NULL)
	{
		if (DNSCurveUDPRequestParameter.Alternate && DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL)
		{
			if (DNSCurveUDPRequestParameter.Encryption)
			{
				if (!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) &&
					!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					((PSOCKADDR_IN6)&SockAddr)->sin6_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
					((PSOCKADDR_IN6)&SockAddr)->sin6_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
			else {
				((PSOCKADDR_IN6)&SockAddr)->sin6_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&SockAddr)->sin6_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
			}
		}
		else if (DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family != NULL) //Main
		{
			if (DNSCurveUDPRequestParameter.Encryption)
			{
				if (!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) &&
					!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					((PSOCKADDR_IN6)&SockAddr)->sin6_addr = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_addr;
					((PSOCKADDR_IN6)&SockAddr)->sin6_port = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
			else {
				((PSOCKADDR_IN6)&SockAddr)->sin6_addr = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&SockAddr)->sin6_port = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_port;
			}
		}
		else {
			return EXIT_FAILURE;
		}

		SockAddr.ss_family = AF_INET6;
		UDPSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		AddrLen = sizeof(sockaddr_in6);
	}
	else if (DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family != NULL) //IPv4
	{
		if (DNSCurveUDPRequestParameter.Alternate && DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL)
		{
		//Encryption mode
			if (DNSCurveUDPRequestParameter.Encryption)
			{
				if (!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) &&
					!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					((PSOCKADDR_IN)&SockAddr)->sin_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
					((PSOCKADDR_IN)&SockAddr)->sin_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
		//Normal mode
			else {
				((PSOCKADDR_IN)&SockAddr)->sin_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)&SockAddr)->sin_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
			}
		}
		else if (DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family != NULL) //Main
		{
		//Encryption mode
			if (DNSCurveUDPRequestParameter.Encryption)
			{
				if (!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) &&
					!CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					((PSOCKADDR_IN)&SockAddr)->sin_addr = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_addr;
					((PSOCKADDR_IN)&SockAddr)->sin_port = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
		//Normal mode
			else {
				((PSOCKADDR_IN)&SockAddr)->sin_addr = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)&SockAddr)->sin_port = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_port;
			}
		}
		else {
			return EXIT_FAILURE;
		}

		SockAddr.ss_family = AF_INET;
		UDPSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		AddrLen = sizeof(sockaddr_in);
	}

//Check socket.
	if (UDPSocket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_WINSOCK, L"DNSCurve socket(s) initialization error", WSAGetLastError(), nullptr, NULL);
		return EXIT_FAILURE;
	}

//Set socket timeout.
/* Old version(2014-07-22)
	if (setsockopt(UDPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR || 
		setsockopt(UDPSocket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR)
*/
	if (setsockopt(UDPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR || 
		setsockopt(UDPSocket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket timeout error", WSAGetLastError(), nullptr, NULL);
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
/* Move to global initialization(2014-08-11)
		std::unique_lock<std::mutex> DNSCurveMutex(Mutex);
		randombytes_stir();
*/
		*(uint32_t *)WholeNonce.get() = randombytes_random();
		*(uint32_t *)(WholeNonce.get() + sizeof(uint32_t)) = randombytes_random();
		*(uint32_t *)(WholeNonce.get() + sizeof(uint32_t) * 2U) = randombytes_random();
		memset(WholeNonce.get() + crypto_box_HALF_NONCEBYTES, 0, crypto_box_HALF_NONCEBYTES);
/* 
		if (randombytes_close() != 0)
		{
			closesocket(UDPSocket);
			PrintError(LOG_ERROR_DNSCURVE, L"Ramdom module close error", NULL, nullptr, NULL);

			return EXIT_FAILURE;
		}
		DNSCurveMutex.unlock();
*/
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

//Send request.
		if (sendto(UDPSocket, RecvBuffer.get(), (int)DNSCurveParameter.DNSCurvePayloadSize, NULL, (PSOCKADDR)&SockAddr, AddrLen) == SOCKET_ERROR)
		{
			PrintError(LOG_ERROR_WINSOCK, L"DNSCurve UDP request error", WSAGetLastError(), nullptr, NULL);
			closesocket(UDPSocket);

			return EXIT_FAILURE;
		}

		memset(RecvBuffer.get(), 0, DNSCurveUDPRequestParameter.RecvSize);
	}
//Normal mode
	else {
		WholeNonce.reset();
		if (sendto(UDPSocket, DNSCurveUDPRequestParameter.Send, (int)DNSCurveUDPRequestParameter.SendSize, NULL, (PSOCKADDR)&SockAddr, AddrLen) == SOCKET_ERROR)
		{
			closesocket(UDPSocket);
			PrintError(LOG_ERROR_WINSOCK, L"DNSCurve UDP request error", WSAGetLastError(), nullptr, NULL);

			return EXIT_FAILURE;
		}
	}

//Receive result.
	SSIZE_T RecvLen = recvfrom(UDPSocket, RecvBuffer.get(), (int)DNSCurveUDPRequestParameter.RecvSize, NULL, (PSOCKADDR)&SockAddr, (PINT)&AddrLen);
	if (RecvLen <= (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES + sizeof(dns_hdr) + 1U + sizeof(dns_qry)))
	{
		if (WSAGetLastError() == WSAETIMEDOUT)
		{
			closesocket(UDPSocket);

			std::unique_lock<std::mutex> DNSCurveMutex(Mutex);
			DNSCurveUDPRequestParameter.ReturnValue = WSAETIMEDOUT;
			return WSAETIMEDOUT;
		}
		else {
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
				for (SSIZE_T Index = RecvLen - (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);Index > (SSIZE_T)(sizeof(dns_hdr) + 1U + sizeof(dns_qry));Index--)
				{
					if ((UCHAR)RecvBuffer.get()[Index] == 0x80)
					{
						RecvLen = Index;
						break;
					}
				}

			//Responses answer(s) check
				if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckDNSLastResult(RecvBuffer.get(), RecvLen))
					return EXIT_FAILURE;

			//Send back.
				std::unique_lock<std::mutex> DNSCurveMutex(Mutex);
				if (CheckEmptyBuffer(DNSCurveUDPRequestParameter.Recv, DNSCurveUDPRequestParameter.RecvSize) && DNSCurveUDPRequestParameter.ReturnValue == 0)
				{
					memcpy(DNSCurveUDPRequestParameter.Recv, RecvBuffer.get(), RecvLen);
					DNSCurveUDPRequestParameter.ReturnValue = RecvLen;
					DNSCurveMutex.unlock();
						
				//Mark DNS Cache
					if (Parameter.CacheType != 0)
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
				for (SSIZE_T Index = RecvLen - (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);Index > (SSIZE_T)(sizeof(dns_hdr) + 1U + sizeof(dns_qry));Index--)
				{
					if ((UCHAR)RecvBuffer.get()[Index] == 0x80)
					{
						RecvLen = Index;
						break;
					}
				}

			//Responses answer(s) check
				if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckDNSLastResult(RecvBuffer.get(), RecvLen))
					return EXIT_FAILURE;

			//Send back.
				std::unique_lock<std::mutex> DNSCurveMutex(Mutex);
				if (CheckEmptyBuffer(DNSCurveUDPRequestParameter.Recv, DNSCurveUDPRequestParameter.RecvSize) && DNSCurveUDPRequestParameter.ReturnValue == 0)
				{
					memcpy(DNSCurveUDPRequestParameter.Recv, RecvBuffer.get(), RecvLen);
					DNSCurveUDPRequestParameter.ReturnValue = RecvLen;
					DNSCurveMutex.unlock();
						
				//Mark DNS Cache
					if (Parameter.CacheType != 0)
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
				for (SSIZE_T Index = RecvLen - (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);Index > (SSIZE_T)(sizeof(dns_hdr) + 1U + sizeof(dns_qry));Index--)
				{
					if ((UCHAR)RecvBuffer.get()[Index] == 0x80)
					{
						RecvLen = Index;
						break;
					}
				}

			//Responses answer(s) check
				if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckDNSLastResult(RecvBuffer.get(), RecvLen))
					return EXIT_FAILURE;

			//Send back.
				std::unique_lock<std::mutex> DNSCurveMutex(Mutex);
				if (CheckEmptyBuffer(DNSCurveUDPRequestParameter.Recv, DNSCurveUDPRequestParameter.RecvSize) && DNSCurveUDPRequestParameter.ReturnValue == 0)
				{
					memcpy(DNSCurveUDPRequestParameter.Recv, RecvBuffer.get(), RecvLen);
					DNSCurveUDPRequestParameter.ReturnValue = RecvLen;
					DNSCurveMutex.unlock();
						
				//Mark DNS Cache
					if (Parameter.CacheType != 0)
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
				for (SSIZE_T Index = RecvLen - (SSIZE_T)(DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);Index > (SSIZE_T)(sizeof(dns_hdr) + 1U + sizeof(dns_qry));Index--)
				{
					if ((UCHAR)RecvBuffer.get()[Index] == 0x80)
					{
						RecvLen = Index;
						break;
					}
				}

			//Responses answer(s) check
				if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckDNSLastResult(RecvBuffer.get(), RecvLen))
					return EXIT_FAILURE;

			//Send back.
				std::unique_lock<std::mutex> DNSCurveMutex(Mutex);
				if (CheckEmptyBuffer(DNSCurveUDPRequestParameter.Recv, DNSCurveUDPRequestParameter.RecvSize) && DNSCurveUDPRequestParameter.ReturnValue == 0)
				{
					memcpy(DNSCurveUDPRequestParameter.Recv, RecvBuffer.get(), RecvLen);
					DNSCurveUDPRequestParameter.ReturnValue = RecvLen;
					DNSCurveMutex.unlock();
						
				//Mark DNS Cache
					if (Parameter.CacheType != 0)
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
	//EDNS0 Label and responses answer(s) check
		auto pdns_hdr = (dns_hdr *)RecvBuffer.get();
		if (pdns_hdr->Additional == 0 || (Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckDNSLastResult(RecvBuffer.get(), RecvLen))
			return EXIT_FAILURE;

	//Send back.
		std::unique_lock<std::mutex> DNSCurveMutex(Mutex);
		if (CheckEmptyBuffer(DNSCurveUDPRequestParameter.Recv, DNSCurveUDPRequestParameter.RecvSize) && DNSCurveUDPRequestParameter.ReturnValue == 0)
		{
			memcpy(DNSCurveUDPRequestParameter.Recv, RecvBuffer.get(), RecvLen);
			DNSCurveUDPRequestParameter.ReturnValue = RecvLen;
			DNSCurveMutex.unlock();
						
		//Mark DNS Cache
			if (Parameter.CacheType != 0)
				MarkDomainCache(RecvBuffer.get(), RecvLen);
			return RecvLen;
		}
		else {
			return EXIT_SUCCESS;
		}
	}

	return EXIT_FAILURE;
}

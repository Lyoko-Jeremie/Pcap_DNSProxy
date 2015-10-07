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

/* DNSCurve/DNSCrypt Protocol version 2

Client -> Server:
*  8 bytes: Magic_query
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
//DNSCurve print error of servers
void __fastcall DNSCurvePrintLog(
	const size_t ServerType, 
	std::wstring &Message)
{
	switch (ServerType)
	{
		case DNSCURVE_MAIN_IPV6:
		{
			Message = L"IPv6 Main Server ";
		}break;
		case DNSCURVE_MAIN_IPV4:
		{
			Message = L"IPv4 Main Server ";
		}break;
		case DNSCURVE_ALTERNATE_IPV6:
		{
			Message = L"IPv6 Alternate Server ";
		}break;
		case DNSCURVE_ALTERNATE_IPV4:
		{
			Message = L"IPv4 Alternate Server ";
		}break;
	}

	return;
}

//DNSCurve check padding data length
SSIZE_T __fastcall DNSCurvePaddingData(
	const bool SetPadding, 
	PSTR Buffer, const SSIZE_T Length)
{
//Set padding data sign.
	if (SetPadding)
	{
		Buffer[Length] = '\x80';
	}
//Check padding data sign.
	else if (Length > (SSIZE_T)DNS_PACKET_MINSIZE)
	{
		SSIZE_T Index = 0;

	//Check padding data sign(0x80).
		for (Index = Length - 1U;Index > (SSIZE_T)DNS_PACKET_MINSIZE;--Index)
		{
			if ((UCHAR)Buffer[Index] == 0x80)
				return Index;
		}

	//Check no null sign.
		for (Index = Length - 1U;Index > (SSIZE_T)DNS_PACKET_MINSIZE;--Index)
		{
			if ((UCHAR)Buffer[Index] > 0)
				return Index;
		}
	}

	return 0;
}

//DNSCurve verify keypair
bool __fastcall DNSCurveVerifyKeypair(
	const unsigned char *PublicKey, 
	const unsigned char *SecretKey)
{
//Initialization
	std::shared_ptr<uint8_t> Test_PublicKey(new uint8_t[crypto_box_PUBLICKEYBYTES]()), 
		Test_SecretKey(new uint8_t[crypto_box_PUBLICKEYBYTES]()), 
		Validation(new uint8_t[crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES + crypto_box_ZEROBYTES]());
	memset(Test_PublicKey.get(), 0, crypto_box_PUBLICKEYBYTES);
	memset(Test_SecretKey.get(), 0, crypto_box_PUBLICKEYBYTES);
	memset(Validation.get(), 0, crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES + crypto_box_ZEROBYTES);

//Keypair, Nonce and validation data
	crypto_box_keypair(Test_PublicKey.get(), Test_SecretKey.get());
	uint8_t Nonce[crypto_box_NONCEBYTES]{DNSCURVE_TEST_NONCE};
	memcpy_s(Validation.get() + crypto_box_ZEROBYTES, crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES, PublicKey, crypto_box_PUBLICKEYBYTES);

//Verify keys
	crypto_box(Validation.get(), Validation.get(), crypto_box_PUBLICKEYBYTES + crypto_box_ZEROBYTES, Nonce, Test_PublicKey.get(), SecretKey);
	if (crypto_box_open(
			Validation.get(), 
			Validation.get(), 
			crypto_box_PUBLICKEYBYTES + crypto_box_ZEROBYTES, 
			Nonce, 
			PublicKey, 
			Test_SecretKey.get()) == LIBSODIUM_ERROR)
		return false;

	return true;
}

//DNSCurve select socket data of DNS target
size_t __fastcall DNSCurveSelectTargetSocket(
	SOCKET_DATA *TargetSocketData, 
	PDNSCURVE_SERVER_DATA &PacketTarget, 
	bool *&IsAlternate, 
	size_t *&AlternateTimeoutTimes, 
	const uint16_t Protocol)
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
		(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_NETWORK_BOTH && GlobalRunningStatus.GatewayAvailable_IPv6 || //Auto select
		DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV6 || //IPv6
		DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV4 && DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family == 0)) //Non-IPv4
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
			if (!DNSCurveParameter.ClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
				DNSCurveParameter.ClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES) || 
				CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
					*IsAlternate = true;
			if (*IsAlternate && 
				(!DNSCurveParameter.ClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
				DNSCurveParameter.ClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES) || 
				CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
					*IsAlternate = false;
		}

		if (*IsAlternate && DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0)
		{
			((PSOCKADDR_IN6)&TargetSocketData->SockAddr)->sin6_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
			((PSOCKADDR_IN6)&TargetSocketData->SockAddr)->sin6_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv6;
			ServerType = DNSCURVE_ALTERNATE_IPV6;
		}
		else { //Main
		//Encryption mode check
			if (DNSCurveParameter.IsEncryption && 
				(!DNSCurveParameter.ClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
				DNSCurveParameter.ClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES) || 
				CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
					return FALSE;

			((PSOCKADDR_IN6)&TargetSocketData->SockAddr)->sin6_addr = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_addr;
			((PSOCKADDR_IN6)&TargetSocketData->SockAddr)->sin6_port = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_port;
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv6;
			ServerType = DNSCURVE_MAIN_IPV6;
		}

		TargetSocketData->AddrLen = sizeof(sockaddr_in6);
		TargetSocketData->SockAddr.ss_family = AF_INET6;
		TargetSocketData->Socket = socket(AF_INET6, SocketType, Protocol);
		return ServerType;
	}
//IPv4
	else if (DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family > 0 && 
		(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_NETWORK_BOTH && GlobalRunningStatus.GatewayAvailable_IPv4 || //Auto select
		DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV4 || //IPv4
		DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV6 && DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family == 0)) //Non-IPv6
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
			if (!DNSCurveParameter.ClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
				DNSCurveParameter.ClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES) || 
				CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
					*IsAlternate = true;
			if (*IsAlternate && 
				(!DNSCurveParameter.ClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
				DNSCurveParameter.ClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES) || 
				CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
					*IsAlternate = false;
		}

		if (*IsAlternate && DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0)
		{
			((PSOCKADDR_IN)&TargetSocketData->SockAddr)->sin_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
			((PSOCKADDR_IN)&TargetSocketData->SockAddr)->sin_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv4;
			ServerType = DNSCURVE_ALTERNATE_IPV4;
		}
		else { //Main
		//Encryption mode check
			if (DNSCurveParameter.IsEncryption && 
				(!DNSCurveParameter.ClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
				DNSCurveParameter.ClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES) || 
				CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
					return FALSE;

			((PSOCKADDR_IN)&TargetSocketData->SockAddr)->sin_addr = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_addr;
			((PSOCKADDR_IN)&TargetSocketData->SockAddr)->sin_port = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_port;
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv4;
			ServerType = DNSCURVE_MAIN_IPV4;
		}

		TargetSocketData->AddrLen = sizeof(sockaddr_in);
		TargetSocketData->SockAddr.ss_family = AF_INET;
		TargetSocketData->Socket = socket(AF_INET, SocketType, Protocol);
		return ServerType;
	}

	return FALSE;
}

//DNSCurve select socket data of DNS target(Multithreading)
bool __fastcall DNSCurveSelectTargetSocketMulti(
	bool &IsIPv6, 
	bool *&IsAlternate, 
	const uint16_t Protocol)
{
//IPv6
	if (DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family > 0 && 
		(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_NETWORK_BOTH && GlobalRunningStatus.GatewayAvailable_IPv6 || //Auto select
		DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV6 || //IPv6
		DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV4 && DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family == 0)) //Non-IPv4
	{
		IsIPv6 = true;
		if (Protocol == IPPROTO_TCP) //TCP
			IsAlternate = &AlternateSwapList.IsSwap[8U];
		else //UDP
			IsAlternate = &AlternateSwapList.IsSwap[10U];
	}
//IPv4
	else if (DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family > 0 && 
		(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_NETWORK_BOTH && GlobalRunningStatus.GatewayAvailable_IPv4 || //Auto select
		DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV4 || //IPv4
		DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV6 && DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family == 0)) //Non-IPv6
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

//DNSCurve set packet target
bool __fastcall DNSCurvePacketTargetSetting(const size_t ServerType, PDNSCURVE_SERVER_DATA &PacketTarget)
{
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

	return true;
}

//DNSCurve set Precomputation Key between client and server
bool __fastcall DNSCurvePrecomputationKeySetting(
	PUINT8 PrecomputationKey, 
	PUINT8 Client_PublicKey, 
	const unsigned char *ServerFingerprint)
{
//Server fingerprint check
	if (CheckEmptyBuffer(ServerFingerprint, crypto_box_PUBLICKEYBYTES))
		return false;
	memset(PrecomputationKey, 0, crypto_box_BEFORENMBYTES);
	memset(Client_PublicKey, 0, crypto_box_PUBLICKEYBYTES);

//Make a client ephemeral key pair.
	std::shared_ptr<uint8_t> Client_SecretKey(new uint8_t[crypto_box_SECRETKEYBYTES]());
	memset(Client_SecretKey.get(), 0, crypto_box_SECRETKEYBYTES);
	if (crypto_box_keypair(Client_PublicKey, Client_SecretKey.get()) == LIBSODIUM_ERROR)
		return false;

//Make a precomputation key.
	if (crypto_box_beforenm(
		PrecomputationKey, 
		ServerFingerprint, 
		Client_SecretKey.get()) == LIBSODIUM_ERROR)
			return false;

	return true;
}

//DNSCurve packet precomputation
void __fastcall DNSCurveSocketPrecomputation(
	const uint16_t Protocol, 
	const char *OriginalSend, 
	const size_t SendSize, 
	const size_t RecvSize, 
	PUINT8 &PrecomputationKey, 
	PUINT8 &Alternate_PrecomputationKey, 
	PDNSCURVE_SERVER_DATA &PacketTarget, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<DNSCURVE_SOCKET_SELECTING_DATA> &SocketSelectingList, 
	std::shared_ptr<char> &SendBuffer, 
	size_t &DataLength, 
	std::shared_ptr<char> &Alternate_SendBuffer, 
	size_t &Alternate_DataLength)
{
//Initialization
	std::shared_ptr<SOCKET_DATA> SocketDataTemp(new SOCKET_DATA());
	std::shared_ptr<DNSCURVE_SOCKET_SELECTING_DATA> SocketSelectingDataTemp(new DNSCURVE_SOCKET_SELECTING_DATA());
	std::vector<SOCKET_DATA> Alternate_SocketDataList;
	std::vector<DNSCURVE_SOCKET_SELECTING_DATA> Alternate_SocketSelectingList;
	std::shared_ptr<uint8_t> Client_PublicKey_PTR(new uint8_t[crypto_box_PUBLICKEYBYTES]());
	memset(Client_PublicKey_PTR.get(), 0, crypto_box_PUBLICKEYBYTES);
	auto Client_PublicKey = Client_PublicKey_PTR.get();
	memset(SocketDataTemp.get(), 0, sizeof(SOCKET_DATA));
	bool *IsAlternate = nullptr;
	auto IsIPv6 = false;
	if (!DNSCurveSelectTargetSocketMulti(IsIPv6, IsAlternate, Protocol))
		return;
	size_t Index = 0, LoopLimits = 0;
	uint16_t InnerProtocol = 0;
	if (Protocol == IPPROTO_TCP) //TCP
		InnerProtocol = SOCK_STREAM;
	else //UDP
		InnerProtocol = SOCK_DGRAM;

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
			(!DNSCurveParameter.ClientEphemeralKey && CheckEmptyBuffer(PacketTarget->PrecomputationKey, crypto_box_BEFORENMBYTES) || 
			DNSCurveParameter.ClientEphemeralKey && CheckEmptyBuffer(PacketTarget->ServerFingerprint, crypto_box_PUBLICKEYBYTES) || 
			CheckEmptyBuffer(PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
				goto SkipMain;

	//Socket initialization
		if (Protocol == IPPROTO_TCP) //TCP
			LoopLimits = Parameter.MultiRequestTimes;
		else //UDP
			LoopLimits = 1U;
		for (Index = 0;Index < LoopLimits;++Index)
		{
			SocketDataTemp->SockAddr = PacketTarget->AddressData.Storage;
			if (IsIPv6) //IPv6
				SocketDataTemp->Socket = socket(AF_INET6, InnerProtocol, Protocol);
			else //IPv4
				SocketDataTemp->Socket = socket(AF_INET, InnerProtocol, Protocol);

		//Socket check and non-blocking mode setting
			if (!SocketSetting(SocketDataTemp->Socket, SOCKET_SETTING_INVALID_CHECK, nullptr) || 
				!SocketSetting(SocketDataTemp->Socket, SOCKET_SETTING_NON_BLOCKING_MODE, nullptr))
			{
				for (auto &SocketDataIter:SocketDataList)
					closesocket(SocketDataIter.Socket);
				SocketDataList.clear();
				SocketSelectingList.clear();

				goto SkipMain;
			}

		//IPv6
			if (IsIPv6)
			{
				SocketDataTemp->AddrLen = sizeof(sockaddr_in6);
				SocketSelectingDataTemp->ServerType = DNSCURVE_MAIN_IPV6;
			}
		//IPv4
			else {
				SocketDataTemp->AddrLen = sizeof(sockaddr_in);
				SocketSelectingDataTemp->ServerType = DNSCURVE_MAIN_IPV4;
			}

			SocketDataList.push_back(*SocketDataTemp);
			SocketSelectingList.push_back(*SocketSelectingDataTemp);
			memset(SocketDataTemp.get(), 0, sizeof(SOCKET_DATA));
		}

	//Make Precomputation Key between client and server.
		if (DNSCurveParameter.IsEncryption && DNSCurveParameter.ClientEphemeralKey)
		{
			if (!DNSCurvePrecomputationKeySetting(PrecomputationKey, Client_PublicKey, PacketTarget->ServerFingerprint))
			{
				for (auto &SocketDataIter:SocketDataList)
					closesocket(SocketDataIter.Socket);
				SocketDataList.clear();
				SocketSelectingList.clear();

				goto SkipMain;
			}
		}
		else {
			Client_PublicKey_PTR.reset();
			Client_PublicKey = DNSCurveParameter.Client_PublicKey;
			PrecomputationKey = PacketTarget->PrecomputationKey;
		}

	//Make encryption or normal packet of Main server.
		if (DNSCurveParameter.IsEncryption || Protocol == IPPROTO_TCP)
		{
			std::shared_ptr<char> SendBufferTemp(new char[RecvSize]());
			memset(SendBufferTemp.get(), 0, RecvSize);
			SendBuffer.swap(SendBufferTemp);
			DataLength = DNSCurvePacketEncryption(Protocol, PacketTarget->SendMagicNumber, Client_PublicKey, PrecomputationKey, OriginalSend, SendSize, SendBuffer.get(), RecvSize);
			if (DataLength < DNS_PACKET_MINSIZE)
			{
				for (auto &SocketDataIter : SocketDataList)
					closesocket(SocketDataIter.Socket);
				SocketDataList.clear();
				SocketSelectingList.clear();
				DataLength = 0;

				goto SkipMain;
			}
		}
	}
	
//Jump here to skip Main process
SkipMain:
	memset(SocketDataTemp.get(), 0, sizeof(SOCKET_DATA));
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
			(!DNSCurveParameter.ClientEphemeralKey && CheckEmptyBuffer(PacketTarget->PrecomputationKey, crypto_box_BEFORENMBYTES) || 
			DNSCurveParameter.ClientEphemeralKey && CheckEmptyBuffer(PacketTarget->ServerFingerprint, crypto_box_PUBLICKEYBYTES) || 
			CheckEmptyBuffer(PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
				return;
	
	//Socket initialization
		if (Protocol == IPPROTO_TCP) //TCP
			LoopLimits = Parameter.MultiRequestTimes;
		else //UDP
			LoopLimits = 1U;
		for (Index = 0;Index < LoopLimits;++Index)
		{
			SocketDataTemp->SockAddr = PacketTarget->AddressData.Storage;
			if (IsIPv6) //IPv6
				SocketDataTemp->Socket = socket(AF_INET6, InnerProtocol, Protocol);
			else //IPv4
				SocketDataTemp->Socket = socket(AF_INET, InnerProtocol, Protocol);

		//Socket check and non-blocking mode setting
			if (!SocketSetting(SocketDataTemp->Socket, SOCKET_SETTING_INVALID_CHECK, nullptr) || 
				!SocketSetting(SocketDataTemp->Socket, SOCKET_SETTING_NON_BLOCKING_MODE, nullptr))
			{
				for (auto &SocketDataIter:Alternate_SocketDataList)
					closesocket(SocketDataIter.Socket);

				return;
			}

		//IPv6
			if (IsIPv6)
			{
				SocketDataTemp->AddrLen = sizeof(sockaddr_in6);
				SocketSelectingDataTemp->ServerType = DNSCURVE_ALTERNATE_IPV6;
			}
		//IPv4
			else {
				SocketDataTemp->AddrLen = sizeof(sockaddr_in);
				SocketSelectingDataTemp->ServerType = DNSCURVE_ALTERNATE_IPV4;
			}

			Alternate_SocketDataList.push_back(*SocketDataTemp);
			Alternate_SocketSelectingList.push_back(*SocketSelectingDataTemp);
			memset(SocketDataTemp.get(), 0, sizeof(SOCKET_DATA));
		}

	//Make Precomputation Key between client and server.
		if (DNSCurveParameter.IsEncryption && DNSCurveParameter.ClientEphemeralKey)
		{
			if (!DNSCurvePrecomputationKeySetting(Alternate_PrecomputationKey, Client_PublicKey, PacketTarget->ServerFingerprint))
			{
				for (auto &SocketDataIter:Alternate_SocketDataList)
					closesocket(SocketDataIter.Socket);

				return;
			}
		}
		else {
			Client_PublicKey_PTR.reset();
			Client_PublicKey = DNSCurveParameter.Client_PublicKey;
			Alternate_PrecomputationKey = PacketTarget->PrecomputationKey;
		}

	//Make encryption or normal packet of Alternate server.
		if (DNSCurveParameter.IsEncryption)
		{
			std::shared_ptr<char> SendBufferTemp(new char[RecvSize]());
			memset(SendBufferTemp.get(), 0, RecvSize);
			Alternate_SendBuffer.swap(SendBufferTemp);
			SendBufferTemp.reset();
			Alternate_DataLength = DNSCurvePacketEncryption(Protocol, PacketTarget->SendMagicNumber, Client_PublicKey, Alternate_PrecomputationKey, OriginalSend, SendSize, Alternate_SendBuffer.get(), RecvSize);
			if (Alternate_DataLength < DNS_PACKET_MINSIZE)
			{
				for (auto &SocketDataIter : Alternate_SocketDataList)
					closesocket(SocketDataIter.Socket);
				Alternate_DataLength = 0;

				return;
			}
		}

	//Add to global list.
		if (!Alternate_SocketDataList.empty() && !Alternate_SocketSelectingList.empty())
		{
			for (auto &SocketDataIter:Alternate_SocketDataList)
				SocketDataList.push_back(SocketDataIter);
			for (auto &SocketSelectingIter:Alternate_SocketSelectingList)
				SocketSelectingList.push_back(SocketSelectingIter);
		}
	}

	return;
}

//DNSCurve packet encryption
size_t __fastcall DNSCurvePacketEncryption(
	const uint16_t Protocol, 
	const char *SendMagicNumber, 
	const unsigned char *Client_PublicKey, 
	const unsigned char *PrecomputationKey, 
	const char *OriginalSend, 
	const size_t Length, 
	PSTR SendBuffer, 
	const size_t SendSize)
{
//Encryption mode
	if (DNSCurveParameter.IsEncryption)
	{
		std::shared_ptr<uint8_t> Nonce(new uint8_t[crypto_box_NONCEBYTES]());
		memset(Nonce.get(), 0, crypto_box_NONCEBYTES);

	//Make nonce.
		*(PUINT32)Nonce.get() = randombytes_random();
		*(PUINT32)(Nonce.get() + sizeof(uint32_t)) = randombytes_random();
		*(PUINT32)(Nonce.get() + sizeof(uint32_t) * 2U) = randombytes_random();
		memset(Nonce.get() + crypto_box_HALF_NONCEBYTES, 0, crypto_box_HALF_NONCEBYTES);

	//Make a crypto box.
		std::shared_ptr<char> Buffer;
		if (Protocol == IPPROTO_TCP) //TCP
		{
			std::shared_ptr<char> BufferTemp(new char[DNSCurveParameter.DNSCurvePayloadSize - DNSCRYPT_BUFFER_RESERVE_LEN]());
			memset(BufferTemp.get(), 0, DNSCurveParameter.DNSCurvePayloadSize - DNSCRYPT_BUFFER_RESERVE_LEN);
			BufferTemp.swap(Buffer);
		}
		else { //UDP
			std::shared_ptr<char> BufferTemp(new char[DNSCurveParameter.DNSCurvePayloadSize - DNSCRYPT_BUFFER_RESERVE_LEN]());
			memset(BufferTemp.get(), 0, DNSCurveParameter.DNSCurvePayloadSize - DNSCRYPT_BUFFER_RESERVE_LEN);
			BufferTemp.swap(Buffer);
		}

		memcpy_s(Buffer.get() + crypto_box_ZEROBYTES, DNSCurveParameter.DNSCurvePayloadSize - crypto_box_ZEROBYTES, OriginalSend, Length);
		DNSCurvePaddingData(true, Buffer.get(), crypto_box_ZEROBYTES + Length);

	//Encrypt data.
		if (Protocol == IPPROTO_TCP) //TCP
		{
			if (crypto_box_afternm(
				(PUCHAR)SendBuffer + DNSCRYPT_BUFFER_RESERVE_TCP_LEN, 
				(PUCHAR)Buffer.get(), 
				DNSCurveParameter.DNSCurvePayloadSize - DNSCRYPT_BUFFER_RESERVE_TCP_LEN, 
				Nonce.get(), 
				PrecomputationKey) != EXIT_SUCCESS)
					return EXIT_FAILURE;
		}
		else { //UDP
			if (crypto_box_afternm(
				(PUCHAR)SendBuffer + DNSCRYPT_BUFFER_RESERVE_LEN, 
				(PUCHAR)Buffer.get(), 
				DNSCurveParameter.DNSCurvePayloadSize - DNSCRYPT_BUFFER_RESERVE_LEN, 
				Nonce.get(), 
				PrecomputationKey) != EXIT_SUCCESS)
					return EXIT_FAILURE;
		}

	//Make DNSCurve encryption packet.
		Buffer.reset();
		if (Protocol == IPPROTO_TCP) //TCP
		{
			memcpy_s(SendBuffer + sizeof(uint16_t), SendSize - sizeof(uint16_t), SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
			memcpy_s(SendBuffer + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN, SendSize - sizeof(uint16_t) - DNSCURVE_MAGIC_QUERY_LEN, Client_PublicKey, crypto_box_PUBLICKEYBYTES);
			memcpy_s(SendBuffer + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES, SendSize - sizeof(uint16_t) - DNSCURVE_MAGIC_QUERY_LEN - crypto_box_PUBLICKEYBYTES, Nonce.get(), crypto_box_HALF_NONCEBYTES);

		//Add length of request packet(It must be written in header when transpot with TCP protocol).
			*(PUINT16)SendBuffer = htons((uint16_t)(DNSCurveParameter.DNSCurvePayloadSize - sizeof(uint16_t)));
		}
		else { //UDP
			memcpy_s(SendBuffer, SendSize, SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
			memcpy_s(SendBuffer + DNSCURVE_MAGIC_QUERY_LEN, SendSize - DNSCURVE_MAGIC_QUERY_LEN, Client_PublicKey, crypto_box_PUBLICKEYBYTES);
			memcpy_s(SendBuffer + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES, SendSize - DNSCURVE_MAGIC_QUERY_LEN - crypto_box_PUBLICKEYBYTES, Nonce.get(), crypto_box_HALF_NONCEBYTES);
		}

		return DNSCurveParameter.DNSCurvePayloadSize;
	}
//Normal mode
	else {
		memcpy_s(SendBuffer, SendSize, OriginalSend, Length);
		if (Protocol == IPPROTO_TCP) //TCP
			return AddLengthDataToHeader(SendBuffer, Length, SendSize); //Add length of request packet(It must be written in header when transpot with TCP protocol).
		else //UDP
			return Length;
	}

	return EXIT_FAILURE;
}

//DNSCurve packet decryption
SSIZE_T DNSCurvePacketDecryption(
	const char *ReceiveMagicNumber, 
	const unsigned char *PrecomputationKey, 
	PSTR OriginalRecv, 
	const size_t RecvSize, 
	const SSIZE_T Length)
{
//Initialization
	SSIZE_T DataLength = Length;

//Encryption mode
	if (DNSCurveParameter.IsEncryption)
	{
	//Receive Magic number check
		memset(OriginalRecv + Length, 0, RecvSize - Length);
		if (memcmp(OriginalRecv, ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN) != EXIT_SUCCESS)
			return EXIT_FAILURE;

	//Nonce initialization
		std::shared_ptr<uint8_t> WholeNonce(new uint8_t[crypto_box_NONCEBYTES]());
		memset(WholeNonce.get(), 0, crypto_box_NONCEBYTES);

	//Copy whole nonce.
		memcpy_s(WholeNonce.get(), crypto_box_NONCEBYTES, OriginalRecv + DNSCURVE_MAGIC_QUERY_LEN, crypto_box_NONCEBYTES);

	//Open crypto box.
		memset(OriginalRecv, 0, DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES);
		memmove_s(OriginalRecv + crypto_box_BOXZEROBYTES, RecvSize - crypto_box_BOXZEROBYTES, OriginalRecv + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES, Length - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
		if (crypto_box_open_afternm(
			(PUCHAR)OriginalRecv, 
			(PUCHAR)OriginalRecv, 
			Length + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES), 
			WholeNonce.get(), 
			PrecomputationKey) != EXIT_SUCCESS)
				return EXIT_FAILURE;
		memmove_s(OriginalRecv, RecvSize, OriginalRecv + crypto_box_ZEROBYTES, Length - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES));
		memset(OriginalRecv + Length - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES), 0, RecvSize - (Length - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES)));

	//Check padding data and responses check.
		DataLength = DNSCurvePaddingData(false, OriginalRecv, Length);
		if (DataLength < (SSIZE_T)DNS_PACKET_MINSIZE)
			return EXIT_FAILURE;
	}

//Responses check
	if (Parameter.HeaderCheck_DNS || Parameter.DataCheck_Blacklist)
	{
		DataLength = CheckResponseData(OriginalRecv, DataLength, false, nullptr);
		if (DataLength < (SSIZE_T)DNS_PACKET_MINSIZE)
			return EXIT_FAILURE;
	}

	return DataLength;
}

//DNSCurve non-blocking mode selecting
SSIZE_T __fastcall DNSCurveSocketSelecting(
	const uint16_t Protocol, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<DNSCURVE_SOCKET_SELECTING_DATA> &SocketSelectingList, 
	PSTR OriginalRecv, 
	const size_t RecvSize)
{
//Initialization(Part 1)
	size_t Index = 0;

//TCP or UDP connecting
	SSIZE_T RecvLen = 0;
	for (Index = 0;Index < SocketDataList.size();++Index)
	{
		RecvLen = SocketConnecting(Protocol, SocketDataList.at(Index).Socket, (PSOCKADDR)&SocketDataList.at(Index).SockAddr, SocketDataList.at(Index).AddrLen, SocketSelectingList.at(Index).SendBuffer, SocketSelectingList.at(Index).SendSize);
		if (RecvLen == EXIT_FAILURE)
		{
			shutdown(SocketDataList.at(Index).Socket, SD_BOTH);
			closesocket(SocketDataList.at(Index).Socket);
			SocketDataList.at(Index).Socket = 0;
		}
	#if defined(PLATFORM_LINUX)
		else if (Protocol == IPPROTO_TCP && Parameter.TCP_FastOpen && RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE)
		{
			SocketSelectingList.at(Index).PacketIsSend = true;
			++Index;
		}
	#endif
	}

//Socket check(Part 1)
	for (auto SocketDataIter = SocketDataList.begin();SocketDataIter != SocketDataList.end();++SocketDataIter)
	{
		if (SocketDataIter->Socket > 0)
			break;
		else if (SocketDataIter + 1U == SocketDataList.end())
			return EXIT_FAILURE;
	}

//Initialization(Part 2)
	std::shared_ptr<fd_set> ReadFDS(new fd_set()), WriteFDS(new fd_set());
	std::shared_ptr<timeval> Timeout(new timeval());
	memset(ReadFDS.get(), 0, sizeof(fd_set));
	memset(WriteFDS.get(), 0, sizeof(fd_set));
	memset(Timeout.get(), 0, sizeof(timeval));
	SSIZE_T SelectResult = 0;
	size_t LastReceiveIndex = 0;
	SYSTEM_SOCKET MaxSocket = 0;
	auto IsAllSocketClosed = false;

//Socket timeout setting
#if defined(PLATFORM_WIN)
	Timeout->tv_sec = DNSCurveParameter.DNSCurve_SocketTimeout_Reliable / SECOND_TO_MILLISECOND;
	Timeout->tv_usec = DNSCurveParameter.DNSCurve_SocketTimeout_Reliable % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	Timeout->tv_sec = DNSCurveParameter.DNSCurve_SocketTimeout_Reliable.tv_sec;
	Timeout->tv_usec = DNSCurveParameter.DNSCurve_SocketTimeout_Reliable.tv_usec;
#endif

//Selecting process
	for (;;)
	{
		Sleep(LOOP_INTERVAL_TIME_NO_DELAY);

	//Socket check(Part 2)
		for (auto SocketDataIter = SocketDataList.begin();SocketDataIter != SocketDataList.end();++SocketDataIter)
		{
			if (SocketDataIter->Socket > 0)
				break;
			else if (SocketDataIter + 1U == SocketDataList.end())
				IsAllSocketClosed = true;
		}

	//Buffer list check(Part 1)
		if (IsAllSocketClosed || Parameter.ReceiveWaiting == 0 || SocketDataList.size() == 1U)
		{
		//Sacn all result.
			RecvLen = DNSCurveSelectingResult(Protocol, SocketDataList, SocketSelectingList, OriginalRecv, RecvSize);
			if (RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE)
				return RecvLen;
		//All socket cloesed. 
			else if (IsAllSocketClosed)
				return EXIT_FAILURE;
		}

	//Reset parameters.
		FD_ZERO(ReadFDS.get());
		FD_ZERO(WriteFDS.get());
		MaxSocket = 0;

	//Socket check and non-blocking process setting
		for (Index = 0;Index < SocketDataList.size();++Index)
		{
		//Non-blocking process setting
			if (SocketDataList.at(Index).Socket > 0)
			{
			//Select structure setting
				if (SocketDataList.at(Index).Socket > MaxSocket)
					MaxSocket = SocketDataList.at(Index).Socket;

			//Receive process
				FD_SET(SocketDataList.at(Index).Socket, ReadFDS.get());

			//Send process
				if (!SocketSelectingList.at(Index).PacketIsSend)
					FD_SET(SocketDataList.at(Index).Socket, WriteFDS.get());
			}
			else if (MaxSocket == 0 && Index + 1U == SocketDataList.size())
			{
				return EXIT_FAILURE;
			}
		}

	//Wait for system calling.
	#if defined(PLATFORM_WIN)
		SelectResult = select(0, ReadFDS.get(), WriteFDS.get(), nullptr, Timeout.get());
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		SelectResult = select(MaxSocket + 1U, ReadFDS.get(), WriteFDS.get(), nullptr, Timeout.get());
	#endif
		if (SelectResult > EXIT_SUCCESS)
		{
			for (Index = 0;Index < SocketDataList.size();++Index)
			{
			//Receive process
				if (FD_ISSET(SocketDataList.at(Index).Socket, ReadFDS.get()))
				{
				//Buffer initialization
					if (!SocketSelectingList.at(Index).RecvBuffer)
					{
						std::shared_ptr<char> RecvBufferTemp(new char[RecvSize]());
						memset(RecvBufferTemp.get(), 0, RecvSize);
						SocketSelectingList.at(Index).RecvBuffer.swap(RecvBufferTemp);
					}

				//Receive from selecting.
					RecvLen = recv(SocketDataList.at(Index).Socket, SocketSelectingList.at(Index).RecvBuffer.get() + SocketSelectingList.at(Index).Length, (int)(RecvSize - SocketSelectingList.at(Index).Length), 0);

				//Connection closed or SOCKET_ERROR
					if (RecvLen <= 0)
					{
						shutdown(SocketDataList.at(Index).Socket, SD_BOTH);
						closesocket(SocketDataList.at(Index).Socket);
						SocketDataList.at(Index).Socket = 0;
						SocketSelectingList.at(Index).RecvBuffer.reset();
						SocketSelectingList.at(Index).Length = 0;
						continue;
					}
					else if (Protocol == IPPROTO_UDP && RecvLen > (SSIZE_T)DNS_PACKET_MINSIZE && SocketSelectingList.at(Index).Length > 0)
					{
						memset(SocketSelectingList.at(Index).RecvBuffer.get(), 0, SocketSelectingList.at(Index).Length);
						memmove_s(SocketSelectingList.at(Index).RecvBuffer.get(), RecvSize, SocketSelectingList.at(Index).RecvBuffer.get() + SocketSelectingList.at(Index).Length, RecvLen);
						SocketSelectingList.at(Index).Length = 0;
					}

				//Whole packet length
					SocketSelectingList.at(Index).Length += RecvLen;

				//Mark last packet.
					LastReceiveIndex = Index;
				}

			//Send process
				if (FD_ISSET(SocketDataList.at(Index).Socket, WriteFDS.get()) && !SocketSelectingList.at(Index).PacketIsSend)
				{
					if (send(SocketDataList.at(Index).Socket, SocketSelectingList.at(Index).SendBuffer, (int)SocketSelectingList.at(Index).SendSize, 0) <= EXIT_SUCCESS)
					{
						shutdown(SocketDataList.at(Index).Socket, SD_BOTH);
						closesocket(SocketDataList.at(Index).Socket);
						SocketDataList.at(Index).Socket = 0;
						SocketSelectingList.at(Index).RecvBuffer.reset();
						SocketSelectingList.at(Index).Length = 0;
					}
					else {
						SocketSelectingList.at(Index).PacketIsSend = true;
					}
				}
			}
		}
	//Timeout
		else if (SelectResult == EXIT_SUCCESS)
		{
			PUINT8 PrecomputationKeyTemp = nullptr;
			PSTR ReceiveMagicNumberTemp = nullptr;
			Index = 0;

		//Swap to last receive packet when Receive Waiting is ON.
			MaxSocket = SocketDataList.at(LastReceiveIndex).Socket;
			SocketDataList.at(LastReceiveIndex).Socket = SocketDataList.at(Index).Socket;
			SocketDataList.at(Index).Socket = MaxSocket;
			PrecomputationKeyTemp = SocketSelectingList.at(Index).PrecomputationKey;
			SocketSelectingList.at(Index).PrecomputationKey = SocketSelectingList.at(LastReceiveIndex).PrecomputationKey;
			SocketSelectingList.at(LastReceiveIndex).PrecomputationKey = PrecomputationKeyTemp;
			ReceiveMagicNumberTemp = SocketSelectingList.at(Index).ReceiveMagicNumber;
			SocketSelectingList.at(Index).ReceiveMagicNumber = SocketSelectingList.at(LastReceiveIndex).ReceiveMagicNumber;
			SocketSelectingList.at(LastReceiveIndex).ReceiveMagicNumber = ReceiveMagicNumberTemp;
			SocketSelectingList.at(LastReceiveIndex).RecvBuffer.swap(SocketSelectingList.at(Index).RecvBuffer);
			RecvLen = SocketSelectingList.at(LastReceiveIndex).Length;
			SocketSelectingList.at(LastReceiveIndex).Length = SocketSelectingList.at(Index).Length;
			SocketSelectingList.at(Index).Length = RecvLen;

		//Buffer list check(Part 2)
			RecvLen = DNSCurveSelectingResult(Protocol, SocketDataList, SocketSelectingList, OriginalRecv, RecvSize);
			if (RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE)
				return RecvLen;

		//Close all sockets.
			for (auto &SocketDataIter:SocketDataList)
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
	for (auto &SocketDataIter:SocketDataList)
	{
		if (SocketDataIter.Socket > 0)
		{
			shutdown(SocketDataIter.Socket, SD_BOTH);
			closesocket(SocketDataIter.Socket);
		}
	}

	return EXIT_FAILURE;
}

//DNSCurve Socket selecting result
SSIZE_T __fastcall DNSCurveSelectingResult(
	uint16_t Protocol, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<DNSCURVE_SOCKET_SELECTING_DATA> &SocketSelectingList, 
	PSTR OriginalRecv, 
	const size_t RecvSize)
{
	SSIZE_T RecvLen = 0;

//Scan all result.
	for (size_t Index = 0;Index < SocketDataList.size();++Index)
	{
		if (SocketSelectingList.at(Index).RecvBuffer && SocketSelectingList.at(Index).Length >= DNS_PACKET_MINSIZE)
		{
		//TCP header length check
			if (Protocol == IPPROTO_TCP)
			{
				RecvLen = ntohs(((PUINT16)SocketSelectingList.at(Index).RecvBuffer.get())[0]);
				if (RecvLen >(SSIZE_T)SocketSelectingList.at(Index).Length)
				{
					goto JumpToRestart;
				}
				else {
					memmove_s(SocketSelectingList.at(Index).RecvBuffer.get(), RecvSize, SocketSelectingList.at(Index).RecvBuffer.get() + sizeof(uint16_t), RecvLen);
					memset(SocketSelectingList.at(Index).RecvBuffer.get() + RecvLen, 0, (SSIZE_T)RecvSize - RecvLen);
				}
			}
		//UDP length
			else {
				RecvLen = SocketSelectingList.at(Index).Length;
			}

		//Receive from buffer list and decrypt or get packet data.
			RecvLen = DNSCurvePacketDecryption(SocketSelectingList.at(Index).ReceiveMagicNumber, SocketSelectingList.at(Index).PrecomputationKey, SocketSelectingList.at(Index).RecvBuffer.get(), RecvSize, RecvLen);
			if (RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
			{
				goto JumpToRestart;
			}
			else {
				memset(OriginalRecv, 0, RecvSize);
				memcpy_s(OriginalRecv, RecvSize, SocketSelectingList.at(Index).RecvBuffer.get(), RecvLen);
			}

		//Close all sockets.
			for (auto &SocketDataIter:SocketDataList)
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

		//Jump here to restart.
		JumpToRestart:
			shutdown(SocketDataList.at(Index).Socket, SD_BOTH);
			closesocket(SocketDataList.at(Index).Socket);
			SocketDataList.at(Index).Socket = 0;
			SocketSelectingList.at(Index).RecvBuffer.reset();
			SocketSelectingList.at(Index).Length = 0;
			continue;
		}
	}

	return EXIT_FAILURE;
}

//DNSCurve initialization
void __fastcall DNSCurveInit(
	void)
{
//DNSCurve signature request TCP Mode
	if (DNSCurveParameter.DNSCurveProtocol_Transport == REQUEST_MODE_TCP)
	{
	//Main(IPv6)
		if (DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family > 0 && 
			(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_NETWORK_BOTH || DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV6 || //Auto select and IPv6
			DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV4 && DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family == 0) && //Non-IPv4
			(!DNSCurveParameter.ClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
			DNSCurveParameter.ClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES) || 
			CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
		{
			std::thread DNSCurveTCPSignatureRequestThread(DNSCurveTCPSignatureRequest, AF_INET6, false);
			DNSCurveTCPSignatureRequestThread.detach();
		}

	//Main(IPv4)
		if (DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family > 0 && 
			(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_NETWORK_BOTH || DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV4 || //Auto select and IPv4
			DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV6 && DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family == 0) && //Non-IPv6
			(!DNSCurveParameter.ClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
			DNSCurveParameter.ClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES) || 
			CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
		{
			std::thread DNSCurveTCPSignatureRequestThread(DNSCurveTCPSignatureRequest, AF_INET, false);
			DNSCurveTCPSignatureRequestThread.detach();
		}

	//Alternate(IPv6)
		if (DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && 
			(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_NETWORK_BOTH || DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV6 || //Auto select and IPv6
			DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV4 && DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family == 0) && //Non-IPv4
			(!DNSCurveParameter.ClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
			DNSCurveParameter.ClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES) || 
			CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
		{
			std::thread DNSCurveTCPSignatureRequestThread(DNSCurveTCPSignatureRequest, AF_INET6, true);
			DNSCurveTCPSignatureRequestThread.detach();
		}

	//Alternate(IPv4)
		if (DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && 
			(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_NETWORK_BOTH || DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV4 || //Auto select and IPv4
			DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV6 && DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family == 0) && //Non-IPv6
			(!DNSCurveParameter.ClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
			DNSCurveParameter.ClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES) || 
			CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
		{
			std::thread DNSCurveTCPSignatureRequestThread(DNSCurveTCPSignatureRequest, AF_INET, true);
			DNSCurveTCPSignatureRequestThread.detach();
		}
	}

//DNSCurve signature request UDP Mode
//Main(IPv6)
	if (DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family > 0 && 
		(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_NETWORK_BOTH || DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV6 || //Auto select and IPv6
		DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV4 && DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family == 0) && //Non-IPv4
		(!DNSCurveParameter.ClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
		DNSCurveParameter.ClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES) || 
		CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
	{
		std::thread DNSCurveUDPSignatureRequestThread(DNSCurveUDPSignatureRequest, AF_INET6, false);
		DNSCurveUDPSignatureRequestThread.detach();
	}

//Main(IPv4)
	if (DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family > 0 && 
		(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_NETWORK_BOTH || DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV4 || //Auto select and IPv4
		DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV6 && DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family == 0) && //Non-IPv6
		(!DNSCurveParameter.ClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
		DNSCurveParameter.ClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES) || 
		CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
	{
		std::thread DNSCurveUDPSignatureRequestThread(DNSCurveUDPSignatureRequest, AF_INET, false);
		DNSCurveUDPSignatureRequestThread.detach();
	}

//Alternate(IPv6)
	if (DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && 
		(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_NETWORK_BOTH || DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV6 || //Auto select and IPv6
		DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV4 && DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family == 0) && //Non-IPv4
		(!DNSCurveParameter.ClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
		DNSCurveParameter.ClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES) || 
		CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
	{
		std::thread DNSCurveUDPSignatureRequestThread(DNSCurveUDPSignatureRequest, AF_INET6, true);
		DNSCurveUDPSignatureRequestThread.detach();
	}

//Alternate(IPv4)
	if (DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && 
		(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_NETWORK_BOTH || DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV4 || //Auto select and IPv4
		DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV6 && DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family == 0) && //Non-IPv6
		(!DNSCurveParameter.ClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) || 
		DNSCurveParameter.ClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES) || 
		CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
	{
		std::thread DNSCurveUDPSignatureRequestThread(DNSCurveUDPSignatureRequest, AF_INET, true);
		DNSCurveUDPSignatureRequestThread.detach();
	}

	return;
}

/* Signature request of DNSCurve protocol must send to target server.
//DNSCurve Local Signature Request
size_t __fastcall DNSCurveSignatureRequest(
	const char *OriginalSend, 
	const size_t SendSize, 
	PSTR OriginalRecv, 
	const size_t RecvSize)
{
//Initialization
	std::shared_ptr<sockaddr_storage> SockAddr(new sockaddr_storage());
	memset(SockAddr.get(), 0, sizeof(sockaddr_storage));
	SYSTEM_SOCKET UDPSocket = 0;
	socklen_t AddrLen = 0;
	memset(OriginalRecv, 0, RecvSize);

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

//Socket check, timeout setting and UDP connecting
	if (!SocketSetting(UDPSocket, SOCKET_SETTING_INVALID_CHECK, nullptr) || 
		!SocketSetting(UDPSocket, SOCKET_SETTING_TIMEOUT, &Parameter.SocketTimeout_Unreliable) || 
		SocketConnecting(IPPROTO_UDP, UDPSocket, (PSOCKADDR)SockAddr.get(), AddrLen, nullptr, 0) == EXIT_FAILURE)
			return EXIT_FAILURE;

//Send request.
	if (send(UDPSocket, OriginalSend, (int)SendSize, 0) <= EXIT_SUCCESS)
	{
		PrintError(LOG_ERROR_NETWORK, L"DNSCurve Local Signature request error", WSAGetLastError(), nullptr, 0);
		shutdown(UDPSocket, SD_BOTH);
		closesocket(UDPSocket);

		return EXIT_FAILURE;
	}

//Receive response.
	SSIZE_T RecvLen = recv(UDPSocket, OriginalRecv, (int)RecvSize, 0);
	shutdown(UDPSocket, SD_BOTH);
	closesocket(UDPSocket);
	if (RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE)
		return RecvLen;
	else 
		memset(OriginalRecv, 0, RecvSize);

	return EXIT_FAILURE;
}
*/

//Send TCP request to get Signature Data of servers
bool __fastcall DNSCurveTCPSignatureRequest(
	const uint16_t Protocol, 
	const bool IsAlternate)
{
//Initialization(Part 1)
	std::shared_ptr<char> SendBuffer(new char[PACKET_MAXSIZE]()), RecvBuffer(new char[LARGE_PACKET_MAXSIZE]());
	memset(SendBuffer.get(), 0, PACKET_MAXSIZE);
	memset(RecvBuffer.get(), 0, LARGE_PACKET_MAXSIZE);
	std::vector<SOCKET_DATA> TCPSocketDataList(1U);
	memset(&TCPSocketDataList.front(), 0, sizeof(SOCKET_DATA));

//Make packet data(Part 1).
	size_t DataLength = sizeof(dns_tcp_hdr);
	auto DNS_TCP_Header = (pdns_tcp_hdr)SendBuffer.get();
#if defined(ENABLE_PCAP)
	DNS_TCP_Header->ID = Parameter.DomainTest_ID;
#else
	DNS_TCP_Header->ID = htons(U16_NUM_ONE);
#endif
	DNS_TCP_Header->Flags = htons(DNS_STANDARD);
	DNS_TCP_Header->Questions = htons(U16_NUM_ONE);
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
	DataLength = AddEDNSLabelToAdditionalRR(SendBuffer.get() + sizeof(uint16_t), DataLength - sizeof(uint16_t), PACKET_MAXSIZE, false);
	DataLength += sizeof(uint16_t);

//Add length of request packet(It must be written in header when transpot with TCP protocol).
	DNS_TCP_Header->Length = htons((uint16_t)(DataLength - sizeof(uint16_t)));

//Socket initialization(Part 1)
	size_t ServerType = 0;
	PDNSCURVE_SERVER_DATA PacketTarget = nullptr;
	if (Protocol == AF_INET6) //IPv6
	{
		if (IsAlternate)
		{
			((PSOCKADDR_IN6)&TCPSocketDataList.front().SockAddr)->sin6_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
			((PSOCKADDR_IN6)&TCPSocketDataList.front().SockAddr)->sin6_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv6;
			ServerType = DNSCURVE_ALTERNATE_IPV6;
		}
		else { //Main
			((PSOCKADDR_IN6)&TCPSocketDataList.front().SockAddr)->sin6_addr = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_addr;
			((PSOCKADDR_IN6)&TCPSocketDataList.front().SockAddr)->sin6_port = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_port;
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv6;
			ServerType = DNSCURVE_MAIN_IPV6;
		}

		TCPSocketDataList.front().AddrLen = sizeof(sockaddr_in6);
		TCPSocketDataList.front().SockAddr.ss_family = AF_INET6;
	}
	else { //IPv4
		if (IsAlternate)
		{
			((PSOCKADDR_IN)&TCPSocketDataList.front().SockAddr)->sin_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
			((PSOCKADDR_IN)&TCPSocketDataList.front().SockAddr)->sin_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv4;
			ServerType = DNSCURVE_ALTERNATE_IPV4;
		}
		else { //Main
			((PSOCKADDR_IN)&TCPSocketDataList.front().SockAddr)->sin_addr = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_addr;
			((PSOCKADDR_IN)&TCPSocketDataList.front().SockAddr)->sin_port = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_port;
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv4;
			ServerType = DNSCURVE_MAIN_IPV4;
		}

		TCPSocketDataList.front().AddrLen = sizeof(sockaddr_in);
		TCPSocketDataList.front().SockAddr.ss_family = AF_INET;
	}

//Initialization(Part 2)
	size_t SleepTime_SignatureRequest = 0, SpeedTime_SignatureRequest = DNSCurveParameter.KeyRecheckTime;
	std::wstring Message;
	SSIZE_T RecvLen = 0;

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
		if (Protocol == AF_INET6) //IPv6
			TCPSocketDataList.front().Socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
		else //IPv4
			TCPSocketDataList.front().Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (!SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_INVALID_CHECK, nullptr))
			goto JumpToRestart;

	//Socket non-blocking mode setting
		if (!SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_NON_BLOCKING_MODE, nullptr))
			goto JumpToRestart;

	//Socket selecting
		RecvLen = SocketSelecting(IPPROTO_TCP, TCPSocketDataList, SendBuffer.get(), DataLength, RecvBuffer.get(), LARGE_PACKET_MAXSIZE, false, true);
		if (RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
		{
			goto JumpToRestart;
		}
		else {
		//Check Signature.
			if (PacketTarget == nullptr || 
				!DNSCruveGetSignatureData(RecvBuffer.get() + DNS_PACKET_RR_LOCATE(RecvBuffer.get()), ServerType) || 
				CheckEmptyBuffer(PacketTarget->ServerFingerprint, crypto_box_PUBLICKEYBYTES) || 
				CheckEmptyBuffer(PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
					goto JumpToRestart;
		}

	//Wait for sending again.
		SleepTime_SignatureRequest += Parameter.FileRefreshTime;
		continue;

	//Jump here to restart.
	JumpToRestart:
		DNSCurvePrintLog(ServerType, Message);
		if (Message.length() > 0)
		{
			Message.append(L"TCP get signature data error");
			PrintError(LOG_ERROR_DNSCURVE, Message.c_str(), 0, nullptr, 0);
		}

	//Send request again.
		memset(RecvBuffer.get(), 0, LARGE_PACKET_MAXSIZE);
		if (Parameter.AlternateMultiRequest)
		{
			if (ServerType == DNSCURVE_MAIN_IPV6)
				++AlternateSwapList.TimeoutTimes[8U];
			else if (ServerType == DNSCURVE_MAIN_IPV4)
				++AlternateSwapList.TimeoutTimes[9U];
		}

		Sleep(SENDING_INTERVAL_TIME);
	}

	PrintError(LOG_ERROR_SYSTEM, L"DNSCurve TCP Signature Request module Monitor terminated", 0, nullptr, 0);
	return true;
}

//Send UDP request to get Signature Data of servers
bool __fastcall DNSCurveUDPSignatureRequest(
	const uint16_t Protocol, 
	const bool IsAlternate)
{
//Initialization(Part 1)
	std::shared_ptr<char> SendBuffer(new char[PACKET_MAXSIZE]()), RecvBuffer(new char[PACKET_MAXSIZE]());
	memset(SendBuffer.get(), 0, PACKET_MAXSIZE);
	memset(RecvBuffer.get(), 0, PACKET_MAXSIZE);
	std::vector<SOCKET_DATA> UDPSocketDataList(1U);
	memset(&UDPSocketDataList.front(), 0, sizeof(SOCKET_DATA));

//Make packet data(Part 1).
	size_t DataLength = sizeof(dns_hdr);
	auto DNS_Header = (pdns_hdr)SendBuffer.get();
#if defined(ENABLE_PCAP)
	DNS_Header->ID = Parameter.DomainTest_ID;
#else
	DNS_Header->ID = htons(U16_NUM_ONE);
#endif
	DNS_Header->Flags = htons(DNS_STANDARD);
	DNS_Header->Questions = htons(U16_NUM_ONE);
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
	DataLength = AddEDNSLabelToAdditionalRR(SendBuffer.get(), DataLength, PACKET_MAXSIZE, false);

//Socket initialization(Part 1)
	size_t ServerType = 0;
	PDNSCURVE_SERVER_DATA PacketTarget = nullptr;
	if (Protocol == AF_INET6) //IPv6
	{
		if (IsAlternate)
		{
			((PSOCKADDR_IN6)&UDPSocketDataList.front().SockAddr)->sin6_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
			((PSOCKADDR_IN6)&UDPSocketDataList.front().SockAddr)->sin6_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv6;
			ServerType = DNSCURVE_ALTERNATE_IPV6;
		}
		else { //Main
			((PSOCKADDR_IN6)&UDPSocketDataList.front().SockAddr)->sin6_addr = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_addr;
			((PSOCKADDR_IN6)&UDPSocketDataList.front().SockAddr)->sin6_port = DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_port;
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv6;
			ServerType = DNSCURVE_MAIN_IPV6;
		}

		UDPSocketDataList.front().AddrLen = sizeof(sockaddr_in6);
		UDPSocketDataList.front().SockAddr.ss_family = AF_INET6;
	}
	else { //IPv4
		if (IsAlternate)
		{
			((PSOCKADDR_IN)&UDPSocketDataList.front().SockAddr)->sin_addr = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
			((PSOCKADDR_IN)&UDPSocketDataList.front().SockAddr)->sin_port = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.Alternate_IPv4;
			ServerType = DNSCURVE_ALTERNATE_IPV4;
		}
		else { //Main
			((PSOCKADDR_IN)&UDPSocketDataList.front().SockAddr)->sin_addr = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_addr;
			((PSOCKADDR_IN)&UDPSocketDataList.front().SockAddr)->sin_port = DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_port;
			PacketTarget = &DNSCurveParameter.DNSCurveTarget.IPv4;
			ServerType = DNSCURVE_MAIN_IPV4;
		}

		UDPSocketDataList.front().AddrLen = sizeof(sockaddr_in);
		UDPSocketDataList.front().SockAddr.ss_family = AF_INET;
	}

//Initialization(Part 2)
	size_t SleepTime_SignatureRequest = 0, SpeedTime_SignatureRequest = DNSCurveParameter.KeyRecheckTime;
	std::wstring Message;
	SSIZE_T RecvLen = 0;

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
		if (Protocol == AF_INET6) //IPv6
			UDPSocketDataList.front().Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		else //IPv4
			UDPSocketDataList.front().Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (!SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_INVALID_CHECK, nullptr))
			goto JumpToRestart;

	//Socket non-blocking mode setting
		if (!SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_NON_BLOCKING_MODE, nullptr))
			goto JumpToRestart;

	//Socket selecting
		RecvLen = SocketSelecting(IPPROTO_UDP, UDPSocketDataList, SendBuffer.get(), DataLength, RecvBuffer.get(), PACKET_MAXSIZE, false, true);
		if (RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
		{
			goto JumpToRestart;
		}
		else {
		//Check Signature.
			if (PacketTarget == nullptr || 
				!DNSCruveGetSignatureData(RecvBuffer.get() + DNS_PACKET_RR_LOCATE(RecvBuffer.get()), ServerType) || 
				CheckEmptyBuffer(PacketTarget->ServerFingerprint, crypto_box_PUBLICKEYBYTES) || 
				CheckEmptyBuffer(PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
					goto JumpToRestart;
		}

	//Wait for sending again.
		SleepTime_SignatureRequest += Parameter.FileRefreshTime;
		continue;

	//Jump here to restart.
	JumpToRestart:
		DNSCurvePrintLog(ServerType, Message);
		if (Message.length() > 0)
		{
			Message.append(L"UDP get signature data error");
			PrintError(LOG_ERROR_DNSCURVE, Message.c_str(), 0, nullptr, 0);
		}

	//Send request again.
		memset(RecvBuffer.get(), 0, PACKET_MAXSIZE);
		if (Parameter.AlternateMultiRequest)
		{
			if (ServerType == DNSCURVE_MAIN_IPV6)
				++AlternateSwapList.TimeoutTimes[10U];
			else if (ServerType == DNSCURVE_MAIN_IPV4)
				++AlternateSwapList.TimeoutTimes[11U];
		}

		Sleep(SENDING_INTERVAL_TIME);
	}

	PrintError(LOG_ERROR_SYSTEM, L"DNSCurve UDP Signature Request module Monitor terminated", 0, nullptr, 0);
	return true;
}

//Get Signature Data of server from packets
bool __fastcall DNSCruveGetSignatureData(
	const char *Buffer, 
	const size_t ServerType)
{
	auto DNS_Record_TXT = (pdns_record_txt)Buffer;
	if (DNS_Record_TXT->Name == htons(DNS_POINTER_QUERY) && 
		DNS_Record_TXT->Length == htons(DNS_Record_TXT->TXT_Length + 1U) && DNS_Record_TXT->TXT_Length == DNSCRYPT_RECORD_TXT_LEN)
	{
		auto DNSCurve_TXT_Header = (pdnscurve_txt_hdr)(Buffer + sizeof(dns_record_txt));
		if (memcmp(&DNSCurve_TXT_Header->CertMagicNumber, DNSCRYPT_CERT_MAGIC, sizeof(uint16_t)) == EXIT_SUCCESS && 
			DNSCurve_TXT_Header->MajorVersion == htons(DNSCURVE_VERSION_MAJOR) && DNSCurve_TXT_Header->MinorVersion == DNSCURVE_VERSION_MINOR)
		{
			ULONGLONG SignatureLength = 0;

		//Get Send Magic Number, Server Fingerprint and Precomputation Key.
			PDNSCURVE_SERVER_DATA PacketTarget = nullptr;
			if (!DNSCurvePacketTargetSetting(ServerType, PacketTarget))
				return false;

		//Check Signature.
			std::shared_ptr<char> DeBuffer(new char[PACKET_MAXSIZE]());
			memset(DeBuffer.get(), 0, PACKET_MAXSIZE);
			if (PacketTarget == nullptr || 
				crypto_sign_open((PUINT8)DeBuffer.get(), &SignatureLength, (PUINT8)(Buffer + sizeof(dns_record_txt) + sizeof(dnscurve_txt_hdr)), DNS_Record_TXT->TXT_Length - sizeof(dnscurve_txt_hdr), PacketTarget->ServerPublicKey) == LIBSODIUM_ERROR)
			{
				std::wstring Message;
				DNSCurvePrintLog(ServerType, Message);
				if (Message.length() > 0)
				{
					Message.append(L"Fingerprint signature validation error");
					PrintError(LOG_ERROR_DNSCURVE, Message.c_str(), 0, nullptr, 0);
				}

				return false;
			}

			auto SignatureData = (pdnscurve_txt_signature)DeBuffer.get();
		//Signature available time check
			if (SignatureData != nullptr && PacketTarget->ServerFingerprint != nullptr && 
				time(nullptr) >= (time_t)ntohl(SignatureData->CertTime_Begin) && time(nullptr) <= (time_t)ntohl(SignatureData->CertTime_End))
			{
				memcpy_s(PacketTarget->SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, SignatureData->MagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
				memcpy_s(PacketTarget->ServerFingerprint, crypto_box_PUBLICKEYBYTES, SignatureData->PublicKey, crypto_box_PUBLICKEYBYTES);
				if (!DNSCurveParameter.ClientEphemeralKey)
					crypto_box_beforenm(
						PacketTarget->PrecomputationKey, 
						PacketTarget->ServerFingerprint, 
						DNSCurveParameter.Client_SecretKey);

				return true;
			}
			else {
				std::wstring Message;
				DNSCurvePrintLog(ServerType, Message);
				if (Message.length() > 0)
				{
					Message.append(L"Fingerprint signature validation error");
					PrintError(LOG_ERROR_DNSCURVE, Message.c_str(), 0, nullptr, 0);
				}
			}
		}
	}

	return false;
}

//Transmission of DNSCurve TCP protocol
size_t __fastcall DNSCurveTCPRequest(
	const char *OriginalSend, 
	const size_t SendSize, 
	PSTR OriginalRecv, 
	const size_t RecvSize)
{
//Initialization
	std::vector<SOCKET_DATA> TCPSocketDataList(1U);
	memset(&TCPSocketDataList.front(), 0, sizeof(SOCKET_DATA));
	std::shared_ptr<DNSCURVE_SOCKET_SELECTING_DATA> TCPSocketSelectingData(new DNSCURVE_SOCKET_SELECTING_DATA());
	PDNSCURVE_SERVER_DATA PacketTarget = nullptr;
	bool *IsAlternate = nullptr;
	size_t *AlternateTimeoutTimes = nullptr;
	memset(OriginalRecv, 0, RecvSize);
	auto SendBuffer = OriginalRecv;

//Socket initialization
	TCPSocketSelectingData->ServerType = DNSCurveSelectTargetSocket(&TCPSocketDataList.front(), PacketTarget, IsAlternate, AlternateTimeoutTimes, IPPROTO_TCP);
	if (TCPSocketSelectingData->ServerType == 0 || TCPSocketDataList.front().Socket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_NETWORK, L"DNSCurve TCP socket initialization error", WSAGetLastError(), nullptr, 0);
		closesocket(TCPSocketDataList.front().Socket);

		return EXIT_FAILURE;
	}

//Make Precomputation Key between client and server.
	PUINT8 Client_PublicKey = nullptr, PrecomputationKey = nullptr;
	std::shared_ptr<uint8_t> Client_PublicKey_PTR, PrecomputationKeyPTR;
	if (DNSCurveParameter.IsEncryption && DNSCurveParameter.ClientEphemeralKey)
	{
		std::shared_ptr<uint8_t> Client_PublicKey_PTR_Temp(new uint8_t[crypto_box_PUBLICKEYBYTES]()), PrecomputationKeyPTR_Temp(new uint8_t[crypto_box_BEFORENMBYTES]());
		Client_PublicKey_PTR_Temp.swap(Client_PublicKey_PTR);
		PrecomputationKeyPTR_Temp.swap(PrecomputationKeyPTR);
		Client_PublicKey = Client_PublicKey_PTR.get();
		PrecomputationKey = PrecomputationKeyPTR.get();
		if (!DNSCurvePrecomputationKeySetting(PrecomputationKey, Client_PublicKey, PacketTarget->ServerFingerprint))
		{
			closesocket(TCPSocketDataList.front().Socket);
			return EXIT_FAILURE;
		}
	}
	else {
		PrecomputationKey = PacketTarget->PrecomputationKey, Client_PublicKey = DNSCurveParameter.Client_PublicKey;
	}

//Socket non-blocking mode setting
	if (!SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_NON_BLOCKING_MODE, nullptr))
		return EXIT_FAILURE;

//Make encryption or normal packet.
	SSIZE_T RecvLen = DNSCurvePacketEncryption(IPPROTO_TCP, PacketTarget->SendMagicNumber, Client_PublicKey, PrecomputationKey, OriginalSend, SendSize, SendBuffer, RecvSize);
	if (RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
	{
		closesocket(TCPSocketDataList.front().Socket);
		return EXIT_FAILURE;
	}

//Socket selecting structure setting
	std::vector<DNSCURVE_SOCKET_SELECTING_DATA> TCPSocketSelectingList;
	if (DNSCurveParameter.IsEncryption) //Encryption mode
	{
		TCPSocketSelectingData->PrecomputationKey = PrecomputationKey;
		TCPSocketSelectingData->ReceiveMagicNumber = PacketTarget->ReceiveMagicNumber;
	}
	TCPSocketSelectingData->SendBuffer = SendBuffer;
	TCPSocketSelectingData->SendSize = RecvLen;
	TCPSocketSelectingData->Length = 0;
	TCPSocketSelectingData->PacketIsSend = false;
	TCPSocketSelectingList.push_back(*TCPSocketSelectingData);
	TCPSocketSelectingData.reset();

//Socket selecting
	RecvLen = DNSCurveSocketSelecting(IPPROTO_TCP, TCPSocketDataList, TCPSocketSelectingList, OriginalRecv, RecvSize);
	if (RecvLen == WSAETIMEDOUT && !Parameter.AlternateMultiRequest) //Mark timeout.
	{
		if (TCPSocketDataList.front().AddrLen == sizeof(sockaddr_in6)) //IPv6
			++AlternateSwapList.TimeoutTimes[9U];
		else //IPv4
			++AlternateSwapList.TimeoutTimes[10U];
	}

	return RecvLen;
}

//Transmission of DNSCurve TCP protocol(Multithreading)
size_t __fastcall DNSCurveTCPRequestMulti(
	const char *OriginalSend, 
	const size_t SendSize, 
	PSTR OriginalRecv, 
	const size_t RecvSize)
{
//Key initialization
	PUINT8 PrecomputationKey = nullptr, Alternate_PrecomputationKey = nullptr;
	std::shared_ptr<uint8_t> PrecomputationKeyPTR, Alternate_PrecomputationKeyPTR;
	if (DNSCurveParameter.IsEncryption && DNSCurveParameter.ClientEphemeralKey)
	{
	//Main
		std::shared_ptr<uint8_t> PrecomputationKeyPTR_Temp(new uint8_t[crypto_box_BEFORENMBYTES]()), Alternate_PrecomputationKeyPTR_Temp(new uint8_t[crypto_box_BEFORENMBYTES]());
		memset(PrecomputationKeyPTR_Temp.get(), 0, crypto_box_BEFORENMBYTES);
		PrecomputationKeyPTR_Temp.swap(PrecomputationKeyPTR);
		PrecomputationKey = PrecomputationKeyPTR.get();

	//Alternate
		memset(Alternate_PrecomputationKeyPTR_Temp.get(), 0, crypto_box_BEFORENMBYTES);
		Alternate_PrecomputationKeyPTR_Temp.swap(Alternate_PrecomputationKeyPTR);
		Alternate_PrecomputationKey = Alternate_PrecomputationKeyPTR.get();
	}

//Initialization(Part 1)
	std::vector<SOCKET_DATA> TCPSocketDataList;
	std::vector<DNSCURVE_SOCKET_SELECTING_DATA> TCPSocketSelectingList;
	std::shared_ptr<char> SendBuffer, Alternate_SendBuffer;
	PDNSCURVE_SERVER_DATA PacketTarget = nullptr;
	size_t DataLength = 0, Alternate_DataLength = 0;
	memset(OriginalRecv, 0, RecvSize);

//Socket precomputation
	DNSCurveSocketPrecomputation(IPPROTO_TCP, OriginalSend, SendSize, RecvSize, PrecomputationKey, Alternate_PrecomputationKey, PacketTarget, 
		TCPSocketDataList, TCPSocketSelectingList, SendBuffer, DataLength, Alternate_SendBuffer, Alternate_DataLength);
	if (TCPSocketDataList.empty() || TCPSocketDataList.size() != TCPSocketSelectingList.size())
		return EXIT_FAILURE;

//Socket selecting structure setting
	for (size_t Index = 0;Index < TCPSocketDataList.size();++Index)
	{
	//Encryption mode
		if (DNSCurveParameter.IsEncryption)
		{
			DNSCurvePacketTargetSetting(TCPSocketSelectingList.at(Index).ServerType, PacketTarget);
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

		TCPSocketSelectingList.at(Index).Length = 0;
		TCPSocketSelectingList.at(Index).PacketIsSend = false;
	}

//Socket selecting
	SSIZE_T RecvLen = DNSCurveSocketSelecting(IPPROTO_TCP, TCPSocketDataList, TCPSocketSelectingList, OriginalRecv, RecvSize);
	if (RecvLen == WSAETIMEDOUT && !Parameter.AlternateMultiRequest) //Mark timeout.
	{
		if (TCPSocketDataList.front().AddrLen == sizeof(sockaddr_in6)) //IPv6
			++AlternateSwapList.TimeoutTimes[10U];
		else //IPv4
			++AlternateSwapList.TimeoutTimes[11U];
	}

	return RecvLen;
}

//Transmission of DNSCurve UDP protocol
size_t __fastcall DNSCurveUDPRequest(
	const char *OriginalSend, 
	const size_t SendSize, 
	PSTR OriginalRecv, 
	const size_t RecvSize)
{
//Initialization
	std::vector<SOCKET_DATA> UDPSocketDataList(1U);
	memset(&UDPSocketDataList.front(), 0, sizeof(SOCKET_DATA));
	std::shared_ptr<DNSCURVE_SOCKET_SELECTING_DATA> UDPSocketSelectingData(new DNSCURVE_SOCKET_SELECTING_DATA());
	PDNSCURVE_SERVER_DATA PacketTarget = nullptr;
	bool *IsAlternate = nullptr;
	size_t *AlternateTimeoutTimes = nullptr;
	memset(OriginalRecv, 0, RecvSize);
	auto SendBuffer = OriginalRecv;

//Socket initialization
	UDPSocketSelectingData->ServerType = DNSCurveSelectTargetSocket(&UDPSocketDataList.front(), PacketTarget, IsAlternate, AlternateTimeoutTimes, IPPROTO_UDP);
	if (UDPSocketSelectingData->ServerType == 0 || UDPSocketDataList.front().Socket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_NETWORK, L"DNSCurve UDP socket initialization error", WSAGetLastError(), nullptr, 0);
		closesocket(UDPSocketDataList.front().Socket);

		return EXIT_FAILURE;
	}

//Make Precomputation Key between client and server.
	PUINT8 Client_PublicKey = nullptr, PrecomputationKey = nullptr;
	std::shared_ptr<uint8_t> Client_PublicKey_PTR, PrecomputationKeyPTR;
	if (DNSCurveParameter.IsEncryption && DNSCurveParameter.ClientEphemeralKey)
	{
		std::shared_ptr<uint8_t> Client_PublicKey_PTR_Temp(new uint8_t[crypto_box_PUBLICKEYBYTES]()), PrecomputationKeyPTR_Temp(new uint8_t[crypto_box_BEFORENMBYTES]());
		Client_PublicKey_PTR_Temp.swap(Client_PublicKey_PTR);
		PrecomputationKeyPTR_Temp.swap(PrecomputationKeyPTR);
		Client_PublicKey = Client_PublicKey_PTR.get();
		PrecomputationKey = PrecomputationKeyPTR.get();
		if (!DNSCurvePrecomputationKeySetting(PrecomputationKey, Client_PublicKey, PacketTarget->ServerFingerprint))
		{
			closesocket(UDPSocketDataList.front().Socket);
			return EXIT_FAILURE;
		}
	}
	else {
		PrecomputationKey = PacketTarget->PrecomputationKey, Client_PublicKey = DNSCurveParameter.Client_PublicKey;
	}

//Socket timeout setting and UDP connecting
	if (!SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_TIMEOUT, &DNSCurveParameter.DNSCurve_SocketTimeout_Unreliable) || 
		SocketConnecting(IPPROTO_UDP, UDPSocketDataList.front().Socket, (PSOCKADDR)&UDPSocketDataList.front().SockAddr, UDPSocketDataList.front().AddrLen, nullptr, 0) == EXIT_FAILURE)
			return EXIT_FAILURE;

//Make encryption or normal packet.
	SSIZE_T RecvLen = DNSCurvePacketEncryption(IPPROTO_UDP, PacketTarget->SendMagicNumber, Client_PublicKey, PrecomputationKey, OriginalSend, SendSize, SendBuffer, RecvSize);
	if (RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
	{
		closesocket(UDPSocketDataList.front().Socket);
		return EXIT_FAILURE;
	}

//Socket selecting structure setting
	std::vector<DNSCURVE_SOCKET_SELECTING_DATA> UDPSocketSelectingList;
	if (DNSCurveParameter.IsEncryption) //Encryption mode
	{
		UDPSocketSelectingData->PrecomputationKey = PrecomputationKey;
		UDPSocketSelectingData->ReceiveMagicNumber = PacketTarget->ReceiveMagicNumber;
		UDPSocketSelectingData->SendBuffer = SendBuffer;
		UDPSocketSelectingData->SendSize = RecvLen;
	}
	else { //Normal
		UDPSocketSelectingData->SendBuffer = (PSTR)OriginalSend;
		UDPSocketSelectingData->SendSize = SendSize;
	}
	UDPSocketSelectingData->Length = 0;
	UDPSocketSelectingData->PacketIsSend = false;
	UDPSocketSelectingList.push_back(*UDPSocketSelectingData);
	UDPSocketSelectingData.reset();

//Socket selecting
	RecvLen = DNSCurveSocketSelecting(IPPROTO_UDP, UDPSocketDataList, UDPSocketSelectingList, OriginalRecv, RecvSize);
	if (RecvLen == WSAETIMEDOUT && !Parameter.AlternateMultiRequest) //Mark timeout.
	{
		if (UDPSocketDataList.front().AddrLen == sizeof(sockaddr_in6)) //IPv6
			++AlternateSwapList.TimeoutTimes[10U];
		else //IPv4
			++AlternateSwapList.TimeoutTimes[11U];
	}

	return RecvLen;
}

//Transmission of DNSCurve UDP protocol(Multithreading)
size_t __fastcall DNSCurveUDPRequestMulti(
	const char *OriginalSend, 
	const size_t SendSize, 
	PSTR OriginalRecv, 
	const size_t RecvSize)
{
//Key initialization
	PUINT8 PrecomputationKey = nullptr, Alternate_PrecomputationKey = nullptr;
	std::shared_ptr<uint8_t> PrecomputationKeyPTR, Alternate_PrecomputationKeyPTR;
	if (DNSCurveParameter.IsEncryption && DNSCurveParameter.ClientEphemeralKey)
	{
	//Main
		std::shared_ptr<uint8_t> PrecomputationKeyPTR_Temp(new uint8_t[crypto_box_BEFORENMBYTES]()), Alternate_PrecomputationKeyPTR_Temp(new uint8_t[crypto_box_BEFORENMBYTES]());
		memset(PrecomputationKeyPTR_Temp.get(), 0, crypto_box_BEFORENMBYTES);
		PrecomputationKeyPTR_Temp.swap(PrecomputationKeyPTR);
		PrecomputationKey = PrecomputationKeyPTR.get();

	//Alternate
		memset(Alternate_PrecomputationKeyPTR_Temp.get(), 0, crypto_box_BEFORENMBYTES);
		Alternate_PrecomputationKeyPTR_Temp.swap(Alternate_PrecomputationKeyPTR);
		Alternate_PrecomputationKey = Alternate_PrecomputationKeyPTR.get();
	}

//Initialization(Part 1)
	std::vector<SOCKET_DATA> UDPSocketDataList;
	std::vector<DNSCURVE_SOCKET_SELECTING_DATA> UDPSocketSelectingList;
	std::shared_ptr<char> SendBuffer, Alternate_SendBuffer;
	PDNSCURVE_SERVER_DATA PacketTarget = nullptr;
	size_t DataLength = 0, Alternate_DataLength = 0;
	memset(OriginalRecv, 0, RecvSize);

//Socket precomputation
	DNSCurveSocketPrecomputation(IPPROTO_UDP, OriginalSend, SendSize, RecvSize, PrecomputationKey, Alternate_PrecomputationKey, PacketTarget, UDPSocketDataList, UDPSocketSelectingList, SendBuffer, DataLength, Alternate_SendBuffer, Alternate_DataLength);
	if (UDPSocketDataList.empty() || UDPSocketDataList.size() != UDPSocketSelectingList.size())
		return EXIT_FAILURE;

//Socket selecting structure setting
	for (size_t Index = 0;Index < UDPSocketDataList.size();++Index)
	{
	//Encryption mode
		if (DNSCurveParameter.IsEncryption)
		{
			DNSCurvePacketTargetSetting(UDPSocketSelectingList.at(Index).ServerType, PacketTarget);
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
			UDPSocketSelectingList.at(Index).SendBuffer = (PSTR)OriginalSend;
			UDPSocketSelectingList.at(Index).SendSize = SendSize;
		}

		UDPSocketSelectingList.at(Index).Length = 0;
		UDPSocketSelectingList.at(Index).PacketIsSend = false;
	}

//Socket selecting
	SSIZE_T RecvLen = DNSCurveSocketSelecting(IPPROTO_UDP, UDPSocketDataList, UDPSocketSelectingList, OriginalRecv, RecvSize);
	if (RecvLen == WSAETIMEDOUT && !Parameter.AlternateMultiRequest) //Mark timeout.
	{
		if (UDPSocketDataList.front().AddrLen == sizeof(sockaddr_in6)) //IPv6
			++AlternateSwapList.TimeoutTimes[10U];
		else //IPv4
			++AlternateSwapList.TimeoutTimes[11U];
	}

	return RecvLen;
}
#endif

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


#include "TransportSecurity.h"

#if defined(ENABLE_TLS)
#if defined(PLATFORM_WIN)
//SSPI SChannel initializtion
bool SSPI_SChannelInitializtion(
	SSPI_HANDLE_TABLE &SSPI_Handle)
{
//Setup SChannel credentials
	SCHANNEL_CRED SChannelCredentials;
	memset(&SChannelCredentials, 0, sizeof(SChannelCredentials));
	SChannelCredentials.dwVersion = SCHANNEL_CRED_VERSION;

//TLS version selection
//Windows XP/2003 and Vista are not support TLS 1.0+.
#if !defined(PLATFORM_WIN_XP)
	if (Parameter.HTTP_CONNECT_TLS_Version == TLS_VERSION_1_2)
		SChannelCredentials.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
	else if (Parameter.HTTP_CONNECT_TLS_Version == TLS_VERSION_1_1)
		SChannelCredentials.grbitEnabledProtocols = SP_PROT_TLS1_1_CLIENT;
	else 
#endif
	if (Parameter.HTTP_CONNECT_TLS_Version == TLS_VERSION_1_0)
		SChannelCredentials.grbitEnabledProtocols = SP_PROT_TLS1_0_CLIENT;
	else //Auto select
		SChannelCredentials.grbitEnabledProtocols = TLS_VERSION_AUTO;

//TLS connection flags
	SChannelCredentials.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS; //Attempting to automatically supply a certificate chain for client authentication.
#if !defined(PLATFORM_WIN_XP)
	SChannelCredentials.dwFlags |= SCH_USE_STRONG_CRYPTO; //Disable known weak cryptographic algorithms, cipher suites, and SSL/TLS protocol versions that may be otherwise enabled for better interoperability.
#endif
	if (Parameter.HTTP_CONNECT_TLS_Validation)
	{
		SChannelCredentials.dwFlags |= SCH_CRED_AUTO_CRED_VALIDATION; //Validate the received server certificate chain.
		SChannelCredentials.dwFlags |= SCH_CRED_REVOCATION_CHECK_CHAIN; //When validating a certificate chain, check all certificates for revocation.
	}
	else {
		SChannelCredentials.dwFlags |= SCH_CRED_IGNORE_NO_REVOCATION_CHECK; //When checking for revoked certificates, ignore CRYPT_E_NO_REVOCATION_CHECK errors.
		SChannelCredentials.dwFlags |= SCH_CRED_IGNORE_REVOCATION_OFFLINE; //When checking for revoked certificates, ignore CRYPT_E_REVOCATION_OFFLINE errors.
		SChannelCredentials.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION; //Prevent Schannel from validating the received server certificate chain.
		SChannelCredentials.dwFlags |= SCH_CRED_NO_SERVERNAME_CHECK; //Prevent Schannel from comparing the supplied target name with the subject names in server certificates.
//		SChannelCredentials.dwFlags |= SCH_CRED_REVOCATION_CHECK_END_CERT; //When validating a certificate chain, check only the last certificate for revocation.
//		SChannelCredentials.dwFlags |= SCH_CRED_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT; //When validating a certificate chain, do not check the root for revocation.
	}

//Get client credentials handle.
	SSPI_Handle.LastReturnValue = AcquireCredentialsHandleW(
		nullptr, 
		UNISP_NAME_W, 
		SECPKG_CRED_OUTBOUND, 
		nullptr, 
		&SChannelCredentials, 
		nullptr, 
		nullptr, 
		&SSPI_Handle.ClientCredentials, 
		nullptr);
	if (SSPI_Handle.LastReturnValue != SEC_E_OK)
	{
		PrintError(LOG_LEVEL_3, LOG_ERROR_TLS, L"SSPI get client credentials handle error", SSPI_Handle.LastReturnValue, nullptr, 0);
		return false;
	}

	return true;
}

//SSPI TLS handshake
bool SSPI_Handshake(
	SSPI_HANDLE_TABLE &SSPI_Handle, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<SOCKET_SELECTING_SERIAL_DATA> &SocketSelectingDataList, 
	std::vector<ssize_t> &ErrorCodeList)
{
//Socket data check
	if (SocketDataList.empty() || SocketSelectingDataList.empty() || ErrorCodeList.empty())
		return false;
	
//Initializtion
	SecBufferDesc OutputBufferDesc;
	SecBuffer OutputBufferSec[1U]{0};
	memset(&OutputBufferDesc, 0, sizeof(OutputBufferDesc));
	OutputBufferSec[0].pvBuffer = nullptr;
	OutputBufferSec[0].BufferType = SECBUFFER_TOKEN;
	OutputBufferSec[0].cbBuffer = 0;
	OutputBufferDesc.cBuffers = 1U;
	OutputBufferDesc.pBuffers = OutputBufferSec;
	OutputBufferDesc.ulVersion = SECBUFFER_VERSION;
	SEC_WCHAR *SSPI_SNI = nullptr;
	if (Parameter.HTTP_CONNECT_TLS_SNI != nullptr && !Parameter.HTTP_CONNECT_TLS_SNI->empty())
		SSPI_SNI = (SEC_WCHAR *)Parameter.HTTP_CONNECT_TLS_SNI->c_str();
	DWORD OutputFlags = 0;

//First handshake
	SSPI_Handle.InputFlags |= ISC_REQ_SEQUENCE_DETECT;
	SSPI_Handle.InputFlags |= ISC_REQ_REPLAY_DETECT;
	SSPI_Handle.InputFlags |= ISC_REQ_CONFIDENTIALITY;
	SSPI_Handle.InputFlags |= ISC_RET_EXTENDED_ERROR;
	SSPI_Handle.InputFlags |= ISC_REQ_ALLOCATE_MEMORY;
	SSPI_Handle.InputFlags |= ISC_REQ_STREAM;
	SSPI_Handle.LastReturnValue = InitializeSecurityContextW(
		&SSPI_Handle.ClientCredentials, 
		nullptr, 
		SSPI_SNI, 
		SSPI_Handle.InputFlags, 
		0, 
		0, 
		nullptr, 
		0, 
		&SSPI_Handle.ContextHandle, 
		&OutputBufferDesc, 
		&OutputFlags, 
		nullptr);
	if (SSPI_Handle.LastReturnValue != SEC_I_CONTINUE_NEEDED || OutputBufferSec[0].pvBuffer == nullptr || OutputBufferSec[0].cbBuffer < sizeof(tls_base_record))
	{
		if (OutputBufferSec[0].pvBuffer != nullptr)
			FreeContextBuffer(OutputBufferSec[0].pvBuffer);
		PrintError(LOG_LEVEL_3, LOG_ERROR_TLS, L"SSPI initialize security context error", SSPI_Handle.LastReturnValue, nullptr, 0);

		return false;
	}
	else {
	//Connect to server.
		auto RecvLen = SocketConnecting(IPPROTO_TCP, SocketDataList.front().Socket, (PSOCKADDR)&SocketDataList.front().SockAddr, SocketDataList.front().AddrLen, (const uint8_t *)OutputBufferSec[0].pvBuffer, OutputBufferSec[0].cbBuffer);
		if (RecvLen == EXIT_FAILURE)
		{
			if (OutputBufferSec[0].pvBuffer != nullptr)
				FreeContextBuffer(OutputBufferSec[0].pvBuffer);
			PrintError(LOG_LEVEL_3, LOG_ERROR_NETWORK, L"TLS connecting error", 0, nullptr, 0);

			return false;
		}
		else if (RecvLen >= DNS_PACKET_MINSIZE)
		{
			SocketSelectingDataList.front().SendBuffer.reset();
			SocketSelectingDataList.front().SendSize = 0;
			SocketSelectingDataList.front().SendLen = 0;
		}

	//Buffer initializtion
		std::shared_ptr<uint8_t> SendBuffer(new uint8_t[OutputBufferSec[0].cbBuffer]());
		memset(SendBuffer.get(), 0, OutputBufferSec[0].cbBuffer);
		memcpy_s(SendBuffer.get(), OutputBufferSec[0].cbBuffer, OutputBufferSec[0].pvBuffer, OutputBufferSec[0].cbBuffer);
		SocketSelectingDataList.front().SendBuffer.swap(SendBuffer);
		SocketSelectingDataList.front().SendSize = OutputBufferSec[0].cbBuffer;
		SocketSelectingDataList.front().SendLen = OutputBufferSec[0].cbBuffer;
		if (OutputBufferSec[0].pvBuffer != nullptr)
			FreeContextBuffer(OutputBufferSec[0].pvBuffer);
		OutputBufferSec[0].pvBuffer = nullptr;
		OutputBufferSec[0].cbBuffer = 0;
		SendBuffer.reset();

	//TLS handshake exchange
		SocketSelectingDataList.front().RecvBuffer.reset();
		SocketSelectingDataList.front().RecvSize = 0;
		SocketSelectingDataList.front().RecvLen = 0;
		RecvLen = SocketSelectingSerial(REQUEST_PROCESS_TLS_HANDSHAKE, IPPROTO_TCP, SocketDataList, SocketSelectingDataList, ErrorCodeList);
		SocketSelectingDataList.front().SendBuffer.reset();
		SocketSelectingDataList.front().SendSize = 0;
		SocketSelectingDataList.front().SendLen = 0;
		if (RecvLen == EXIT_FAILURE || SocketSelectingDataList.front().RecvLen < sizeof(tls_base_record))
		{
			PrintError(LOG_LEVEL_3, LOG_ERROR_NETWORK, L"TLS request error", ErrorCodeList.front(), nullptr, 0);
			return false;
		}
	}

//TLS handshake loop and get TLS stream sizes.
	if (!SSPI_HandshakeLoop(SSPI_Handle, SocketDataList, SocketSelectingDataList, ErrorCodeList) || !SSPI_GetStreamSize(SSPI_Handle))
		return false;
	
	return true;
}

//SSPI TLS handshake loop
bool SSPI_HandshakeLoop(
	SSPI_HANDLE_TABLE &SSPI_Handle, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<SOCKET_SELECTING_SERIAL_DATA> &SocketSelectingDataList, 
	std::vector<ssize_t> &ErrorCodeList)
{
//Socket data check
	if (SocketDataList.empty() || SocketSelectingDataList.empty() || ErrorCodeList.empty())
		return false;

//Initializtion
	SecBufferDesc InputBufferDesc, OutputBufferDesc;
	memset(&InputBufferDesc, 0, sizeof(InputBufferDesc));
	memset(&OutputBufferDesc, 0, sizeof(OutputBufferDesc));
	SecBuffer InputBufferSec[2U]{0}, OutputBufferSec[1U]{0};
	SSPI_Handle.LastReturnValue = SEC_I_CONTINUE_NEEDED;
	SEC_WCHAR *SSPI_SNI = nullptr;
	if (Parameter.HTTP_CONNECT_TLS_SNI != nullptr && !Parameter.HTTP_CONNECT_TLS_SNI->empty())
		SSPI_SNI = (SEC_WCHAR *)Parameter.HTTP_CONNECT_TLS_SNI->c_str();
	DWORD OutputFlags = 0;
	size_t RecvLen = 0;

//Handshake loop exchange
	for (;;)
	{
	//Reset parameter.
		SSPI_Handle.InputFlags |= ISC_REQ_SEQUENCE_DETECT;
		SSPI_Handle.InputFlags |= ISC_REQ_REPLAY_DETECT;
		SSPI_Handle.InputFlags |= ISC_REQ_CONFIDENTIALITY;
		SSPI_Handle.InputFlags |= ISC_RET_EXTENDED_ERROR;
		SSPI_Handle.InputFlags |= ISC_RET_ALLOCATED_MEMORY;
		SSPI_Handle.InputFlags |= ISC_REQ_STREAM;
		InputBufferSec[0].BufferType = SECBUFFER_TOKEN;
		InputBufferSec[0].pvBuffer = SocketSelectingDataList.front().RecvBuffer.get();
		InputBufferSec[0].cbBuffer = (DWORD)SocketSelectingDataList.front().RecvLen;
		InputBufferSec[1U].BufferType = SECBUFFER_EMPTY;
		InputBufferSec[1U].pvBuffer = nullptr;
		InputBufferSec[1U].cbBuffer = 0;
		OutputBufferSec[0].BufferType = SECBUFFER_TOKEN;
		OutputBufferSec[0].pvBuffer = nullptr;
		OutputBufferSec[0].cbBuffer = 0;
		InputBufferDesc.ulVersion = SECBUFFER_VERSION;
		InputBufferDesc.pBuffers = InputBufferSec;
		InputBufferDesc.cBuffers = 2U;
		OutputBufferDesc.ulVersion = SECBUFFER_VERSION;
		OutputBufferDesc.pBuffers = OutputBufferSec;
		OutputBufferDesc.cBuffers = 1U;

	//Initialize security context.
		SSPI_Handle.LastReturnValue = InitializeSecurityContextW(
			&SSPI_Handle.ClientCredentials, 
			&SSPI_Handle.ContextHandle, 
			SSPI_SNI, 
			SSPI_Handle.InputFlags, 
			0, 
			0, 
			&InputBufferDesc, 
			0, 
			nullptr, 
			&OutputBufferDesc, 
			&OutputFlags, 
			nullptr);
		if (SSPI_Handle.LastReturnValue == SEC_E_OK)
		{
			if (OutputBufferSec[0].pvBuffer != nullptr)
				FreeContextBuffer(OutputBufferSec[0].pvBuffer);

			break;
		}
		else if (SSPI_Handle.LastReturnValue == SEC_I_COMPLETE_NEEDED || SSPI_Handle.LastReturnValue == SEC_I_COMPLETE_AND_CONTINUE)
		{
		//Complete authentication token.
			SSPI_Handle.LastReturnValue = CompleteAuthToken(&SSPI_Handle.ContextHandle, &OutputBufferDesc);
			if (SSPI_Handle.LastReturnValue != SEC_E_OK)
			{
				if (OutputBufferSec[0].pvBuffer != nullptr)
					FreeContextBuffer(OutputBufferSec[0].pvBuffer);
				PrintError(LOG_LEVEL_3, LOG_ERROR_TLS, L"SSPI complete authentication token error", SSPI_Handle.LastReturnValue, nullptr, 0);

				return false;
			}

			if (OutputBufferSec[0].pvBuffer != nullptr)
				FreeContextBuffer(OutputBufferSec[0].pvBuffer);
			break;
		}
		else if (SSPI_Handle.LastReturnValue == SEC_I_CONTINUE_NEEDED)
		{
		//Buffer initializtion
			if (OutputBufferSec[0].pvBuffer != nullptr && OutputBufferSec[0].cbBuffer >= sizeof(tls_base_record))
			{
				std::shared_ptr<uint8_t> SendBuffer(new uint8_t[OutputBufferSec[0].cbBuffer]());
				memset(SendBuffer.get(), 0, OutputBufferSec[0].cbBuffer);
				memcpy_s(SendBuffer.get(), OutputBufferSec[0].cbBuffer, OutputBufferSec[0].pvBuffer, OutputBufferSec[0].cbBuffer);
				SocketSelectingDataList.front().SendBuffer.swap(SendBuffer);
				SocketSelectingDataList.front().SendSize = OutputBufferSec[0].cbBuffer;
				SocketSelectingDataList.front().SendLen = OutputBufferSec[0].cbBuffer;
				if (OutputBufferSec[0].pvBuffer != nullptr)
					FreeContextBuffer(OutputBufferSec[0].pvBuffer);
				OutputBufferSec[0].pvBuffer = nullptr;
				OutputBufferSec[0].cbBuffer = 0;
			}
			else {
				continue;
			}
		}
		else {
			if (OutputBufferSec[0].pvBuffer != nullptr)
				FreeContextBuffer(OutputBufferSec[0].pvBuffer);
			PrintError(LOG_LEVEL_3, LOG_ERROR_TLS, L"SSPI initialize security context error", SSPI_Handle.LastReturnValue, nullptr, 0);

			return false;
		}

	//TLS handshake exchange
		SocketSelectingDataList.front().RecvBuffer.reset();
		SocketSelectingDataList.front().RecvSize = 0;
		SocketSelectingDataList.front().RecvLen = 0;
		RecvLen = SocketSelectingSerial(REQUEST_PROCESS_TLS_HANDSHAKE, IPPROTO_TCP, SocketDataList, SocketSelectingDataList, ErrorCodeList);
		SocketSelectingDataList.front().SendBuffer.reset();
		SocketSelectingDataList.front().SendSize = 0;
		SocketSelectingDataList.front().SendLen = 0;
		if (RecvLen == EXIT_FAILURE || SocketSelectingDataList.front().RecvLen < sizeof(tls_base_record))
		{
			PrintError(LOG_LEVEL_3, LOG_ERROR_NETWORK, L"TLS request error", ErrorCodeList.front(), nullptr, 0);
			return false;
		}
	}

	return true;
}

//SSPI get the stream encryption sizes
bool SSPI_GetStreamSize(
	SSPI_HANDLE_TABLE &SSPI_Handle)
{
//Get the stream encryption sizes, this needs to be done once per connection.
	SSPI_Handle.LastReturnValue = QueryContextAttributesW(
		&SSPI_Handle.ContextHandle, 
		SECPKG_ATTR_STREAM_SIZES, 
		&SSPI_Handle.StreamSizes);
	if (FAILED(SSPI_Handle.LastReturnValue))
	{
		PrintError(LOG_LEVEL_3, LOG_ERROR_TLS, L"SSPI get stream encryption sizes error", SSPI_Handle.LastReturnValue, nullptr, 0);
		return false;
	}

	return true;
}

//SSPI encryption process
bool SSPI_EncryptPacket(
	SSPI_HANDLE_TABLE &SSPI_Handle, 
	std::vector<SOCKET_SELECTING_SERIAL_DATA> &SocketSelectingDataList)
{
//Socket data check
	if (SocketSelectingDataList.empty())
		return false;

//Send length check
	if (SocketSelectingDataList.front().SendLen >= SSPI_Handle.StreamSizes.cbMaximumMessage)
	{
		PrintError(LOG_LEVEL_3, LOG_ERROR_TLS, L"SSPI plaintext sent to encrypt API is too large", 0, nullptr, 0);
		return false;
	}

//Initializtion
	SecBufferDesc BufferDesc;
	memset(&BufferDesc, 0, sizeof(BufferDesc));
	SecBuffer BufferSec[SSPI_SECURE_BUFFER_NUM]{0};

//Allocate a working buffer.
//The plaintext sent to EncryptMessage can never be more than 'Sizes.cbMaximumMessage', so a buffer size of Sizes.cbMaximumMessage plus the header and trailer sizes is sufficient for the longest message.
	std::shared_ptr<uint8_t> SendBuffer(new uint8_t[SSPI_Handle.StreamSizes.cbHeader + SSPI_Handle.StreamSizes.cbMaximumMessage + SSPI_Handle.StreamSizes.cbTrailer]());
	memset(SendBuffer.get(), 0, SSPI_Handle.StreamSizes.cbHeader + SSPI_Handle.StreamSizes.cbMaximumMessage + SSPI_Handle.StreamSizes.cbTrailer);
	memcpy_s(SendBuffer.get() + SSPI_Handle.StreamSizes.cbHeader, SSPI_Handle.StreamSizes.cbMaximumMessage + SSPI_Handle.StreamSizes.cbTrailer, SocketSelectingDataList.front().SendBuffer.get(), SocketSelectingDataList.front().SendLen);
	BufferSec[0].BufferType = SECBUFFER_STREAM_HEADER;
	BufferSec[0].pvBuffer = SendBuffer.get();
	BufferSec[0].cbBuffer = SSPI_Handle.StreamSizes.cbHeader;
	BufferSec[1U].BufferType = SECBUFFER_DATA;
	BufferSec[1U].pvBuffer = SendBuffer.get() + SSPI_Handle.StreamSizes.cbHeader;
	BufferSec[1U].cbBuffer = (DWORD)SocketSelectingDataList.front().SendLen;
	BufferSec[2U].BufferType = SECBUFFER_STREAM_TRAILER;
	BufferSec[2U].pvBuffer = SendBuffer.get() + SSPI_Handle.StreamSizes.cbHeader + SocketSelectingDataList.front().SendLen;
	BufferSec[2U].cbBuffer = SSPI_Handle.StreamSizes.cbTrailer;
	BufferSec[3U].BufferType = SECBUFFER_EMPTY;
	BufferSec[3U].pvBuffer = nullptr;
	BufferSec[3U].cbBuffer = 0;
	BufferDesc.ulVersion = SECBUFFER_VERSION;
	BufferDesc.pBuffers = BufferSec;
	BufferDesc.cBuffers = SSPI_SECURE_BUFFER_NUM;

//Encrypt data.
	SSPI_Handle.LastReturnValue = EncryptMessage(
		&SSPI_Handle.ContextHandle, 
		0, 
		&BufferDesc, 
		0);
	if (FAILED(SSPI_Handle.LastReturnValue))
	{
		PrintError(LOG_LEVEL_3, LOG_ERROR_TLS, L"SSPI encrypt data error", SSPI_Handle.LastReturnValue, nullptr, 0);
		return false;
	}
	else {
		SocketSelectingDataList.front().SendBuffer.swap(SendBuffer);
		SocketSelectingDataList.front().SendLen += SSPI_Handle.StreamSizes.cbHeader + SSPI_Handle.StreamSizes.cbTrailer;
		SocketSelectingDataList.front().SendSize = SSPI_Handle.StreamSizes.cbHeader + SSPI_Handle.StreamSizes.cbMaximumMessage + SSPI_Handle.StreamSizes.cbTrailer;
	}

	return true;
}

//SSPI decryption process
bool SSPI_DecryptPacket(
	SSPI_HANDLE_TABLE &SSPI_Handle, 
	std::vector<SOCKET_SELECTING_SERIAL_DATA> &SocketSelectingDataList)
{
//Socket data check
	if (SocketSelectingDataList.empty())
		return false;

//Initializtion
	SecBufferDesc BufferDesc;
	memset(&BufferDesc, 0, sizeof(BufferDesc));
	SecBuffer BufferSec[SSPI_SECURE_BUFFER_NUM]{0};
	BufferSec[0].pvBuffer = SocketSelectingDataList.front().RecvBuffer.get();
	BufferSec[0].cbBuffer = (DWORD)SocketSelectingDataList.front().RecvLen;
	BufferSec[0].BufferType = SECBUFFER_DATA;
	BufferSec[1U].BufferType = SECBUFFER_EMPTY;
	BufferSec[1U].pvBuffer = nullptr;
	BufferSec[1U].cbBuffer = 0;
	BufferSec[2U].BufferType = SECBUFFER_EMPTY;
	BufferSec[2U].pvBuffer = nullptr;
	BufferSec[2U].cbBuffer = 0;
	BufferSec[3U].BufferType = SECBUFFER_EMPTY;
	BufferSec[3U].pvBuffer = nullptr;
	BufferSec[3U].cbBuffer = 0;
	BufferDesc.ulVersion = SECBUFFER_VERSION;
	BufferDesc.pBuffers = BufferSec;
	BufferDesc.cBuffers = SSPI_SECURE_BUFFER_NUM;
	size_t Index = 0;

//Decrypt data.
	SSPI_Handle.LastReturnValue = DecryptMessage(
		&SSPI_Handle.ContextHandle, 
		&BufferDesc, 
		0, 
		nullptr);
	if (FAILED(SSPI_Handle.LastReturnValue))
	{
		PrintError(LOG_LEVEL_3, LOG_ERROR_TLS, L"SSPI decrypt data error", SSPI_Handle.LastReturnValue, nullptr, 0);
		return false;
	}
	else {
	//Scan all security buffers.
		for (Index = 0;Index < SSPI_SECURE_BUFFER_NUM;++Index)
		{
			if (BufferSec[Index].BufferType == SECBUFFER_DATA && BufferSec[Index].pvBuffer != nullptr && BufferSec[Index].cbBuffer >= sizeof(tls_base_record))
			{
				break;
			}
			else if (Index + 1U == SSPI_SECURE_BUFFER_NUM)
			{
				PrintError(LOG_LEVEL_3, LOG_ERROR_TLS, L"SSPI decrypt data error", 0, nullptr, 0);
				return false;
			}
		}

	//Buffer initializtion
		std::shared_ptr<uint8_t> RecvBuffer(new uint8_t[BufferSec[Index].cbBuffer]());
		memset(RecvBuffer.get(), 0, BufferSec[Index].cbBuffer);
		memcpy_s(RecvBuffer.get(), BufferSec[Index].cbBuffer, BufferSec[Index].pvBuffer, BufferSec[Index].cbBuffer);
		SocketSelectingDataList.front().RecvBuffer.swap(RecvBuffer);
		SocketSelectingDataList.front().RecvSize = BufferSec[Index].cbBuffer;
		SocketSelectingDataList.front().RecvLen = BufferSec[Index].cbBuffer;
		RecvBuffer.reset();
	}

	return true;
}

//Transport with TLS security connection
bool TLS_TransportSerial(
	const size_t PacketMinSize, 
	SSPI_HANDLE_TABLE &SSPI_Handle, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<SOCKET_SELECTING_SERIAL_DATA> &SocketSelectingDataList, 
	std::vector<ssize_t> &ErrorCodeList)
{
//Socket data check
	if (SocketDataList.empty() || SocketSelectingDataList.empty() || ErrorCodeList.empty())
		return false;

//TLS encrypt packet.
	if (!SSPI_EncryptPacket(SSPI_Handle, SocketSelectingDataList) || SocketSelectingDataList.front().SendLen < sizeof(tls_base_record))
	{
		SocketSelectingDataList.front().SendBuffer.reset();
		SocketSelectingDataList.front().SendSize = 0;
		SocketSelectingDataList.front().SendLen = 0;

		return false;
	}

//Request exchange 
	SocketSelectingDataList.front().RecvBuffer.reset();
	SocketSelectingDataList.front().RecvSize = 0;
	SocketSelectingDataList.front().RecvLen = 0;
	auto RecvLen = SocketSelectingSerial(REQUEST_PROCESS_TLS_TRANSPORT, IPPROTO_TCP, SocketDataList, SocketSelectingDataList, ErrorCodeList);
	SocketSelectingDataList.front().SendBuffer.reset();
	SocketSelectingDataList.front().SendSize = 0;
	SocketSelectingDataList.front().SendLen = 0;
	if (RecvLen == EXIT_FAILURE || SSPI_Handle.LastReturnValue == SEC_I_CONTEXT_EXPIRED || 
		SocketSelectingDataList.front().RecvLen < sizeof(tls_base_record))
	{
		SocketSelectingDataList.front().RecvBuffer.reset();
		SocketSelectingDataList.front().RecvSize = 0;
		SocketSelectingDataList.front().RecvLen = 0;

		return false;
	}
	else {
	//TLS decrypt packet.
		if (SSPI_DecryptPacket(SSPI_Handle, SocketSelectingDataList) && SocketSelectingDataList.front().RecvLen >= PacketMinSize)
			return true;
	}

	return false;
}

//SSPI shutdown SChannel security connection
bool SSPI_ShutdownConnection(
	SSPI_HANDLE_TABLE &SSPI_Handle, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<ssize_t> &ErrorCodeList)
{
//Socket data check
	if (SocketDataList.empty() || ErrorCodeList.empty())
		return false;

//Socket check
	if (!SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_INVALID_CHECK, false, nullptr))
		return false;

//Buffer initializtion(Part 1)
	std::vector<SOCKET_SELECTING_SERIAL_DATA> SocketSelectingDataList(1U);
	SecBufferDesc BufferDesc;
	memset(&BufferDesc, 0, sizeof(BufferDesc));
	SecBuffer BufferSec[1U]{0};
	SSPI_Handle.InputFlags = SCHANNEL_SHUTDOWN;
	BufferSec[0].pvBuffer = &SSPI_Handle.InputFlags;
	BufferSec[0].BufferType = SECBUFFER_TOKEN;
	BufferSec[0].cbBuffer = sizeof(SSPI_Handle.InputFlags);
	BufferDesc.cBuffers = 1U;
	BufferDesc.pBuffers = BufferSec;
	BufferDesc.ulVersion = SECBUFFER_VERSION;

//Apply control token.
	SSPI_Handle.LastReturnValue = ApplyControlToken(
		&SSPI_Handle.ContextHandle, 
		&BufferDesc);
	if (FAILED(SSPI_Handle.LastReturnValue))
	{
		PrintError(LOG_LEVEL_3, LOG_ERROR_TLS, L"SSPI initialize security context error", SSPI_Handle.LastReturnValue, nullptr, 0);
		return false;
	}

//Buffer initializtion(Part 2)
	SSPI_Handle.InputFlags |= ISC_REQ_SEQUENCE_DETECT;
	SSPI_Handle.InputFlags |= ISC_REQ_REPLAY_DETECT;
	SSPI_Handle.InputFlags |= ISC_REQ_CONFIDENTIALITY;
	SSPI_Handle.InputFlags |= ISC_RET_EXTENDED_ERROR;
	SSPI_Handle.InputFlags |= ISC_REQ_ALLOCATE_MEMORY;
	SSPI_Handle.InputFlags |= ISC_REQ_STREAM;
	BufferSec[0].BufferType = SECBUFFER_TOKEN;
	BufferSec[0].pvBuffer = nullptr;
	BufferSec[0].cbBuffer = 0;
	BufferDesc.cBuffers = 1U;
	BufferDesc.pBuffers = BufferSec;
	BufferDesc.ulVersion = SECBUFFER_VERSION;
	SEC_WCHAR *SSPI_SNI = nullptr;
	if (Parameter.HTTP_CONNECT_TLS_SNI != nullptr && !Parameter.HTTP_CONNECT_TLS_SNI->empty())
		SSPI_SNI = (SEC_WCHAR *)Parameter.HTTP_CONNECT_TLS_SNI->c_str();
	DWORD OutputFlags = 0;

//Send "Close notify" to server to notify shutdown connection.
	SSPI_Handle.LastReturnValue = InitializeSecurityContextW(
		&SSPI_Handle.ClientCredentials, 
		&SSPI_Handle.ContextHandle, 
		SSPI_SNI, 
		SSPI_Handle.InputFlags, 
		0, 
		0, 
		nullptr, 
		0, 
		nullptr, 
		&BufferDesc, 
		&OutputFlags, 
		nullptr);
	if (FAILED(SSPI_Handle.LastReturnValue) || BufferSec[0].pvBuffer == nullptr || BufferSec[0].cbBuffer < sizeof(tls_base_record))
	{
		if (BufferSec[0].pvBuffer != nullptr)
			FreeContextBuffer(BufferSec[0].pvBuffer);
		PrintError(LOG_LEVEL_3, LOG_ERROR_TLS, L"SSPI initialize security context error", SSPI_Handle.LastReturnValue, nullptr, 0);

		return false;
	}
	else {
	//Buffer initializtion
		std::shared_ptr<uint8_t> SendBuffer(new uint8_t[BufferSec[0].cbBuffer]());
		memset(SendBuffer.get(), 0, BufferSec[0].cbBuffer);
		memcpy_s(SendBuffer.get(), BufferSec[0].cbBuffer, BufferSec[0].pvBuffer, BufferSec[0].cbBuffer);
		SocketSelectingDataList.front().SendBuffer.swap(SendBuffer);
		SocketSelectingDataList.front().SendSize = BufferSec[0].cbBuffer;
		SocketSelectingDataList.front().SendLen = BufferSec[0].cbBuffer;
		if (BufferSec[0].pvBuffer != nullptr)
			FreeContextBuffer(BufferSec[0].pvBuffer);
		SendBuffer.reset();

	//TLS handshake exchange
		SocketSelectingDataList.front().RecvBuffer.reset();
		SocketSelectingDataList.front().RecvSize = 0;
		SocketSelectingDataList.front().RecvLen = 0;
		auto RecvLen = SocketSelectingSerial(REQUEST_PROCESS_TLS_SHUTDOWN, IPPROTO_TCP, SocketDataList, SocketSelectingDataList, ErrorCodeList);
		SocketSelectingDataList.front().SendBuffer.reset();
		SocketSelectingDataList.front().SendSize = 0;
		SocketSelectingDataList.front().SendLen = 0;
		if (RecvLen == EXIT_FAILURE)
		{
			PrintError(LOG_LEVEL_3, LOG_ERROR_NETWORK, L"TLS request error", ErrorCodeList.front(), nullptr, 0);
			return false;
		}
	}

	return true;
}
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
//OpenSSL print error message process
bool OpenSSL_PrintError(
	const uint8_t *OpenSSL_ErrorMessage, 
	const wchar_t *ErrorMessage)
{
//Message check
	if (OpenSSL_ErrorMessage == nullptr || ErrorMessage == nullptr || 
		strnlen((const char *)OpenSSL_ErrorMessage, OPENSSL_STATIC_BUFFER_SIZE) == 0 || 
		wcsnlen(ErrorMessage, OPENSSL_STATIC_BUFFER_SIZE) == 0)
	{
		PrintError(LOG_LEVEL_2, LOG_ERROR_SYSTEM, L"Convert multiple byte or wide char string error", 0, nullptr, 0);
		return false;
	}

//Convert message.
	std::wstring Message;
	if (MBS_To_WCS_String(OpenSSL_ErrorMessage, OPENSSL_STATIC_BUFFER_SIZE, Message))
	{
		std::wstring InnerMessage(ErrorMessage); //OpenSSL will return message like "error:..."
		InnerMessage.append(Message);
		PrintError(LOG_LEVEL_3, LOG_ERROR_TLS, InnerMessage.c_str(), 0, nullptr, 0);
	}
	else {
		PrintError(LOG_LEVEL_2, LOG_ERROR_SYSTEM, L"Convert multiple byte or wide char string error", 0, nullptr, 0);
		return false;
	}

	return true;
}

//OpenSSL initializtion
void OpenSSL_Library_Init(
	bool IsLoad)
{
//Load all OpenSSL libraries, algorithms and strings.
	if (IsLoad)
	{
	#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_1_1_0 //OpenSSL version after 1.1.0
		OPENSSL_init_ssl(0, nullptr);
	#else //OpenSSL version before 1.1.0
		SSL_library_init();
		OpenSSL_add_all_algorithms();
		SSL_load_error_strings();
		ERR_load_crypto_strings();
		OPENSSL_config(nullptr);
	#endif
	}
#if OPENSSL_VERSION_NUMBER < OPENSSL_VERSION_1_1_0 //OpenSSL version brfore 1.1.0
	else { //Unoad all OpenSSL libraries, algorithms and strings.
		CONF_modules_unload(TRUE);
		ERR_free_strings();
		EVP_cleanup();
	}
#endif

	return;
}

//OpenSSL TLS CTX initializtion
bool OpenSSL_CTX_Initializtion(
	OPENSSL_CONTEXT_TABLE &OpenSSL_CTX)
{
	ssize_t Result = 0;

//TLS version selection(Part 1)
#if OPENSSL_VERSION_NUMBER < OPENSSL_VERSION_1_0_1 //OpenSSL version before 1.0.1
	if (Parameter.HTTP_CONNECT_TLS_Version == TLS_VERSION_1_0) //OpenSSL version before 1.0.1 only support TLS version 1.0
		OpenSSL_CTX.MethodContext = SSL_CTX_new(TLSv1_0_method());
	else //Auto-select
		OpenSSL_CTX.MethodContext = SSL_CTX_new(SSLv23_method());
#elif OPENSSL_VERSION_NUMBER < OPENSSL_VERSION_1_1_0 //OpenSSL version between 1.0.1 and 1.1.0
	if (Parameter.HTTP_CONNECT_TLS_Version == TLS_VERSION_1_2)
		OpenSSL_CTX.MethodContext = SSL_CTX_new(TLSv1_2_method());
	else if (Parameter.HTTP_CONNECT_TLS_Version == TLS_VERSION_1_1)
		OpenSSL_CTX.MethodContext = SSL_CTX_new(TLSv1_1_method());
	else if (Parameter.HTTP_CONNECT_TLS_Version == TLS_VERSION_1_0)
		OpenSSL_CTX.MethodContext = SSL_CTX_new(TLSv1_method());
	else //Auto select
		OpenSSL_CTX.MethodContext = SSL_CTX_new(SSLv23_method());
#else //OpenSSL version after 1.1.0
	OpenSSL_CTX.MethodContext = SSL_CTX_new(TLS_method()); //TLS selection after OpenSSL version 1.1.0 must set flags of method context.
#endif

//Create new client-method instance.
	if (OpenSSL_CTX.MethodContext == nullptr)
	{
		OpenSSL_PrintError((const uint8_t *)ERR_error_string(ERR_get_error(), nullptr), L"OpenSSL create new client-method instance ");
		return false;
	}
	
//TLS version selection(Part 2)
#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_1_1_0 //OpenSSL version after 1.1.0
	if (Parameter.HTTP_CONNECT_TLS_Version == TLS_VERSION_1_2)
	{
		Result = SSL_CTX_set_min_proto_version(OpenSSL_CTX.MethodContext, TLS1_2_VERSION);
		Result = SSL_CTX_set_max_proto_version(OpenSSL_CTX.MethodContext, TLS1_2_VERSION);
	}
	else if (Parameter.HTTP_CONNECT_TLS_Version == TLS_VERSION_1_1)
	{
		Result = SSL_CTX_set_min_proto_version(OpenSSL_CTX.MethodContext, TLS1_1_VERSION);
		Result = SSL_CTX_set_max_proto_version(OpenSSL_CTX.MethodContext, TLS1_1_VERSION);
	}
	else if (Parameter.HTTP_CONNECT_TLS_Version == TLS_VERSION_1_0)
	{
		Result = SSL_CTX_set_min_proto_version(OpenSSL_CTX.MethodContext, TLS1_VERSION);
		Result = SSL_CTX_set_max_proto_version(OpenSSL_CTX.MethodContext, TLS1_VERSION);
	}
	else { //Setting the minimum or maximum version to 0, will enable protocol versions down to the lowest version, or up to the highest version supported by the library, respectively.
		Result = SSL_CTX_set_max_proto_version(OpenSSL_CTX.MethodContext, 0);
	}

//TLS selection check
	if (Result == FALSE)
	{
		OpenSSL_PrintError((const uint8_t *)ERR_error_string(ERR_get_error(), nullptr), L"OpenSSL TLS version selection ");
		return false;
	}
#endif

//TLS connection flags
	SSL_CTX_set_options(OpenSSL_CTX.MethodContext, SSL_OP_NO_SSLv2); //Block SSLv2 protocol
	SSL_CTX_set_options(OpenSSL_CTX.MethodContext, SSL_OP_NO_SSLv3); //Block SSLv3 protocol
	SSL_CTX_set_options(OpenSSL_CTX.MethodContext, SSL_OP_NO_COMPRESSION); //Block TLS compression
	SSL_CTX_set_options(OpenSSL_CTX.MethodContext, SSL_OP_SINGLE_DH_USE); //Always create a new key when using temporary/ephemeral DH parameters.
	if (Parameter.HTTP_CONNECT_TLS_Validation)
	{
	//Locate default certificate store.
		Result = SSL_CTX_set_default_verify_paths(OpenSSL_CTX.MethodContext);
		if (Result == FALSE)
		{
			OpenSSL_PrintError((const uint8_t *)ERR_error_string(ERR_get_error(), nullptr), L"OpenSSL locate default certificate store ");
			return false;
		}

	//Set certificate verification.
		SSL_CTX_set_verify(OpenSSL_CTX.MethodContext, SSL_VERIFY_PEER, nullptr);
	}

	return true;
}

//OpenSSL BIO initializtion
bool OpenSSL_BIO_Initializtion(
	OPENSSL_CONTEXT_TABLE &OpenSSL_CTX)
{
//Create a new BIO method.
	OpenSSL_CTX.SessionBIO = BIO_new_ssl_connect(OpenSSL_CTX.MethodContext);
	if (OpenSSL_CTX.SessionBIO == nullptr)
	{
		OpenSSL_PrintError((const uint8_t *)ERR_error_string(ERR_get_error(), nullptr), L"OpenSSL create new BIO method ");
		return false;
	}

//BIO attribute settings
	BIO_set_nbio(OpenSSL_CTX.SessionBIO, TRUE); //Socket non-blocking mode
	BIO_set_conn_hostname(OpenSSL_CTX.SessionBIO, OpenSSL_CTX.AddressString.c_str()); //Set connect target
	BIO_get_ssl(OpenSSL_CTX.SessionBIO, &OpenSSL_CTX.SessionData);

//Get SSL method data.
	if (OpenSSL_CTX.SessionData == nullptr)
	{
		OpenSSL_PrintError((const uint8_t *)ERR_error_string(ERR_get_error(), nullptr), L"OpenSSL BIO and SSL data attribute setting ");
		return false;
	}

//SSL data attribute settings
	ssize_t Result = 0;
	SSL_set_mode(OpenSSL_CTX.SessionData, SSL_MODE_AUTO_RETRY);
#if defined(SSL_MODE_RELEASE_BUFFERS)
	SSL_set_mode(OpenSSL_CTX.SessionData, SSL_MODE_RELEASE_BUFFERS);
#endif
	if (Parameter.MBS_HTTP_CONNECT_TLS_SNI != nullptr && !Parameter.MBS_HTTP_CONNECT_TLS_SNI->empty())
		SSL_set_tlsext_host_name(OpenSSL_CTX.SessionData, Parameter.MBS_HTTP_CONNECT_TLS_SNI->c_str()); //TLS Server Name Indication/SNI

//Set ciphers suites.
#if OPENSSL_VERSION_NUMBER < OPENSSL_VERSION_1_0_1 //OpenSSL version before 1.0.1
	Result = SSL_set_cipher_list(OpenSSL_CTX.SessionData, OPENSSL_CIPHER_LIST_COMPATIBILITY);
#else //OpenSSL version after 1.0.1
	if (Parameter.HTTP_CONNECT_TLS_Version == TLS_VERSION_1_0 || Parameter.HTTP_CONNECT_TLS_Version == TLS_VERSION_1_1)
		Result = SSL_set_cipher_list(OpenSSL_CTX.SessionData, OPENSSL_CIPHER_LIST_COMPATIBILITY);
	else //Auto select and newer TLS version
		Result = SSL_set_cipher_list(OpenSSL_CTX.SessionData, OPENSSL_CIPHER_LIST_STRONG);
#endif
	if (Result == FALSE)
	{
		OpenSSL_PrintError((const uint8_t *)ERR_error_string(ERR_get_error(), nullptr), L"OpenSSL set strong ciphers ");
		return false;
	}

//Built-in functionality for hostname checking and validation after OpenSSL 1.0.2.
#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_1_0_2 //OpenSSL version after 1.0.2
	if (Parameter.HTTP_CONNECT_TLS_Validation && Parameter.MBS_HTTP_CONNECT_TLS_SNI != nullptr && !Parameter.MBS_HTTP_CONNECT_TLS_SNI->empty())
	{
	//Get certificate paremeter.
		X509_VERIFY_PARAM *X509_Param = nullptr;
		X509_Param = SSL_get0_param(OpenSSL_CTX.SessionData);
		if (X509_Param == nullptr)
		{
			OpenSSL_PrintError((const uint8_t *)ERR_error_string(ERR_get_error(), nullptr), L"OpenSSL hostname checking and validation ");
			return false;
		}
		
	//Set certificate paremeter flags.
		X509_VERIFY_PARAM_set_hostflags(X509_Param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
		if (X509_VERIFY_PARAM_set1_host(X509_Param, Parameter.MBS_HTTP_CONNECT_TLS_SNI->c_str(), 0) == FALSE)
		{
			OpenSSL_PrintError((const uint8_t *)ERR_error_string(ERR_get_error(), nullptr), L"OpenSSL hostname checking and validation ");
			return false;
		}
	}
#endif

//Set certificate verification.
	if (Parameter.HTTP_CONNECT_TLS_Validation)
		SSL_set_verify(OpenSSL_CTX.SessionData, SSL_VERIFY_PEER, nullptr);

	return true;
}

//OpenSSL TLS handshake
bool OpenSSL_Handshake(
	OPENSSL_CONTEXT_TABLE &OpenSSL_CTX)
{
//Initializtion
	ssize_t RecvLen = 0;
	size_t Timeout = 0;

//OpenSSL BIO connecting
	while (RecvLen <= 0)
	{
		RecvLen = BIO_do_connect(OpenSSL_CTX.SessionBIO);
		if (RecvLen == TRUE)
		{
			break;
		}
		else if (Timeout <= Parameter.SocketTimeout_Reliable_Serial.tv_sec * SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND + Parameter.SocketTimeout_Reliable_Serial.tv_usec && 
			BIO_should_retry(OpenSSL_CTX.SessionBIO))
		{
			usleep(LOOP_INTERVAL_TIME_NO_DELAY);
			Timeout += LOOP_INTERVAL_TIME_NO_DELAY;
		}
		else {
			OpenSSL_PrintError((const uint8_t *)ERR_error_string(ERR_get_error(), nullptr), L"OpenSSL connecting ");
			return false;
		}
	}

//OpenSSL TLS handshake
	RecvLen = 0;
	Timeout = 0;
	while (RecvLen <= 0)
	{
		RecvLen = BIO_do_handshake(OpenSSL_CTX.SessionBIO);
		if (RecvLen == TRUE)
		{
			break;
		}
		else if (Timeout <= Parameter.SocketTimeout_Reliable_Serial.tv_sec * SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND + Parameter.SocketTimeout_Reliable_Serial.tv_usec && 
			BIO_should_retry(OpenSSL_CTX.SessionBIO))
		{
			usleep(LOOP_INTERVAL_TIME_NO_DELAY);
			Timeout += LOOP_INTERVAL_TIME_NO_DELAY;
		}
		else {
			OpenSSL_PrintError((const uint8_t *)ERR_error_string(ERR_get_error(), nullptr), L"OpenSSL handshake ");
			return false;
		}
	}

//Verify a server certificate was presented during the negotiation.
	auto Certificate = SSL_get_peer_certificate(OpenSSL_CTX.SessionData);
	if (Certificate == nullptr)
	{
		OpenSSL_PrintError((const uint8_t *)ERR_error_string(ERR_get_error(), nullptr), L"OpenSSL verify server certificate ");
		return false;
	}
	else {
		X509_free(Certificate);
		Certificate = nullptr;
	}

//Verify the result of chain verification, verification performed according to RFC 4158.
	if (Parameter.HTTP_CONNECT_TLS_Validation && SSL_get_verify_result(OpenSSL_CTX.SessionData) != X509_V_OK)
	{
		OpenSSL_PrintError((const uint8_t *)ERR_error_string(ERR_get_error(), nullptr), L"OpenSSL verify the result of chain verification ");
		return false;
	}

	return true;
}

//Transport with TLS security connection
bool TLS_TransportSerial(
	const size_t RequestType, 
	const size_t PacketMinSize, 
	OPENSSL_CONTEXT_TABLE &OpenSSL_CTX, 
	std::vector<SOCKET_SELECTING_SERIAL_DATA> &SocketSelectingDataList)
{
//Socket data check
	if (SocketSelectingDataList.empty())
		return false;

//Initializtion
	ssize_t RecvLen = 0;
	size_t Timeout = 0;

//OpenSSL transport(Send process)
	if (SocketSelectingDataList.front().SendBuffer && SocketSelectingDataList.front().SendLen > 0)
	{
		while (RecvLen <= 0)
		{
			RecvLen = BIO_write(OpenSSL_CTX.SessionBIO, SocketSelectingDataList.front().SendBuffer.get(), (int)SocketSelectingDataList.front().SendLen);
			if (RecvLen >= (ssize_t)SocketSelectingDataList.front().SendLen)
			{
				break;
			}
			else if (Timeout <= Parameter.SocketTimeout_Reliable_Serial.tv_sec * SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND + Parameter.SocketTimeout_Reliable_Serial.tv_usec && 
				BIO_should_retry(OpenSSL_CTX.SessionBIO))
			{
				usleep(LOOP_INTERVAL_TIME_NO_DELAY);
				Timeout += LOOP_INTERVAL_TIME_NO_DELAY;
			}
			else {
			//Buffer initializtion
				SocketSelectingDataList.front().SendBuffer.reset();
				SocketSelectingDataList.front().SendSize = 0;
				SocketSelectingDataList.front().SendLen = 0;

			//Print error message.
				OpenSSL_PrintError((const uint8_t *)ERR_error_string(ERR_get_error(), nullptr), L"OpenSSL send data ");
				return false;
			}
		}
	}

//Buffer initializtion
	SocketSelectingDataList.front().SendBuffer.reset();
	SocketSelectingDataList.front().SendSize = 0;
	SocketSelectingDataList.front().SendLen = 0;
	SocketSelectingDataList.front().RecvBuffer.reset();
	SocketSelectingDataList.front().RecvSize = 0;
	SocketSelectingDataList.front().RecvLen = 0;
	RecvLen = 0;
	Timeout = 0;

//OpenSSL transpot(Receive process)
	for (;;)
	{
	//Prepare buffer.
		if (!SocketSelectingDataList.front().RecvBuffer)
		{
			std::shared_ptr<uint8_t> RecvBuffer(new uint8_t[Parameter.LargeBufferSize]);
			memset(RecvBuffer.get(), 0, Parameter.LargeBufferSize);
			SocketSelectingDataList.front().RecvBuffer.swap(RecvBuffer);
			SocketSelectingDataList.front().RecvSize = Parameter.LargeBufferSize;
			SocketSelectingDataList.front().RecvLen = 0;
		}
		else if (SocketSelectingDataList.front().RecvSize < SocketSelectingDataList.front().RecvLen + Parameter.LargeBufferSize)
		{
			std::shared_ptr<uint8_t> RecvBuffer(new uint8_t[SocketSelectingDataList.front().RecvSize + Parameter.LargeBufferSize]);
			memset(RecvBuffer.get(), 0, SocketSelectingDataList.front().RecvSize + Parameter.LargeBufferSize);
			memcpy_s(RecvBuffer.get(), SocketSelectingDataList.front().RecvSize + Parameter.LargeBufferSize, SocketSelectingDataList.front().RecvBuffer.get(), SocketSelectingDataList.front().RecvLen);
			SocketSelectingDataList.front().RecvBuffer.swap(RecvBuffer);
			SocketSelectingDataList.front().RecvSize += Parameter.LargeBufferSize;
		}

	//Receive process
		RecvLen = BIO_read(OpenSSL_CTX.SessionBIO, SocketSelectingDataList.front().RecvBuffer.get() + SocketSelectingDataList.front().RecvLen, (int)Parameter.LargeBufferSize);
		if (RecvLen <= 0)
		{
			if (Timeout <= Parameter.SocketTimeout_Reliable_Serial.tv_sec * SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND + Parameter.SocketTimeout_Reliable_Serial.tv_usec && 
				BIO_should_retry(OpenSSL_CTX.SessionBIO))
			{
				usleep(LOOP_INTERVAL_TIME_NO_DELAY);
				Timeout += LOOP_INTERVAL_TIME_NO_DELAY;
			}
			else if (RequestType == REQUEST_PROCESS_TLS_SHUTDOWN) //Do not print any error messages when connecting is shutting down.
			{
				return false;
			}
			else {
			//Buffer initializtion
				SocketSelectingDataList.front().RecvBuffer.reset();
				SocketSelectingDataList.front().RecvSize = 0;
				SocketSelectingDataList.front().RecvLen = 0;

			//Print error message.
				OpenSSL_PrintError((const uint8_t *)ERR_error_string(ERR_get_error(), nullptr), L"OpenSSL receive data ");
				return false;
			}
		}
		else {
			SocketSelectingDataList.front().RecvLen += RecvLen;
			if (RecvLen < (ssize_t)Parameter.LargeBufferSize && SocketSelectingDataList.front().RecvLen >= PacketMinSize && 
				(RequestType != REQUEST_PROCESS_TCP || //Only TCP DNS response should be check.
				CheckConnectionStreamFin(RequestType, SocketSelectingDataList.front().RecvBuffer.get(), SocketSelectingDataList.front().RecvLen)))
					return true;
		}
	}

	return false;
}

//OpenSSL shutdown security connection
bool OpenSSL_ShutdownConnection(
	OPENSSL_CONTEXT_TABLE &OpenSSL_CTX)
{
//Initializtion
	std::vector<SOCKET_SELECTING_SERIAL_DATA> SocketSelectingDataList(1U);
	ssize_t Result = 0;

//Send "Close notify" to server to notify shutdown connection.
	while (Result == 0)
	{
	//Shutdown security connection.
		Result = SSL_shutdown(OpenSSL_CTX.SessionData);
		if (Result < 0)
			return false;

	//Receive rest of data.
		SocketSelectingDataList.front().RecvBuffer.reset();
		SocketSelectingDataList.front().RecvSize = 0;
		SocketSelectingDataList.front().RecvLen = 0;
		TLS_TransportSerial(REQUEST_PROCESS_TLS_SHUTDOWN, sizeof(tls_base_record), OpenSSL_CTX, SocketSelectingDataList);
	}

	return true;
}
#endif
#endif

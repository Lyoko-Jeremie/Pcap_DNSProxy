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


#include "Process.h"

//Montior request provider
void MonitorRequestProvider(
	const MONITOR_QUEUE_DATA &MonitorQueryData)
{
//Add to blocking queue.
	MonitorBlockingQueue.push(MonitorQueryData);

//Thread pool check
	if (Parameter.ThreadPoolBaseNum > 0 && GlobalRunningStatus.ThreadRunningFreeNum->load() == 0 && 
		GlobalRunningStatus.ThreadRunningNum->load() < Parameter.ThreadPoolMaxNum)
	{
		auto ThreadIncreaseNum = Parameter.ThreadPoolBaseNum;
		if (GlobalRunningStatus.ThreadRunningNum->load() + Parameter.ThreadPoolBaseNum > Parameter.ThreadPoolMaxNum)
			ThreadIncreaseNum = Parameter.ThreadPoolMaxNum - GlobalRunningStatus.ThreadRunningNum->load();
		(*GlobalRunningStatus.ThreadRunningNum) += ThreadIncreaseNum;
		(*GlobalRunningStatus.ThreadRunningFreeNum) += ThreadIncreaseNum;

	//Start threads.
		for (size_t Index = 0;Index < ThreadIncreaseNum;++Index)
		{
			std::thread MonitorConsumerThread(std::bind(MonitorRequestConsumer));
			MonitorConsumerThread.detach();
		}
	}

	return;
}

//Monitor request consumer
void MonitorRequestConsumer(
	void)
{
//Initialization
	MONITOR_QUEUE_DATA MonitorQueryData;
	std::unique_ptr<uint8_t[]> SendBuffer(new uint8_t[Parameter.LargeBufferSize + PADDING_RESERVED_BYTES]());
	std::unique_ptr<uint8_t[]> RecvBuffer(new uint8_t[Parameter.LargeBufferSize + PADDING_RESERVED_BYTES]());
	memset(SendBuffer.get(), 0, Parameter.LargeBufferSize + PADDING_RESERVED_BYTES);
	memset(RecvBuffer.get(), 0, Parameter.LargeBufferSize + PADDING_RESERVED_BYTES);
	size_t LastActiveTime = 0;

//Start request Monitor consumer.
	for (;;)
	{
	//Reset parameters.
		memset(SendBuffer.get(), 0, Parameter.LargeBufferSize + PADDING_RESERVED_BYTES);
		memset(RecvBuffer.get(), 0, Parameter.LargeBufferSize + PADDING_RESERVED_BYTES);
		if (Parameter.ThreadPoolBaseNum > 0)
			LastActiveTime = static_cast<size_t>(GetCurrentSystemTime());

	//Pop from blocking queue.
		MonitorBlockingQueue.pop(MonitorQueryData);
		if (Parameter.ThreadPoolBaseNum > 0 && GlobalRunningStatus.ThreadRunningFreeNum->load() > 0)
			--(*GlobalRunningStatus.ThreadRunningFreeNum);

	//Handle process
		memcpy_s(SendBuffer.get(), Parameter.LargeBufferSize, MonitorQueryData.first.Buffer, MonitorQueryData.first.Length);
		MonitorQueryData.first.Buffer = SendBuffer.get();
		MonitorQueryData.first.BufferSize = Parameter.LargeBufferSize;
		if (MonitorQueryData.first.Protocol == IPPROTO_TCP)
			TCP_AcceptProcess(MonitorQueryData, RecvBuffer.get(), Parameter.LargeBufferSize);
		else if (MonitorQueryData.first.Protocol == IPPROTO_UDP)
			EnterRequestProcess(MonitorQueryData, RecvBuffer.get(), Parameter.LargeBufferSize);

	//Thread pool check
		if (Parameter.ThreadPoolBaseNum > 0)
		{
			if (LastActiveTime + Parameter.ThreadPoolResetTime <= GetCurrentSystemTime() && 
				GlobalRunningStatus.ThreadRunningNum->load() > Parameter.ThreadPoolBaseNum && 
				GlobalRunningStatus.ThreadRunningFreeNum->load() > 0)
			{
				--(*GlobalRunningStatus.ThreadRunningNum);
				break;
			}
			else {
				++(*GlobalRunningStatus.ThreadRunningFreeNum);
			}
		}
	}

	return;
}

//Independent request process
bool EnterRequestProcess(
	MONITOR_QUEUE_DATA MonitorQueryData, 
	uint8_t *RecvBuffer, 
	size_t RecvSize)
{
//Initialization(Send buffer part)
	std::unique_ptr<uint8_t[]> SendBuffer(nullptr);
	if ((RecvBuffer == nullptr || RecvSize == 0) && MonitorQueryData.first.Protocol == IPPROTO_UDP) //New thread mode
	{
		if (Parameter.CompressionPointerMutation)
		{
			if (Parameter.CPM_PointerToAdditional)
			{
				std::unique_ptr<uint8_t[]> SendBufferTemp(new uint8_t[MonitorQueryData.first.Length + 2U + sizeof(dns_record_aaaa) + sizeof(uint16_t) + PADDING_RESERVED_BYTES]());
				memset(SendBufferTemp.get(), 0, MonitorQueryData.first.Length + 2U + sizeof(dns_record_aaaa) + sizeof(uint16_t) + PADDING_RESERVED_BYTES);
				std::swap(SendBuffer, SendBufferTemp);
				MonitorQueryData.first.BufferSize = MonitorQueryData.first.Length + 2U + sizeof(dns_record_aaaa) + sizeof(uint16_t);
			}
			else if (Parameter.CPM_PointerToRR)
			{
				std::unique_ptr<uint8_t[]> SendBufferTemp(new uint8_t[MonitorQueryData.first.Length + 2U + sizeof(uint16_t) + PADDING_RESERVED_BYTES]());
				memset(SendBufferTemp.get(), 0, MonitorQueryData.first.Length + 2U + sizeof(uint16_t) + PADDING_RESERVED_BYTES);
				std::swap(SendBuffer, SendBufferTemp);
				MonitorQueryData.first.BufferSize = MonitorQueryData.first.Length + 2U + sizeof(uint16_t);
			}
			else { //Pointer to header
				std::unique_ptr<uint8_t[]> SendBufferTemp(new uint8_t[MonitorQueryData.first.Length + 1U + sizeof(uint16_t) + PADDING_RESERVED_BYTES]());
				memset(SendBufferTemp.get(), 0, MonitorQueryData.first.Length + 1U + sizeof(uint16_t) + PADDING_RESERVED_BYTES);
				std::swap(SendBuffer, SendBufferTemp);
				MonitorQueryData.first.BufferSize = MonitorQueryData.first.Length + 1U + sizeof(uint16_t);
			}
		}
		else {
			std::unique_ptr<uint8_t[]> SendBufferTemp(new uint8_t[MonitorQueryData.first.Length + sizeof(uint16_t) + PADDING_RESERVED_BYTES]()); //Reserved 2 bytes for TCP header length.
			memset(SendBufferTemp.get(), 0, MonitorQueryData.first.Length + sizeof(uint16_t) + PADDING_RESERVED_BYTES);
			std::swap(SendBuffer, SendBufferTemp);
			MonitorQueryData.first.BufferSize = MonitorQueryData.first.Length + sizeof(uint16_t);
		}

		memcpy_s(SendBuffer.get(), MonitorQueryData.first.BufferSize, MonitorQueryData.first.Buffer, MonitorQueryData.first.Length);
		MonitorQueryData.first.Buffer = SendBuffer.get();
	}

//Initialization(Receive buffer part)
	std::unique_ptr<uint8_t[]> InnerRecvBuffer(nullptr);
	if (RecvBuffer == nullptr || RecvSize == 0) //New thread mode
	{
	//TCP
		if (Parameter.RequestMode_Transport == REQUEST_MODE_TRANSPORT::FORCE_TCP || Parameter.RequestMode_Transport == REQUEST_MODE_TRANSPORT::TCP || 
			MonitorQueryData.first.Protocol == IPPROTO_TCP || //TCP request
			Parameter.LocalProtocol_Transport == REQUEST_MODE_TRANSPORT::FORCE_TCP || Parameter.LocalProtocol_Transport == REQUEST_MODE_TRANSPORT::TCP || //Local request
			(Parameter.SOCKS_Proxy && Parameter.SOCKS_Protocol_Transport == REQUEST_MODE_TRANSPORT::TCP) || //SOCKS TCP request
			Parameter.HTTP_CONNECT_Proxy //HTTP CONNECT Proxy request
		#if defined(ENABLE_LIBSODIUM)
			|| (Parameter.IsDNSCurve && 
			(DNSCurveParameter.DNSCurveProtocol_Transport == REQUEST_MODE_TRANSPORT::FORCE_TCP || DNSCurveParameter.DNSCurveProtocol_Transport == REQUEST_MODE_TRANSPORT::TCP)) //DNSCurve TCP request
		#endif
			)
		{
			std::unique_ptr<uint8_t[]> TCPRecvBuffer(new uint8_t[Parameter.LargeBufferSize + PADDING_RESERVED_BYTES]());
			memset(TCPRecvBuffer.get(), 0, Parameter.LargeBufferSize + PADDING_RESERVED_BYTES);
			std::swap(InnerRecvBuffer, TCPRecvBuffer);
			RecvSize = Parameter.LargeBufferSize;
		}
	//UDP
		else {
			std::unique_ptr<uint8_t[]> UDPRecvBuffer(new uint8_t[NORMAL_PACKET_MAXSIZE + PADDING_RESERVED_BYTES]());
			memset(UDPRecvBuffer.get(), 0, NORMAL_PACKET_MAXSIZE + PADDING_RESERVED_BYTES);
			std::swap(InnerRecvBuffer, UDPRecvBuffer);
			RecvSize = NORMAL_PACKET_MAXSIZE;
		}

		RecvBuffer = InnerRecvBuffer.get();
	}

//Local request process
	if (MonitorQueryData.first.IsLocalRequest)
	{
		const auto Result = LocalRequestProcess(MonitorQueryData, RecvBuffer, RecvSize);
		if (Result || (MonitorQueryData.first.IsLocalInWhite && Parameter.IsLocalForce))
		{
		//Fin TCP request connection.
			if (MonitorQueryData.first.Protocol == IPPROTO_TCP && SocketSetting(MonitorQueryData.second.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
				SocketSetting(MonitorQueryData.second.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

			return Result;
		}
	}

//Compression Pointer Mutation
	if (Parameter.CompressionPointerMutation && 
		MonitorQueryData.first.EDNS_Location == 0 && MonitorQueryData.first.EDNS_Length == 0 && 
		reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Additional == 0)
	{
		const auto DataLength = MakeCompressionPointerMutation(MonitorQueryData.first.Buffer, MonitorQueryData.first.Length, MonitorQueryData.first.BufferSize);
		if (DataLength > MonitorQueryData.first.Length)
			MonitorQueryData.first.Length = DataLength;
	}

//SOCKS proxy request process
	if (Parameter.SOCKS_Proxy)
	{
	//SOCKS request
		if (SOCKS_RequestProcess(MonitorQueryData))
			return true;

	//SOCKS Proxy Only mode
		if (Parameter.SOCKS_Only)
		{
		//Fin TCP request connection.
			if (MonitorQueryData.first.Protocol == IPPROTO_TCP && SocketSetting(MonitorQueryData.second.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
				SocketSetting(MonitorQueryData.second.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

			return true;
		}
	}

//HTTP CONNECT proxy request process
	if (Parameter.HTTP_CONNECT_Proxy)
	{
	//HTTP CONNECT request
		if (HTTP_CONNECT_RequestProcess(MonitorQueryData))
			return true;

	//HTTP CONNECT Proxy Only mode
		if (Parameter.HTTP_CONNECT_Only)
		{
		//Fin TCP request connection.
			if (MonitorQueryData.first.Protocol == IPPROTO_TCP && SocketSetting(MonitorQueryData.second.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
				SocketSetting(MonitorQueryData.second.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

			return true;
		}
	}

//Direct Request request process
	if (Parameter.DirectRequest != REQUEST_MODE_DIRECT::NONE && DirectRequestProcess(MonitorQueryData, RecvBuffer, RecvSize, false))
	{
	//Fin TCP request connection.
		if (MonitorQueryData.first.Protocol == IPPROTO_TCP && SocketSetting(MonitorQueryData.second.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
			SocketSetting(MonitorQueryData.second.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

		return true;
	}

//DNSCurve request process
#if defined(ENABLE_LIBSODIUM)
	if (Parameter.IsDNSCurve)
	{
	//DNSCurve check
		if (DNSCurveParameter.IsEncryption && MonitorQueryData.first.Length + DNSCRYPT_BUFFER_RESERVED_LEN > DNSCurveParameter.DNSCurvePayloadSize)
			goto SkipDNSCurve;

	//DNSCurve request
		if (DNSCurveRequestProcess(MonitorQueryData, RecvBuffer, RecvSize))
			return true;

	//DNSCurve Encryption Only mode
		if (DNSCurveParameter.IsEncryptionOnly)
		{
		//Fin TCP request connection.
			if (MonitorQueryData.first.Protocol == IPPROTO_TCP && SocketSetting(MonitorQueryData.second.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
				SocketSetting(MonitorQueryData.second.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

			return true;
		}
	}

//Jump here to skip DNSCurve process.
SkipDNSCurve:
#endif

//TCP request process
	if (((Parameter.RequestMode_Transport == REQUEST_MODE_TRANSPORT::FORCE_TCP || Parameter.RequestMode_Transport == REQUEST_MODE_TRANSPORT::TCP || 
		MonitorQueryData.first.Protocol == IPPROTO_TCP) && TCP_RequestProcess(MonitorQueryData, RecvBuffer, RecvSize)) || 
		Parameter.RequestMode_Transport == REQUEST_MODE_TRANSPORT::FORCE_TCP) //Force protocol(TCP).
			return true;

//Direct request when Pcap Capture module is not available.
#if defined(ENABLE_PCAP)
	if (!Parameter.IsPcapCapture)
	{
#endif
		DirectRequestProcess(MonitorQueryData, RecvBuffer, RecvSize, true);

	//Fin TCP request connection.
		if (MonitorQueryData.first.Protocol == IPPROTO_TCP && SocketSetting(MonitorQueryData.second.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
			SocketSetting(MonitorQueryData.second.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

		return true;
#if defined(ENABLE_PCAP)
	}

//Buffer cleanup
	if (InnerRecvBuffer)
		InnerRecvBuffer.reset();

//UDP request
	UDP_RequestProcess(MonitorQueryData);
	return true;
#endif
}

//Check white and banned hosts list
size_t CheckWhiteBannedHostsProcess(
	const size_t Length, 
	const HostsTable &HostsTableIter, 
	dns_hdr * const DNS_Header, 
	dns_qry * const DNS_Query, 
	bool * const IsLocalRequest, 
	bool * const IsLocalInBlack)
{
//Whitelist Hosts
	if (HostsTableIter.PermissionType == HOSTS_TYPE::WHITE)
	{
	//Reset flag.
		if (IsLocalRequest != nullptr)
		{
			*IsLocalRequest = false;

		//Mark the flag to show this is the rule.
			if (IsLocalInBlack != nullptr)
				*IsLocalInBlack = true;
		}

	//Ignore all types.
		if (HostsTableIter.RecordTypeList.empty())
		{
			return EXIT_FAILURE;
		}
		else {
		//Permit or Deny mode check
			if (HostsTableIter.PermissionOperation)
			{
			//Only ignore some types.
				for (auto RecordTypeIter = HostsTableIter.RecordTypeList.begin();RecordTypeIter != HostsTableIter.RecordTypeList.end();++RecordTypeIter)
				{
					if (*RecordTypeIter == DNS_Query->Type)
						break;
					else if (RecordTypeIter + 1U == HostsTableIter.RecordTypeList.end())
						return EXIT_FAILURE;
				}
			}
		//Ignore some types.
			else {
				for (const auto &RecordTypeIter:HostsTableIter.RecordTypeList)
				{
					if (RecordTypeIter == DNS_Query->Type)
						return EXIT_FAILURE;
				}
			}
		}
	}
//Banned Hosts
	else if (HostsTableIter.PermissionType == HOSTS_TYPE::BANNED)
	{
	//Reset flag.
		if (IsLocalRequest != nullptr)
		{
			*IsLocalRequest = false;

		//Mark the flag to show this is the rule.
			if (IsLocalInBlack != nullptr)
				*IsLocalInBlack = true;
		}

	//Block all types.
		if (HostsTableIter.RecordTypeList.empty())
		{
			DNS_Header->Flags = htons(DNS_FLAG_SET_R_SNH);
			return Length;
		}
		else {
		//Permit or Deny mode check
			if (HostsTableIter.PermissionOperation)
			{
			//Only some types are allowed.
				for (auto RecordTypeIter = HostsTableIter.RecordTypeList.begin();RecordTypeIter != HostsTableIter.RecordTypeList.end();++RecordTypeIter)
				{
					if (*RecordTypeIter == DNS_Query->Type)
					{
						break;
					}
					else if (RecordTypeIter + 1U == HostsTableIter.RecordTypeList.end())
					{
						DNS_Header->Flags = htons(DNS_FLAG_SQR_NE);
						return Length;
					}
				}
			}
		//Block some types.
			else {
				for (const auto &RecordTypeIter:HostsTableIter.RecordTypeList)
				{
					if (RecordTypeIter == DNS_Query->Type)
					{
						DNS_Header->Flags = htons(DNS_FLAG_SQR_NE);
						return Length;
					}
				}
			}
		}
	}

	return EXIT_SUCCESS;
}

//Check hosts from global list
size_t CheckHostsProcess(
	DNS_PACKET_DATA * const PacketStructure, 
	uint8_t * const Result, 
	const size_t ResultSize, 
	const SOCKET_DATA &LocalSocketData)
{
//Initilization
	std::string Domain;
	auto DNS_Header = reinterpret_cast<dns_hdr *>(PacketStructure->Buffer);

//Request check
	if (CheckQueryNameLength(PacketStructure->Buffer + sizeof(dns_hdr)) + NULL_TERMINATE_LENGTH < DOMAIN_MAXSIZE)
	{
		if (PacketQueryToString(PacketStructure->Buffer + sizeof(dns_hdr), Domain) <= DOMAIN_MINSIZE || Domain.empty())
			return EXIT_SUCCESS;
		else 
			CaseConvert(Domain, false);
	}
	else {
		return EXIT_FAILURE;
	}

//Response initilization and Classes check
	memset(Result, 0, ResultSize);
	memcpy_s(Result, ResultSize, PacketStructure->Buffer, PacketStructure->Length);
	DNS_Header = reinterpret_cast<dns_hdr *>(Result);
	const auto DNS_Query = reinterpret_cast<dns_qry *>(Result + DNS_PACKET_QUERY_LOCATE(Result));
	if (ntohs(DNS_Query->Classes) != DNS_CLASS_INTERNET)
		return EXIT_FAILURE;

//Check Accept Types list.
	if (Parameter.AcceptTypeList != nullptr)
	{
	//Permit mode
		if (Parameter.IsAcceptTypePermit)
		{
			for (auto TypeTableIter = Parameter.AcceptTypeList->begin();TypeTableIter != Parameter.AcceptTypeList->end();++TypeTableIter)
			{
				if (TypeTableIter + 1U == Parameter.AcceptTypeList->end())
				{
					if (*TypeTableIter != DNS_Query->Type)
					{
						DNS_Header->Flags = htons(DNS_FLAG_SET_R_SNH);
						return PacketStructure->Length;
					}
				}
				else if (*TypeTableIter == DNS_Query->Type)
				{
					break;
				}
			}
		}
	//Deny mode
		else {
			for (const auto &TypeTableIter:*Parameter.AcceptTypeList)
			{
				if (TypeTableIter == DNS_Query->Type)
				{
					DNS_Header->Flags = htons(DNS_FLAG_SET_R_SNH);
					return PacketStructure->Length;
				}
			}
		}
	}

//Make domain reversed.
	std::string ReverseDomain(Domain);
	MakeStringReversed(ReverseDomain);
	ReverseDomain.append(".");
	size_t DataLength = 0;
	void *DNS_Record = nullptr;

//Buffer initilization
	std::unique_ptr<uint8_t[]> EDNS_Buffer(nullptr);

//Domain Name Reservation Considerations for "test."
//RFC 6761, Special-Use Domain Names(https://tools.ietf.org/html/rfc6761)
// Caching DNS servers SHOULD recognize test names as special and SHOULD NOT, by default, attempt to look up NS records for them, 
// or otherwise query authoritative DNS servers in an attempt to resolve test names. Instead, caching DNS servers SHOULD, by
// default, generate immediate negative responses for all such queries. This is to avoid unnecessary load on the root name
// servers and other name servers.  Caching DNS servers SHOULD offer a configuration option (disabled by default) to enable upstream
// resolving of test names, for use in networks where test names are known to be handled by an authoritative DNS server in said private network.

//Domain Name Reservation Considerations for "localhost."
//RFC 6761, Special-Use Domain Names(https://tools.ietf.org/html/rfc6761)
	if (CompareStringReversed("tsohlacol.", ReverseDomain))
	{
	//AAAA record(IPv6)
		if (ntohs(DNS_Query->Type) == DNS_TYPE_AAAA)
		{
		//Store EDNS Label temporary.
			if (PacketStructure->EDNS_Location > 0 && PacketStructure->EDNS_Length > 0)
			{
				std::unique_ptr<uint8_t[]> BufferTemp(new uint8_t[PacketStructure->EDNS_Length + PADDING_RESERVED_BYTES]());
				memset(BufferTemp.get(), 0, PacketStructure->EDNS_Length + PADDING_RESERVED_BYTES);
				memcpy_s(BufferTemp.get(), PacketStructure->EDNS_Length, Result + PacketStructure->EDNS_Location, PacketStructure->EDNS_Length);
				EDNS_Buffer.swap(BufferTemp);
			}

		//Set header flags and convert DNS query to DNS response packet.
			DNS_Header->Flags = htons(DNS_FLAG_SQR_NE);
			DataLength = sizeof(dns_hdr) + PacketStructure->Records_QuestionLen;
			memset(Result + DataLength, 0, ResultSize - DataLength);

		//Make resource records.
			DNS_Record = reinterpret_cast<dns_record_aaaa *>(Result + DataLength);
			reinterpret_cast<dns_record_aaaa *>(DNS_Record)->Name = htons(DNS_POINTER_QUERY);
			reinterpret_cast<dns_record_aaaa *>(DNS_Record)->Classes = htons(DNS_CLASS_INTERNET);
			if (Parameter.HostsDefaultTTL > 0)
				reinterpret_cast<dns_record_aaaa *>(DNS_Record)->TTL = htonl(Parameter.HostsDefaultTTL);
			else 
				reinterpret_cast<dns_record_aaaa *>(DNS_Record)->TTL = htonl(DEFAULT_HOSTS_TTL);
			reinterpret_cast<dns_record_aaaa *>(DNS_Record)->Type = htons(DNS_TYPE_AAAA);
			reinterpret_cast<dns_record_aaaa *>(DNS_Record)->Length = htons(sizeof(in6_addr));
			reinterpret_cast<dns_record_aaaa *>(DNS_Record)->Address = in6addr_loopback;
			DataLength += sizeof(dns_record_aaaa);

		//Copy back EDNS Label.
			if (PacketStructure->EDNS_Location > 0 && PacketStructure->EDNS_Length > 0)
			{
				memcpy_s(Result + DataLength, ResultSize - DataLength, EDNS_Buffer.get(), PacketStructure->EDNS_Length);
				EDNS_Buffer.reset();

			//Update EDNS Label information.
				DNS_Header->Additional = htons(UINT16_NUM_ONE);
				DataLength += PacketStructure->EDNS_Length;
			}

		//Rebuild DNS header counts.
			DNS_Header->Answer = htons(UINT16_NUM_ONE);
			DNS_Header->Authority = 0;
			return DataLength;
		}
	//A record(IPv4)
		else if (ntohs(DNS_Query->Type) == DNS_TYPE_A)
		{
		//Store EDNS Label temporary.
			if (PacketStructure->EDNS_Location > 0 && PacketStructure->EDNS_Length > 0)
			{
				std::unique_ptr<uint8_t[]> BufferTemp(new uint8_t[PacketStructure->EDNS_Length + PADDING_RESERVED_BYTES]());
				memset(BufferTemp.get(), 0, PacketStructure->EDNS_Length + PADDING_RESERVED_BYTES);
				memcpy_s(BufferTemp.get(), PacketStructure->EDNS_Length, Result + PacketStructure->EDNS_Location, PacketStructure->EDNS_Length);
				EDNS_Buffer.swap(BufferTemp);
			}

		//Set header flags and convert DNS query to DNS response packet.
			DNS_Header->Flags = htons(DNS_FLAG_SQR_NE);
			DataLength = sizeof(dns_hdr) + PacketStructure->Records_QuestionLen;
			memset(Result + DataLength, 0, ResultSize - DataLength);

		//Make resource records.
			DNS_Record = reinterpret_cast<dns_record_a *>(Result + DataLength);
			reinterpret_cast<dns_record_a *>(DNS_Record)->Name = htons(DNS_POINTER_QUERY);
			reinterpret_cast<dns_record_a *>(DNS_Record)->Classes = htons(DNS_CLASS_INTERNET);
			if (Parameter.HostsDefaultTTL > 0)
				reinterpret_cast<dns_record_a *>(DNS_Record)->TTL = htonl(Parameter.HostsDefaultTTL);
			else 
				reinterpret_cast<dns_record_a *>(DNS_Record)->TTL = htonl(DEFAULT_HOSTS_TTL);
			reinterpret_cast<dns_record_a *>(DNS_Record)->Type = htons(DNS_TYPE_A);
			reinterpret_cast<dns_record_a *>(DNS_Record)->Length = htons(sizeof(in_addr));
			reinterpret_cast<dns_record_a *>(DNS_Record)->Address.s_addr = htonl(INADDR_LOOPBACK);
			DataLength += sizeof(dns_record_a);

		//Copy back EDNS Label.
			if (PacketStructure->EDNS_Location > 0 && PacketStructure->EDNS_Length > 0)
			{
				memcpy_s(Result + DataLength, ResultSize - DataLength, EDNS_Buffer.get(), PacketStructure->EDNS_Length);
				EDNS_Buffer.reset();

			//Update EDNS Label information.
				DNS_Header->Additional = htons(UINT16_NUM_ONE);
				DataLength += PacketStructure->EDNS_Length;
			}

		//Rebuild DNS header counts.
			DNS_Header->Answer = htons(UINT16_NUM_ONE);
			DNS_Header->Authority = 0;
			return DataLength;
		}
	}

//Domain Name Reservation Considerations for "invalid."
//RFC 6761, Special-Use Domain Names(https://tools.ietf.org/html/rfc6761)
	if (CompareStringReversed("dilavni.", ReverseDomain))
	{
		DNS_Header->Flags = htons(DNS_FLAG_SET_R_SNH);
		return PacketStructure->Length;
	}

//Domain Name Reservation Considerations for Example Domains
//RFC 6761, Special-Use Domain Names(https://tools.ietf.org/html/rfc6761)
// The domains "example.", "example.com.", "example.net.", "example.org.", and any names falling within those domains.
// Caching DNS servers SHOULD NOT recognize example names as special and SHOULD resolve them normally.

//PTR Records
//LLMNR protocol of macOS powered by mDNS with PTR records
#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
	if (ntohs(DNS_Query->Type) == DNS_TYPE_PTR && Parameter.LocalServer_Length + PacketStructure->Length <= ResultSize)
	{
		auto Is_PTR_ResponseSend = false;

	//RFC 6761, Special-Use Domain Names(https://tools.ietf.org/html/rfc6761)
		if (Domain == ("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa") || //Loopback address(::1, Section 2.5.3 in RFC 4291)
			Domain.find(".127.in-addr.arpa") != std::string::npos || //Loopback address(127.0.0.0/8, Section 3.2.1.3 in RFC 1122)
			Domain.find(".254.169.in-addr.arpa") != std::string::npos) //Link-local address(169.254.0.0/16, RFC 3927)
		{
			Is_PTR_ResponseSend = true;
		}
		else {
		//IPv6 check
			std::unique_lock<std::mutex> LocalAddressMutexIPv6(LocalAddressLock[NETWORK_LAYER_TYPE_IPV6]);
			for (const auto &StringIter:*GlobalRunningStatus.LocalAddress_PointerResponse[NETWORK_LAYER_TYPE_IPV6])
			{
				if (StringIter == Domain)
				{
					Is_PTR_ResponseSend = true;
					break;
				}
			}

			LocalAddressMutexIPv6.unlock();

		//IPv4 check
			if (!Is_PTR_ResponseSend)
			{
				std::lock_guard<std::mutex> LocalAddressMutexIPv4(LocalAddressLock[NETWORK_LAYER_TYPE_IPV4]);
				for (const auto &StringIter:*GlobalRunningStatus.LocalAddress_PointerResponse[NETWORK_LAYER_TYPE_IPV4])
				{
					if (StringIter == Domain)
					{
						Is_PTR_ResponseSend = true;
						break;
					}
				}
			}
		}

	//Send local machine DNS PTR response.
		if (Is_PTR_ResponseSend)
		{
		//Store EDNS Label temporary.
			if (PacketStructure->EDNS_Location > 0 && PacketStructure->EDNS_Length > 0)
			{
				std::unique_ptr<uint8_t[]> BufferTemp(new uint8_t[PacketStructure->EDNS_Length + PADDING_RESERVED_BYTES]());
				memset(BufferTemp.get(), 0, PacketStructure->EDNS_Length + PADDING_RESERVED_BYTES);
				memcpy_s(BufferTemp.get(), PacketStructure->EDNS_Length, Result + PacketStructure->EDNS_Location, PacketStructure->EDNS_Length);
				EDNS_Buffer.swap(BufferTemp);
			}

		//Set header flags and copy response to buffer.
			DNS_Header->Flags = htons(ntohs(DNS_Header->Flags) | DNS_FLAG_SET_R_A);
			DataLength = sizeof(dns_hdr) + PacketStructure->Records_QuestionLen;
			memset(Result + DataLength, 0, PacketStructure->Length - DataLength);
			memcpy_s(Result + DataLength, ResultSize - DataLength, Parameter.LocalServer_Response, Parameter.LocalServer_Length);
			DataLength += Parameter.LocalServer_Length;

		//Copy back EDNS Label.
			if (PacketStructure->EDNS_Location > 0 && PacketStructure->EDNS_Length > 0)
			{
				memcpy_s(Result + DataLength, ResultSize - DataLength, EDNS_Buffer.get(), PacketStructure->EDNS_Length);
				EDNS_Buffer.reset();

			//Update EDNS Label information.
				DNS_Header->Additional = htons(UINT16_NUM_ONE);
				DataLength += PacketStructure->EDNS_Length;
			}

		//Rebuild DNS header counts.
			DNS_Header->Answer = htons(UINT16_NUM_ONE);
			DNS_Header->Authority = 0;
			return DataLength;
		}
	}
#endif

//Local FQDN check
//RFC 6761, Special-Use Domain Names(https://tools.ietf.org/html/rfc6761)
	if (Parameter.Local_FQDN_String != nullptr && Domain == *Parameter.Local_FQDN_String
/*
	//Private class A addresses(10.0.0.0/8, Section 3 in RFC 1918)
		|| Domain.find("10.in-addr.arpa") != std::string::npos || 
	//Private class B addresses(172.16.0.0/12, Section 3 in RFC 1918)
		Domain.find("16.172.in-addr.arpa") != std::string::npos || Domain.find("17.172.in-addr.arpa") != std::string::npos || Domain.find("18.172.in-addr.arpa") != std::string::npos || 
		Domain.find("19.172.in-addr.arpa") != std::string::npos || Domain.find("20.172.in-addr.arpa") != std::string::npos || Domain.find("21.172.in-addr.arpa") != std::string::npos || 
		Domain.find("22.172.in-addr.arpa") != std::string::npos || Domain.find("23.172.in-addr.arpa") != std::string::npos || Domain.find("24.172.in-addr.arpa") != std::string::npos || 
		Domain.find("25.172.in-addr.arpa") != std::string::npos || Domain.find("26.172.in-addr.arpa") != std::string::npos || Domain.find("27.172.in-addr.arpa") != std::string::npos || 
		Domain.find("28.172.in-addr.arpa") != std::string::npos || Domain.find("29.172.in-addr.arpa") != std::string::npos || Domain.find("30.172.in-addr.arpa") != std::string::npos || 
		Domain.find("31.172.in-addr.arpa") != std::string::npos || 
	//Private class C addresses(192.168.0.0/16, Section 3 in RFC 1918)
		Domain.find("168.192.in-addr.arpa") != std::string::npos
*/
		)
	{
	//AAAA record(IPv6)
		if (ntohs(DNS_Query->Type) == DNS_TYPE_AAAA)
		{
		//Store EDNS Label temporary.
			if (PacketStructure->EDNS_Location > 0 && PacketStructure->EDNS_Length > 0)
			{
				std::unique_ptr<uint8_t[]> BufferTemp(new uint8_t[PacketStructure->EDNS_Length + PADDING_RESERVED_BYTES]());
				memset(BufferTemp.get(), 0, PacketStructure->EDNS_Length + PADDING_RESERVED_BYTES);
				memcpy_s(BufferTemp.get(), PacketStructure->EDNS_Length, Result + PacketStructure->EDNS_Location, PacketStructure->EDNS_Length);
				EDNS_Buffer.swap(BufferTemp);
			}

		//Copy response to buffer.
			std::lock_guard<std::mutex> LocalAddressMutexIPv6(LocalAddressLock[NETWORK_LAYER_TYPE_IPV6]);
			if (GlobalRunningStatus.LocalAddress_Length[NETWORK_LAYER_TYPE_IPV6] >= DNS_PACKET_MINSIZE)
			{
				memset(Result + sizeof(uint16_t), 0, ResultSize - sizeof(uint16_t));
				memcpy_s(Result + sizeof(uint16_t), ResultSize - sizeof(uint16_t), GlobalRunningStatus.LocalAddress_Response[NETWORK_LAYER_TYPE_IPV6] + sizeof(uint16_t), GlobalRunningStatus.LocalAddress_Length[NETWORK_LAYER_TYPE_IPV6] - sizeof(uint16_t));
				DataLength = GlobalRunningStatus.LocalAddress_Length[NETWORK_LAYER_TYPE_IPV6];

			//Copy back EDNS Label.
				if (PacketStructure->EDNS_Location > 0 && PacketStructure->EDNS_Length > 0)
				{
					memcpy_s(Result + DataLength, ResultSize - DataLength, EDNS_Buffer.get(), PacketStructure->EDNS_Length);
					EDNS_Buffer.reset();

				//Update EDNS Label information.
					DNS_Header->Additional = htons(UINT16_NUM_ONE);
					DataLength += PacketStructure->EDNS_Length;
				}

				return DataLength;
			}
		}
	//A record(IPv4)
		else if (ntohs(DNS_Query->Type) == DNS_TYPE_A)
		{
		//Store EDNS Label temporary.
			if (PacketStructure->EDNS_Location > 0 && PacketStructure->EDNS_Length > 0)
			{
				std::unique_ptr<uint8_t[]> BufferTemp(new uint8_t[PacketStructure->EDNS_Length + PADDING_RESERVED_BYTES]());
				memset(BufferTemp.get(), 0, PacketStructure->EDNS_Length + PADDING_RESERVED_BYTES);
				memcpy_s(BufferTemp.get(), PacketStructure->EDNS_Length, Result + PacketStructure->EDNS_Location, PacketStructure->EDNS_Length);
				EDNS_Buffer.swap(BufferTemp);
			}

		//Copy response to buffer.
			std::lock_guard<std::mutex> LocalAddressMutexIPv4(LocalAddressLock[NETWORK_LAYER_TYPE_IPV4]);
			if (GlobalRunningStatus.LocalAddress_Length[NETWORK_LAYER_TYPE_IPV4] >= DNS_PACKET_MINSIZE)
			{
				memset(Result + sizeof(uint16_t), 0, ResultSize - sizeof(uint16_t));
				memcpy_s(Result + sizeof(uint16_t), ResultSize - sizeof(uint16_t), GlobalRunningStatus.LocalAddress_Response[NETWORK_LAYER_TYPE_IPV4] + sizeof(uint16_t), GlobalRunningStatus.LocalAddress_Length[NETWORK_LAYER_TYPE_IPV4] - sizeof(uint16_t));
				DataLength = GlobalRunningStatus.LocalAddress_Length[NETWORK_LAYER_TYPE_IPV4];

			//Copy back EDNS Label.
				if (PacketStructure->EDNS_Location > 0 && PacketStructure->EDNS_Length > 0)
				{
					memcpy_s(Result + DataLength, ResultSize - DataLength, EDNS_Buffer.get(), PacketStructure->EDNS_Length);
					EDNS_Buffer.reset();

				//Update EDNS Label information.
					DNS_Header->Additional = htons(UINT16_NUM_ONE);
					DataLength += PacketStructure->EDNS_Length;
				}

				return DataLength;
			}
		}
	}

//Local Routing parameter check
	if (Parameter.IsLocalRouting)
		PacketStructure->IsLocalRequest = true;

//Normal Hosts check
	auto IsMatchItem = false;
	std::unique_lock<std::mutex> HostsFileMutex(HostsFileLock);
	for (const auto &HostsFileSetIter:*HostsFileSetUsing)
	{
		for (const auto &HostsTableIter:HostsFileSetIter.HostsList_Normal)
		{
			IsMatchItem = false;

		//Dnsmasq normal mode, please visit http://www.thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html.
			if (HostsTableIter.IsStringMatching && !HostsTableIter.PatternOrDomainString.empty())
			{
				if (HostsTableIter.PatternOrDomainString == ("#") || //Dnsmasq "#" matches any domain.
					(HostsTableIter.PatternOrDomainString.front() == ReverseDomain.front() && //Quick check to reduce resource using
					CompareStringReversed(HostsTableIter.PatternOrDomainString, ReverseDomain)))
						IsMatchItem = true;
			}
		//Regex mode
			else if (std::regex_match(Domain, HostsTableIter.PatternRegex))
			{
				IsMatchItem = true;
			}

		//Match hosts.
			if (IsMatchItem)
			{
			//Source Hosts check
				if (!HostsTableIter.SourceList.empty())
				{
					for (const auto &SourceListIter:HostsTableIter.SourceList)
					{
					//IPv6
						if (SourceListIter.first.ss_family == AF_INET6 && LocalSocketData.SockAddr.ss_family == AF_INET6)
						{
							if (SourceListIter.second < sizeof(in6_addr) * BYTES_TO_BITS / 2U)
							{
								const auto AddressPart = hton64(ntoh64(*reinterpret_cast<const uint64_t *>(&reinterpret_cast<const sockaddr_in6 *>(&LocalSocketData.SockAddr)->sin6_addr)) & (UINT64_MAX << (sizeof(in6_addr) * BYTES_TO_BITS / 2U - SourceListIter.second)));
								if (memcmp(&AddressPart, &reinterpret_cast<const sockaddr_in6 *>(&SourceListIter.first)->sin6_addr, sizeof(AddressPart)) == 0)
									goto JumpToContinue;
							}
							else if (memcmp(&reinterpret_cast<const sockaddr_in6 *>(&LocalSocketData.SockAddr)->sin6_addr, &reinterpret_cast<const sockaddr_in6 *>(&SourceListIter.first)->sin6_addr, sizeof(uint64_t)) == 0) //Mark high 64 bits.
							{
								const auto AddressPart = hton64(ntoh64(*reinterpret_cast<const uint64_t *>(reinterpret_cast<const uint8_t *>(&reinterpret_cast<const sockaddr_in6 *>(&LocalSocketData.SockAddr)->sin6_addr) + sizeof(in6_addr) / 2U)) & (UINT64_MAX << (sizeof(in6_addr) * BYTES_TO_BITS - SourceListIter.second)));
								if (memcmp(&AddressPart, reinterpret_cast<const uint8_t *>(&reinterpret_cast<const sockaddr_in6 *>(&SourceListIter.first)->sin6_addr) + sizeof(in6_addr) / 2U, sizeof(AddressPart)) == 0) //Mark low 64 bits.
									goto JumpToContinue;
							}
						}
					//IPv4
						else if (SourceListIter.first.ss_family == AF_INET && LocalSocketData.SockAddr.ss_family == AF_INET && 
							htonl(ntohl(reinterpret_cast<const sockaddr_in *>(&LocalSocketData.SockAddr)->sin_addr.s_addr) & (UINT32_MAX << (sizeof(in_addr) * BYTES_TO_BITS - SourceListIter.second))) == 
							reinterpret_cast<const sockaddr_in *>(&SourceListIter.first)->sin_addr.s_addr)
						{
							goto JumpToContinue;
						}
					}

					continue;
				}

			//Jump here to continue.
			JumpToContinue:

			//Check white and banned hosts list, empty record type list check
				DataLength = CheckWhiteBannedHostsProcess(PacketStructure->Length, HostsTableIter, DNS_Header, DNS_Query, &PacketStructure->IsLocalRequest, &PacketStructure->IsLocalInBlack);
				if (DataLength >= DNS_PACKET_MINSIZE)
					return DataLength;
				else if (DataLength == EXIT_FAILURE)
					goto StopLoop_NormalHosts;

			//Initialization
				size_t RamdomIndex = 0, Index = 0;

			//AAAA record(IPv6)
				if (ntohs(DNS_Query->Type) == DNS_TYPE_AAAA && HostsTableIter.RecordTypeList.front() == htons(DNS_TYPE_AAAA))
				{
				//Store EDNS Label temporary.
					if (PacketStructure->EDNS_Location > 0 && PacketStructure->EDNS_Length > 0)
					{
						std::unique_ptr<uint8_t[]> BufferTemp(new uint8_t[PacketStructure->EDNS_Length + PADDING_RESERVED_BYTES]());
						memset(BufferTemp.get(), 0, PacketStructure->EDNS_Length + PADDING_RESERVED_BYTES);
						memcpy_s(BufferTemp.get(), PacketStructure->EDNS_Length, Result + PacketStructure->EDNS_Location, PacketStructure->EDNS_Length);
						EDNS_Buffer.swap(BufferTemp);
					}

				//Set header flags and convert DNS query to DNS response packet.
					DNS_Header->Flags = htons(DNS_FLAG_SQR_NE);
					DataLength = sizeof(dns_hdr) + PacketStructure->Records_QuestionLen;
					memset(Result + DataLength, 0, ResultSize - DataLength);

				//Hosts load balancing
					if (HostsTableIter.AddrOrTargetList.size() > 1U)
					{
						std::uniform_int_distribution<size_t> RamdomDistribution(0, HostsTableIter.AddrOrTargetList.size() - 1U);
						RamdomIndex = RamdomDistribution(*GlobalRunningStatus.RamdomEngine);
					}

				//Make response.
					for (Index = 0;Index < HostsTableIter.AddrOrTargetList.size();++Index)
					{
					//Make resource records.
						DNS_Record = reinterpret_cast<dns_record_aaaa *>(Result + DataLength);
						DataLength += sizeof(dns_record_aaaa);
						reinterpret_cast<dns_record_aaaa *>(DNS_Record)->Name = htons(DNS_POINTER_QUERY);
						reinterpret_cast<dns_record_aaaa *>(DNS_Record)->Classes = htons(DNS_CLASS_INTERNET);
						if (Parameter.HostsDefaultTTL > 0)
							reinterpret_cast<dns_record_aaaa *>(DNS_Record)->TTL = htonl(Parameter.HostsDefaultTTL);
						else 
							reinterpret_cast<dns_record_aaaa *>(DNS_Record)->TTL = htonl(DEFAULT_HOSTS_TTL);
						reinterpret_cast<dns_record_aaaa *>(DNS_Record)->Type = htons(DNS_TYPE_AAAA);
						reinterpret_cast<dns_record_aaaa *>(DNS_Record)->Length = htons(sizeof(in6_addr));
						if (Index == 0)
							reinterpret_cast<dns_record_aaaa *>(DNS_Record)->Address = HostsTableIter.AddrOrTargetList.at(RamdomIndex).IPv6.sin6_addr;
						else if (Index == RamdomIndex)
							reinterpret_cast<dns_record_aaaa *>(DNS_Record)->Address = HostsTableIter.AddrOrTargetList.front().IPv6.sin6_addr;
						else 
							reinterpret_cast<dns_record_aaaa *>(DNS_Record)->Address = HostsTableIter.AddrOrTargetList.at(Index).IPv6.sin6_addr;

					//Hosts items length check
						if ((PacketStructure->EDNS_Location > 0 && PacketStructure->EDNS_Length > 0 && DataLength + sizeof(dns_record_aaaa) + PacketStructure->EDNS_Length >= ResultSize) || //EDNS Label query
							DataLength + sizeof(dns_record_aaaa) >= ResultSize) //Normal query
						{
							++Index;
							break;
						}
					}

				//Copy back EDNS Label.
					if (PacketStructure->EDNS_Location > 0 && PacketStructure->EDNS_Length > 0)
					{
						memcpy_s(Result + DataLength, ResultSize - DataLength, EDNS_Buffer.get(), PacketStructure->EDNS_Length);
						EDNS_Buffer.reset();

					//Update EDNS Label information.
						DNS_Header->Additional = htons(UINT16_NUM_ONE);
						DataLength += PacketStructure->EDNS_Length;
					}

				//Rebuild DNS header counts.
					DNS_Header->Answer = htons(static_cast<uint16_t>(Index));
					DNS_Header->Authority = 0;
					return DataLength;
				}
			//A record(IPv4)
				else if (ntohs(DNS_Query->Type) == DNS_TYPE_A && HostsTableIter.RecordTypeList.front() == htons(DNS_TYPE_A))
				{
				//Store EDNS Label temporary.
					if (PacketStructure->EDNS_Location > 0 && PacketStructure->EDNS_Length > 0)
					{
						std::unique_ptr<uint8_t[]> BufferTemp(new uint8_t[PacketStructure->EDNS_Length + PADDING_RESERVED_BYTES]());
						memset(BufferTemp.get(), 0, PacketStructure->EDNS_Length + PADDING_RESERVED_BYTES);
						memcpy_s(BufferTemp.get(), PacketStructure->EDNS_Length, Result + PacketStructure->EDNS_Location, PacketStructure->EDNS_Length);
						EDNS_Buffer.swap(BufferTemp);
					}

				//Set header flags and convert DNS query to DNS response packet.
					DNS_Header->Flags = htons(DNS_FLAG_SQR_NE);
					DataLength = sizeof(dns_hdr) + PacketStructure->Records_QuestionLen;
					memset(Result + DataLength, 0, ResultSize - DataLength);

				//Hosts load balancing
					if (HostsTableIter.AddrOrTargetList.size() > 1U)
					{
						std::uniform_int_distribution<size_t> RamdomDistribution(0, HostsTableIter.AddrOrTargetList.size() - 1U);
						RamdomIndex = RamdomDistribution(*GlobalRunningStatus.RamdomEngine);
					}

				//Make response.
					for (Index = 0;Index < HostsTableIter.AddrOrTargetList.size();++Index)
					{
					//Make resource records.
						DNS_Record = reinterpret_cast<dns_record_a *>(Result + DataLength);
						DataLength += sizeof(dns_record_a);
						reinterpret_cast<dns_record_a *>(DNS_Record)->Name = htons(DNS_POINTER_QUERY);
						reinterpret_cast<dns_record_a *>(DNS_Record)->Classes = htons(DNS_CLASS_INTERNET);
						if (Parameter.HostsDefaultTTL > 0)
							reinterpret_cast<dns_record_a *>(DNS_Record)->TTL = htonl(Parameter.HostsDefaultTTL);
						else 
							reinterpret_cast<dns_record_a *>(DNS_Record)->TTL = htonl(DEFAULT_HOSTS_TTL);
						reinterpret_cast<dns_record_a *>(DNS_Record)->Type = htons(DNS_TYPE_A);
						reinterpret_cast<dns_record_a *>(DNS_Record)->Length = htons(sizeof(in_addr));
						if (Index == 0)
							reinterpret_cast<dns_record_a *>(DNS_Record)->Address = HostsTableIter.AddrOrTargetList.at(RamdomIndex).IPv4.sin_addr;
						else if (Index == RamdomIndex)
							reinterpret_cast<dns_record_a *>(DNS_Record)->Address = HostsTableIter.AddrOrTargetList.front().IPv4.sin_addr;
						else 
							reinterpret_cast<dns_record_a *>(DNS_Record)->Address = HostsTableIter.AddrOrTargetList.at(Index).IPv4.sin_addr;

					//Hosts items length check
						if ((PacketStructure->EDNS_Location > 0 && PacketStructure->EDNS_Length > 0 && DataLength + sizeof(dns_record_a) + PacketStructure->EDNS_Length >= ResultSize) || //EDNS Label query
							DataLength + sizeof(dns_record_a) >= ResultSize) //Normal query
						{
							++Index;
							break;
						}
					}

				//Copy back EDNS Label.
					if (PacketStructure->EDNS_Location > 0 && PacketStructure->EDNS_Length > 0)
					{
						memcpy_s(Result + DataLength, ResultSize - DataLength, EDNS_Buffer.get(), PacketStructure->EDNS_Length);
						EDNS_Buffer.reset();

					//Update EDNS Label information.
						DNS_Header->Additional = htons(UINT16_NUM_ONE);
						DataLength += PacketStructure->EDNS_Length;
					}

				//Rebuild DNS header counts.
					DNS_Header->Answer = htons(static_cast<uint16_t>(Index));
					DNS_Header->Authority = 0;
					return DataLength;
				}
			}
		}
	}

//Jump here to stop loop.
StopLoop_NormalHosts:
	HostsFileMutex.unlock();

//Reset buffer pointer.
	EDNS_Buffer.reset();

//Check DNS cache.
	if (Parameter.DNS_CacheType != DNS_CACHE_TYPE::NONE)
	{
		DataLength = CheckDomainCache(Result, ResultSize, Domain, DNS_Query, LocalSocketData);
		if (DataLength >= DNS_PACKET_MINSIZE)
			return DataLength;
	}

//Local Hosts check
	HostsFileMutex.lock();
	for (const auto &HostsFileSetIter:*HostsFileSetUsing)
	{
		for (const auto &HostsTableIter:HostsFileSetIter.HostsList_Local)
		{
			IsMatchItem = false;

		//Dnsmasq normal mode
			if (HostsTableIter.IsStringMatching && !HostsTableIter.PatternOrDomainString.empty())
			{
				if ((HostsTableIter.PatternOrDomainString.empty() && Domain.find(ASCII_PERIOD) == std::string::npos) || //Dnsmasq unqualified names only
					(HostsTableIter.PatternOrDomainString.front() == ReverseDomain.front() && //Quick check to reduce resource using
					CompareStringReversed(HostsTableIter.PatternOrDomainString, ReverseDomain)))
						IsMatchItem = true;
			}
		//Regex mode
			else if (std::regex_match(Domain, HostsTableIter.PatternRegex))
			{
				IsMatchItem = true;
			}

		//Match hosts.
			if (IsMatchItem)
			{
				PacketStructure->IsLocalInWhite = true;

			//Check white and banned hosts list.
				DataLength = CheckWhiteBannedHostsProcess(PacketStructure->Length, HostsTableIter, DNS_Header, DNS_Query, &PacketStructure->IsLocalRequest, &PacketStructure->IsLocalInBlack);
				if (DataLength >= DNS_PACKET_MINSIZE)
					return DataLength;
				else if (DataLength == EXIT_SUCCESS)
					PacketStructure->IsLocalRequest = true;

			//Mark Local server target.
				if (PacketStructure->IsLocalRequest && !HostsTableIter.AddrOrTargetList.empty())
					PacketStructure->LocalTarget = HostsTableIter.AddrOrTargetList.front();

			//Stop loop
				goto StopLoop_LocalHosts;
			}
		}
	}

//Jump here to stop loop.
StopLoop_LocalHosts:
	HostsFileMutex.unlock();

//Domain Case Conversion
	if (Parameter.DomainCaseConversion)
		MakeDomainCaseConversion(PacketStructure->Buffer + sizeof(dns_hdr));

	return EXIT_SUCCESS;
}

//Request Process(Local part)
bool LocalRequestProcess(
	MONITOR_QUEUE_DATA &MonitorQueryData, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize)
{
	memset(OriginalRecv, 0, RecvSize);

//EDNS switching(Part 1)
	std::unique_ptr<uint8_t[]> EDNS_Buffer(nullptr);
	const auto EDNS_Packet_Flags = reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags;
	if (Parameter.EDNS_Label && !Parameter.EDNS_Switch_Local && 
		MonitorQueryData.first.EDNS_Location > 0 && MonitorQueryData.first.EDNS_Length > 0)
	{
	//Store EDNS Label temporary.
		std::unique_ptr<uint8_t[]> BufferTemp(new uint8_t[MonitorQueryData.first.EDNS_Length + PADDING_RESERVED_BYTES]());
		memset(BufferTemp.get(), 0, MonitorQueryData.first.EDNS_Length + PADDING_RESERVED_BYTES);
		memcpy_s(BufferTemp.get(), MonitorQueryData.first.EDNS_Length, MonitorQueryData.first.Buffer + MonitorQueryData.first.EDNS_Location, MonitorQueryData.first.EDNS_Length);
		EDNS_Buffer.swap(BufferTemp);

	//Remove EDNS Label.
		memset(MonitorQueryData.first.Buffer + MonitorQueryData.first.EDNS_Location, 0, MonitorQueryData.first.EDNS_Length);
		MonitorQueryData.first.Length -= MonitorQueryData.first.EDNS_Length;

	//Build DNS header counts.
		reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags = htons(ntohs(reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags) & (~DNS_FLAG_GET_BIT_AD));
		reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags = htons(ntohs(reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags) & (~DNS_FLAG_GET_BIT_CD));
		if (reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Additional > 0)
			reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Additional = htons(ntohs(reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Additional) - 1U);
	}

//TCP request
	size_t DataLength = 0;
	if (Parameter.LocalProtocol_Transport == REQUEST_MODE_TRANSPORT::FORCE_TCP || 
		Parameter.LocalProtocol_Transport == REQUEST_MODE_TRANSPORT::TCP || 
		MonitorQueryData.first.Protocol == IPPROTO_TCP)
	{
		DataLength = TCP_RequestSingle(REQUEST_PROCESS_TYPE::LOCAL, MonitorQueryData.first.Buffer, MonitorQueryData.first.Length, OriginalRecv, RecvSize, &MonitorQueryData.first.LocalTarget, &MonitorQueryData.second);

	//Send response.
		if (DataLength >= DNS_PACKET_MINSIZE && DataLength < RecvSize)
		{
			SendToRequester(MonitorQueryData.first.Protocol, OriginalRecv, DataLength, RecvSize, MonitorQueryData.second);
			return true;
		}

	//Force protocol(TCP).
		if (Parameter.LocalProtocol_Transport == REQUEST_MODE_TRANSPORT::FORCE_TCP)
			return false;
	}

//UDP request and Send response.
	DataLength = UDP_CompleteRequestSingle(REQUEST_PROCESS_TYPE::LOCAL, MonitorQueryData.first.Buffer, MonitorQueryData.first.Length, OriginalRecv, RecvSize, &MonitorQueryData.first.LocalTarget, &MonitorQueryData.second);
	if (DataLength >= DNS_PACKET_MINSIZE && DataLength < RecvSize)
	{
		SendToRequester(MonitorQueryData.first.Protocol, OriginalRecv, DataLength, RecvSize, MonitorQueryData.second);
		return true;
	}

//EDNS switching(Part 2)
	if (Parameter.EDNS_Label && !Parameter.EDNS_Switch_Local && 
		MonitorQueryData.first.EDNS_Location > 0 && MonitorQueryData.first.EDNS_Length > 0)
	{
	//Copy back EDNS Label.
		memcpy_s(MonitorQueryData.first.Buffer + MonitorQueryData.first.EDNS_Location, MonitorQueryData.first.BufferSize - MonitorQueryData.first.EDNS_Location, EDNS_Buffer.get(), MonitorQueryData.first.EDNS_Length);
		MonitorQueryData.first.Length += MonitorQueryData.first.EDNS_Length;

	//Rebuild DNS header counts.
		reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags = EDNS_Packet_Flags;
		reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Additional = htons(ntohs(reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Additional) + 1U);
	}

	return false;
}

//Request Process(SOCKS part)
bool SOCKS_RequestProcess(
	MONITOR_QUEUE_DATA &MonitorQueryData)
{
//EDNS switching(Part 1)
	std::unique_ptr<uint8_t[]> EDNS_Buffer(nullptr);
	const auto EDNS_Packet_Flags = reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags;
	if (Parameter.EDNS_Label && !Parameter.EDNS_Switch_SOCKS && 
		MonitorQueryData.first.EDNS_Location > 0 && MonitorQueryData.first.EDNS_Length > 0)
	{
	//Store EDNS Label temporary.
		std::unique_ptr<uint8_t[]> BufferTemp(new uint8_t[MonitorQueryData.first.EDNS_Length + PADDING_RESERVED_BYTES]());
		memset(BufferTemp.get(), 0, MonitorQueryData.first.EDNS_Length + PADDING_RESERVED_BYTES);
		memcpy_s(BufferTemp.get(), MonitorQueryData.first.EDNS_Length, MonitorQueryData.first.Buffer + MonitorQueryData.first.EDNS_Location, MonitorQueryData.first.EDNS_Length);
		EDNS_Buffer.swap(BufferTemp);

	//Remove EDNS Label.
		memset(MonitorQueryData.first.Buffer + MonitorQueryData.first.EDNS_Location, 0, MonitorQueryData.first.EDNS_Length);
		MonitorQueryData.first.Length -= MonitorQueryData.first.EDNS_Length;

	//Build DNS header counts.
		reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags = htons(ntohs(reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags) & (~DNS_FLAG_GET_BIT_AD));
		reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags = htons(ntohs(reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags) & (~DNS_FLAG_GET_BIT_CD));
		if (reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Additional > 0)
			reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Additional = htons(ntohs(reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Additional) - 1U);
	}

//UDP request
	std::unique_ptr<uint8_t[]> RecvBuffer(nullptr);
	size_t DataLength = 0, RecvSize = 0;
	if (Parameter.SOCKS_Version == SOCKS_VERSION_5 && 
		(Parameter.SOCKS_Protocol_Transport == REQUEST_MODE_TRANSPORT::FORCE_UDP || Parameter.SOCKS_Protocol_Transport == REQUEST_MODE_TRANSPORT::UDP))
	{
	//UDP request process
		DataLength = SOCKS_UDP_Request(MonitorQueryData.first.Buffer, MonitorQueryData.first.Length, RecvBuffer, RecvSize, MonitorQueryData.second);

	//Send response.
		if (RecvBuffer && RecvSize >= DNS_PACKET_MINSIZE && DataLength >= DNS_PACKET_MINSIZE && DataLength < RecvSize)
		{
			SendToRequester(MonitorQueryData.first.Protocol, RecvBuffer.get(), DataLength, RecvSize, MonitorQueryData.second);
			return true;
		}
		else {
			RecvBuffer.reset();
			RecvSize = 0;
		}

	//Force protocol(UDP).
		if (Parameter.SOCKS_Protocol_Transport == REQUEST_MODE_TRANSPORT::FORCE_UDP)
			return false;
	}

//TCP request
	DataLength = SOCKS_TCP_Request(MonitorQueryData.first.Buffer, MonitorQueryData.first.Length, RecvBuffer, RecvSize, MonitorQueryData.second);

//Send response.
	if (RecvBuffer && RecvSize >= DNS_PACKET_MINSIZE && DataLength >= DNS_PACKET_MINSIZE && DataLength < RecvSize)
	{
		SendToRequester(MonitorQueryData.first.Protocol, RecvBuffer.get(), DataLength, RecvSize, MonitorQueryData.second);
		return true;
	}

//EDNS switching(Part 2)
	if (Parameter.EDNS_Label && !Parameter.EDNS_Switch_SOCKS && 
		MonitorQueryData.first.EDNS_Location > 0 && MonitorQueryData.first.EDNS_Length > 0)
	{
	//Copy back EDNS Label.
		memcpy_s(MonitorQueryData.first.Buffer + MonitorQueryData.first.EDNS_Location, MonitorQueryData.first.BufferSize - MonitorQueryData.first.EDNS_Location, EDNS_Buffer.get(), MonitorQueryData.first.EDNS_Length);
		MonitorQueryData.first.Length += MonitorQueryData.first.EDNS_Length;

	//Rebuild DNS header counts.
		reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags = EDNS_Packet_Flags;
		reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Additional = htons(ntohs(reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Additional) + 1U);
	}

	return false;
}

//Request Process(HTTP CONNECT part)
bool HTTP_CONNECT_RequestProcess(
	MONITOR_QUEUE_DATA &MonitorQueryData)
{
//EDNS switching(Part 1)
	std::unique_ptr<uint8_t[]> EDNS_Buffer(nullptr);
	const auto EDNS_Packet_Flags = reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags;
	if (Parameter.EDNS_Label && !Parameter.EDNS_Switch_HTTP_CONNECT && 
		MonitorQueryData.first.EDNS_Location > 0 && MonitorQueryData.first.EDNS_Length > 0)
	{
	//Store EDNS Label temporary.
		std::unique_ptr<uint8_t[]> BufferTemp(new uint8_t[MonitorQueryData.first.EDNS_Length + PADDING_RESERVED_BYTES]());
		memset(BufferTemp.get(), 0, MonitorQueryData.first.EDNS_Length + PADDING_RESERVED_BYTES);
		memcpy_s(BufferTemp.get(), MonitorQueryData.first.EDNS_Length, MonitorQueryData.first.Buffer + MonitorQueryData.first.EDNS_Location, MonitorQueryData.first.EDNS_Length);
		EDNS_Buffer.swap(BufferTemp);

	//Remove EDNS Label.
		memset(MonitorQueryData.first.Buffer + MonitorQueryData.first.EDNS_Location, 0, MonitorQueryData.first.EDNS_Length);
		MonitorQueryData.first.Length -= MonitorQueryData.first.EDNS_Length;

	//Build DNS header counts.
		reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags = htons(ntohs(reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags) & (~DNS_FLAG_GET_BIT_AD));
		reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags = htons(ntohs(reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags) & (~DNS_FLAG_GET_BIT_CD));
		if (reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Additional > 0)
			reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Additional = htons(ntohs(reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Additional) - 1U);
	}

//HTTP CONNECT request
	std::unique_ptr<uint8_t[]> RecvBuffer(nullptr);
	size_t RecvSize = 0, DataLength = HTTP_CONNECT_Request(MonitorQueryData.first.Buffer, MonitorQueryData.first.Length, RecvBuffer, RecvSize, MonitorQueryData.second);

//Send response.
	if (RecvBuffer && RecvSize >= DNS_PACKET_MINSIZE && DataLength >= DNS_PACKET_MINSIZE && DataLength < RecvSize)
	{
		SendToRequester(MonitorQueryData.first.Protocol, RecvBuffer.get(), DataLength, RecvSize, MonitorQueryData.second);
		return true;
	}

//EDNS switching(Part 2)
	if (Parameter.EDNS_Label && !Parameter.EDNS_Switch_HTTP_CONNECT && 
		MonitorQueryData.first.EDNS_Location > 0 && MonitorQueryData.first.EDNS_Length > 0)
	{
	//Copy back EDNS Label.
		memcpy_s(MonitorQueryData.first.Buffer + MonitorQueryData.first.EDNS_Location, MonitorQueryData.first.BufferSize - MonitorQueryData.first.EDNS_Location, EDNS_Buffer.get(), MonitorQueryData.first.EDNS_Length);
		MonitorQueryData.first.Length += MonitorQueryData.first.EDNS_Length;

	//Rebuild DNS header counts.
		reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags = EDNS_Packet_Flags;
		reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Additional = htons(ntohs(reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Additional) + 1U);
	}

	return false;
}

//Request Process(Direct connections part)
bool DirectRequestProcess(
	MONITOR_QUEUE_DATA &MonitorQueryData, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize, 
	const bool IsAutomatic)
{
	memset(OriginalRecv, 0, RecvSize);

//Direct Request mode check
	size_t DataLength = SelectDirectProtocol();
	if (!IsAutomatic && 
		((DataLength == AF_INET6 && Parameter.DirectRequest == REQUEST_MODE_DIRECT::IPV4) || //IPv6
		(DataLength == AF_INET && Parameter.DirectRequest == REQUEST_MODE_DIRECT::IPV6))) //IPv4
			return false;

//EDNS switching(Part 1)
	std::unique_ptr<uint8_t[]> EDNS_Buffer(nullptr);
	const auto EDNS_Packet_Flags = reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags;
	if (Parameter.EDNS_Label && !Parameter.EDNS_Switch_Direct && 
		MonitorQueryData.first.EDNS_Location > 0 && MonitorQueryData.first.EDNS_Length > 0)
	{
	//Store EDNS Label temporary.
		std::unique_ptr<uint8_t[]> BufferTemp(new uint8_t[MonitorQueryData.first.EDNS_Length + PADDING_RESERVED_BYTES]());
		memset(BufferTemp.get(), 0, MonitorQueryData.first.EDNS_Length + PADDING_RESERVED_BYTES);
		memcpy_s(BufferTemp.get(), MonitorQueryData.first.EDNS_Length, MonitorQueryData.first.Buffer + MonitorQueryData.first.EDNS_Location, MonitorQueryData.first.EDNS_Length);
		EDNS_Buffer.swap(BufferTemp);

	//Remove EDNS Label.
		memset(MonitorQueryData.first.Buffer + MonitorQueryData.first.EDNS_Location, 0, MonitorQueryData.first.EDNS_Length);
		MonitorQueryData.first.Length -= MonitorQueryData.first.EDNS_Length;

	//Build DNS header counts.
		reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags = htons(ntohs(reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags) & (~DNS_FLAG_GET_BIT_AD));
		reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags = htons(ntohs(reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags) & (~DNS_FLAG_GET_BIT_CD));
		if (reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Additional > 0)
			reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Additional = htons(ntohs(reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Additional) - 1U);
	}

//TCP request
	if (Parameter.RequestMode_Transport == REQUEST_MODE_TRANSPORT::FORCE_TCP || Parameter.RequestMode_Transport == REQUEST_MODE_TRANSPORT::TCP || MonitorQueryData.first.Protocol == IPPROTO_TCP)
	{
	//Multiple request process
		if (Parameter.AlternateMultipleRequest || Parameter.MultipleRequestTimes > 1U)
			DataLength = TCP_RequestMultiple(REQUEST_PROCESS_TYPE::DIRECT, MonitorQueryData.first.Buffer, MonitorQueryData.first.Length, OriginalRecv, RecvSize, &MonitorQueryData.second);
	//Normal request process
		else 
			DataLength = TCP_RequestSingle(REQUEST_PROCESS_TYPE::DIRECT, MonitorQueryData.first.Buffer, MonitorQueryData.first.Length, OriginalRecv, RecvSize, nullptr, &MonitorQueryData.second);

	//Send response.
		if (DataLength >= DNS_PACKET_MINSIZE && DataLength < RecvSize)
		{
			SendToRequester(MonitorQueryData.first.Protocol, OriginalRecv, DataLength, RecvSize, MonitorQueryData.second);
			return true;
		}

	//Force protocol(TCP).
		if (Parameter.RequestMode_Transport == REQUEST_MODE_TRANSPORT::FORCE_TCP)
			return false;
	}

//UDP request
	if (Parameter.AlternateMultipleRequest || Parameter.MultipleRequestTimes > 1U) //Multiple request process
		DataLength = UDP_CompleteRequestMultiple(REQUEST_PROCESS_TYPE::DIRECT, MonitorQueryData.first.Buffer, MonitorQueryData.first.Length, OriginalRecv, RecvSize, &MonitorQueryData.second);
	else //Normal request process
		DataLength = UDP_CompleteRequestSingle(REQUEST_PROCESS_TYPE::DIRECT, MonitorQueryData.first.Buffer, MonitorQueryData.first.Length, OriginalRecv, RecvSize, nullptr, &MonitorQueryData.second);

//Send response.
	if (DataLength >= DNS_PACKET_MINSIZE && DataLength < RecvSize)
	{
		SendToRequester(MonitorQueryData.first.Protocol, OriginalRecv, DataLength, RecvSize, MonitorQueryData.second);
		return true;
	}

//EDNS switching(Part 2)
	if (Parameter.EDNS_Label && !Parameter.EDNS_Switch_Direct && 
		MonitorQueryData.first.EDNS_Location > 0 && MonitorQueryData.first.EDNS_Length > 0)
	{
	//Copy back EDNS Label.
		memcpy_s(MonitorQueryData.first.Buffer + MonitorQueryData.first.EDNS_Location, MonitorQueryData.first.BufferSize - MonitorQueryData.first.EDNS_Location, EDNS_Buffer.get(), MonitorQueryData.first.EDNS_Length);
		MonitorQueryData.first.Length += MonitorQueryData.first.EDNS_Length;

	//Rebuild DNS header counts.
		reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags = EDNS_Packet_Flags;
		reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Additional = htons(ntohs(reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Additional) + 1U);
	}

	return false;
}

//Request Process(DNSCurve part)
#if defined(ENABLE_LIBSODIUM)
bool DNSCurveRequestProcess(
	MONITOR_QUEUE_DATA &MonitorQueryData, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize)
{
	memset(OriginalRecv, 0, RecvSize);

//EDNS switching(Part 1)
	std::unique_ptr<uint8_t[]> EDNS_Buffer(nullptr);
	const auto EDNS_Packet_Flags = reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags;
	if (Parameter.EDNS_Label && !Parameter.EDNS_Switch_DNSCurve && 
		MonitorQueryData.first.EDNS_Location > 0 && MonitorQueryData.first.EDNS_Length > 0)
	{
	//Store EDNS Label temporary.
		std::unique_ptr<uint8_t[]> BufferTemp(new uint8_t[MonitorQueryData.first.EDNS_Length + PADDING_RESERVED_BYTES]());
		memset(BufferTemp.get(), 0, MonitorQueryData.first.EDNS_Length + PADDING_RESERVED_BYTES);
		memcpy_s(BufferTemp.get(), MonitorQueryData.first.EDNS_Length, MonitorQueryData.first.Buffer + MonitorQueryData.first.EDNS_Location, MonitorQueryData.first.EDNS_Length);
		EDNS_Buffer.swap(BufferTemp);

	//Remove EDNS Label.
		memset(MonitorQueryData.first.Buffer + MonitorQueryData.first.EDNS_Location, 0, MonitorQueryData.first.EDNS_Length);
		MonitorQueryData.first.Length -= MonitorQueryData.first.EDNS_Length;

	//Build DNS header counts.
		reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags = htons(ntohs(reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags) & (~DNS_FLAG_GET_BIT_AD));
		reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags = htons(ntohs(reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags) & (~DNS_FLAG_GET_BIT_CD));
		if (reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Additional > 0)
			reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Additional = htons(ntohs(reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Additional) - 1U);
	}

//TCP request
	size_t DataLength = 0;
	if (DNSCurveParameter.DNSCurveProtocol_Transport == REQUEST_MODE_TRANSPORT::FORCE_TCP || DNSCurveParameter.DNSCurveProtocol_Transport == REQUEST_MODE_TRANSPORT::TCP || MonitorQueryData.first.Protocol == IPPROTO_TCP)
	{
	//Multiple request process
		if (Parameter.AlternateMultipleRequest || Parameter.MultipleRequestTimes > 1U)
			DataLength = DNSCurve_TCP_RequestMultiple(MonitorQueryData.first.Buffer, MonitorQueryData.first.Length, OriginalRecv, RecvSize, MonitorQueryData.second);
	//Normal request process
		else 
			DataLength = DNSCurve_TCP_RequestSingle(MonitorQueryData.first.Buffer, MonitorQueryData.first.Length, OriginalRecv, RecvSize, MonitorQueryData.second);

	//Send response.
		if (DataLength >= DNS_PACKET_MINSIZE && DataLength < RecvSize)
		{
			SendToRequester(MonitorQueryData.first.Protocol, OriginalRecv, DataLength, RecvSize, MonitorQueryData.second);
			return true;
		}

	//Force protocol(TCP).
		if (DNSCurveParameter.DNSCurveProtocol_Transport == REQUEST_MODE_TRANSPORT::FORCE_TCP)
			return false;
	}

//UDP request
	if (Parameter.AlternateMultipleRequest || Parameter.MultipleRequestTimes > 1U) //Multiple request process
		DataLength = DNSCurve_UDP_RequestMultiple(MonitorQueryData.first.Buffer, MonitorQueryData.first.Length, OriginalRecv, RecvSize, MonitorQueryData.second);
	else //Normal request process
		DataLength = DNSCurve_UDP_RequestSingle(MonitorQueryData.first.Buffer, MonitorQueryData.first.Length, OriginalRecv, RecvSize, MonitorQueryData.second);

//Send response.
	if (DataLength >= DNS_PACKET_MINSIZE && DataLength < RecvSize)
	{
		SendToRequester(MonitorQueryData.first.Protocol, OriginalRecv, DataLength, RecvSize, MonitorQueryData.second);
		return true;
	}

//EDNS switching(Part 2)
	if (Parameter.EDNS_Label && !Parameter.EDNS_Switch_DNSCurve && 
		MonitorQueryData.first.EDNS_Location > 0 && MonitorQueryData.first.EDNS_Length > 0)
	{
	//Copy back EDNS Label.
		memcpy_s(MonitorQueryData.first.Buffer + MonitorQueryData.first.EDNS_Location, MonitorQueryData.first.BufferSize - MonitorQueryData.first.EDNS_Location, EDNS_Buffer.get(), MonitorQueryData.first.EDNS_Length);
		MonitorQueryData.first.Length += MonitorQueryData.first.EDNS_Length;

	//Rebuild DNS header counts.
		reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags = EDNS_Packet_Flags;
		reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Additional = htons(ntohs(reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Additional) + 1U);
	}

	return false;
}
#endif

//Request Process(TCP part)
bool TCP_RequestProcess(
	MONITOR_QUEUE_DATA &MonitorQueryData, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize)
{
	memset(OriginalRecv, 0, RecvSize);

//EDNS switching(Part 1)
	std::unique_ptr<uint8_t[]> EDNS_Buffer(nullptr);
	const auto EDNS_Packet_Flags = reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags;
	if (Parameter.EDNS_Label && !Parameter.EDNS_Switch_TCP && 
		MonitorQueryData.first.EDNS_Location > 0 && MonitorQueryData.first.EDNS_Length > 0)
	{
	//Store EDNS Label temporary.
		std::unique_ptr<uint8_t[]> BufferTemp(new uint8_t[MonitorQueryData.first.EDNS_Length + PADDING_RESERVED_BYTES]());
		memset(BufferTemp.get(), 0, MonitorQueryData.first.EDNS_Length + PADDING_RESERVED_BYTES);
		memcpy_s(BufferTemp.get(), MonitorQueryData.first.EDNS_Length, MonitorQueryData.first.Buffer + MonitorQueryData.first.EDNS_Location, MonitorQueryData.first.EDNS_Length);
		EDNS_Buffer.swap(BufferTemp);

	//Remove EDNS Label.
		memset(MonitorQueryData.first.Buffer + MonitorQueryData.first.EDNS_Location, 0, MonitorQueryData.first.EDNS_Length);
		MonitorQueryData.first.Length -= MonitorQueryData.first.EDNS_Length;

	//Build DNS header counts.
		reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags = htons(ntohs(reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags) & (~DNS_FLAG_GET_BIT_AD));
		reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags = htons(ntohs(reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags) & (~DNS_FLAG_GET_BIT_CD));
		if (reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Additional > 0)
			reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Additional = htons(ntohs(reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Additional) - 1U);
	}

//Multiple request process
	size_t DataLength = 0;
	if (Parameter.AlternateMultipleRequest || Parameter.MultipleRequestTimes > 1U)
		DataLength = TCP_RequestMultiple(REQUEST_PROCESS_TYPE::TCP_NORMAL, MonitorQueryData.first.Buffer, MonitorQueryData.first.Length, OriginalRecv, RecvSize, &MonitorQueryData.second);
//Normal request process
	else 
		DataLength = TCP_RequestSingle(REQUEST_PROCESS_TYPE::TCP_NORMAL, MonitorQueryData.first.Buffer, MonitorQueryData.first.Length, OriginalRecv, RecvSize, nullptr, &MonitorQueryData.second);

//Send response.
	if (DataLength >= DNS_PACKET_MINSIZE && DataLength < RecvSize)
	{
		SendToRequester(MonitorQueryData.first.Protocol, OriginalRecv, DataLength, RecvSize, MonitorQueryData.second);
		return true;
	}

//EDNS switching(Part 2)
	if (Parameter.EDNS_Label && !Parameter.EDNS_Switch_TCP && 
		MonitorQueryData.first.EDNS_Location > 0 && MonitorQueryData.first.EDNS_Length > 0)
	{
	//Copy back EDNS Label.
		memcpy_s(MonitorQueryData.first.Buffer + MonitorQueryData.first.EDNS_Location, MonitorQueryData.first.BufferSize - MonitorQueryData.first.EDNS_Location, EDNS_Buffer.get(), MonitorQueryData.first.EDNS_Length);
		MonitorQueryData.first.Length += MonitorQueryData.first.EDNS_Length;

	//Rebuild DNS header counts.
		reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags = EDNS_Packet_Flags;
		reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Additional = htons(ntohs(reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Additional) + 1U);
	}

	return false;
}

//Select network layer protocol of direct request
uint16_t SelectDirectProtocol(
	void)
{
//IPv6
	if (Parameter.Target_Server_Main_IPv6.AddressData.Storage.ss_family != 0 && 
		((Parameter.RequestMode_Network == REQUEST_MODE_NETWORK::BOTH && GlobalRunningStatus.GatewayAvailable_IPv6) || //Auto select
		Parameter.RequestMode_Network == REQUEST_MODE_NETWORK::IPV6 || //IPv6
		(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK::IPV4 && Parameter.Target_Server_Main_IPv4.AddressData.Storage.ss_family == 0))) //Non-IPv4
			return AF_INET6;
//IPv4
	else if (Parameter.Target_Server_Main_IPv4.AddressData.Storage.ss_family != 0 && 
		((Parameter.RequestMode_Network == REQUEST_MODE_NETWORK::BOTH && GlobalRunningStatus.GatewayAvailable_IPv4) || //Auto select
		Parameter.RequestMode_Network == REQUEST_MODE_NETWORK::IPV4 || //IPv4
		(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK::IPV6 && Parameter.Target_Server_Main_IPv6.AddressData.Storage.ss_family == 0))) //Non-IPv6
			return AF_INET;

	return 0;
}

//Request Process(UDP part)
#if defined(ENABLE_PCAP)
void UDP_RequestProcess(
	MONITOR_QUEUE_DATA &MonitorQueryData)
{
//EDNS switching(Part 1)
//UDP_RequestProcess is the last process, so no need to restore packet.
	std::unique_ptr<uint8_t[]> EDNS_Buffer(nullptr);
	if (Parameter.EDNS_Label && !Parameter.EDNS_Switch_UDP && 
		MonitorQueryData.first.EDNS_Location > 0 && MonitorQueryData.first.EDNS_Length > 0)
	{
	//Store EDNS Label temporary.
		std::unique_ptr<uint8_t[]> BufferTemp(new uint8_t[MonitorQueryData.first.EDNS_Length + PADDING_RESERVED_BYTES]());
		memset(BufferTemp.get(), 0, MonitorQueryData.first.EDNS_Length + PADDING_RESERVED_BYTES);
		memcpy_s(BufferTemp.get(), MonitorQueryData.first.EDNS_Length, MonitorQueryData.first.Buffer + MonitorQueryData.first.EDNS_Location, MonitorQueryData.first.EDNS_Length);
		EDNS_Buffer.swap(BufferTemp);

	//Remove EDNS Label.
		memset(MonitorQueryData.first.Buffer + MonitorQueryData.first.EDNS_Location, 0, MonitorQueryData.first.EDNS_Length);
		MonitorQueryData.first.Length -= MonitorQueryData.first.EDNS_Length;

	//Build DNS header counts.
		reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags = htons(ntohs(reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags) & (~DNS_FLAG_GET_BIT_AD));
		reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags = htons(ntohs(reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags) & (~DNS_FLAG_GET_BIT_CD));
		if (reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Additional > 0)
			reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Additional = htons(ntohs(reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Additional) - 1U);
	}

//Multiple request process
	if (Parameter.AlternateMultipleRequest || Parameter.MultipleRequestTimes > 1U)
		UDP_RequestMultiple(REQUEST_PROCESS_TYPE::UDP_NORMAL, MonitorQueryData.first.Protocol, MonitorQueryData.first.Buffer, MonitorQueryData.first.Length, &MonitorQueryData.second);
//Normal request process
	else 
		UDP_RequestSingle(REQUEST_PROCESS_TYPE::UDP_NORMAL, MonitorQueryData.first.Protocol, MonitorQueryData.first.Buffer, MonitorQueryData.first.Length, &MonitorQueryData.second);

//Fin TCP request connection.
	if (MonitorQueryData.first.Protocol == IPPROTO_TCP && SocketSetting(MonitorQueryData.second.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
		SocketSetting(MonitorQueryData.second.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

/* UDP_RequestProcess is the last process, no need to restore the packet.
//EDNS switching(Part 2)
	if (Parameter.EDNS_Label && !Parameter.EDNS_Switch_UDP && 
		MonitorQueryData.first.EDNS_Location > 0 && MonitorQueryData.first.EDNS_Length > 0)
	{
	//Copy back EDNS Label.
		memcpy_s(MonitorQueryData.first.Buffer + MonitorQueryData.first.EDNS_Location, MonitorQueryData.first.BufferSize - MonitorQueryData.first.EDNS_Location, EDNS_Buffer.get(), MonitorQueryData.first.EDNS_Length);
		MonitorQueryData.first.Length += MonitorQueryData.first.EDNS_Length;

	//Rebuild DNS header counts.
		reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Flags = EDNS_Packet_Flags;
		reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Additional = htons(ntohs(reinterpret_cast<dns_hdr *>(MonitorQueryData.first.Buffer)->Additional) + 1U);
	}
*/

	return;
}
#endif

//Send responses to requester
bool SendToRequester(
	const uint16_t Protocol, 
	uint8_t * const RecvBuffer, 
	const size_t RecvSize, 
	const size_t MaxLen, 
	SOCKET_DATA &LocalSocketData)
{
//Response check
	if (RecvSize < DNS_PACKET_MINSIZE || CheckEmptyBuffer(RecvBuffer, RecvSize) || 
		!SocketSetting(LocalSocketData.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr) || 
//		reinterpret_cast<dns_hdr *>(RecvBuffer)->ID == 0 || //DNS header ID must not be set 0.
		reinterpret_cast<dns_hdr *>(RecvBuffer)->Flags == 0) //DNS header flags must not be set 0.
			return false;

//TCP protocol
	if (Protocol == IPPROTO_TCP)
	{
		if (AddLengthDataToHeader(RecvBuffer, RecvSize, MaxLen) == EXIT_FAILURE)
		{
			SocketSetting(LocalSocketData.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
			return false;
		}
		else {
			send(LocalSocketData.Socket, reinterpret_cast<const char *>(RecvBuffer), static_cast<int>(RecvSize + sizeof(uint16_t)), 0);
			SocketSetting(LocalSocketData.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
		}
	}
//UDP protocol
	else if (Protocol == IPPROTO_UDP)
	{
		sendto(LocalSocketData.Socket, reinterpret_cast<const char *>(RecvBuffer), static_cast<int>(RecvSize), 0, reinterpret_cast<const sockaddr *>(&LocalSocketData.SockAddr), LocalSocketData.AddrLen);
	}
	else {
		return false;
	}

	return true;
}

//Mark responses to domains Cache
bool MarkDomainCache(
	const uint8_t * const Buffer, 
	const size_t Length, 
	const SOCKET_DATA * const LocalSocketData)
{
//Check conditions.
	const auto DNS_Header = reinterpret_cast<const dns_hdr *>(Buffer);
	if (
	//Not a response packet
		(ntohs(DNS_Header->Flags) & DNS_FLAG_GET_BIT_RESPONSE) == 0 || 
	//Question Resource Records must be one.
		ntohs(DNS_Header->Question) != UINT16_NUM_ONE || 
	//Not any Answer Resource Records
		(DNS_Header->Answer == 0 && DNS_Header->Authority == 0 /* && DNS_Header->Additional == 0 */ ) || 
	//OPCode must be set Query/0.
		(ntohs(DNS_Header->Flags) & DNS_FLAG_GET_BIT_OPCODE) != DNS_OPCODE_QUERY || 
	//Truncated bit must not be set.
		(ntohs(DNS_Header->Flags) & DNS_FLAG_GET_BIT_TC) > 0 || 
	//RCode must be set No Error or Non-Existent Domain.
		((ntohs(DNS_Header->Flags) & DNS_FLAG_GET_BIT_RCODE) != DNS_RCODE_NOERROR && 
		(ntohs(DNS_Header->Flags) & DNS_FLAG_GET_BIT_RCODE) != DNS_RCODE_NXDOMAIN))
			return false;

//Initialization(A part)
	DNS_CACHE_DATA DNSCacheDataTemp;
	DNSCacheDataTemp.RecordType = reinterpret_cast<const dns_qry *>(Buffer + DNS_PACKET_QUERY_LOCATE(Buffer))->Type;
	uint32_t ResponseTTL = 0;

//Mark DNS A records and AAAA records only.
	if (DNSCacheDataTemp.RecordType == htons(DNS_TYPE_AAAA) || DNSCacheDataTemp.RecordType == htons(DNS_TYPE_A))
	{
		size_t DataLength = DNS_PACKET_RR_LOCATE(Buffer), TTLCounts = 0;

	//Scan all Answers Resource Records.
		for (size_t Index = 0;Index < ntohs(DNS_Header->Answer);++Index)
		{
		//Domain pointer check
			if (DataLength + sizeof(uint16_t) < Length && Buffer[DataLength] >= DNS_POINTER_8_BITS)
			{
				const uint16_t DNS_Pointer = ntohs(*reinterpret_cast<const uint16_t *>(Buffer + DataLength)) & DNS_POINTER_BITS_GET_LOCATE;
				if (DNS_Pointer >= Length || DNS_Pointer < sizeof(dns_hdr) || DNS_Pointer == DataLength || DNS_Pointer == DataLength + 1U)
					return false;
			}

		//Resource Records Name(Domain Name)
			DataLength += CheckQueryNameLength(Buffer + DataLength) + NULL_TERMINATE_LENGTH;
			if (DataLength + sizeof(dns_record_standard) > Length)
				break;

		//Standard Resource Records
			auto DNS_Record_Standard = reinterpret_cast<const dns_record_standard *>(Buffer + DataLength);
			DataLength += sizeof(dns_record_standard);
			if (DataLength > Length || DataLength + ntohs(DNS_Record_Standard->Length) > Length)
				break;

		//Resource Records Data
			if (ntohs(DNS_Record_Standard->Classes) == DNS_CLASS_INTERNET && DNS_Record_Standard->TTL > 0 && 
				((ntohs(DNS_Record_Standard->Type) == DNS_TYPE_AAAA && ntohs(DNS_Record_Standard->Length) == sizeof(in6_addr)) || 
				(ntohs(DNS_Record_Standard->Type) == DNS_TYPE_A && ntohs(DNS_Record_Standard->Length) == sizeof(in_addr))))
			{
				ResponseTTL += ntohl(DNS_Record_Standard->TTL);
				++TTLCounts;
			}

			DataLength += ntohs(DNS_Record_Standard->Length);
		}

	//Calculate average TTL.
		if (TTLCounts > 0)
			ResponseTTL = ResponseTTL / static_cast<uint32_t>(TTLCounts) + ResponseTTL % static_cast<uint32_t>(TTLCounts);
	}

//Set cache TTL.
	if (ResponseTTL == 0 && DNS_Header->Authority == 0) //Only mark A and AAAA records.
	{
		return false;
	}
	else {
	//Timer mode
		if (Parameter.DNS_CacheType == DNS_CACHE_TYPE::TIMER)
		{
		//Cache time is <TTL> seconds when Cache Parameter is 0.
		//Cache time is <Cache Parameter> seconds when TTL is shorter than Cache Parameter.
		//Cache time is <TTL + Cache Parameter> seconds when TTL is longer than Cache Parameter.
			if (Parameter.DNS_CacheParameter > 0)
			{
				if (ResponseTTL <= Parameter.DNS_CacheParameter)
					ResponseTTL = static_cast<uint32_t>(Parameter.DNS_CacheParameter);
				else 
					ResponseTTL += static_cast<uint32_t>(Parameter.DNS_CacheParameter);
			}
		}
	//Both mode
		else if (Parameter.DNS_CacheType == DNS_CACHE_TYPE::BOTH)
		{
		//Cache time is <TTL> seconds when Cache Parameter is 0.
		//Cache time is <Default TTL> seconds when TTL is shorter than Default TTL.
		//Cache time is <TTL + Default TTL> seconds when TTL is longer than Default TTL.
			if (Parameter.HostsDefaultTTL > 0)
			{
				if (ResponseTTL <= Parameter.HostsDefaultTTL)
					ResponseTTL = static_cast<uint32_t>(Parameter.HostsDefaultTTL);
				else 
					ResponseTTL += static_cast<uint32_t>(Parameter.HostsDefaultTTL);
			}
		}
	}

//Initialization(B part)
	if (Length <= DOMAIN_MAXSIZE)
	{
		std::unique_ptr<uint8_t[]> DNSCacheDataBufferTemp(new uint8_t[DOMAIN_MAXSIZE + PADDING_RESERVED_BYTES]());
		memset(DNSCacheDataBufferTemp.get(), 0, DOMAIN_MAXSIZE + PADDING_RESERVED_BYTES);
		std::swap(DNSCacheDataTemp.Response, DNSCacheDataBufferTemp);
	}
	else {
		std::unique_ptr<uint8_t[]> DNSCacheDataBufferTemp(new uint8_t[Length + PADDING_RESERVED_BYTES]());
		memset(DNSCacheDataBufferTemp.get(), 0, Length + PADDING_RESERVED_BYTES);
		std::swap(DNSCacheDataTemp.Response, DNSCacheDataBufferTemp);
	}

//Mark domain.
	if (PacketQueryToString(Buffer + sizeof(dns_hdr), DNSCacheDataTemp.Domain) <= DOMAIN_MINSIZE)
		return false;

//Domain Case Conversion
	CaseConvert(DNSCacheDataTemp.Domain, false);
	memcpy_s(DNSCacheDataTemp.Response.get(), NORMAL_PACKET_MAXSIZE, Buffer + sizeof(uint16_t), Length - sizeof(uint16_t));
	DNSCacheDataTemp.Length = Length - sizeof(uint16_t);
	DNSCacheDataTemp.ClearCacheTime = GetCurrentSystemTime() + ResponseTTL * SECOND_TO_MILLISECOND;

//Single address single cache
	if (LocalSocketData != nullptr) //Some network test thread do not need to mark request address, put them in default queue.
	{
	//IPv6
		if (Parameter.DNS_CacheSinglePrefix_IPv6 > 0 && LocalSocketData->SockAddr.ss_family == AF_INET6 && 
			!OperationModeFilter(AF_INET6, &reinterpret_cast<const sockaddr_in6 *>(&LocalSocketData->SockAddr)->sin6_addr, LISTEN_MODE::PRIVATE)) //Put private network addessses in default queue.
		{
			DNSCacheDataTemp.ForAddress.Storage.ss_family = AF_INET6;
			if (Parameter.DNS_CacheSinglePrefix_IPv6 < sizeof(in6_addr) * BYTES_TO_BITS / 2U) //Mark high 64 bits.
			{
				*reinterpret_cast<uint64_t *>(&DNSCacheDataTemp.ForAddress.IPv6.sin6_addr) = hton64(ntoh64(*reinterpret_cast<const uint64_t *>(&reinterpret_cast<const sockaddr_in6 *>(&LocalSocketData->SockAddr)->sin6_addr)) & (UINT64_MAX << (sizeof(in6_addr) * BYTES_TO_BITS / 2U - Parameter.DNS_CacheSinglePrefix_IPv6)));
			}
			else { //Mark low 64 bits.
				*reinterpret_cast<uint64_t *>(&DNSCacheDataTemp.ForAddress.IPv6.sin6_addr) = *reinterpret_cast<const uint64_t *>(&reinterpret_cast<const sockaddr_in6 *>(&LocalSocketData->SockAddr)->sin6_addr);
				*reinterpret_cast<uint64_t *>(reinterpret_cast<uint8_t *>(&DNSCacheDataTemp.ForAddress.IPv6.sin6_addr) + sizeof(in6_addr) / 2U) = hton64(ntoh64(*reinterpret_cast<const uint64_t *>(reinterpret_cast<const uint8_t *>(&reinterpret_cast<const sockaddr_in6 *>(&LocalSocketData->SockAddr)->sin6_addr) + sizeof(in6_addr) / 2U)) & (UINT64_MAX << (sizeof(in6_addr) * BYTES_TO_BITS - Parameter.DNS_CacheSinglePrefix_IPv6)));
			}
		}
	//IPv4
		else if (Parameter.DNS_CacheSinglePrefix_IPv4 > 0 && LocalSocketData->SockAddr.ss_family == AF_INET && 
			!OperationModeFilter(AF_INET, &reinterpret_cast<const sockaddr_in *>(&LocalSocketData->SockAddr)->sin_addr, LISTEN_MODE::PRIVATE)) //Put private network addessses in default queue.
		{
			DNSCacheDataTemp.ForAddress.Storage.ss_family = AF_INET;
			DNSCacheDataTemp.ForAddress.IPv4.sin_addr.s_addr = htonl(ntohl(reinterpret_cast<const sockaddr_in *>(&LocalSocketData->SockAddr)->sin_addr.s_addr) & (UINT32_MAX << (sizeof(in_addr) * BYTES_TO_BITS - Parameter.DNS_CacheSinglePrefix_IPv4)));
		}
	//Default queue, single address single cache has been shutdown or request protocol is not supported.
//		else {
//			;
//		}
	}

//Delete old cache, mark cache data to global list and global index list.
	std::lock_guard<std::mutex> DNSCacheListMutex(DNSCacheListLock);
	AutoRemoveExpired_DNS_Cache();
	DNSCacheList.push_front(std::move(DNSCacheDataTemp));
	DNSCacheIndexList.insert(std::make_pair(DNSCacheList.front().Domain, DNSCacheList.begin()));

	return true;
}

//Check domain cache and make response
size_t CheckDomainCache(
	uint8_t * const Result, 
	const size_t ResultSize, 
	const std::string &Domain, 
	const dns_qry * const DNS_Query, 
	const SOCKET_DATA &LocalSocketData)
{
//Single address single cache(Part 1)
	uint64_t AddrPart = 0;
	if (LocalSocketData.SockAddr.ss_family == AF_INET6 && Parameter.DNS_CacheSinglePrefix_IPv6 > 0) //IPv6
	{
		if (Parameter.DNS_CacheSinglePrefix_IPv6 < sizeof(in6_addr) * BYTES_TO_BITS / 2U) //Mark high 64 bits.
			AddrPart = hton64(ntoh64(*reinterpret_cast<const uint64_t *>(&reinterpret_cast<const sockaddr_in6 *>(&LocalSocketData.SockAddr)->sin6_addr)) & (UINT64_MAX << (sizeof(in6_addr) * BYTES_TO_BITS / 2U - Parameter.DNS_CacheSinglePrefix_IPv6)));
		else //Mark low 64 bits.
			AddrPart = hton64(ntoh64(*reinterpret_cast<const uint64_t *>(reinterpret_cast<const uint8_t *>(&reinterpret_cast<const sockaddr_in6 *>(&LocalSocketData.SockAddr)->sin6_addr) + sizeof(in6_addr) / 2U)) & (UINT64_MAX << (sizeof(in6_addr) * BYTES_TO_BITS - Parameter.DNS_CacheSinglePrefix_IPv6)));
	}
	else if (LocalSocketData.SockAddr.ss_family == AF_INET && Parameter.DNS_CacheSinglePrefix_IPv4 > 0) //IPv4
	{
		AddrPart = htonl(ntohl(reinterpret_cast<const sockaddr_in *>(&LocalSocketData.SockAddr)->sin_addr.s_addr) & (UINT32_MAX << (sizeof(in_addr) * BYTES_TO_BITS - Parameter.DNS_CacheSinglePrefix_IPv4)));
	}

//Find all matched DNS cache.
	std::lock_guard<std::mutex> DNSCacheListMutex(DNSCacheListLock);
	AutoRemoveExpired_DNS_Cache();
	if (DNSCacheIndexList.find(Domain) != DNSCacheIndexList.end())
	{
		const auto MapRange = DNSCacheIndexList.equal_range(Domain);
		for (auto MapIter = MapRange.first;MapIter != MapRange.second;++MapIter)
		{
		//Single address single cache(Part 2, IPv6)
			if (MapIter->second->ForAddress.Storage.ss_family == AF_INET6)
			{
			//Check if the request protocol is not matched.
				if (LocalSocketData.SockAddr.ss_family != AF_INET6)
					continue;

			//Check address prefix.
				if (Parameter.DNS_CacheSinglePrefix_IPv6 > 0 && 
					((Parameter.DNS_CacheSinglePrefix_IPv6 < sizeof(in6_addr) * BYTES_TO_BITS / 2U && memcmp(&AddrPart, &MapIter->second->ForAddress.IPv6.sin6_addr, sizeof(AddrPart)) != 0) || 
					(Parameter.DNS_CacheSinglePrefix_IPv6 >= sizeof(in6_addr) * BYTES_TO_BITS / 2U && 
					(memcmp(&reinterpret_cast<const sockaddr_in6 *>(&LocalSocketData.SockAddr)->sin6_addr, &MapIter->second->ForAddress.IPv6.sin6_addr, sizeof(uint64_t)) != 0 || 
					memcmp(&AddrPart, reinterpret_cast<const uint8_t *>(&MapIter->second->ForAddress.IPv6.sin6_addr) + sizeof(in6_addr) / 2U, sizeof(AddrPart)) != 0))))
						continue;
			}
		//Single address single cache(Part 2, IPv4)
			else if (MapIter->second->ForAddress.Storage.ss_family == AF_INET)
			{
			//Check if the request protocol is not matched.
				if (LocalSocketData.SockAddr.ss_family != AF_INET)
					continue;

			//Check address prefix.
				if (Parameter.DNS_CacheSinglePrefix_IPv4 > 0 && static_cast<uint32_t>(AddrPart) != MapIter->second->ForAddress.IPv4.sin_addr.s_addr)
					continue;
			}
		//Single address single cache(Part 2, default queue or single address single cache has been shutdown are always pass)
//			else {
//				;
//			}

		//Scan cache data.
			if (MapIter->second->RecordType == DNS_Query->Type)
			{
				memset(Result + sizeof(uint16_t), 0, ResultSize - sizeof(uint16_t));
				memcpy_s(Result + sizeof(uint16_t), ResultSize - sizeof(uint16_t), MapIter->second->Response.get(), MapIter->second->Length);

				return MapIter->second->Length + sizeof(uint16_t);
			}
		}
	}

	return EXIT_SUCCESS;
}

//Automatic remove expired DNS cache
void AutoRemoveExpired_DNS_Cache(
	void)
{
//Timer mode
	if (Parameter.DNS_CacheType == DNS_CACHE_TYPE::TIMER)
	{
	//Expired check
		for (auto DNSCacheDataIter = DNSCacheList.begin();DNSCacheDataIter != DNSCacheList.end();)
		{
			if (DNSCacheDataIter->ClearCacheTime <= GetCurrentSystemTime())
			{
			//Remove from DNS cache index list.
				if (DNSCacheIndexList.find(DNSCacheDataIter->Domain) != DNSCacheIndexList.end())
				{
					const auto MapRange = DNSCacheIndexList.equal_range(DNSCacheDataIter->Domain);
					for (auto MapIter = MapRange.first;MapIter != MapRange.second;++MapIter)
					{
						if (MapIter->second == DNSCacheDataIter)
						{
							DNSCacheIndexList.erase(MapIter);
							break;
						}
					}
				}

			//Remove from DNS cache data list.
				DNSCacheDataIter = DNSCacheList.erase(DNSCacheDataIter);
			}
			else {
				++DNSCacheDataIter;
			}
		}
	}
//Queue mode
	else if (Parameter.DNS_CacheType == DNS_CACHE_TYPE::QUEUE)
	{
	//Queue length check
		while (DNSCacheList.size() > Parameter.DNS_CacheParameter)
		{
		//Remove from DNS cache index list.
			if (DNSCacheIndexList.find(DNSCacheList.back().Domain) != DNSCacheIndexList.end())
			{
				auto DNSCacheListIter = DNSCacheList.end();
				--DNSCacheListIter;
				const auto MapRange = DNSCacheIndexList.equal_range(DNSCacheList.back().Domain);
				for (auto MapIter = MapRange.first;MapIter != MapRange.second;++MapIter)
				{
					if (MapIter->second == DNSCacheListIter)
					{
						DNSCacheIndexList.erase(MapIter);
						break;
					}
				}
			}

		//Remove from DNS cache data list.
			DNSCacheList.pop_back();
		}
	}
//Both mode(Timer + Queue)
	else if (Parameter.DNS_CacheType == DNS_CACHE_TYPE::BOTH)
	{
	//Expired check
		for (auto DNSCacheDataIter = DNSCacheList.begin();DNSCacheDataIter != DNSCacheList.end();)
		{
			if (DNSCacheDataIter->ClearCacheTime <= GetCurrentSystemTime())
			{
			//Remove from DNS cache index list.
				if (DNSCacheIndexList.find(DNSCacheDataIter->Domain) != DNSCacheIndexList.end())
				{
					const auto MapRange = DNSCacheIndexList.equal_range(DNSCacheDataIter->Domain);
					for (auto MapIter = MapRange.first;MapIter != MapRange.second;++MapIter)
					{
						if (MapIter->second == DNSCacheDataIter)
						{
							DNSCacheIndexList.erase(MapIter);
							break;
						}
					}
				}

			//Remove from DNS cache data list.
				DNSCacheDataIter = DNSCacheList.erase(DNSCacheDataIter);
			}
			else {
				++DNSCacheDataIter;
			}
		}

	//Queue length check
		while (DNSCacheList.size() > Parameter.DNS_CacheParameter)
		{
		//Remove from DNS cache index list.
			if (DNSCacheIndexList.find(DNSCacheList.back().Domain) != DNSCacheIndexList.end())
			{
				auto DNSCacheListIter = DNSCacheList.end();
				--DNSCacheListIter;
				const auto MapRange = DNSCacheIndexList.equal_range(DNSCacheList.back().Domain);
				for (auto MapIter = MapRange.first;MapIter != MapRange.second;++MapIter)
				{
					if (MapIter->second == DNSCacheListIter)
					{
						DNSCacheIndexList.erase(MapIter);
						break;
					}
				}
			}

		//Remove from DNS cache data list.
			DNSCacheList.pop_back();
		}
	}

	return;
}

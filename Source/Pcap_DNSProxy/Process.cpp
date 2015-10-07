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


#include "Process.h"

//Independent request process
bool __fastcall EnterRequestProcess(
	const char *OriginalSend, 
	const size_t Length, 
	const SOCKET_DATA LocalSocketData, 
	const uint16_t Protocol, 
	const bool IsLocal)
{
//Initialization(Send buffer part)
	std::shared_ptr<char> SendBuffer, RecvBuffer;
	if (Parameter.CompressionPointerMutation)
	{
		if (Parameter.CPM_PointerToAdditional)
		{
			std::shared_ptr<char> SendBufferTemp(new char[Length + 2U + sizeof(dns_record_aaaa) + sizeof(uint16_t)]());
			memset(SendBufferTemp.get(), 0, Length + 2U + sizeof(dns_record_aaaa) + sizeof(uint16_t));
			SendBufferTemp.swap(SendBuffer);
		}
		else if (Parameter.CPM_PointerToRR)
		{
			std::shared_ptr<char> SendBufferTemp(new char[Length + 2U + sizeof(uint16_t)]());
			memset(SendBufferTemp.get(), 0, Length + 2U + sizeof(uint16_t));
			SendBufferTemp.swap(SendBuffer);
		}
		else { //Pointer to header
			std::shared_ptr<char> SendBufferTemp(new char[Length + 1U + sizeof(uint16_t)]());
			memset(SendBufferTemp.get(), 0, Length + 1U + sizeof(uint16_t));
			SendBufferTemp.swap(SendBuffer);
		}
	}
	else {
		std::shared_ptr<char> SendBufferTemp(new char[Length + sizeof(uint16_t)]()); //Reserved 2 bytes for TCP header length.
		memset(SendBufferTemp.get(), 0, Length + sizeof(uint16_t));
		SendBufferTemp.swap(SendBuffer);
	}
	memcpy_s(SendBuffer.get(), Length, OriginalSend, Length);

//Initialization(Receive buffer part)
	size_t RecvSize = 0;
	if (Parameter.RequestMode_Transport == REQUEST_MODE_TCP || Protocol == IPPROTO_TCP || //TCP request
		Parameter.LocalProtocol_Transport == REQUEST_MODE_TCP || //Local request
		Parameter.SOCKS && Parameter.SOCKS_Protocol_Transport == REQUEST_MODE_TCP //SOCKS TCP request
	#if defined(ENABLE_LIBSODIUM)
		|| Parameter.DNSCurve && DNSCurveParameter.DNSCurveProtocol_Transport == REQUEST_MODE_TCP //DNSCurve TCP request
	#endif
		)
	{
		std::shared_ptr<char> TCPRecvBuffer(new char[LARGE_PACKET_MAXSIZE + sizeof(uint16_t)]());
		memset(TCPRecvBuffer.get(), 0, LARGE_PACKET_MAXSIZE + sizeof(uint16_t));
		RecvBuffer.swap(TCPRecvBuffer);
		RecvSize = LARGE_PACKET_MAXSIZE;
	}
	else { //UDP
		std::shared_ptr<char> UDPRecvBuffer(new char[PACKET_MAXSIZE + sizeof(uint16_t)]());
		memset(UDPRecvBuffer.get(), 0, PACKET_MAXSIZE + sizeof(uint16_t));
		RecvBuffer.swap(UDPRecvBuffer);
		RecvSize = PACKET_MAXSIZE;
	}

//Local request process
	if (IsLocal && LocalRequestProcess(SendBuffer.get(), Length, RecvBuffer.get(), RecvSize, Protocol, LocalSocketData))
	{
	//Fin TCP request connection.
		if (Protocol == IPPROTO_TCP && LocalSocketData.Socket != INVALID_SOCKET)
		{
			shutdown(LocalSocketData.Socket, SD_BOTH);
			closesocket(LocalSocketData.Socket);
		}

		return true;
	}
	
	auto DNS_Header = (pdns_hdr)SendBuffer.get();
	size_t DataLength = Length;
//Compression Pointer Mutation
	if (Parameter.CompressionPointerMutation && DNS_Header->Additional == 0)
	{
		DataLength = MakeCompressionPointerMutation(SendBuffer.get(), Length);
		if (DataLength < Length)
			DataLength = Length;
	}

//SOCKS request process
	if (Parameter.SOCKS)
	{
	//SOCKS request
		if (SOCKSRequestProcess(SendBuffer.get(), DataLength, RecvBuffer.get(), RecvSize, Protocol, LocalSocketData))
			return true;

	//SOCKS Proxy Only mode
		if (Parameter.SOCKS_Only)
		{
		//Fin TCP request connection.
			if (Protocol == IPPROTO_TCP && LocalSocketData.Socket != INVALID_SOCKET)
			{
				shutdown(LocalSocketData.Socket, SD_BOTH);
				closesocket(LocalSocketData.Socket);
			}

			return true;
		}
	}

//Direct Request request process
	if (Parameter.DirectRequest > DIRECT_REQUEST_MODE_NONE && DirectRequestProcess(SendBuffer.get(), DataLength, RecvBuffer.get(), RecvSize, Protocol, true, LocalSocketData))
	{
	//Fin TCP request connection.
		if (Protocol == IPPROTO_TCP && LocalSocketData.Socket != INVALID_SOCKET)
		{
			shutdown(LocalSocketData.Socket, SD_BOTH);
			closesocket(LocalSocketData.Socket);
		}

		return true;
	}

//DNSCurve request process
#if defined(ENABLE_LIBSODIUM)
	if (Parameter.DNSCurve)
	{
	//DNSCurve check
		if (DNSCurveParameter.IsEncryption && DataLength + DNSCRYPT_BUFFER_RESERVE_LEN > DNSCurveParameter.DNSCurvePayloadSize)
			goto SkipDNSCurve;

	//DNSCurve request
		if (DNSCurveRequestProcess(SendBuffer.get(), DataLength, RecvBuffer.get(), RecvSize, Protocol, LocalSocketData))
			return true;

	//DNSCurve Encryption Only mode
		if (DNSCurveParameter.IsEncryptionOnly)
		{
		//Fin TCP request connection.
			if (Protocol == IPPROTO_TCP && LocalSocketData.Socket != INVALID_SOCKET)
			{
				shutdown(LocalSocketData.Socket, SD_BOTH);
				closesocket(LocalSocketData.Socket);
			}

			return true;
		}
	}
	
//Jump here to skip DNSCurve process.
SkipDNSCurve:
#endif

//TCP request process
	if ((Parameter.RequestMode_Transport == REQUEST_MODE_TCP || Protocol == IPPROTO_TCP) && 
		TCPRequestProcess(SendBuffer.get(), DataLength, RecvBuffer.get(), RecvSize, Protocol, LocalSocketData))
			return true;

//Direct request when Pcap Capture module is turn OFF.
#if defined(ENABLE_PCAP)
	if (!Parameter.PcapCapture)
	{
#endif
		DirectRequestProcess(SendBuffer.get(), DataLength, RecvBuffer.get(), RecvSize, Protocol, false, LocalSocketData);

	//Fin TCP request connection.
		if (Protocol == IPPROTO_TCP && LocalSocketData.Socket != INVALID_SOCKET)
		{
			shutdown(LocalSocketData.Socket, SD_BOTH);
			closesocket(LocalSocketData.Socket);
		}

		return true;
#if defined(ENABLE_PCAP)
	}

//UDP request
	RecvBuffer.reset();
	UDPRequestProcess(SendBuffer.get(), DataLength, LocalSocketData, Protocol);

	return true;
#endif
}

//Check hosts from list
size_t __fastcall CheckHostsProcess(
	PSTR OriginalRequest, 
	const size_t Length, 
	PSTR Result, 
	const size_t ResultSize)
{
//Initilization
	std::string Domain;
	auto DNS_Header = (pdns_hdr)OriginalRequest;
	memset(Result, 0, ResultSize);

//Request check
	if (DNS_Header->Questions == htons(U16_NUM_ONE) && CheckQueryNameLength(OriginalRequest + sizeof(dns_hdr)) + 1U < DOMAIN_MAXSIZE)
	{
		if (DNSQueryToChar(OriginalRequest + sizeof(dns_hdr), Result) > DOMAIN_MINSIZE)
		{
		//Domain Case Conversion
			CaseConvert(false, Result, strnlen_s(Result, ResultSize));

		//Copy domain string.
			Domain = Result;
			memset(Result, 0, ResultSize);
		}
		else {
			return EXIT_FAILURE;
		}
	}
	else {
		return EXIT_FAILURE;
	}

//Response
	memcpy_s(Result, ResultSize, OriginalRequest, Length);
	DNS_Header = (pdns_hdr)Result;
	auto DNS_Query = (pdns_qry)(Result + DNS_PACKET_QUERY_LOCATE(Result));

//Check Classes.
	if (DNS_Query->Classes != htons(DNS_CLASS_IN))
		return EXIT_FAILURE;

//Check Accept Types list.
	if (Parameter.AcceptType) //Permit
	{
		for (auto AcceptTypeTableIter = Parameter.AcceptTypeList->begin();AcceptTypeTableIter != Parameter.AcceptTypeList->end();++AcceptTypeTableIter)
		{
			if (AcceptTypeTableIter + 1U == Parameter.AcceptTypeList->end())
			{
				if (*AcceptTypeTableIter != DNS_Query->Type)
				{
					DNS_Header->Flags = htons(ntohs(DNS_Header->Flags) | DNS_SET_R_SNH);
					return Length;
				}
			}
			else if (*AcceptTypeTableIter == DNS_Query->Type)
			{
				break;
			}
		}
	}
	else { //Deny
		for (auto AcceptTypeTableIter:*Parameter.AcceptTypeList)
		{
			if (DNS_Query->Type == AcceptTypeTableIter)
			{
				DNS_Header->Flags = htons(ntohs(DNS_Header->Flags) | DNS_SET_R_SNH);
				return Length;
			}
		}
	}

	size_t DataLength = 0;
//PTR Records
#if !defined(PLATFORM_MACX)
	if (DNS_Query->Type == htons(DNS_RECORD_PTR) && Parameter.LocalServer_Length + Length <= ResultSize)
	{
		auto IsSendPTR = false;

	//IPv6 check
		if (Domain == ("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa") || //Loopback address(::1, Section 2.5.3 in RFC 4291)
	//IPv4 check
			Domain.find(".127.in-addr.arpa") != std::string::npos || //Loopback address(127.0.0.0/8, Section 3.2.1.3 in RFC 1122)
			Domain.find(".254.169.in-addr.arpa") != std::string::npos) //Link-local address(169.254.0.0/16, RFC 3927)
		{
			IsSendPTR = true;
		}
		else {
		//IPv6 check
			std::unique_lock<std::mutex> LocalAddressMutexIPv6(LocalAddressLock[0]);
			for (auto StringIter:*GlobalRunningStatus.LocalAddress_ResponsePTR[0])
			{
				if (Domain == StringIter)
				{
					IsSendPTR = true;
					break;
				}
			}
			LocalAddressMutexIPv6.unlock();

		//IPv4 check
			if (!IsSendPTR)
			{
				std::unique_lock<std::mutex> LocalAddressMutexIPv4(LocalAddressLock[1U]);
				for (auto StringIter:*GlobalRunningStatus.LocalAddress_ResponsePTR[1U])
				{
					if (Domain == StringIter)
					{
						IsSendPTR = true;
						break;
					}
				}
			}
		}

	//Send Localhost PTR.
		if (IsSendPTR)
		{
		//Set header flags and copy response to buffer.
			DNS_Header->Flags = htons(ntohs(DNS_Header->Flags) | DNS_SER_RA);
			DNS_Header->Answer = htons(U16_NUM_ONE);
			memset(Result + DNS_PACKET_QUERY_LOCATE(Result) + sizeof(dns_qry), 0, ResultSize - (DNS_PACKET_QUERY_LOCATE(Result) + sizeof(dns_qry)));
			memcpy_s(Result + DNS_PACKET_QUERY_LOCATE(Result) + sizeof(dns_qry), ResultSize - (DNS_PACKET_QUERY_LOCATE(Result) + sizeof(dns_qry)), Parameter.LocalServer_Response, Parameter.LocalServer_Length);
			DataLength = DNS_PACKET_QUERY_LOCATE(Result) + sizeof(dns_qry) + Parameter.LocalServer_Length;

		//EDNS Label
			if (Parameter.EDNS_Label || DNS_Header->Additional > 0)
			{
				DNS_Header->Additional = 0;
				DataLength = AddEDNSLabelToAdditionalRR(Result, DataLength, ResultSize, false);
			}
			
			return DataLength;
		}
	}
#endif

//LocalFQDN check
	if (Domain == *Parameter.LocalFQDN_String)
	{
	//IPv6
		if (DNS_Query->Type == htons(DNS_RECORD_AAAA))
		{
			std::unique_lock<std::mutex> LocalAddressMutexIPv6(LocalAddressLock[0]);
			if (GlobalRunningStatus.LocalAddress_Length[0] >= DNS_PACKET_MINSIZE)
			{
				memset(Result + sizeof(uint16_t), 0, ResultSize - sizeof(uint16_t));
				memcpy_s(Result + sizeof(uint16_t), ResultSize - sizeof(uint16_t), GlobalRunningStatus.LocalAddress_Response[0] + sizeof(uint16_t), GlobalRunningStatus.LocalAddress_Length[0] - sizeof(uint16_t));
				return GlobalRunningStatus.LocalAddress_Length[0];
			}
		}
	//IPv4
		else if (DNS_Query->Type == htons(DNS_RECORD_A))
		{
			std::unique_lock<std::mutex> LocalAddressMutexIPv4(LocalAddressLock[1U]);
			if (GlobalRunningStatus.LocalAddress_Length[1U] >= DNS_PACKET_MINSIZE)
			{
				memset(Result + sizeof(uint16_t), 0, ResultSize - sizeof(uint16_t));
				memcpy_s(Result + sizeof(uint16_t), ResultSize - sizeof(uint16_t), GlobalRunningStatus.LocalAddress_Response[1U] + sizeof(uint16_t), GlobalRunningStatus.LocalAddress_Length[1U] - sizeof(uint16_t));
				return GlobalRunningStatus.LocalAddress_Length[1U];
			}
		}
	}

//Check DNS cache.
	std::unique_lock<std::mutex> DNSCacheListMutex(DNSCacheListLock);
	for (auto DNSCacheDataIter:DNSCacheList)
	{
		if (Domain == DNSCacheDataIter.Domain && DNS_Query->Type == DNSCacheDataIter.RecordType)
		{
			memset(Result + sizeof(uint16_t), 0, ResultSize - sizeof(uint16_t));
			memcpy_s(Result + sizeof(uint16_t), ResultSize - sizeof(uint16_t), DNSCacheDataIter.Response.get(), DNSCacheDataIter.Length);

			return DNSCacheDataIter.Length + sizeof(uint16_t);
		}
	}
	DNSCacheListMutex.unlock();

//Local Main check
	auto IsLocal = false;
	if (Parameter.LocalMain)
		IsLocal = true;

//Main check
	std::unique_lock<std::mutex> HostsFileMutex(HostsFileLock);
	for (auto HostsFileSetIter:*HostsFileSetUsing)
	{
		for (auto HostsTableIter:HostsFileSetIter.HostsList)
		{
			if (std::regex_match(Domain, HostsTableIter.Pattern))
			{
			//Check white list.
				if (HostsTableIter.Type_Hosts == HOSTS_TYPE_WHITE)
				{
					IsLocal = false;
					if (HostsTableIter.Type_Record.empty()) //Ignore all types.
					{
						goto StopLoop;
					}
					else {
					//Permit or Deny check
						if (HostsTableIter.Type_Operation)
						{
						//Only ignore some types.
							for (auto RecordTypeIter = HostsTableIter.Type_Record.begin();RecordTypeIter != HostsTableIter.Type_Record.end();++RecordTypeIter)
							{
								if (DNS_Query->Type == *RecordTypeIter)
									break;
								else if (RecordTypeIter + 1U == HostsTableIter.Type_Record.end())
									goto StopLoop;
							}
						}
						else {
						//Ignore some types.
							for (auto RecordTypeIter:HostsTableIter.Type_Record)
							{
								if (DNS_Query->Type == RecordTypeIter)
									goto StopLoop;
							}
						}
					}
				}
			//Check banned list.
				else if (HostsTableIter.Type_Hosts == HOSTS_TYPE_BANNED)
				{
					IsLocal = false;
					if (HostsTableIter.Type_Record.empty()) //Block all types.
					{
						DNS_Header->Flags = htons(ntohs(DNS_Header->Flags) | DNS_SET_R_SNH);
						return Length;
					}
					else {
					//Permit or Deny check
						if (HostsTableIter.Type_Operation)
						{
						//Only allow some types.
							for (auto RecordTypeIter = HostsTableIter.Type_Record.begin();RecordTypeIter != HostsTableIter.Type_Record.end();++RecordTypeIter)
							{
								if (DNS_Query->Type == *RecordTypeIter)
								{
									break;
								}
								else if (RecordTypeIter + 1U == HostsTableIter.Type_Record.end())
								{
									DNS_Header->Flags = htons(ntohs(DNS_Header->Flags) | DNS_SET_R);
									return Length;
								}
							}
						}
						else {
						//Block some types.
							for (auto RecordTypeIter:HostsTableIter.Type_Record)
							{
								if (DNS_Query->Type == RecordTypeIter)
								{
									DNS_Header->Flags = htons(ntohs(DNS_Header->Flags) | DNS_SET_R);
									return Length;
								}
							}
						}
					}
				}
			//Check main Hosts.
				else if (HostsTableIter.Type_Hosts == HOSTS_TYPE_NORMAL)
				{
				//IPv6
					if (DNS_Query->Type == htons(DNS_RECORD_AAAA) && HostsTableIter.Type_Record.front() == htons(DNS_RECORD_AAAA))
					{
					//Set header flags.
						DNS_Header->Flags = htons(ntohs(DNS_Header->Flags) | DNS_SET_R);
						DNS_Header->Answer = htons((uint16_t)(HostsTableIter.Length / sizeof(dns_record_aaaa)));
						
					//Hosts item length check
						DataLength = DNS_PACKET_QUERY_LOCATE(Result) + sizeof(dns_qry) + HostsTableIter.Length;
						if (Parameter.EDNS_Label || DNS_Header->Additional > 0)
						{
							while (DataLength > PACKET_MAXSIZE - EDNS_ADDITIONAL_MAXSIZE)
							{
								DataLength -= sizeof(dns_record_aaaa);
								DNS_Header->Answer = htons(ntohs(DNS_Header->Answer) - 1U);
							}
						}
						else {
							while (DataLength > PACKET_MAXSIZE)
							{
								DataLength -= sizeof(dns_record_aaaa);
								DNS_Header->Answer = htons(ntohs(DNS_Header->Answer) - 1U);
							}
						}

					//Copy response to buffer.
						memset(Result + DNS_PACKET_QUERY_LOCATE(Result) + sizeof(dns_qry), 0, ResultSize - (DNS_PACKET_QUERY_LOCATE(Result) + sizeof(dns_qry)));
						memcpy_s(Result + DNS_PACKET_QUERY_LOCATE(Result) + sizeof(dns_qry), ResultSize - (DNS_PACKET_QUERY_LOCATE(Result) + sizeof(dns_qry)), HostsTableIter.Response.get(), DataLength - (DNS_PACKET_QUERY_LOCATE(Result) + sizeof(dns_qry)));

					//Hosts load balancing
						if (ntohs(DNS_Header->Answer) > U16_NUM_ONE)
						{
							std::shared_ptr<dns_record_aaaa> DNS_AAAA_Temp(new dns_record_aaaa());
							memset(DNS_AAAA_Temp.get(), 0, sizeof(dns_record_aaaa));

						//Select a ramdom preferred result.
							std::uniform_int_distribution<int> RamdomDistribution(0, ntohs(DNS_Header->Answer) - 1U);
							size_t RamdomIndex = RamdomDistribution(*GlobalRunningStatus.RamdomEngine);
							if (RamdomIndex > 0)
							{
								memcpy_s(DNS_AAAA_Temp.get(), sizeof(dns_record_aaaa), Result + DNS_PACKET_QUERY_LOCATE(Result) + sizeof(dns_qry), sizeof(dns_record_aaaa));
								memset(Result + DNS_PACKET_QUERY_LOCATE(Result) + sizeof(dns_qry), 0, sizeof(dns_record_aaaa));
								memcpy_s(Result + DNS_PACKET_QUERY_LOCATE(Result) + sizeof(dns_qry), ResultSize - (DNS_PACKET_QUERY_LOCATE(Result) + sizeof(dns_qry)), Result + DNS_PACKET_QUERY_LOCATE(Result) + sizeof(dns_qry) + sizeof(dns_record_aaaa) * RamdomIndex, sizeof(dns_record_aaaa));
								memset(Result + DNS_PACKET_QUERY_LOCATE(Result) + sizeof(dns_qry) + sizeof(dns_record_aaaa) * RamdomIndex, 0, sizeof(dns_record_aaaa));
								memcpy_s(Result + DNS_PACKET_QUERY_LOCATE(Result) + sizeof(dns_qry) + sizeof(dns_record_aaaa) * RamdomIndex, sizeof(dns_record_aaaa), DNS_AAAA_Temp.get(), sizeof(dns_record_aaaa));
							}
						}

					//EDNS Label
						if (Parameter.EDNS_Label || DNS_Header->Additional > 0)
						{
							DNS_Header->Additional = 0;
							DataLength = AddEDNSLabelToAdditionalRR(Result, DataLength, ResultSize, false);
						}

						return DataLength;
					}
					else if (DNS_Query->Type == htons(DNS_RECORD_A) && HostsTableIter.Type_Record.front() == htons(DNS_RECORD_A))
					{
					//Set header flags.
						DNS_Header->Flags = htons(ntohs(DNS_Header->Flags) | DNS_SET_R);
						DNS_Header->Answer = htons((uint16_t)(HostsTableIter.Length / sizeof(dns_record_a)));
						
					//Hosts item length check
						DataLength = DNS_PACKET_QUERY_LOCATE(Result) + sizeof(dns_qry) + HostsTableIter.Length;
						if (Parameter.EDNS_Label || DNS_Header->Additional > 0)
						{
							while (DataLength > PACKET_MAXSIZE - EDNS_ADDITIONAL_MAXSIZE)
							{
								DataLength -= sizeof(dns_record_a);
								DNS_Header->Answer = htons(ntohs(DNS_Header->Answer) - 1U);
							}
						}
						else {
							while (DataLength > PACKET_MAXSIZE)
							{
								DataLength -= sizeof(dns_record_a);
								DNS_Header->Answer = htons(ntohs(DNS_Header->Answer) - 1U);
							}
						}

					//Copy response to buffer.
						memset(Result + DNS_PACKET_QUERY_LOCATE(Result) + sizeof(dns_qry), 0, ResultSize - (DNS_PACKET_QUERY_LOCATE(Result) + sizeof(dns_qry)));
						memcpy_s(Result + DNS_PACKET_QUERY_LOCATE(Result) + sizeof(dns_qry), ResultSize - (DNS_PACKET_QUERY_LOCATE(Result) + sizeof(dns_qry)), HostsTableIter.Response.get(), DataLength - (DNS_PACKET_QUERY_LOCATE(Result) + sizeof(dns_qry)));

					//Hosts load balancing
						if (ntohs(DNS_Header->Answer) > U16_NUM_ONE)
						{
							std::shared_ptr<dns_record_a> DNS_A_Temp(new dns_record_a());
							memset(DNS_A_Temp.get(), 0, sizeof(dns_record_a));

						//Select a ramdom preferred result.
							std::uniform_int_distribution<int> RamdomDistribution(0, ntohs(DNS_Header->Answer) - 1U);
							size_t RamdomIndex = RamdomDistribution(*GlobalRunningStatus.RamdomEngine);
							if (RamdomIndex > 0)
							{
								memcpy_s(DNS_A_Temp.get(), sizeof(dns_record_a), Result + DNS_PACKET_QUERY_LOCATE(Result) + sizeof(dns_qry), sizeof(dns_record_a));
								memset(Result + DNS_PACKET_QUERY_LOCATE(Result) + sizeof(dns_qry), 0, sizeof(dns_record_a));
								memcpy_s(Result + DNS_PACKET_QUERY_LOCATE(Result) + sizeof(dns_qry), ResultSize - (DNS_PACKET_QUERY_LOCATE(Result) + sizeof(dns_qry)), Result + DNS_PACKET_QUERY_LOCATE(Result) + sizeof(dns_qry) + sizeof(dns_record_a) * RamdomIndex, sizeof(dns_record_a));
								memset(Result + DNS_PACKET_QUERY_LOCATE(Result) + sizeof(dns_qry) + sizeof(dns_record_a) * RamdomIndex, 0, sizeof(dns_record_a));
								memcpy_s(Result + DNS_PACKET_QUERY_LOCATE(Result) + sizeof(dns_qry) + sizeof(dns_record_a) * RamdomIndex, sizeof(dns_record_a), DNS_A_Temp.get(), sizeof(dns_record_a));
							}
						}

					//EDNS Label
						if (Parameter.EDNS_Label || DNS_Header->Additional > 0)
						{
							DNS_Header->Additional = 0;
							DataLength = AddEDNSLabelToAdditionalRR(Result, DataLength, ResultSize, false);
						}

						return DataLength;
					}
				}
			//Check local request.
				else if (HostsTableIter.Type_Hosts == HOSTS_TYPE_LOCAL)
				{
					IsLocal = true;
					goto StopLoop;
				}
			}
		}
	}

//Jump here to stop loop.
StopLoop:
	HostsFileMutex.unlock();

//Domain Case Conversion
	if (Parameter.DomainCaseConversion)
		MakeDomainCaseConversion(OriginalRequest + sizeof(dns_hdr));

//Local request
	if (IsLocal)
		return EXIT_CHECK_HOSTS_TYPE_LOCAL;

	return EXIT_SUCCESS;
}

//Request Process(Local part)
bool __fastcall LocalRequestProcess(
	const char *OriginalSend, 
	const size_t SendSize, 
	PSTR OriginalRecv, 
	const size_t RecvSize, 
	const uint16_t Protocol, 
	const SOCKET_DATA &LocalSocketData)
{
	size_t DataLength = 0;

//TCP request
	if (Parameter.LocalProtocol_Transport == REQUEST_MODE_TCP || Protocol == IPPROTO_TCP)
	{
		DataLength = TCPRequest(OriginalSend, SendSize, OriginalRecv, RecvSize, true);

	//Send response.
		if (DataLength >= DNS_PACKET_MINSIZE && DataLength < RecvSize)
		{
			SendToRequester(OriginalRecv, DataLength, RecvSize, Protocol, LocalSocketData);
			return true;
		}
	}

//UDP request
	DataLength = UDPCompleteRequest(OriginalSend, SendSize, OriginalRecv, RecvSize, true);

//Send response.
	if (DataLength >= DNS_PACKET_MINSIZE && DataLength < RecvSize)
	{
		SendToRequester(OriginalRecv, DataLength, RecvSize, Protocol, LocalSocketData);
		return true;
	}

	return false;
}

//Request Process(SOCKS part)
bool __fastcall SOCKSRequestProcess(
	const char *OriginalSend, 
	const size_t SendSize, 
	PSTR OriginalRecv, 
	const size_t RecvSize, 
	const uint16_t Protocol, 
	const SOCKET_DATA &LocalSocketData)
{
	size_t DataLength = 0;

//UDP request
	if (Parameter.SOCKS_Version == SOCKS_VERSION_5 && Parameter.SOCKS_Protocol_Transport == REQUEST_MODE_UDP)
	{
	//UDP request process
		DataLength = SOCKSUDPRequest(OriginalSend, SendSize, OriginalRecv, RecvSize);
		
	//Send response.
		if (DataLength >= DNS_PACKET_MINSIZE && DataLength < RecvSize)
		{
			SendToRequester(OriginalRecv, DataLength, RecvSize, Protocol, LocalSocketData);
			return true;
		}
	}

//TCP request
	DataLength = SOCKSTCPRequest(OriginalSend, SendSize, OriginalRecv, RecvSize);

//Send response.
	if (DataLength >= DNS_PACKET_MINSIZE && DataLength < RecvSize)
	{
		SendToRequester(OriginalRecv, DataLength, RecvSize, Protocol, LocalSocketData);
		return true;
	}

	return false;
}

//Request Process(Direct connections part)
bool __fastcall DirectRequestProcess(
	const char *OriginalSend, 
	const size_t SendSize, 
	PSTR OriginalRecv, 
	const size_t RecvSize, 
	const uint16_t Protocol, 
	const bool DirectRequest, 
	const SOCKET_DATA &LocalSocketData)
{
	size_t DataLength = 0;

//Direct Request mode check
	DataLength = SelectNetworkProtocol();
	if (DirectRequest && (DataLength == AF_INET6 && Parameter.DirectRequest == DIRECT_REQUEST_MODE_IPV4 || //IPv6
		DataLength == AF_INET && Parameter.DirectRequest == DIRECT_REQUEST_MODE_IPV6)) //IPv4
			return false;

//TCP request
	if (Parameter.RequestMode_Transport == REQUEST_MODE_TCP || Protocol == IPPROTO_TCP)
	{
	//Multi request process
		if (Parameter.AlternateMultiRequest || Parameter.MultiRequestTimes > 1U)
			DataLength = TCPRequestMulti(OriginalSend, SendSize, OriginalRecv, RecvSize);
	//Normal request process
		else 
			DataLength = TCPRequest(OriginalSend, SendSize, OriginalRecv, RecvSize, false);

	//Send response.
		if (DataLength >= DNS_PACKET_MINSIZE && DataLength < RecvSize)
		{
			SendToRequester(OriginalRecv, DataLength, RecvSize, Protocol, LocalSocketData);
			return true;
		}
	}

//UDP request

//Multi request process
	if (Parameter.AlternateMultiRequest || Parameter.MultiRequestTimes > 1U)
		DataLength = UDPCompleteRequestMulti(OriginalSend, SendSize, OriginalRecv, RecvSize);
//Normal request process
	else 
		DataLength = UDPCompleteRequest(OriginalSend, SendSize, OriginalRecv, RecvSize, false);

//Send response.
	if (DataLength >= DNS_PACKET_MINSIZE && DataLength < RecvSize)
	{
		SendToRequester(OriginalRecv, DataLength, RecvSize, Protocol, LocalSocketData);
		return true;
	}

	return false;
}

//Request Process(DNSCurve part)
#if defined(ENABLE_LIBSODIUM)
bool __fastcall DNSCurveRequestProcess(
	const char *OriginalSend, 
	const size_t SendSize, 
	PSTR OriginalRecv, 
	const size_t RecvSize, 
	const uint16_t Protocol, 
	const SOCKET_DATA &LocalSocketData)
{
	size_t DataLength = 0;

//TCP request
	if (DNSCurveParameter.DNSCurveProtocol_Transport == REQUEST_MODE_TCP || Protocol == IPPROTO_TCP)
	{
	//Multi request process
		if (Parameter.AlternateMultiRequest || Parameter.MultiRequestTimes > 1U)
			DataLength = DNSCurveTCPRequestMulti(OriginalSend, SendSize, OriginalRecv, RecvSize);
	//Normal request process
		else 
			DataLength = DNSCurveTCPRequest(OriginalSend, SendSize, OriginalRecv, RecvSize);

	//Send response.
		if (DataLength >= DNS_PACKET_MINSIZE && DataLength < RecvSize)
		{
			SendToRequester(OriginalRecv, DataLength, RecvSize, Protocol, LocalSocketData);
			return true;
		}
	}

//UDP request
//Multi request process
	if (Parameter.AlternateMultiRequest || Parameter.MultiRequestTimes > 1U)
		DataLength = DNSCurveUDPRequestMulti(OriginalSend, SendSize, OriginalRecv, RecvSize);
	//Normal request process
	else 
		DataLength = DNSCurveUDPRequest(OriginalSend, SendSize, OriginalRecv, RecvSize);

//Send response.
	if (DataLength >= DNS_PACKET_MINSIZE && DataLength < RecvSize)
	{
		SendToRequester(OriginalRecv, DataLength, RecvSize, Protocol, LocalSocketData);
		return true;
	}

	return false;
}
#endif

//Request Process(TCP part)
bool __fastcall TCPRequestProcess(
	const char *OriginalSend, 
	const size_t SendSize, 
	PSTR OriginalRecv, 
	const size_t RecvSize, 
	const uint16_t Protocol, 
	const SOCKET_DATA &LocalSocketData)
{
	size_t DataLength = 0;

//Multi request process
	if (Parameter.AlternateMultiRequest || Parameter.MultiRequestTimes > 1U)
		DataLength = TCPRequestMulti(OriginalSend, SendSize, OriginalRecv, RecvSize);
//Normal request process
	else 
		DataLength = TCPRequest(OriginalSend, SendSize, OriginalRecv, RecvSize, false);

//Send response.
	if (DataLength >= DNS_PACKET_MINSIZE && DataLength < RecvSize)
	{
		SendToRequester(OriginalRecv, DataLength, RecvSize, Protocol, LocalSocketData);
		return true;
	}

	return false;
}

//Select network layer protocol of packets sending
uint16_t __fastcall SelectNetworkProtocol(
	void)
{
//IPv6
	if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0 && 
		(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK_BOTH && GlobalRunningStatus.GatewayAvailable_IPv6 || //Auto select
		Parameter.RequestMode_Network == REQUEST_MODE_IPV6 || //IPv6
		Parameter.RequestMode_Network == REQUEST_MODE_IPV4 && Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family == 0)) //Non-IPv4
			return AF_INET6;
//IPv4
	else if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0 && 
		(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK_BOTH && GlobalRunningStatus.GatewayAvailable_IPv4 || //Auto select
		Parameter.RequestMode_Network == REQUEST_MODE_IPV4 || //IPv4
		Parameter.RequestMode_Network == REQUEST_MODE_IPV6 && Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family == 0)) //Non-IPv6
			return AF_INET;

	return FALSE;
}

//Request Process(UDP part)
#if defined(ENABLE_PCAP)
void __fastcall UDPRequestProcess(
	const char *OriginalSend, 
	const size_t SendSize, 
	const SOCKET_DATA &LocalSocketData, 
	const uint16_t Protocol)
{
//Multi request process
	if (Parameter.AlternateMultiRequest || Parameter.MultiRequestTimes > 1U)
		UDPRequestMulti(OriginalSend, SendSize, &LocalSocketData, Protocol);
//Normal request process
	else 
		UDPRequest(OriginalSend, SendSize, &LocalSocketData, Protocol);

//Fin TCP request connection.
	if (Protocol == IPPROTO_TCP && LocalSocketData.Socket != INVALID_SOCKET)
	{
		shutdown(LocalSocketData.Socket, SD_BOTH);
		closesocket(LocalSocketData.Socket);
	}

	return;
}
#endif

//Send responses to requester
bool __fastcall SendToRequester(
	PSTR RecvBuffer, 
	const size_t RecvSize, 
	const size_t MaxLen, 
	const uint16_t Protocol, 
	const SOCKET_DATA &LocalSocketData)
{
//TCP
	if (Protocol == IPPROTO_TCP)
	{
		if (AddLengthDataToHeader(RecvBuffer, RecvSize, MaxLen) == EXIT_FAILURE)
		{
			shutdown(LocalSocketData.Socket, SD_BOTH);
			closesocket(LocalSocketData.Socket);
			return false;
		}

		send(LocalSocketData.Socket, RecvBuffer, (int)(RecvSize + sizeof(uint16_t)), 0);
		shutdown(LocalSocketData.Socket, SD_BOTH);
		closesocket(LocalSocketData.Socket);
	}
//UDP
	else {
		sendto(LocalSocketData.Socket, RecvBuffer, (int)RecvSize, 0, (PSOCKADDR)&LocalSocketData.SockAddr, LocalSocketData.AddrLen);
	}

	return true;
}

//Mark responses to domains Cache
bool __fastcall MarkDomainCache(
	const char *Buffer, 
	const size_t Length)
{
//Check conditions.
	auto DNS_Header = (pdns_hdr)Buffer;
	if (
	//Not a response packet
		(ntohs(DNS_Header->Flags) & DNS_GET_BIT_RESPONSE) == 0 || 
	//Question Resource Records must be one.
		DNS_Header->Questions != htons(U16_NUM_ONE) || 
	//Not any Answer Resource Records
		DNS_Header->Answer == 0 && DNS_Header->Authority == 0 /* && DNS_Header->Additional == 0 */ || 
	//OPCode must be set Query/0.
		(ntohs(DNS_Header->Flags) & DNS_GET_BIT_OPCODE) != DNS_OPCODE_QUERY || 
	//Truncated bit must not be set.
		(ntohs(DNS_Header->Flags) & DNS_GET_BIT_TC) != 0 || 
	//RCode must be set No Error or Non-Existent Domain.
		(ntohs(DNS_Header->Flags) & DNS_GET_BIT_RCODE) != DNS_RCODE_NOERROR && (ntohs(DNS_Header->Flags) & DNS_GET_BIT_RCODE) != DNS_RCODE_NXDOMAIN)
			return false;

//Initialization(A part)
	DNSCACHE_DATA DNSCacheDataTemp;
	DNSCacheDataTemp.Length = 0;
	DNSCacheDataTemp.ClearCacheTime = 0;
	auto DNS_Query = (pdns_qry)(Buffer + DNS_PACKET_QUERY_LOCATE(Buffer));
	DNSCacheDataTemp.RecordType = DNS_Query->Type;
	uint32_t ResponseTTL = 0;

//Mark DNS A records and AAAA records only.
	if (DNSCacheDataTemp.RecordType == htons(DNS_RECORD_AAAA) || DNSCacheDataTemp.RecordType == htons(DNS_RECORD_A))
	{
		size_t DataLength = DNS_PACKET_RR_LOCATE(Buffer), TTLCounts = 0;
		pdns_record_standard DNS_Record_Standard = nullptr;
		uint16_t DNS_Pointer = 0;

	//Scan all Answers Resource Records.
		for (size_t Index = 0;Index < (size_t)ntohs(DNS_Header->Answer);++Index)
		{
		//Pointer check
			if (DataLength + sizeof(uint16_t) < Length && (UCHAR)Buffer[DataLength] >= DNS_POINTER_BITS)
			{
				DNS_Pointer = ntohs(*(PUINT16)(Buffer + DataLength)) & DNS_POINTER_BITS_GET_LOCATE;
				if (DNS_Pointer >= Length || DNS_Pointer < sizeof(dns_hdr) || DNS_Pointer == DataLength || DNS_Pointer == DataLength + 1U)
					return false;
			}

		//Resource Records Name(Domain Name)
			DataLength += CheckQueryNameLength(Buffer + DataLength) + 1U;
			if (DataLength + sizeof(dns_record_standard) > Length)
				break;

		//Standard Resource Records
			DNS_Record_Standard = (pdns_record_standard)(Buffer + DataLength);
			DataLength += sizeof(dns_record_standard);
			if (DataLength > Length || DNS_Record_Standard != nullptr && DataLength + ntohs(DNS_Record_Standard->Length) > Length)
				break;

		//Resource Records Data
			if (DNS_Record_Standard->Classes == htons(DNS_CLASS_IN) && DNS_Record_Standard->TTL > 0 && 
				(DNS_Record_Standard->Type == htons(DNS_RECORD_AAAA) && DNS_Record_Standard->Length == htons(sizeof(in6_addr)) || 
				DNS_Record_Standard->Type == htons(DNS_RECORD_A) && DNS_Record_Standard->Length == htons(sizeof(in_addr))))
			{
				ResponseTTL += ntohl(DNS_Record_Standard->TTL);
				++TTLCounts;
			}

			DataLength += ntohs(DNS_Record_Standard->Length);
		}

	//Calculate average TTL.
		if (TTLCounts > 0)
			ResponseTTL = ResponseTTL / (uint32_t)TTLCounts + ResponseTTL % (uint32_t)TTLCounts;
	}

//Set cache TTL.
	if (ResponseTTL == 0 && DNS_Header->Authority == 0) //Only mark A and AAAA records.
	{
		return false;
	}
	else {
		if (Parameter.CacheType == CACHE_TYPE_TIMER)
		{
			if (ResponseTTL * SECOND_TO_MILLISECOND < Parameter.CacheParameter)
				ResponseTTL = (uint32_t)(Parameter.CacheParameter / SECOND_TO_MILLISECOND - ResponseTTL + STANDARD_TIMEOUT / SECOND_TO_MILLISECOND);
		}
		else { //CACHE_TYPE_QUEUE
			if (ResponseTTL < Parameter.HostsDefaultTTL)
				ResponseTTL = Parameter.HostsDefaultTTL - ResponseTTL + STANDARD_TIMEOUT / SECOND_TO_MILLISECOND;
		}
	}

//Initialization(B part)
	if (Length <= DOMAIN_MAXSIZE)
	{
		std::shared_ptr<char> DNSCacheDataBufferTemp(new char[DOMAIN_MAXSIZE]());
		memset(DNSCacheDataBufferTemp.get(), 0, DOMAIN_MAXSIZE);
		DNSCacheDataTemp.Response.swap(DNSCacheDataBufferTemp);
	}
	else {
		std::shared_ptr<char> DNSCacheDataBufferTemp(new char[Length]());
		memset(DNSCacheDataBufferTemp.get(), 0, Length);
		DNSCacheDataTemp.Response.swap(DNSCacheDataBufferTemp);
	}

//Mark to global list.
	if (DNSQueryToChar(Buffer + sizeof(dns_hdr), DNSCacheDataTemp.Response.get()) > DOMAIN_MINSIZE)
	{
	//Domain Case Conversion
		CaseConvert(false, DNSCacheDataTemp.Response.get(), strnlen_s(DNSCacheDataTemp.Response.get(), DOMAIN_MAXSIZE));
		DNSCacheDataTemp.Domain = DNSCacheDataTemp.Response.get();
		memset(DNSCacheDataTemp.Response.get(), 0, DOMAIN_MAXSIZE);
		memcpy_s(DNSCacheDataTemp.Response.get(), PACKET_MAXSIZE, Buffer + sizeof(uint16_t), Length - sizeof(uint16_t));
		DNSCacheDataTemp.Length = Length - sizeof(uint16_t);

	//Minimum supported system of GetTickCount64() is Windows Vista(Windows XP with SP3 support).
	#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
		if (GlobalRunningStatus.FunctionPTR_GetTickCount64 != nullptr)
			DNSCacheDataTemp.ClearCacheTime = (size_t)((*GlobalRunningStatus.FunctionPTR_GetTickCount64)() + ResponseTTL * SECOND_TO_MILLISECOND);
		else 
			DNSCacheDataTemp.ClearCacheTime = GetTickCount() + ResponseTTL * SECOND_TO_MILLISECOND;
	#else
		DNSCacheDataTemp.ClearCacheTime = GetTickCount64() + ResponseTTL * SECOND_TO_MILLISECOND;
	#endif

		std::unique_lock<std::mutex> DNSCacheListMutex(DNSCacheListLock);
	//Check repeating items, delete duque rear and add new item to deque front.
		for (auto DNSCacheDataIter = DNSCacheList.begin();DNSCacheDataIter != DNSCacheList.end();++DNSCacheDataIter)
		{
			if (DNSCacheDataTemp.Domain == DNSCacheDataIter->Domain && DNSCacheDataTemp.RecordType == DNSCacheDataIter->RecordType)
			{
				DNSCacheList.erase(DNSCacheDataIter);
				break;
			}
		}

	//Delete cache.
		if (Parameter.CacheType == CACHE_TYPE_QUEUE)
		{
			while (DNSCacheList.size() > Parameter.CacheParameter)
				DNSCacheList.pop_front();
		}
		else { //CACHE_TYPE_TIMER
		//Minimum supported system of GetTickCount64() is Windows Vista(Windows XP with SP3 support).
		#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
			while (!DNSCacheList.empty() && (GlobalRunningStatus.FunctionPTR_GetTickCount64 != nullptr && (*GlobalRunningStatus.FunctionPTR_GetTickCount64)() >= DNSCacheList.front().ClearCacheTime || 
				GetTickCount() >= DNSCacheList.front().ClearCacheTime))
		#else
			while (!DNSCacheList.empty() && GetTickCount64() >= DNSCacheList.front().ClearCacheTime)
		#endif
				DNSCacheList.pop_front();
		}

		DNSCacheList.push_back(DNSCacheDataTemp);
		DNSCacheList.shrink_to_fit();
		return true;
	}

	return false;
}

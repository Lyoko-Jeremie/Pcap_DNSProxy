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


#include "Configuration.h"

//Global variables
extern size_t ParameterHopLimitsIndex[];

//Check parameter list and set default values
bool Parameter_CheckSetting(
	const bool IsFirstRead, 
	const size_t FileIndex)
{
//Initialization
	CONFIGURATION_TABLE *ParameterPointer = nullptr;
#if defined(ENABLE_LIBSODIUM)
	DNSCURVE_CONFIGURATION_TABLE *DNSCurveParameterPointer = nullptr;
#endif
	if (IsFirstRead)
	{
		ParameterPointer = &Parameter;
	#if defined(ENABLE_LIBSODIUM)
		DNSCurveParameterPointer = &DNSCurveParameter;
	#endif
	}
	else {
		ParameterPointer = &ParameterModificating;
	#if defined(ENABLE_LIBSODIUM)
		DNSCurveParameterPointer = &DNSCurveParameterModificating;
	#endif
	}

//[Base] block
	//Configuration file version check
	if (ParameterPointer->Version_Major != CONFIG_VERSION_MAJOR || ParameterPointer->Version_Minor != CONFIG_VERSION_MINOR)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Configuration file version error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
		return false;
	}

//[Log] block
	//Log maximum size check
	if (ParameterPointer->LogMaxSize < LOG_READING_MINSIZE || ParameterPointer->LogMaxSize >= FILE_READING_MAXSIZE)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Log file size error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
		return false;
	}

//[Listen] block
	//Listen Port default setting
	if (IsFirstRead && Parameter.ListenPort->empty())
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NOTICE, L"Listen Port is empty, set to standard DNS port(53)", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
		Parameter.ListenPort->push_back(htons(IPPORT_DNS));
	}

	//Sort AcceptTypeList.
	if (ParameterPointer->AcceptTypeList != nullptr && !ParameterPointer->AcceptTypeList->empty())
		std::sort(ParameterPointer->AcceptTypeList->begin(), ParameterPointer->AcceptTypeList->end());

//[DNS] block part 1
	//DNS cache check
	if (IsFirstRead && Parameter.DNS_CacheParameter == 0 && //DNS Cache queue mode must set cache parameter.
		(Parameter.DNS_CacheType == DNS_CACHE_TYPE::BOTH || Parameter.DNS_CacheType == DNS_CACHE_TYPE::QUEUE))
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"DNS cache error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
		return false;
	}

//[Local DNS] block
	//Local Protocol(IPv6)
	if (Parameter.Target_Server_Local_Main_IPv6.Storage.ss_family == 0 && ParameterPointer->LocalProtocol_Network == REQUEST_MODE_NETWORK::IPV6)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NOTICE, L"IPv6 Request Mode require IPv6 DNS server", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
		ParameterPointer->LocalProtocol_Network = REQUEST_MODE_NETWORK::BOTH;
	}

//Local Protocol(IPv4)
	if (Parameter.Target_Server_Local_Main_IPv4.Storage.ss_family == 0 && ParameterPointer->LocalProtocol_Network == REQUEST_MODE_NETWORK::IPV4)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NOTICE, L"IPv4 Request Mode require IPv4 DNS server", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
		ParameterPointer->LocalProtocol_Network = REQUEST_MODE_NETWORK::BOTH;
	}

	if (IsFirstRead)
	{
	//Local Hosts, Local Routing and Local Force Request check
		if ((Parameter.IsLocalForce && !Parameter.IsLocalHosts) || //Local Force Request require Local Hosts.
			((Parameter.IsLocalHosts || Parameter.IsLocalRouting) && 
			Parameter.Target_Server_Local_Main_IPv6.Storage.ss_family == 0 && Parameter.Target_Server_Local_Main_IPv4.Storage.ss_family == 0))
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Local request options error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
			return false;
		}

//[Addresses] block
	//Listen Address list check(IPv6)
		if (Parameter.ListenAddress_IPv6->empty())
		{
			delete Parameter.ListenAddress_IPv6;
			Parameter.ListenAddress_IPv6 = nullptr;
		}

	//Listen Address list check(IPv4)
		if (Parameter.ListenAddress_IPv4->empty())
		{
			delete Parameter.ListenAddress_IPv4;
			Parameter.ListenAddress_IPv4 = nullptr;
		}

	//EDNS Client Subnet Address check(IPv6)
		if (Parameter.LocalMachineSubnet_IPv6->first.ss_family == 0)
		{
			delete Parameter.LocalMachineSubnet_IPv6;
			Parameter.LocalMachineSubnet_IPv6 = nullptr;
		}
		else if (!Parameter.EDNS_Label)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NOTICE, L"EDNS Client Subnet require EDNS Label", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
			Parameter.EDNS_Label = true;
		}

	//EDNS Client Subnet Address check(IPv4)
		if (Parameter.LocalMachineSubnet_IPv4->first.ss_family == 0)
		{
			delete Parameter.LocalMachineSubnet_IPv4;
			Parameter.LocalMachineSubnet_IPv4 = nullptr;
		}
		else if (!Parameter.EDNS_Label)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NOTICE, L"EDNS Client Subnet require EDNS Label", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
			Parameter.EDNS_Label = true;
		}

	//IPv6 multiple list exchange
		if (!Parameter.Target_Server_IPv6_Multiple->empty())
		{
		//Copy DNS Server Data when Main server data is empty.
			if (Parameter.Target_Server_Main_IPv6.AddressData.Storage.ss_family == 0)
			{
				Parameter.Target_Server_Main_IPv6 = Parameter.Target_Server_IPv6_Multiple->front();
				Parameter.Target_Server_IPv6_Multiple->erase(Parameter.Target_Server_IPv6_Multiple->begin());
			}

		//Copy DNS Server Data when Alternate server data is empty.
			if (!Parameter.Target_Server_IPv6_Multiple->empty() && Parameter.Target_Server_Alternate_IPv6.AddressData.Storage.ss_family == 0)
			{
				Parameter.Target_Server_Alternate_IPv6 = Parameter.Target_Server_IPv6_Multiple->front();
				Parameter.Target_Server_IPv6_Multiple->erase(Parameter.Target_Server_IPv6_Multiple->begin());
			}

		//Multiple DNS Server check
			if (Parameter.Target_Server_IPv6_Multiple->empty())
			{
				delete Parameter.Target_Server_IPv6_Multiple;
				Parameter.Target_Server_IPv6_Multiple = nullptr;
			}
			else {
				Parameter.AlternateMultipleRequest = true;
			}
		}
		else {
			delete Parameter.Target_Server_IPv6_Multiple;
			Parameter.Target_Server_IPv6_Multiple = nullptr;
		}

	//IPv4 multiple list exchange
		if (!Parameter.Target_Server_IPv4_Multiple->empty())
		{
		//Copy DNS Server Data when Main server data is empty.
			if (Parameter.Target_Server_Main_IPv4.AddressData.Storage.ss_family == 0)
			{
				Parameter.Target_Server_Main_IPv4 = Parameter.Target_Server_IPv4_Multiple->front();
				Parameter.Target_Server_IPv4_Multiple->erase(Parameter.Target_Server_IPv4_Multiple->begin());
			}

		//Copy DNS Server Data when Alternate server data is empty.
			if (!Parameter.Target_Server_IPv4_Multiple->empty() && Parameter.Target_Server_Alternate_IPv4.AddressData.Storage.ss_family == 0)
			{
				Parameter.Target_Server_Alternate_IPv4 = Parameter.Target_Server_IPv4_Multiple->front();
				Parameter.Target_Server_IPv4_Multiple->erase(Parameter.Target_Server_IPv4_Multiple->begin());
			}

		//Multiple DNS Server check
			if (Parameter.Target_Server_IPv4_Multiple->empty())
			{
				delete Parameter.Target_Server_IPv4_Multiple;
				Parameter.Target_Server_IPv4_Multiple = nullptr;
			}
			else {
				Parameter.AlternateMultipleRequest = true;
			}
		}
		else {
			delete Parameter.Target_Server_IPv4_Multiple;
			Parameter.Target_Server_IPv4_Multiple = nullptr;
		}
	}

//[DNS] block part 2
	if (IsFirstRead)
	{
	//Protocol IPv6 check
		if (Parameter.Target_Server_Main_IPv6.AddressData.Storage.ss_family == 0 && Parameter.RequestMode_Network == REQUEST_MODE_NETWORK::IPV6)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NOTICE, L"IPv6 Request Mode require IPv6 DNS server", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
			Parameter.RequestMode_Network = REQUEST_MODE_NETWORK::BOTH;
		}

	//Protocol IPv4 check
		if (Parameter.Target_Server_Main_IPv4.AddressData.Storage.ss_family == 0 && Parameter.RequestMode_Network == REQUEST_MODE_NETWORK::IPV4)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NOTICE, L"IPv4 Request Mode require IPv4 DNS server", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
			Parameter.RequestMode_Network = REQUEST_MODE_NETWORK::BOTH;
		}
	}

//Direct Request check
	if ((ParameterPointer->DirectRequest == REQUEST_MODE_DIRECT::IPV6 && Parameter.Target_Server_Main_IPv6.AddressData.Storage.ss_family == 0) || 
		(ParameterPointer->DirectRequest == REQUEST_MODE_DIRECT::IPV4 && Parameter.Target_Server_Main_IPv4.AddressData.Storage.ss_family == 0))
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Direct Request error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
		return false;
	}

//[Values] block
	if (IsFirstRead)
	{
	//Thread pool check
		if (Parameter.ThreadPoolMaxNum < Parameter.ThreadPoolBaseNum)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Thread pool number error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
			return false;
		}

	//EDNS Payload Size check
		if (Parameter.EDNS_PayloadSize < DNS_PACKET_MAXSIZE_TRADITIONAL)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NOTICE, L"EDNS Payload Size must longer than traditional DNS packet minimum supported size(512 bytes)", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
			Parameter.EDNS_PayloadSize = DNS_PACKET_MAXSIZE_TRADITIONAL;
		}
		else if (Parameter.EDNS_PayloadSize > EDNS_PACKET_MAXSIZE)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NOTICE, L"EDNS Payload Size is too large", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
			Parameter.EDNS_PayloadSize = EDNS_PACKET_MAXSIZE;
		}
	}

	//Hop Limits Fluctuations check
#if defined(ENABLE_PCAP)
	if (ParameterPointer->HopLimitsFluctuation > 0)
	{
	//Hop Limits and TTL must between 1 and 255.
		if (
		//IPv6
			(ParameterPointer->Target_Server_Main_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_Assign > 0 && 
			(static_cast<size_t>(ParameterPointer->Target_Server_Main_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_Assign) + static_cast<size_t>(ParameterPointer->HopLimitsFluctuation) > UINT8_MAX || 
			static_cast<ssize_t>(ParameterPointer->Target_Server_Main_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_Assign) < static_cast<ssize_t>(ParameterPointer->HopLimitsFluctuation) + 1)) || 
			(ParameterPointer->Target_Server_Alternate_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_Assign > 0 && 
			(static_cast<size_t>(ParameterPointer->Target_Server_Alternate_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_Assign) + static_cast<size_t>(ParameterPointer->HopLimitsFluctuation) > UINT8_MAX || 
			static_cast<ssize_t>(ParameterPointer->Target_Server_Alternate_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_Assign) < static_cast<ssize_t>(ParameterPointer->HopLimitsFluctuation) + 1)) || 
		//IPv4
			(ParameterPointer->Target_Server_Main_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_Assign > 0 && 
			(static_cast<size_t>(ParameterPointer->Target_Server_Main_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_Assign) + static_cast<size_t>(ParameterPointer->HopLimitsFluctuation) > UINT8_MAX || 
			static_cast<ssize_t>(ParameterPointer->Target_Server_Main_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_Assign) < static_cast<ssize_t>(ParameterPointer->HopLimitsFluctuation) + 1)) || 
			(ParameterPointer->Target_Server_Alternate_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_Assign > 0 && 
			(static_cast<size_t>(ParameterPointer->Target_Server_Alternate_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_Assign) + static_cast<size_t>(ParameterPointer->HopLimitsFluctuation) > UINT8_MAX || 
			static_cast<ssize_t>(ParameterPointer->Target_Server_Alternate_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_Assign) < static_cast<ssize_t>(ParameterPointer->HopLimitsFluctuation) + 1)))
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Hop Limits Fluctuation error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
			return false;
		}

	//Hop Limits and TTL check in multiple list(IPv6)
		if (Parameter.Target_Server_IPv6_Multiple != nullptr)
		{
			for (const auto &DNSServerDataIter:*Parameter.Target_Server_IPv6_Multiple)
			{
				if (DNSServerDataIter.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_Assign > 0 && 
					(static_cast<size_t>(DNSServerDataIter.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_Assign) + static_cast<size_t>(ParameterPointer->HopLimitsFluctuation) > UINT8_MAX || 
					static_cast<ssize_t>(DNSServerDataIter.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_Assign) < static_cast<ssize_t>(ParameterPointer->HopLimitsFluctuation) + 1))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Hop Limits Fluctuation error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					return false;
				}
			}
		}

	//Hop Limits and TTL check in multiple list(IPv4)
		if (Parameter.Target_Server_IPv4_Multiple != nullptr)
		{
			for (const auto &DNSServerDataIter:*Parameter.Target_Server_IPv4_Multiple)
			{
				if (DNSServerDataIter.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_Assign > 0 && 
					(static_cast<size_t>(DNSServerDataIter.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_Assign) + static_cast<size_t>(ParameterPointer->HopLimitsFluctuation) > UINT8_MAX || 
					static_cast<ssize_t>(DNSServerDataIter.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_Assign) < static_cast<ssize_t>(ParameterPointer->HopLimitsFluctuation) + 1))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Hop Limits Fluctuation error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					return false;
				}
			}
		}
	}
#endif

	//Multiple Request Times check
	if (ParameterPointer->MultipleRequestTimes == 0)
		++ParameterPointer->MultipleRequestTimes;
	if ((Parameter.Target_Server_IPv4_Multiple != nullptr && 
		(Parameter.Target_Server_IPv4_Multiple->size() + 2U) * ParameterPointer->MultipleRequestTimes > MULTIPLE_REQUEST_MAXNUM) || 
		(Parameter.Target_Server_IPv4_Multiple == nullptr && 
		ParameterPointer->MultipleRequestTimes * 2U > MULTIPLE_REQUEST_MAXNUM))
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv4 total request number error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
		return false;
	}
	else if ((Parameter.Target_Server_IPv6_Multiple != nullptr && 
		(Parameter.Target_Server_IPv6_Multiple->size() + 2U) * ParameterPointer->MultipleRequestTimes > MULTIPLE_REQUEST_MAXNUM) || 
		(Parameter.Target_Server_IPv6_Multiple == nullptr && 
		ParameterPointer->MultipleRequestTimes * 2U > MULTIPLE_REQUEST_MAXNUM))
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv6 total request number error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
		return false;
	}

	if (IsFirstRead)
	{
	//Alternate Multiple request check
		if (Parameter.AlternateMultipleRequest && 
			Parameter.Target_Server_Alternate_IPv4.AddressData.Storage.ss_family == 0 && Parameter.Target_Server_Alternate_IPv6.AddressData.Storage.ss_family == 0
		#if defined(ENABLE_LIBSODIUM)
			&& Parameter.IsDNSCurve && DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.AddressData.Storage.ss_family == 0
			&& DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.AddressData.Storage.ss_family == 0
		#endif
			)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Alternate Multiple request error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
			return false;
		}

//[Switches] block
	//EDNS Label check
		if (Parameter.EDNS_Label && 
			!Parameter.EDNS_Switch_Local && 
			!Parameter.EDNS_Switch_SOCKS && 
			!Parameter.EDNS_Switch_HTTP_CONNECT && 
			!Parameter.EDNS_Switch_Direct && 
		#if defined(ENABLE_LIBSODIUM)
			!Parameter.EDNS_Switch_DNSCurve && 
		#endif
			!Parameter.EDNS_Switch_TCP && 
			!Parameter.EDNS_Switch_UDP)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NOTICE, L"EDNS Label require at least of one process", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
			Parameter.EDNS_Label = false;
		}

	//DNSSEC Force Validation check
		if (Parameter.DNSSEC_ForceRecord && (!Parameter.EDNS_Label || !Parameter.DNSSEC_Request))
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NOTICE, L"DNSSEC Force Record require EDNS Label and DNSSEC Request", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
			Parameter.EDNS_Label = true;
			Parameter.DNSSEC_Request = true;
		}

	//EDNS Label check
		if (!Parameter.EDNS_Label)
		{
		//EDNS Client Subnet Relay check
			if (Parameter.EDNS_ClientSubnet_Relay)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NOTICE, L"EDNS Client Subnet require EDNS Label", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
				Parameter.EDNS_Label = true;
			}

		//DNSSEC check
			if (Parameter.DNSSEC_Request)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NOTICE, L"DNSSEC Request require EDNS Label", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
				Parameter.EDNS_Label = true;
			}
		}
		else {
		//Compression Pointer Mutation check
			if (Parameter.CompressionPointerMutation)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NOTICE, L"EDNS Label must be shutdown when Compression Pointer Mutation is enabled", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
				Parameter.CompressionPointerMutation = false;
			}
		}
	}

#if defined(ENABLE_PCAP)
	//TCP Mode option check
	if (ParameterPointer->PacketCheck_TCP && !Parameter.IsPcapCapture)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NOTICE, L"TCP Data Filter require Pcap Cpature", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
		ParameterPointer->PacketCheck_TCP = false;
	}
#endif

//[Data] block
	if (IsFirstRead)
	{
	//Domain Test domain name check
	#if defined(ENABLE_PCAP)
		if (CheckEmptyBuffer(Parameter.DomainTest_Data, DOMAIN_MAXSIZE))
		{
			delete[] Parameter.DomainTest_Data;
			Parameter.DomainTest_Data = nullptr;
		}
	#endif

	//Default Local DNS server name
		if (Parameter.Local_FQDN_Length == 0)
		{
			Parameter.Local_FQDN_Length = StringToPacketQuery(reinterpret_cast<const uint8_t *>(DEFAULT_LOCAL_SERVER_NAME), Parameter.Local_FQDN_Response);
			*Parameter.Local_FQDN_String = DEFAULT_LOCAL_SERVER_NAME;
		}

	//Set Local DNS server PTR response.
	//LLMNR protocol in macOS is powered by mDNS with DNS PTR records.
	#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
		if (Parameter.LocalServer_Length == 0)
		{
		//Make DNS PTR response packet.
			reinterpret_cast<dns_record_ptr *>(Parameter.LocalServer_Response)->Pointer = htons(DNS_POINTER_QUERY);
			reinterpret_cast<dns_record_ptr *>(Parameter.LocalServer_Response)->Classes = htons(DNS_CLASS_INTERNET);
			if (Parameter.HostsDefaultTTL > 0)
				reinterpret_cast<dns_record_ptr *>(Parameter.LocalServer_Response)->TTL = htonl(Parameter.HostsDefaultTTL);
			else 
				reinterpret_cast<dns_record_ptr *>(Parameter.LocalServer_Response)->TTL = htonl(DEFAULT_HOSTS_TTL);
			reinterpret_cast<dns_record_ptr *>(Parameter.LocalServer_Response)->Type = htons(DNS_TYPE_PTR);
			reinterpret_cast<dns_record_ptr *>(Parameter.LocalServer_Response)->Length = htons(static_cast<uint16_t>(Parameter.Local_FQDN_Length));
			Parameter.LocalServer_Length += sizeof(dns_record_ptr);

		//Copy to global buffer.
			memcpy_s(Parameter.LocalServer_Response + Parameter.LocalServer_Length, NORMAL_PACKET_MAXSIZE - Parameter.LocalServer_Length, Parameter.Local_FQDN_Response, Parameter.Local_FQDN_Length);
			Parameter.LocalServer_Length += Parameter.Local_FQDN_Length;
		}
	#endif
	}

//[Proxy] block
//SOCKS Proxy check
	if (Parameter.SOCKS_Proxy)
	{
		if (IsFirstRead)
		{
		//SOCKS IPv4 and IPv6 addresses check
			if (Parameter.SOCKS_Address_IPv6.Storage.ss_family == 0 && Parameter.SOCKS_Address_IPv4.Storage.ss_family == 0)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::SOCKS, L"SOCKS address error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
				return false;
			}
			else if ((Parameter.SOCKS_Address_IPv6.Storage.ss_family == 0 && Parameter.SOCKS_Protocol_Network == REQUEST_MODE_NETWORK::IPV6) || 
				(Parameter.SOCKS_Address_IPv4.Storage.ss_family == 0 && Parameter.SOCKS_Protocol_Network == REQUEST_MODE_NETWORK::IPV4))
			{
				Parameter.SOCKS_Protocol_Network = REQUEST_MODE_NETWORK::BOTH;
			}

		//Only SOCKS version 5 support client authentication.
			if (Parameter.SOCKS_Version != SOCKS_VERSION_5)
			{
				delete Parameter.SOCKS_Password;
				Parameter.SOCKS_Password = nullptr;
			}

		//SOCKS UDP support check
			if ((Parameter.SOCKS_Protocol_Transport == REQUEST_MODE_TRANSPORT::FORCE_UDP || Parameter.SOCKS_Protocol_Transport == REQUEST_MODE_TRANSPORT::UDP) && 
				(Parameter.SOCKS_Version == SOCKS_VERSION_4 || Parameter.SOCKS_Version == SOCKS_VERSION_CONFIG_4A))
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::SOCKS, L"SOCKS version 4 and 4a are not support UDP relay", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
				Parameter.SOCKS_Protocol_Transport = REQUEST_MODE_TRANSPORT::TCP;
			}

		//SOCKS UDP no handshake check
			if (Parameter.SOCKS_Protocol_Transport != REQUEST_MODE_TRANSPORT::FORCE_UDP && Parameter.SOCKS_Protocol_Transport != REQUEST_MODE_TRANSPORT::UDP)
				Parameter.SOCKS_UDP_NoHandshake = false;
		}

	//SOCKS Target Server check
		if (ParameterPointer->SOCKS_TargetServer.Storage.ss_family == 0 && ParameterPointer->SOCKS_TargetDomain->empty())
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::SOCKS, L"SOCKS target server error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
			return false;
		}

	//SOCKS IPv6 support check
		if (ParameterPointer->SOCKS_TargetServer.Storage.ss_family != AF_INET && 
			(Parameter.SOCKS_Version == SOCKS_VERSION_4 || (Parameter.SOCKS_Version == SOCKS_VERSION_CONFIG_4A && ParameterPointer->SOCKS_TargetDomain->empty())))
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::SOCKS, L"SOCKS version 4 and 4a are not support IPv6 target server", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
			return false;
		}

	//SOCKS domain support check
		if (!ParameterPointer->SOCKS_TargetDomain->empty() && Parameter.SOCKS_Version == SOCKS_VERSION_4)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::SOCKS, L"SOCKS version 4 is not support domain target server", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
			return false;
		}

	//SOCKS username and password check
		if (Parameter.SOCKS_Version == SOCKS_VERSION_5 && Parameter.SOCKS_Username->empty() && !Parameter.SOCKS_Password->empty())
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::SOCKS, L"SOCKS username and password error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
			return false;
		}
	}
	else if (IsFirstRead)
	{
		delete Parameter.SOCKS_TargetDomain;
		delete Parameter.SOCKS_Username;
		delete Parameter.SOCKS_Password;

		Parameter.SOCKS_TargetDomain = nullptr;
		Parameter.SOCKS_Username = nullptr;
		Parameter.SOCKS_Password = nullptr;
	}

//HTTP CONNECT Proxy check
	if (Parameter.HTTP_CONNECT_Proxy)
	{
		if (IsFirstRead)
		{
		//HTTP CONNECT IPv4 and IPv6 address check
			if (Parameter.HTTP_CONNECT_Address_IPv6.Storage.ss_family == 0 && Parameter.HTTP_CONNECT_Address_IPv4.Storage.ss_family == 0)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HTTP_CONNECT, L"HTTP CONNECT address error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
				return false;
			}
			else if ((Parameter.HTTP_CONNECT_Address_IPv6.Storage.ss_family == 0 && Parameter.HTTP_CONNECT_Protocol == REQUEST_MODE_NETWORK::IPV6) || 
				(Parameter.HTTP_CONNECT_Address_IPv4.Storage.ss_family == 0 && Parameter.HTTP_CONNECT_Protocol == REQUEST_MODE_NETWORK::IPV4))
			{
				Parameter.HTTP_CONNECT_Protocol = REQUEST_MODE_NETWORK::BOTH;
			}

		//HTTP CONNECT version check
			if (Parameter.HTTP_CONNECT_Version == HTTP_VERSION_SELECTION::VERSION_AUTO)
				Parameter.HTTP_CONNECT_Version = HTTP_VERSION_SELECTION::VERSION_1;
		}

	//HTTP CONNECT Target Server check
		if (ParameterPointer->HTTP_CONNECT_TargetDomain != nullptr && (ParameterPointer->HTTP_CONNECT_TargetDomain->empty() || 
			(Parameter.HTTP_CONNECT_Version == HTTP_VERSION_SELECTION::VERSION_2 && ParameterPointer->HTTP_CONNECT_TargetDomain->length() >= HTTP_2_FREAM_MAXSIZE)))
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HTTP_CONNECT, L"HTTP CONNECT target server error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
			return false;
		}

	//HTTP Header Field check
		if (ParameterPointer->HTTP_CONNECT_HeaderField != nullptr && !ParameterPointer->HTTP_CONNECT_HeaderField->empty())
		{
		//HTTP Header Field format is "Name: Value".
			if (ParameterPointer->HTTP_CONNECT_HeaderField->size() % 2U != 0)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HTTP_CONNECT, L"HTTP CONNECT header field data error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
				return false;
			}
			else {
				auto IsLiteralFlag = true;
				for (auto &StringIter:*ParameterPointer->HTTP_CONNECT_HeaderField)
				{
				//HTTP version 1.x is not allowed to set ":" in the first byte in header Names field.
					if (Parameter.HTTP_CONNECT_Version == HTTP_VERSION_SELECTION::VERSION_1)
					{
						if (IsLiteralFlag && StringIter.compare(0, strlen(":"), (":")) == 0)
						{
							PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HTTP_CONNECT, L"HTTP CONNECT header field data error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
							return false;
						}
					}
				//HTTP version 2 require all Names are lower case and all header field must no longer than frame maximum size.
					else if (Parameter.HTTP_CONNECT_Version == HTTP_VERSION_SELECTION::VERSION_2)
					{
						if (StringIter.length() >= HTTP_2_FREAM_MAXSIZE)
						{
							PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HTTP_CONNECT, L"HTTP CONNECT header field data error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
							return false;
						}
						else if (IsLiteralFlag)
						{
							CaseConvert(StringIter, false);
						}
					}
					else {
						PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HTTP_CONNECT, L"HTTP CONNECT header field data error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
						return false;
					}

					IsLiteralFlag = !IsLiteralFlag;
				}
			}
		}

	//HTTP CONNECT TLS check
	#if defined(ENABLE_TLS)
		if (IsFirstRead)
		{
			if (!Parameter.HTTP_CONNECT_TLS_Handshake)
			{
				delete Parameter.HTTP_CONNECT_TLS_SNI;
				delete Parameter.MBS_HTTP_CONNECT_TLS_SNI;
			#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				delete Parameter.HTTP_CONNECT_TLS_AddressString_IPv6;
				delete Parameter.HTTP_CONNECT_TLS_AddressString_IPv4;
			#endif
				Parameter.HTTP_CONNECT_TLS_SNI = nullptr;
				Parameter.MBS_HTTP_CONNECT_TLS_SNI = nullptr;
			#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				Parameter.HTTP_CONNECT_TLS_AddressString_IPv6 = nullptr;
				Parameter.HTTP_CONNECT_TLS_AddressString_IPv4 = nullptr;
			#endif
			}
			else {
			#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			//HTTP CONNECT IPv4/IPv6 address check
				if (Parameter.HTTP_CONNECT_TLS_AddressString_IPv6->empty() && Parameter.HTTP_CONNECT_TLS_AddressString_IPv4->empty())
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HTTP_CONNECT, L"HTTP CONNECT address error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					return false;
				}

			//OpenSSL libraries initialization
				if (!GlobalRunningStatus.IsInitialized_OpenSSL)
				{
					OpenSSL_Library_Init(true);
					GlobalRunningStatus.IsInitialized_OpenSSL = true;
				}
			#endif

			//Mark TLS Server Name Indication/SNI.
				if (Parameter.MBS_HTTP_CONNECT_TLS_SNI != nullptr && !Parameter.MBS_HTTP_CONNECT_TLS_SNI->empty())
				{
					if (!MBS_To_WCS_String(reinterpret_cast<const uint8_t *>(Parameter.MBS_HTTP_CONNECT_TLS_SNI->c_str()), Parameter.MBS_HTTP_CONNECT_TLS_SNI->length(), *Parameter.HTTP_CONNECT_TLS_SNI))
					{
						PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"Convert multiple byte or wide char string error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
						delete Parameter.HTTP_CONNECT_TLS_SNI;
						delete Parameter.MBS_HTTP_CONNECT_TLS_SNI;
						Parameter.HTTP_CONNECT_TLS_SNI = nullptr;
						Parameter.MBS_HTTP_CONNECT_TLS_SNI = nullptr;
					}
				}
				else {
					delete Parameter.HTTP_CONNECT_TLS_SNI;
					delete Parameter.MBS_HTTP_CONNECT_TLS_SNI;
					Parameter.HTTP_CONNECT_TLS_SNI = nullptr;
					Parameter.MBS_HTTP_CONNECT_TLS_SNI = nullptr;
				}

			//TLS ALPN extension check
			#if !defined(PLATFORM_WIN_XP)
				if (!Parameter.HTTP_CONNECT_TLS_ALPN && Parameter.HTTP_CONNECT_Version == HTTP_VERSION_SELECTION::VERSION_2)
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NOTICE, L"HTTP version 2 require TLS ALPN extension", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					Parameter.HTTP_CONNECT_TLS_ALPN = true;
				}
			#endif
			}
		}
		else if (Parameter.HTTP_CONNECT_TLS_Handshake)
		{
		//TLS Server Name Indication/SNI check
			if ((Parameter.HTTP_CONNECT_TLS_SNI == nullptr || Parameter.HTTP_CONNECT_TLS_SNI->empty() || 
				Parameter.MBS_HTTP_CONNECT_TLS_SNI == nullptr || Parameter.MBS_HTTP_CONNECT_TLS_SNI->empty()) && 
				Parameter.HTTP_CONNECT_Version == HTTP_VERSION_SELECTION::VERSION_2)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HTTP_CONNECT, L"HTTP version 2 require TLS SNI extension", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
				return false;
			}

		//TLS version check
			if ((ParameterPointer->HTTP_CONNECT_TLS_Version == TLS_VERSION_SELECTION::VERSION_AUTO || 
				ParameterPointer->HTTP_CONNECT_TLS_Version == TLS_VERSION_SELECTION::VERSION_1_0 || 
				ParameterPointer->HTTP_CONNECT_TLS_Version == TLS_VERSION_SELECTION::VERSION_1_1) && 
				Parameter.HTTP_CONNECT_Version == HTTP_VERSION_SELECTION::VERSION_2)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NOTICE, L"HTTP version 2 require TLS 1.2 and above", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
				ParameterPointer->HTTP_CONNECT_TLS_Version = TLS_VERSION_SELECTION::VERSION_1_2;
			}
		}
	#endif
	}
	else if (IsFirstRead)
	{
		delete Parameter.HTTP_CONNECT_TargetDomain;
		delete Parameter.HTTP_CONNECT_HeaderField;
		delete Parameter.HTTP_CONNECT_ProxyAuthorization;
	#if defined(ENABLE_TLS)
		delete Parameter.HTTP_CONNECT_TLS_SNI;
		delete Parameter.MBS_HTTP_CONNECT_TLS_SNI;
		#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			delete Parameter.HTTP_CONNECT_TLS_AddressString_IPv6;
			delete Parameter.HTTP_CONNECT_TLS_AddressString_IPv4;
		#endif
	#endif

		Parameter.HTTP_CONNECT_TargetDomain = nullptr;
		Parameter.HTTP_CONNECT_HeaderField = nullptr;
		Parameter.HTTP_CONNECT_ProxyAuthorization = nullptr;
	#if defined(ENABLE_TLS)
		Parameter.HTTP_CONNECT_TLS_SNI = nullptr;
		Parameter.MBS_HTTP_CONNECT_TLS_SNI = nullptr;
		#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			Parameter.HTTP_CONNECT_TLS_AddressString_IPv6 = nullptr;
			Parameter.HTTP_CONNECT_TLS_AddressString_IPv4 = nullptr;
		#endif
	#endif
	}

//[DNSCurve] block
#if defined(ENABLE_LIBSODIUM)
	if (Parameter.IsDNSCurve)
	{
	//DNSCurve Protocol check
		if (IsFirstRead)
		{
		//DNSCurve targets check
			if (DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.AddressData.Storage.ss_family == 0 && DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.AddressData.Storage.ss_family != 0)
			{
				DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6 = DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6;
				sodium_memzero(&DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6, sizeof(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6));
			}
			if (DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.AddressData.Storage.ss_family == 0 && DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.AddressData.Storage.ss_family != 0)
			{
				DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4 = DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4;
				sodium_memzero(&DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4, sizeof(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4));
			}

		//IPv6
			if (Parameter.IsDNSCurve && DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.AddressData.Storage.ss_family == 0 && 
				DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_NETWORK::IPV6)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NOTICE, L"IPv6 Request Mode require IPv6 DNS server", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
				DNSCurveParameter.DNSCurveProtocol_Network = REQUEST_MODE_NETWORK::BOTH;
			}

		//IPv4
			if (Parameter.IsDNSCurve && DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.AddressData.Storage.ss_family == 0 && 
				DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_NETWORK::IPV4)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NOTICE, L"IPv4 Request Mode require IPv4 DNS server", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
				DNSCurveParameter.DNSCurveProtocol_Network = REQUEST_MODE_NETWORK::BOTH;
			}
		}

	//Client keys check
		if (DNSCurveParameter.IsEncryption && !DNSCurveParameter.IsClientEphemeralKey && 
			DNSCurveParameterPointer->Client_PublicKey != nullptr && DNSCurveParameterPointer->Client_SecretKey != nullptr)
		{
			if (!CheckEmptyBuffer(DNSCurveParameterPointer->Client_PublicKey, crypto_box_PUBLICKEYBYTES) && 
				!CheckEmptyBuffer(DNSCurveParameterPointer->Client_SecretKey, crypto_box_SECRETKEYBYTES))
			{
				if (!DNSCurveVerifyKeypair(DNSCurveParameterPointer->Client_PublicKey, DNSCurveParameterPointer->Client_SecretKey))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::DNSCURVE, L"Client keypair error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);

					sodium_memzero(DNSCurveParameterPointer->Client_PublicKey, crypto_box_PUBLICKEYBYTES);
					sodium_memzero(DNSCurveParameterPointer->Client_SecretKey, crypto_box_SECRETKEYBYTES);
					if (crypto_box_keypair(
							DNSCurveParameterPointer->Client_PublicKey, 
							DNSCurveParameterPointer->Client_SecretKey) != 0)
					{
						PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::DNSCURVE, L"Client keypair error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
						return false;
					}
				}
			}
			else {
				sodium_memzero(DNSCurveParameterPointer->Client_PublicKey, crypto_box_PUBLICKEYBYTES);
				sodium_memzero(DNSCurveParameterPointer->Client_SecretKey, crypto_box_SECRETKEYBYTES);
				if (crypto_box_keypair(
						DNSCurveParameterPointer->Client_PublicKey, 
						DNSCurveParameterPointer->Client_SecretKey) != 0)
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::DNSCURVE, L"Client keypair error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					return false;
				}
			}
		}
		else if (IsFirstRead)
		{
			delete[] DNSCurveParameter.Client_PublicKey;
			sodium_free(DNSCurveParameter.Client_SecretKey);
			DNSCurveParameter.Client_PublicKey = nullptr;
			DNSCurveParameter.Client_SecretKey = nullptr;
		}

		if (IsFirstRead)
		{
		//Check repeat items.
			if ((DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.AddressData.Storage.ss_family == 0 && DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.AddressData.Storage.ss_family == 0) || 
				(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.AddressData.Storage.ss_family != 0 && 
				DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.AddressData.Storage.ss_family != 0 && 
				memcmp(&DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.AddressData.IPv6.sin6_addr, &DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.AddressData.IPv6.sin6_addr, sizeof(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.AddressData.IPv6.sin6_addr)) == 0) || 
				(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.AddressData.Storage.ss_family != 0 && 
				DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.AddressData.Storage.ss_family != 0 && 
				DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.AddressData.IPv4.sin_addr.s_addr == DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.AddressData.IPv4.sin_addr.s_addr))
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"DNSCurve target error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
				return false;
			}

		//Eencryption options check
			if (DNSCurveParameter.IsEncryptionOnly && !DNSCurveParameter.IsEncryption)
			{
				DNSCurveParameter.IsEncryption = true;
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"DNSCurve encryption options error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
			}
		}

	//Main(IPv6)
		if (DNSCurveParameter.IsEncryption && DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.AddressData.Storage.ss_family != 0)
		{
		//Empty Server Fingerprint
			if (CheckEmptyBuffer(DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES))
			{
			//Encryption Only mode check
				if (DNSCurveParameter.IsEncryptionOnly && 
					CheckEmptyBuffer(DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"DNSCurve Encryption Only mode error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					return false;
				}

			//Empty Provider Name
				if (CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ProviderName, DOMAIN_MAXSIZE))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"DNSCurve empty Provider Name error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					return false;
				}

			//Empty Public Key
				if (CheckEmptyBuffer(DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"DNSCurve empty Public Key error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					return false;
				}
			}
			else if (!DNSCurveParameter.IsClientEphemeralKey && 
				crypto_box_beforenm(
					DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv6.PrecomputationKey, 
					DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv6.ServerFingerprint, 
					DNSCurveParameterPointer->Client_SecretKey) != 0)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::DNSCURVE, L"Key calculating error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
				return false;
			}
		}
		else if (IsFirstRead)
		{
			delete[] DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ProviderName;
			sodium_free(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.PrecomputationKey);
			delete[] DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ServerPublicKey;
			delete[] DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber;
			delete[] DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.SendMagicNumber;

			DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ProviderName = nullptr;
			DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.PrecomputationKey = nullptr;
			DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ServerPublicKey = nullptr;
			DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber = nullptr;
			DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.SendMagicNumber = nullptr;
		}

	//Main(IPv4)
		if (DNSCurveParameter.IsEncryption && DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.AddressData.Storage.ss_family != 0)
		{
		//Empty Server Fingerprint
			if (CheckEmptyBuffer(DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES))
			{
			//Encryption Only mode check
				if (DNSCurveParameter.IsEncryptionOnly && 
					CheckEmptyBuffer(DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"DNSCurve Encryption Only mode error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					return false;
				}

			//Empty Provider Name
				if (CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ProviderName, DOMAIN_MAXSIZE))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"DNSCurve empty Provider Name error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					return false;
				}

			//Empty Public Key
				if (CheckEmptyBuffer(DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"DNSCurve empty Public Key error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					return false;
				}
			}
			else if (!DNSCurveParameter.IsClientEphemeralKey && 
				crypto_box_beforenm(
					DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv4.PrecomputationKey, 
					DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv4.ServerFingerprint, 
					DNSCurveParameterPointer->Client_SecretKey) != 0)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::DNSCURVE, L"Key calculating error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
				return false;
			}
		}
		else if (IsFirstRead)
		{
			delete[] DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ProviderName;
			sodium_free(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.PrecomputationKey);
			delete[] DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ServerPublicKey;
			delete[] DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber;
			delete[] DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.SendMagicNumber;

			DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ProviderName = nullptr;
			DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.PrecomputationKey = nullptr;
			DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ServerPublicKey = nullptr;
			DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber = nullptr;
			DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.SendMagicNumber = nullptr;
		}

	//Alternate(IPv6)
		if (DNSCurveParameter.IsEncryption && DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.AddressData.Storage.ss_family != 0)
		{
		//Empty Server Fingerprint
			if (CheckEmptyBuffer(DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES))
			{
			//Encryption Only mode check
				if (DNSCurveParameter.IsEncryptionOnly && 
					CheckEmptyBuffer(DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"DNSCurve Encryption Only mode error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					return false;
				}

			//Empty Provider Name
				if (CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ProviderName, DOMAIN_MAXSIZE))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"DNSCurve empty Provider Name error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					return false;
				}

			//Empty Public Key
				if (CheckEmptyBuffer(DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"DNSCurve empty Public Key error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					return false;
				}
			}
			else if (!DNSCurveParameter.IsClientEphemeralKey && 
				crypto_box_beforenm(
					DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey, 
					DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint, 
					DNSCurveParameterPointer->Client_SecretKey) != 0)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::DNSCURVE, L"Key calculating error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
				return false;
			}
		}
		else if (IsFirstRead)
		{
			delete[] DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ProviderName;
			sodium_free(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey);
			delete[] DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey;
			delete[] DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber;
			delete[] DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber;

			DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ProviderName = nullptr;
			DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey = nullptr;
			DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey = nullptr;
			DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber = nullptr;
			DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber = nullptr;
		}

	//Alternate(IPv4)
		if (DNSCurveParameter.IsEncryption && DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.AddressData.Storage.ss_family != 0)
		{
		//Empty Server Fingerprint
			if (CheckEmptyBuffer(DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES))
			{
			//Encryption Only mode check
				if (DNSCurveParameter.IsEncryptionOnly && 
					CheckEmptyBuffer(DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"DNSCurve Encryption Only mode error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					return false;
				}

			//Empty Provider Name
				if (CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ProviderName, DOMAIN_MAXSIZE))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"DNSCurve empty Provider Name error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					return false;
				}

			//Empty Public Key
				if (CheckEmptyBuffer(DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"DNSCurve empty Public Key error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					return false;
				}
			}
			else if (!DNSCurveParameter.IsClientEphemeralKey && 
				crypto_box_beforenm(
					DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey, 
					DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint, 
					DNSCurveParameterPointer->Client_SecretKey) != 0)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::DNSCURVE, L"Key calculating error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
				return false;
			}
		}
		else if (IsFirstRead)
		{
			delete[] DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ProviderName;
			sodium_free(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey);
			delete[] DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey;
			delete[] DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber;
			delete[] DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber;

			DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ProviderName = nullptr;
			DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey = nullptr;
			DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey = nullptr;
			DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber = nullptr;
			DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber = nullptr;
		}

	//DNSCurve Encryption mode check
		if (DNSCurveParameter.IsEncryption)
		{
			if (IsFirstRead)
			{
			//DNSCurve PayloadSize check
				if (DNSCurveParameter.DNSCurvePayloadSize % DNSCURVE_PAYLOAD_MULTIPLE_TIME != 0)
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::DNSCURVE, L"DNSCurve Payload Size must remain a multiple of 64 bytes", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					return false;
				}
				else if (DNSCurveParameter.DNSCurvePayloadSize < DNS_PACKET_MAXSIZE_TRADITIONAL)
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NOTICE, L"DNSCurve Payload Size must longer than traditional DNS packet minimum supported size(512 bytes)", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					DNSCurveParameter.DNSCurvePayloadSize = DNS_PACKET_MAXSIZE_TRADITIONAL;
				}
				else if (DNSCurveParameter.DNSCurvePayloadSize >= NORMAL_PACKET_MAXSIZE - DNSCRYPT_HEADER_RESERVED_LEN)
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NOTICE, L"DNSCurve Payload Size is too large", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					DNSCurveParameter.DNSCurvePayloadSize = EDNS_PACKET_MINSIZE;
				}
			}

		//Main(IPv6)
			if (DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.AddressData.Storage.ss_family != 0 && 
				CheckEmptyBuffer(DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
					memcpy_s(DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCRYPT_RECEIVE_MAGIC, DNSCURVE_MAGIC_QUERY_LEN);

		//Main(IPv4)
			if (DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.AddressData.Storage.ss_family != 0 && 
				CheckEmptyBuffer(DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
					memcpy_s(DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCRYPT_RECEIVE_MAGIC, DNSCURVE_MAGIC_QUERY_LEN);

		//Alternate(IPv6)
			if (DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.AddressData.Storage.ss_family != 0 && 
				CheckEmptyBuffer(DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
					memcpy_s(DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCRYPT_RECEIVE_MAGIC, DNSCURVE_MAGIC_QUERY_LEN);

		//Alternate(IPv4)
			if (DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.AddressData.Storage.ss_family != 0 && 
				CheckEmptyBuffer(DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
					memcpy_s(DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCRYPT_RECEIVE_MAGIC, DNSCURVE_MAGIC_QUERY_LEN);

		//DNSCurve keys recheck time
			if (DNSCurveParameterPointer->KeyRecheckTime == 0)
				DNSCurveParameterPointer->KeyRecheckTime = DEFAULT_DNSCURVE_RECHECK_TIME * SECOND_TO_MILLISECOND;
		}
	}
	else if (IsFirstRead)
	{
	//[DNSCurve Addresses] block
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ProviderName;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ProviderName;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ProviderName;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ProviderName;
	//[DNSCurve Keys] block
		delete[] DNSCurveParameter.Client_PublicKey;
		sodium_free(DNSCurveParameter.Client_SecretKey);
		sodium_free(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.PrecomputationKey);
		sodium_free(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey);
		sodium_free(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.PrecomputationKey);
		sodium_free(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey);
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ServerPublicKey;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ServerPublicKey;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ServerFingerprint;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ServerFingerprint;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint;
	//[DNSCurve Magic Number] block
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.SendMagicNumber;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.SendMagicNumber;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber;

		DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ProviderName = nullptr, DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ProviderName = nullptr, DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ProviderName = nullptr, DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ProviderName = nullptr;
		DNSCurveParameter.Client_PublicKey = nullptr, DNSCurveParameter.Client_SecretKey = nullptr;
		DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.PrecomputationKey = nullptr, DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey = nullptr, DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.PrecomputationKey = nullptr, DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey = nullptr;
		DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ServerPublicKey = nullptr, DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey = nullptr, DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ServerPublicKey = nullptr, DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey = nullptr;
		DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ServerFingerprint = nullptr, DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint = nullptr, DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ServerFingerprint = nullptr, DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint = nullptr;
		DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.SendMagicNumber = nullptr, DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber = nullptr, DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.SendMagicNumber = nullptr, DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber = nullptr;
		DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber = nullptr, DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber = nullptr, DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber = nullptr, DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber = nullptr;
	}
#endif

	return true;
}

//Convert service name to port
uint16_t ServiceNameToBinary(
	const uint8_t * const OriginalBuffer)
{
	std::string Buffer(reinterpret_cast<const char *>(OriginalBuffer));
	CaseConvert(Buffer, true);

//Server name
	if (Buffer == ("TCPMUX"))
		return htons(IPPORT_TCPMUX);
	else if (Buffer == ("ECHO"))
		return htons(IPPORT_ECHO);
	else if (Buffer == ("DISCARD"))
		return htons(IPPORT_DISCARD);
	else if (Buffer == ("SYSTAT"))
		return htons(IPPORT_SYSTAT);
	else if (Buffer == ("DAYTIME"))
		return htons(IPPORT_DAYTIME);
	else if (Buffer == ("NETSTAT"))
		return htons(IPPORT_NETSTAT);
	else if (Buffer == ("QOTD"))
		return htons(IPPORT_QOTD);
	else if (Buffer == ("MSP"))
		return htons(IPPORT_MSP);
	else if (Buffer == ("CHARGEN"))
		return htons(IPPORT_CHARGEN);
	else if (Buffer == ("FTPDATA"))
		return htons(IPPORT_FTP_DATA);
	else if (Buffer == ("FTP"))
		return htons(IPPORT_FTP);
	else if (Buffer == ("SSH"))
		return htons(IPPORT_SSH);
	else if (Buffer == ("TELNET"))
		return htons(IPPORT_TELNET);
	else if (Buffer == ("SMTP"))
		return htons(IPPORT_SMTP);
	else if (Buffer == ("TIMESERVER"))
		return htons(IPPORT_TIMESERVER);
	else if (Buffer == ("RAP"))
		return htons(IPPORT_RAP);
	else if (Buffer == ("RLP"))
		return htons(IPPORT_RLP);
	else if (Buffer == ("NAMESERVER"))
		return htons(IPPORT_NAMESERVER);
	else if (Buffer == ("WHOIS"))
		return htons(IPPORT_WHOIS);
	else if (Buffer == ("TACACS"))
		return htons(IPPORT_TACACS);
	else if (Buffer == ("DNS"))
		return htons(IPPORT_DNS);
	else if (Buffer == ("XNSAUTH"))
		return htons(IPPORT_XNSAUTH);
	else if (Buffer == ("MTP"))
		return htons(IPPORT_MTP);
	else if (Buffer == ("BOOTPS"))
		return htons(IPPORT_BOOTPS);
	else if (Buffer == ("BOOTPC"))
		return htons(IPPORT_BOOTPC);
	else if (Buffer == ("TFTP"))
		return htons(IPPORT_TFTP);
	else if (Buffer == ("RJE"))
		return htons(IPPORT_RJE);
	else if (Buffer == ("FINGER"))
		return htons(IPPORT_FINGER);
	else if (Buffer == ("HTTP"))
		return htons(IPPORT_HTTP);
	else if (Buffer == ("HTTPBACKUP"))
		return htons(IPPORT_HTTPBACKUP);
	else if (Buffer == ("TTYLINK"))
		return htons(IPPORT_TTYLINK);
	else if (Buffer == ("SUPDUP"))
		return htons(IPPORT_SUPDUP);
	else if (Buffer == ("POP3"))
		return htons(IPPORT_POP3);
	else if (Buffer == ("SUNRPC"))
		return htons(IPPORT_SUNRPC);
	else if (Buffer == ("SQL"))
		return htons(IPPORT_SQL);
	else if (Buffer == ("NTP"))
		return htons(IPPORT_NTP);
	else if (Buffer == ("EPMAP"))
		return htons(IPPORT_EPMAP);
	else if (Buffer == ("NETBIOS_NS"))
		return htons(IPPORT_NETBIOS_NS);
	else if (Buffer == ("NETBIOS_DGM"))
		return htons(IPPORT_NETBIOS_DGM);
	else if (Buffer == ("NETBIOS_SSN"))
		return htons(IPPORT_NETBIOS_SSN);
	else if (Buffer == ("IMAP"))
		return htons(IPPORT_IMAP);
	else if (Buffer == ("BFTP"))
		return htons(IPPORT_BFTP);
	else if (Buffer == ("SGMP"))
		return htons(IPPORT_SGMP);
	else if (Buffer == ("SQLSRV"))
		return htons(IPPORT_SQLSRV);
	else if (Buffer == ("DMSP"))
		return htons(IPPORT_DMSP);
	else if (Buffer == ("SNMP"))
		return htons(IPPORT_SNMP);
	else if (Buffer == ("SNMP_TRAP"))
		return htons(IPPORT_SNMP_TRAP);
	else if (Buffer == ("ATRTMP"))
		return htons(IPPORT_ATRTMP);
	else if (Buffer == ("ATHBP"))
		return htons(IPPORT_ATHBP);
	else if (Buffer == ("QMTP"))
		return htons(IPPORT_QMTP);
	else if (Buffer == ("IPX"))
		return htons(IPPORT_IPX);
	else if (Buffer == ("IMAP3"))
		return htons(IPPORT_IMAP3);
	else if (Buffer == ("BGMP"))
		return htons(IPPORT_BGMP);
	else if (Buffer == ("TSP"))
		return htons(IPPORT_TSP);
	else if (Buffer == ("IMMP"))
		return htons(IPPORT_IMMP);
	else if (Buffer == ("ODMR"))
		return htons(IPPORT_ODMR);
	else if (Buffer == ("RPC2PORTMAP"))
		return htons(IPPORT_RPC2PORTMAP);
	else if (Buffer == ("CLEARCASE"))
		return htons(IPPORT_CLEARCASE);
	else if (Buffer == ("HPALARMMGR"))
		return htons(IPPORT_HPALARMMGR);
	else if (Buffer == ("ARNS"))
		return htons(IPPORT_ARNS);
	else if (Buffer == ("AURP"))
		return htons(IPPORT_AURP);
	else if (Buffer == ("LDAP"))
		return htons(IPPORT_LDAP);
	else if (Buffer == ("UPS"))
		return htons(IPPORT_UPS);
	else if (Buffer == ("SLP"))
		return htons(IPPORT_SLP);
	else if (Buffer == ("HTTPS"))
		return htons(IPPORT_HTTPS);
	else if (Buffer == ("SNPP"))
		return htons(IPPORT_SNPP);
	else if (Buffer == ("MICROSOFTDS"))
		return htons(IPPORT_MICROSOFT_DS);
	else if (Buffer == ("KPASSWD"))
		return htons(IPPORT_KPASSWD);
	else if (Buffer == ("TCPNETHASPSRV"))
		return htons(IPPORT_TCPNETHASPSRV);
	else if (Buffer == ("RETROSPECT"))
		return htons(IPPORT_RETROSPECT);
	else if (Buffer == ("ISAKMP"))
		return htons(IPPORT_ISAKMP);
	else if (Buffer == ("BIFFUDP"))
		return htons(IPPORT_BIFFUDP);
	else if (Buffer == ("WHOSERVER"))
		return htons(IPPORT_WHOSERVER);
	else if (Buffer == ("SYSLOG"))
		return htons(IPPORT_SYSLOG);
	else if (Buffer == ("ROUTERSERVER"))
		return htons(IPPORT_ROUTESERVER);
	else if (Buffer == ("NCP"))
		return htons(IPPORT_NCP);
	else if (Buffer == ("COURIER"))
		return htons(IPPORT_COURIER);
	else if (Buffer == ("COMMERCE"))
		return htons(IPPORT_COMMERCE);
	else if (Buffer == ("RTSP"))
		return htons(IPPORT_RTSP);
	else if (Buffer == ("NNTP"))
		return htons(IPPORT_NNTP);
	else if (Buffer == ("HTTPRPCEPMAP"))
		return htons(IPPORT_HTTPRPCEPMAP);
	else if (Buffer == ("IPP"))
		return htons(IPPORT_IPP);
	else if (Buffer == ("LDAPS"))
		return htons(IPPORT_LDAPS);
	else if (Buffer == ("MSDP"))
		return htons(IPPORT_MSDP);
	else if (Buffer == ("AODV"))
		return htons(IPPORT_AODV);
	else if (Buffer == ("FTPSDATA"))
		return htons(IPPORT_FTPSDATA);
	else if (Buffer == ("FTPS"))
		return htons(IPPORT_FTPS);
	else if (Buffer == ("NAS"))
		return htons(IPPORT_NAS);
	else if (Buffer == ("TELNETS"))
		return htons(IPPORT_TELNETS);

//No match.
	return 0;
}

//Convert DNS type name to hex
uint16_t DNSTypeNameToBinary(
	const uint8_t * const OriginalBuffer)
{
	std::string Buffer(reinterpret_cast<const char *>(OriginalBuffer));
	CaseConvert(Buffer, true);

//DNS type name
	if (Buffer == ("A"))
		return htons(DNS_TYPE_A);
	else if (Buffer == ("NS"))
		return htons(DNS_TYPE_NS);
	else if (Buffer == ("MD"))
		return htons(DNS_TYPE_MD);
	else if (Buffer == ("MF"))
		return htons(DNS_TYPE_MF);
	else if (Buffer == ("CNAME"))
		return htons(DNS_TYPE_CNAME);
	else if (Buffer == ("SOA"))
		return htons(DNS_TYPE_SOA);
	else if (Buffer == ("MB"))
		return htons(DNS_TYPE_MB);
	else if (Buffer == ("MG"))
		return htons(DNS_TYPE_MG);
	else if (Buffer == ("MR"))
		return htons(DNS_TYPE_MR);
	else if (Buffer == ("PTR"))
		return htons(DNS_TYPE_PTR);
	else if (Buffer == ("NULL"))
		return htons(DNS_TYPE_NULL);
	else if (Buffer == ("WKS"))
		return htons(DNS_TYPE_WKS);
	else if (Buffer == ("HINFO"))
		return htons(DNS_TYPE_HINFO);
	else if (Buffer == ("MINFO"))
		return htons(DNS_TYPE_MINFO);
	else if (Buffer == ("MX"))
		return htons(DNS_TYPE_MX);
	else if (Buffer == ("TXT"))
		return htons(DNS_TYPE_TEXT);
	else if (Buffer == ("RP"))
		return htons(DNS_TYPE_RP);
	else if (Buffer == ("AFSDB"))
		return htons(DNS_TYPE_AFSDB);
	else if (Buffer == ("X25"))
		return htons(DNS_TYPE_X25);
	else if (Buffer == ("ISDN"))
		return htons(DNS_TYPE_ISDN);
	else if (Buffer == ("RT"))
		return htons(DNS_TYPE_RT);
	else if (Buffer == ("NSAP"))
		return htons(DNS_TYPE_NSAP);
	else if (Buffer == ("NSAPPTR"))
		return htons(DNS_TYPE_NSAPPTR);
	else if (Buffer == ("SIG"))
		return htons(DNS_TYPE_SIG);
	else if (Buffer == ("KEY"))
		return htons(DNS_TYPE_KEY);
	else if (Buffer == ("AAAA"))
		return htons(DNS_TYPE_AAAA);
	else if (Buffer == ("PX"))
		return htons(DNS_TYPE_PX);
	else if (Buffer == ("GPOS"))
		return htons(DNS_TYPE_GPOS);
	else if (Buffer == ("LOC"))
		return htons(DNS_TYPE_LOC);
	else if (Buffer == ("NXT"))
		return htons(DNS_TYPE_NXT);
	else if (Buffer == ("EID"))
		return htons(DNS_TYPE_EID);
	else if (Buffer == ("NIMLOC"))
		return htons(DNS_TYPE_NIMLOC);
	else if (Buffer == ("SRV"))
		return htons(DNS_TYPE_SRV);
	else if (Buffer == ("ATMA"))
		return htons(DNS_TYPE_ATMA);
	else if (Buffer == ("NAPTR"))
		return htons(DNS_TYPE_NAPTR);
	else if (Buffer == ("KX"))
		return htons(DNS_TYPE_KX);
	else if (Buffer == ("CERT"))
		return htons(DNS_TYPE_CERT);
	else if (Buffer == ("A6"))
		return htons(DNS_TYPE_A6);
	else if (Buffer == ("DNAME"))
		return htons(DNS_TYPE_DNAME);
	else if (Buffer == ("SINK"))
		return htons(DNS_TYPE_SINK);
	else if (Buffer == ("OPT"))
		return htons(DNS_TYPE_OPT);
	else if (Buffer == ("APL"))
		return htons(DNS_TYPE_APL);
	else if (Buffer == ("DS"))
		return htons(DNS_TYPE_DS);
	else if (Buffer == ("SSHFP"))
		return htons(DNS_TYPE_SSHFP);
	else if (Buffer == ("IPSECKEY"))
		return htons(DNS_TYPE_IPSECKEY);
	else if (Buffer == ("RRSIG"))
		return htons(DNS_TYPE_RRSIG);
	else if (Buffer == ("NSEC"))
		return htons(DNS_TYPE_NSEC);
	else if (Buffer == ("DNSKEY"))
		return htons(DNS_TYPE_DNSKEY);
	else if (Buffer == ("DHCID"))
		return htons(DNS_TYPE_DHCID);
	else if (Buffer == ("NSEC3"))
		return htons(DNS_TYPE_NSEC3);
	else if (Buffer == ("NSEC3PARAM"))
		return htons(DNS_TYPE_NSEC3PARAM);
	else if (Buffer == ("TLSA"))
		return htons(DNS_TYPE_TLSA);
	else if (Buffer == ("HIP"))
		return htons(DNS_TYPE_HIP);
	else if (Buffer == ("NINFO"))
		return htons(DNS_TYPE_NINFO);
	else if (Buffer == ("RKEY"))
		return htons(DNS_TYPE_RKEY);
	else if (Buffer == ("TALINK"))
		return htons(DNS_TYPE_TALINK);
	else if (Buffer == ("CDS"))
		return htons(DNS_TYPE_CDS);
	else if (Buffer == ("CDNSKEY"))
		return htons(DNS_TYPE_CDNSKEY);
	else if (Buffer == ("OPENPGPKEY"))
		return htons(DNS_TYPE_OPENPGPKEY);
	else if (Buffer == ("SPF"))
		return htons(DNS_TYPE_SPF);
	else if (Buffer == ("UINFO"))
		return htons(DNS_TYPE_UINFO);
	else if (Buffer == ("UID"))
		return htons(DNS_TYPE_UID);
	else if (Buffer == ("GID"))
		return htons(DNS_TYPE_GID);
	else if (Buffer == ("UNSPEC"))
		return htons(DNS_TYPE_UNSPEC);
	else if (Buffer == ("NID"))
		return htons(DNS_TYPE_NID);
	else if (Buffer == ("L32"))
		return htons(DNS_TYPE_L32);
	else if (Buffer == ("L64"))
		return htons(DNS_TYPE_L64);
	else if (Buffer == ("LP"))
		return htons(DNS_TYPE_LP);
	else if (Buffer == ("EUI48"))
		return htons(DNS_TYPE_EUI48);
	else if (Buffer == ("EUI64"))
		return htons(DNS_TYPE_EUI64);
	else if (Buffer == ("ADDRS"))
		return htons(DNS_TYPE_ADDRS);
	else if (Buffer == ("TKEY"))
		return htons(DNS_TYPE_TKEY);
	else if (Buffer == ("TSIG"))
		return htons(DNS_TYPE_TSIG);
	else if (Buffer == ("IXFR"))
		return htons(DNS_TYPE_IXFR);
	else if (Buffer == ("AXFR"))
		return htons(DNS_TYPE_AXFR);
	else if (Buffer == ("MAILB"))
		return htons(DNS_TYPE_MAILB);
	else if (Buffer == ("MAILA"))
		return htons(DNS_TYPE_MAILA);
	else if (Buffer == ("ANY"))
		return htons(DNS_TYPE_ANY);
	else if (Buffer == ("URI"))
		return htons(DNS_TYPE_URI);
	else if (Buffer == ("CAA"))
		return htons(DNS_TYPE_CAA);
	else if (Buffer == ("TA"))
		return htons(DNS_TYPE_TA);
	else if (Buffer == ("DLV"))
		return htons(DNS_TYPE_DLV);
	else if (Buffer == ("RESERVED"))
		return htons(DNS_TYPE_RESERVED);

//No match.
	return 0;
}

//Read parameter data from files
bool ReadParameterData(
	std::string Data, 
	const size_t FileIndex, 
	const bool IsFirstRead, 
	const size_t Line)
{
//Remove spaces, horizontal tab/HT, check comments(Number Sign/NS and double slashs) and check minimum length of ipfilter items.
//Remove comments(Number Sign/NS and double slashs) and check minimum length of configuration items.
//Additional Path, Hosts File Name, IPFilter File Name, HTTP CONNECT Header Field and DNSCurve Database Name must not be removed spaces or horizontal tab/HT.
	if (Data.compare(0, strlen("#"), ("#")) == 0 || Data.compare(0, strlen("/"), ("/")) == 0)
	{
		return true;
	}
	else if (Data.compare(0, strlen("Additional Path = "), ("Additional Path = ")) != 0 && 
		Data.compare(0, strlen("IPFilter File Name = "), ("IPFilter File Name = ")) != 0 && 
		Data.compare(0, strlen("Hosts File Name ="), ("Hosts File Name =")) != 0 && 
		Data.compare(0, strlen("HTTP CONNECT Header Field = "), ("HTTP CONNECT Header Field = ")) != 0
	#if defined(ENABLE_LIBSODIUM)
		&& Data.compare(0, strlen("DNSCurve Database Name = "), ("DNSCurve Database Name = ")) != 0
	#endif
		)
	{
		while (Data.find(ASCII_HT) != std::string::npos)
			Data.erase(Data.find(ASCII_HT), 1U);
		while (Data.find(ASCII_SPACE) != std::string::npos)
			Data.erase(Data.find(ASCII_SPACE), 1U);
	}
	if (Data.find(ASCII_HASHTAG) != std::string::npos)
		Data.erase(Data.find(ASCII_HASHTAG), Data.length() - Data.find(ASCII_HASHTAG));
	if (Data.find("//") != std::string::npos)
		Data.erase(Data.find("//"), Data.length() - Data.find("//"));
	if (Data.length() < READ_PARAMETER_MINSIZE)
		return true;

//Initialization
	CONFIGURATION_TABLE *ParameterPointer = nullptr;
#if defined(ENABLE_LIBSODIUM)
	DNSCURVE_CONFIGURATION_TABLE *DNSCurveParameterPointer = nullptr;
#endif
	size_t UnsignedResult = 0;
	if (IsFirstRead)
	{
		ParameterPointer = &Parameter;
	#if defined(ENABLE_LIBSODIUM)
		DNSCurveParameterPointer = &DNSCurveParameter;
	#endif
	}
	else {
		ParameterPointer = &ParameterModificating;
	#if defined(ENABLE_LIBSODIUM)
		DNSCurveParameterPointer = &DNSCurveParameterModificating;
	#endif
	}

//[Base] block
	if (Data.compare(0, strlen("Version="), ("Version=")) == 0)
	{
		_set_errno(0);
		if (Data.length() > strlen("Version=") && 
			Data.length() < strlen("Version=") + 8U && Data.find(ASCII_PERIOD) != std::string::npos) //Version = x.x(x)
		{
		//Get list data.
			std::vector<std::string> ListData;
			GetParameterListData(ListData, Data, strlen("Version="), Data.length(), ASCII_PERIOD, true, true);
			if (ListData.size() != CONFIG_VERSION_COUNT)
				goto PrintDataFormatError;

		//Convert major version.
			_set_errno(0);
			UnsignedResult = strtoul(ListData.front().c_str(), nullptr, 0);
			if ((UnsignedResult == 0 && errno == 0) || UnsignedResult < ULONG_MAX)
				ParameterPointer->Version_Major = UnsignedResult;
			else 
				goto PrintDataFormatError;

		//Convert minor version.
			_set_errno(0);
			UnsignedResult = strtoul(ListData.back().c_str(), nullptr, 0);
			if ((UnsignedResult == 0 && errno == 0) || UnsignedResult < ULONG_MAX)
				ParameterPointer->Version_Minor = UnsignedResult;
			else 
				goto PrintDataFormatError;
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (Data.compare(0, strlen("FileRefreshTime="), ("FileRefreshTime=")) == 0 && Data.length() > strlen("FileRefreshTime="))
	{
		if (Data.length() < strlen("FileRefreshTime=") + UINT16_MAX_STRING_LENGTH)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("FileRefreshTime="), nullptr, 0);
			if (UnsignedResult >= SHORTEST_FILEREFRESH_TIME && UnsignedResult < ULONG_MAX)
				ParameterPointer->FileRefreshTime = UnsignedResult * SECOND_TO_MILLISECOND;
		}
		else {
			goto PrintDataFormatError;
		}
	}

	if (IsFirstRead)
	{
		if (Data.compare(0, strlen("LargeBufferSize="), ("LargeBufferSize=")) == 0 && Data.length() > strlen("LargeBufferSize="))
		{
			if (Data.length() < strlen("LargeBufferSize=") + UINT16_MAX_STRING_LENGTH)
			{
				_set_errno(0);
				UnsignedResult = strtoul(Data.c_str() + strlen("LargeBufferSize="), nullptr, 0);
				if (UnsignedResult >= NORMAL_PACKET_MAXSIZE && UnsignedResult < ULONG_MAX)
					Parameter.LargeBufferSize = UnsignedResult;
			}
			else {
				goto PrintDataFormatError;
			}
		}
		else if (Data.compare(0, strlen("Additional Path = "), ("Additional Path = ")) == 0 && Data.length() > strlen("Additional Path = "))
		{
		#if defined(PLATFORM_WIN)
			if (!ReadName_PathFile(Data, strlen("Additional Path = "), true, GlobalRunningStatus.Path_Global, FileIndex, Line))
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			if (!ReadName_PathFile(Data, strlen("Additional Path = "), true, GlobalRunningStatus.Path_Global, GlobalRunningStatus.MBS_Path_Global, FileIndex, Line))
		#endif
				return false;
		}
		else if (Data.compare(0, strlen("Hosts File Name = "), ("Hosts File Name = ")) == 0 && Data.length() > strlen("Hosts File Name = "))
		{
		#if defined(PLATFORM_WIN)
			if (!ReadName_PathFile(Data, strlen("Hosts File Name = "), false, GlobalRunningStatus.FileList_Hosts, FileIndex, Line))
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			if (!ReadName_PathFile(Data, strlen("Hosts File Name = "), false, GlobalRunningStatus.FileList_Hosts, GlobalRunningStatus.MBS_FileList_Hosts, FileIndex, Line))
		#endif
				return false;
		}
		else if (Data.compare(0, strlen("IPFilter File Name = "), ("IPFilter File Name = ")) == 0 && Data.length() > strlen("IPFilter File Name = "))
		{
		#if defined(PLATFORM_WIN)
			if (!ReadName_PathFile(Data, strlen("IPFilter File Name = "), false, GlobalRunningStatus.FileList_IPFilter, FileIndex, Line))
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			if (!ReadName_PathFile(Data, strlen("IPFilter File Name = "), false, GlobalRunningStatus.FileList_IPFilter, GlobalRunningStatus.MBS_FileList_IPFilter, FileIndex, Line))
		#endif
				return false;
		}
	}

//[Log] block
	if (Data.compare(0, strlen("PrintLogLevel="), ("PrintLogLevel=")) == 0)
	{
		if (Data.length() == strlen("PrintLogLevel=") + NULL_TERMINATE_LENGTH)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("PrintLogLevel="), nullptr, 0);
			if (UnsignedResult == 0 && errno == 0) //Level 0
				ParameterPointer->PrintLogLevel = LOG_LEVEL_TYPE::LEVEL_0;
			else if (UnsignedResult == 1U) //Level 1
				ParameterPointer->PrintLogLevel = LOG_LEVEL_TYPE::LEVEL_1;
			else if (UnsignedResult == 2U) //Level 2
				ParameterPointer->PrintLogLevel = LOG_LEVEL_TYPE::LEVEL_2;
			else if (UnsignedResult == 3U) //Level 3
				ParameterPointer->PrintLogLevel = LOG_LEVEL_TYPE::LEVEL_3;
/*			else if (UnsignedResult == 4U) //Reserved
				ParameterPointer->PrintLogLevel = LOG_LEVEL_TYPE::LEVEL_4;
			else if (UnsignedResult == 5U) //Reserved
				ParameterPointer->PrintLogLevel = LOG_LEVEL_TYPE::LEVEL_5;
*/
			else 
				goto PrintDataFormatError;
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (Data.compare(0, strlen("LogMaximumSize="), ("LogMaximumSize=")) == 0 && Data.length() > strlen("LogMaximumSize="))
	{
		CaseConvert(Data, true);
		if (Data.find("KB") != std::string::npos)
		{
			Data.erase(Data.length() - 2U, 2U);

		//Mark bytes.
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("LogMaximumSize="), nullptr, 0);
			if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult < ULONG_MAX))
				ParameterPointer->LogMaxSize = UnsignedResult * KIBIBYTE_TIMES;
			else 
				goto PrintDataFormatError;
		}
		else if (Data.find("MB") != std::string::npos)
		{
			Data.erase(Data.length() - 2U, 2U);

		//Mark bytes.
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("LogMaximumSize="), nullptr, 0);
			if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult < ULONG_MAX))
				ParameterPointer->LogMaxSize = UnsignedResult * MEBIBYTE_TIMES;
			else 
				goto PrintDataFormatError;
		}
		else if (Data.find("GB") != std::string::npos)
		{
			Data.erase(Data.length() - 2U, 2U);

		//Mark bytes.
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("LogMaximumSize="), nullptr, 0);
			if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult < ULONG_MAX))
				ParameterPointer->LogMaxSize = UnsignedResult * GIBIBYTE_TIMES;
			else 
				goto PrintDataFormatError;
		}
		else {
		//Check number.
			for (auto StringIter = Data.begin() + strlen("LogMaximumSize=");StringIter != Data.end();++StringIter)
			{
				if (*StringIter < ASCII_ZERO || *StringIter > ASCII_NINE)
					goto PrintDataFormatError;
			}

		//Mark bytes.
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("LogMaximumSize="), nullptr, 0);
			if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult < ULONG_MAX))
				ParameterPointer->LogMaxSize = UnsignedResult;
			else 
				goto PrintDataFormatError;
		}
	}

//[Listen] block
	if (IsFirstRead)
	{
		if (Data.compare(0, strlen("ProcessUnique=1"), ("ProcessUnique=1")) == 0)
		{
			Parameter.IsProcessUnique = true;
		}

	#if defined(ENABLE_PCAP)
		else if (Data.compare(0, strlen("PcapCapture=1"), ("PcapCapture=1")) == 0)
		{
			Parameter.IsPcapCapture = true;
		}
		else if (Data.compare(0, strlen("PcapDevicesBlacklist="), ("PcapDevicesBlacklist=")) == 0)
		{
			GetParameterListData(*Parameter.PcapDevicesBlacklist, Data, strlen("PcapDevicesBlacklist="), Data.length(), ASCII_VERTICAL, true, false);
		}
		else if (Data.compare(0, strlen("PcapReadingTimeout="), ("PcapReadingTimeout=")) == 0)
		{
			if (Data.length() < strlen("PcapReadingTimeout=") + UINT16_MAX_STRING_LENGTH)
			{
				_set_errno(0);
				UnsignedResult = strtoul(Data.c_str() + strlen("PcapReadingTimeout="), nullptr, 0);
				if (UnsignedResult > PCAP_CAPTURE_MIN_TIMEOUT && UnsignedResult < ULONG_MAX)
					Parameter.PcapReadingTimeout = UnsignedResult;
			}
			else {
				goto PrintDataFormatError;
			}
		}
	#endif

		else if (Data.compare(0, strlen("ListenProtocol="), ("ListenProtocol=")) == 0 && Data.length() > strlen("ListenProtocol="))
		{
			CaseConvert(Data, true);

		//Network layer
			if (Data.find("IPV6") != std::string::npos)
			{
				if (Data.find("IPV4") != std::string::npos)
					Parameter.ListenProtocol_Network = LISTEN_PROTOCOL_NETWORK::BOTH;
				else 
					Parameter.ListenProtocol_Network = LISTEN_PROTOCOL_NETWORK::IPV6;
			}
			else {
				Parameter.ListenProtocol_Network = LISTEN_PROTOCOL_NETWORK::IPV4;
			}

		//Transport layer
			if (Data.find("TCP") != std::string::npos)
			{
				if (Data.find("UDP") != std::string::npos)
					Parameter.ListenProtocol_Transport = LISTEN_PROTOCOL_TRANSPORT::BOTH;
				else 
					Parameter.ListenProtocol_Transport = LISTEN_PROTOCOL_TRANSPORT::TCP;
			}
			else {
				Parameter.ListenProtocol_Transport = LISTEN_PROTOCOL_TRANSPORT::UDP;
			}
		}
		else if (Data.compare(0, strlen("ListenPort="), ("ListenPort=")) == 0 && Data.length() > strlen("ListenPort="))
		{
		//Get list data.
			std::vector<std::string> ListData;
			GetParameterListData(ListData, Data, strlen("ListenPort="), Data.length(), ASCII_VERTICAL, false, false);
			Parameter.ListenPort->clear();

		//List all data.
			for (const auto &StringIter:ListData)
			{
				UnsignedResult = ServiceNameToBinary(reinterpret_cast<const uint8_t *>(StringIter.c_str()));
				if (UnsignedResult == 0)
				{
					_set_errno(0);
					UnsignedResult = strtoul(StringIter.c_str(), nullptr, 0);
					if (UnsignedResult == 0 || UnsignedResult > UINT16_MAX)
					{
						PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Local machine listening port error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
						return false;
					}
				}

			//Mark to global list.
				Parameter.ListenPort->push_back(htons(static_cast<uint16_t>(UnsignedResult)));
			}
		}
		else if (Data.compare(0, strlen("OperationMode="), ("OperationMode=")) == 0 && Data.length() > strlen("OperationMode="))
		{
			CaseConvert(Data, true);
			if (Data.find("PRIVATE") != std::string::npos)
				Parameter.OperationMode = LISTEN_MODE::PRIVATE;
			else if (Data.find("SERVER") != std::string::npos)
				Parameter.OperationMode = LISTEN_MODE::SERVER;
			else if (Data.find("CUSTOM") != std::string::npos)
				Parameter.OperationMode = LISTEN_MODE::CUSTOM;
			else if (Data.find("PROXY") != std::string::npos)
				Parameter.OperationMode = LISTEN_MODE::PROXY;
		}
	}

	if (Data.compare(0, strlen("IPFilterType="), ("IPFilterType=")) == 0 && Data.length() > strlen("IPFilterType="))
	{
		CaseConvert(Data, true);
		if (Data.compare(0, strlen("IPFILTERTYPE=PERMIT"), ("IPFILTERTYPE=PERMIT")) == 0)
			ParameterPointer->IsIPFilterTypePermit = true;
	}
	else if (Data.compare(0, strlen("IPFilterLevel<"), ("IPFilterLevel<")) == 0 && Data.length() > strlen("IPFilterLevel<"))
	{
		if (Data.length() < strlen("IPFilterLevel<") + UINT8_MAX_STRING_LENGTH)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("IPFilterLevel<"), nullptr, 0);
			if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult <= UINT16_MAX))
			{
				ParameterPointer->IPFilterLevel = UnsignedResult;
			}
			else {
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPFilter Level error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
				return false;
			}
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (Data.compare(0, strlen("AcceptType="), ("AcceptType=")) == 0 && Data.length() > strlen("AcceptType="))
	{
		if (Data.find(ASCII_COLON) == std::string::npos)
		{
			goto PrintDataFormatError;
		}
		else {
			CaseConvert(Data, true);

		//Permit or Deny mode check
			if (Data.find("PERMIT:") != std::string::npos)
				ParameterPointer->IsAcceptTypePermit = true;
			else 
				ParameterPointer->IsAcceptTypePermit = false;

		//Get list data.
			std::vector<std::string> ListData;
			GetParameterListData(ListData, Data, Data.find(ASCII_COLON) + 1U, Data.length(), ASCII_VERTICAL, false, false);
			ParameterPointer->AcceptTypeList->clear();

		//List all data.
			for (const auto &StringIter:ListData)
			{
				UnsignedResult = DNSTypeNameToBinary(reinterpret_cast<const uint8_t *>(StringIter.c_str()));
				if (UnsignedResult == 0)
				{
					_set_errno(0);
					UnsignedResult = strtoul(StringIter.c_str(), nullptr, 0);
					if (UnsignedResult == 0 || UnsignedResult > UINT16_MAX)
					{
						PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"DNS record type error", errno, FileList_Config.at(FileIndex).FileName.c_str(), Line);
						return false;
					}
				}

			//Mark to all list.
				ParameterPointer->AcceptTypeList->push_back(static_cast<uint16_t>(UnsignedResult));
			}
		}
	}

//[DNS] block
	if (IsFirstRead && Data.compare(0, strlen("OutgoingProtocol="), ("OutgoingProtocol=")) == 0 && Data.length() > strlen("OutgoingProtocol="))
	{
		CaseConvert(Data, true);

	//Network layer
		if (Data.find("IPV6") != std::string::npos)
		{
			if (Data.find("IPV4") != std::string::npos)
				Parameter.RequestMode_Network = REQUEST_MODE_NETWORK::BOTH;
			else 
				Parameter.RequestMode_Network = REQUEST_MODE_NETWORK::IPV6;
		}
		else {
			Parameter.RequestMode_Network = REQUEST_MODE_NETWORK::IPV4;
		}

	//Transport layer
		if (Data.find("FORCE") != std::string::npos)
			Parameter.RequestMode_Transport = REQUEST_MODE_TRANSPORT::FORCE_TCP;
		else if (Data.find("TCP") != std::string::npos)
			Parameter.RequestMode_Transport = REQUEST_MODE_TRANSPORT::TCP;
		else 
			Parameter.RequestMode_Transport = REQUEST_MODE_TRANSPORT::UDP;
	}
	else if (Data.compare(0, strlen("DirectRequest="), ("DirectRequest=")) == 0 && Data.length() > strlen("DirectRequest="))
	{
		if (Data.compare(0, strlen("DirectRequest=1"), ("DirectRequest=1")) == 0)
		{
			ParameterPointer->DirectRequest = REQUEST_MODE_DIRECT::BOTH;
		}
		else {
			CaseConvert(Data, true);
			if (Data.find("IPV6") != std::string::npos)
			{
				if (Data.find("IPV4") != std::string::npos)
					ParameterPointer->DirectRequest = REQUEST_MODE_DIRECT::BOTH;
				else 
					ParameterPointer->DirectRequest = REQUEST_MODE_DIRECT::IPV6;
			}
			else if (Data.find("IPV4") != std::string::npos)
			{
				if (Data.find("IPV6") != std::string::npos)
					ParameterPointer->DirectRequest = REQUEST_MODE_DIRECT::BOTH;
				else 
					ParameterPointer->DirectRequest = REQUEST_MODE_DIRECT::IPV4;
			}
		}
	}

	if (IsFirstRead)
	{
		if (Data.compare(0, strlen("CacheType="), ("CacheType=")) == 0 && Data.length() > strlen("CacheType="))
		{
			CaseConvert(Data, true);
			if (Data.find("QUEUE") != std::string::npos && Data.find("TIMER") != std::string::npos)
				Parameter.DNS_CacheType = DNS_CACHE_TYPE::BOTH;
			else if (Data.find("TIMER") != std::string::npos)
				Parameter.DNS_CacheType = DNS_CACHE_TYPE::TIMER;
			else if (Data.find("QUEUE") != std::string::npos)
				Parameter.DNS_CacheType = DNS_CACHE_TYPE::QUEUE;
		}
		else if (Data.compare(0, strlen("CacheParameter="), ("CacheParameter="))== 0 && Data.length() > strlen("CacheParameter="))
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("CacheParameter="), nullptr, 0);
			if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult < ULONG_MAX))
				Parameter.DNS_CacheParameter = UnsignedResult;
			else 
				goto PrintDataFormatError;
		}
		else if (Data.compare(0, strlen("CacheSingleIPv4AddressPrefix="), ("CacheSingleIPv4AddressPrefix="))== 0 && Data.length() > strlen("CacheSingleIPv4AddressPrefix="))
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("CacheSingleIPv4AddressPrefix="), nullptr, 0);
			if (UnsignedResult > 0 && UnsignedResult <= sizeof(in_addr) * BYTES_TO_BITS)
				Parameter.DNS_CacheSinglePrefix_IPv4 = UnsignedResult;
		}
		else if (Data.compare(0, strlen("CacheSingleIPv6AddressPrefix="), ("CacheSingleIPv6AddressPrefix="))== 0 && Data.length() > strlen("CacheSingleIPv6AddressPrefix="))
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("CacheSingleIPv6AddressPrefix="), nullptr, 0);
			if (UnsignedResult > 0 && UnsignedResult <= sizeof(in6_addr) * BYTES_TO_BITS)
				Parameter.DNS_CacheSinglePrefix_IPv6 = UnsignedResult;
		}
	}

	if (Data.compare(0, strlen("DefaultTTL="), ("DefaultTTL=")) == 0 && Data.length() > strlen("DefaultTTL="))
	{
		if (Data.length() < strlen("DefaultTTL=") + UINT16_MAX_STRING_LENGTH)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("DefaultTTL="), nullptr, 0);
			if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult < ULONG_MAX))
			{
				ParameterPointer->HostsDefaultTTL = static_cast<uint32_t>(UnsignedResult);
			}
			else {
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Default TTL error", errno, FileList_Config.at(FileIndex).FileName.c_str(), Line);
				return false;
			}
		}
		else {
			goto PrintDataFormatError;
		}
	}

//[Local DNS] block
	if (Data.compare(0, strlen("LocalProtocol="), ("LocalProtocol=")) == 0)
	{
		CaseConvert(Data, true);

	//Network layer
		if (Data.find("IPV6") != std::string::npos)
		{
			if (Data.find("IPV4") != std::string::npos)
				ParameterPointer->LocalProtocol_Network = REQUEST_MODE_NETWORK::BOTH;
			else 
				ParameterPointer->LocalProtocol_Network = REQUEST_MODE_NETWORK::IPV6;
		}
		else {
			ParameterPointer->LocalProtocol_Network = REQUEST_MODE_NETWORK::IPV4;
		}

	//Transport layer
		if (Data.find("FORCE") != std::string::npos)
			ParameterPointer->LocalProtocol_Transport = REQUEST_MODE_TRANSPORT::FORCE_TCP;
		else if (Data.find("TCP") != std::string::npos)
			ParameterPointer->LocalProtocol_Transport = REQUEST_MODE_TRANSPORT::TCP;
		else 
			ParameterPointer->LocalProtocol_Transport = REQUEST_MODE_TRANSPORT::UDP;
	}

	if (IsFirstRead)
	{
		if (Data.compare(0, strlen("LocalHosts=1"), ("LocalHosts=1")) == 0)
		{
			Parameter.IsLocalHosts = true;
		}
		else if (Data.compare(0, strlen("LocalRouting=1"), ("LocalRouting=1")) == 0)
		{
			Parameter.IsLocalRouting = true;
		}
		else if (Data.compare(0, strlen("LocalForceRequest=1"), ("LocalForceRequest=1")) == 0)
		{
			Parameter.IsLocalForce = true;
		}

//[Addresses] block
		else if (Data.compare(0, strlen("IPv4ListenAddress="), ("IPv4ListenAddress=")) == 0 && 
			Data.length() > strlen("IPv4ListenAddress="))
		{
		//Get list data.
			std::vector<DNS_SERVER_DATA> DNSServerDataTemp;
			if (!ReadMultipleAddresses(AF_INET, Data, strlen("IPv4ListenAddress="), &DNSServerDataTemp, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
				return false;

		//Mark to global list.
			for (const auto &DNSServerDataIter:DNSServerDataTemp)
				Parameter.ListenAddress_IPv4->push_back(DNSServerDataIter.AddressData.Storage);
		}
		else if (Data.compare(0, strlen("IPv4EDNSClientSubnetAddress="), ("IPv4EDNSClientSubnetAddress=")) == 0 && 
			Data.length() > strlen("IPv4EDNSClientSubnetAddress="))
		{
			if (!ReadAddressPrefixBlock(AF_INET, Data, strlen("IPv4EDNSClientSubnetAddress="), Parameter.LocalMachineSubnet_IPv4, FileList_Config, FileIndex, Line))
				return false;
		}
		else if (Data.compare(0, strlen("IPv4MainDNSAddress="), ("IPv4MainDNSAddress=")) == 0 && 
			Data.length() > strlen("IPv4MainDNSAddress="))
		{
			if (!ReadMultipleAddresses(AF_INET, Data, strlen("IPv4MainDNSAddress="), Parameter.Target_Server_IPv4_Multiple, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
				return false;
		}
		else if (Data.compare(0, strlen("IPv4AlternateDNSAddress="), ("IPv4AlternateDNSAddress=")) == 0 && 
			Data.length() > strlen("IPv4AlternateDNSAddress="))
		{
			if (!ReadMultipleAddresses(AF_INET, Data, strlen("IPv4AlternateDNSAddress="), Parameter.Target_Server_IPv4_Multiple, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
				return false;
		}
		else if (Data.compare(0, strlen("IPv4LocalMainDNSAddress="), ("IPv4LocalMainDNSAddress=")) == 0 && 
			Data.length() > strlen("IPv4LocalMainDNSAddress="))
		{
			std::vector<DNS_SERVER_DATA> DNSServerDataTemp;
			if (!ReadMultipleAddresses(AF_INET, Data, strlen("IPv4LocalMainDNSAddress="), &DNSServerDataTemp, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line) || DNSServerDataTemp.empty())
				return false;
			else 
				Parameter.Target_Server_Local_Main_IPv4 = DNSServerDataTemp.front().AddressData;
		}
		else if (Data.compare(0, strlen("IPv4LocalAlternateDNSAddress="), ("IPv4LocalAlternateDNSAddress=")) == 0 && 
			Data.length() > strlen("IPv4LocalAlternateDNSAddress="))
		{
			std::vector<DNS_SERVER_DATA> DNSServerDataTemp;
			if (!ReadMultipleAddresses(AF_INET, Data, strlen("IPv4LocalAlternateDNSAddress="), &DNSServerDataTemp, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line) || DNSServerDataTemp.empty())
				return false;
			else 
				Parameter.Target_Server_Local_Alternate_IPv4 = DNSServerDataTemp.front().AddressData;
		}
		else if (Data.compare(0, strlen("IPv6ListenAddress="), ("IPv6ListenAddress=")) == 0 && 
			Data.length() > strlen("IPv6ListenAddress="))
		{
		//Get list data.
			std::vector<DNS_SERVER_DATA> DNSServerDataTemp;
			if (!ReadMultipleAddresses(AF_INET6, Data, strlen("IPv6ListenAddress="), &DNSServerDataTemp, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
				return false;

		//Mark to global list.
			for (const auto &DNSServerDataIter:DNSServerDataTemp)
				Parameter.ListenAddress_IPv6->push_back(DNSServerDataIter.AddressData.Storage);
		}
		else if (Data.compare(0, strlen("IPv6EDNSClientSubnetAddress="), ("IPv6EDNSClientSubnetAddress=")) == 0 && 
			Data.length() > strlen("IPv6EDNSClientSubnetAddress="))
		{
			if (!ReadAddressPrefixBlock(AF_INET6, Data, strlen("IPv6EDNSClientSubnetAddress="), Parameter.LocalMachineSubnet_IPv6, FileList_Config, FileIndex, Line))
				return false;
		}
		else if (Data.compare(0, strlen("IPv6MainDNSAddress="), ("IPv6MainDNSAddress=")) == 0 && 
			Data.length() > strlen("IPv6MainDNSAddress="))
		{
			if (!ReadMultipleAddresses(AF_INET6, Data, strlen("IPv6MainDNSAddress="), Parameter.Target_Server_IPv6_Multiple, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
				return false;
		}
		else if (Data.compare(0, strlen("IPv6AlternateDNSAddress="), ("IPv6AlternateDNSAddress=")) == 0 && 
			Data.length() > strlen("IPv6AlternateDNSAddress="))
		{
			if (!ReadMultipleAddresses(AF_INET6, Data, strlen("IPv6AlternateDNSAddress="), Parameter.Target_Server_IPv6_Multiple, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
				return false;
		}
		else if (Data.compare(0, strlen("IPv6LocalMainDNSAddress="), ("IPv6LocalMainDNSAddress=")) == 0 && 
			Data.length() > strlen("IPv6LocalMainDNSAddress="))
		{
			std::vector<DNS_SERVER_DATA> DNSServerDataTemp;
			if (!ReadMultipleAddresses(AF_INET6, Data, strlen("IPv6LocalMainDNSAddress="), &DNSServerDataTemp, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line) || DNSServerDataTemp.empty())
				return false;
			else 
				Parameter.Target_Server_Local_Main_IPv6 = DNSServerDataTemp.front().AddressData;
		}
		else if (Data.compare(0, strlen("IPv6LocalAlternateDNSAddress="), ("IPv6LocalAlternateDNSAddress=")) == 0 && 
			Data.length() > strlen("IPv6LocalAlternateDNSAddress="))
		{
			std::vector<DNS_SERVER_DATA> DNSServerDataTemp;
			if (!ReadMultipleAddresses(AF_INET6, Data, strlen("IPv6LocalAlternateDNSAddress="),  &DNSServerDataTemp, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line) || DNSServerDataTemp.empty())
				return false;
			else 
				Parameter.Target_Server_Local_Alternate_IPv6 = DNSServerDataTemp.front().AddressData;
		}
	}

//[Values] block
	if (IsFirstRead)
	{
		if (Data.compare(0, strlen("ThreadPoolBaseNumber="), ("ThreadPoolBaseNumber=")) == 0 && Data.length() > strlen("ThreadPoolBaseNumber="))
		{
			if (Data.length() < strlen("ThreadPoolBaseNumber=") + UINT32_MAX_STRING_LENGTH - 1U)
			{
				_set_errno(0);
				UnsignedResult = strtoul(Data.c_str() + strlen("ThreadPoolBaseNumber="), nullptr, 0);
				if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult <= THREAD_POOL_MAXNUM))
					Parameter.ThreadPoolBaseNum = UnsignedResult;
			}
			else {
				goto PrintDataFormatError;
			}
		}
		else if (Data.compare(0, strlen("ThreadPoolMaximumNumber="), ("ThreadPoolMaximumNumber=")) == 0 && Data.length() > strlen("ThreadPoolMaximumNumber="))
		{
			if (Data.length() < strlen("ThreadPoolMaximumNumber=") + UINT32_MAX_STRING_LENGTH - 1U)
			{
				_set_errno(0);
				UnsignedResult = strtoul(Data.c_str() + strlen("ThreadPoolMaximumNumber="), nullptr, 0);
				if (UnsignedResult >= THREAD_POOL_MINNUM && UnsignedResult <= THREAD_POOL_MAXNUM)
					Parameter.ThreadPoolMaxNum = UnsignedResult;
			}
			else {
				goto PrintDataFormatError;
			}
		}
	}

	if (Data.compare(0, strlen("ThreadPoolResetTime="), ("ThreadPoolResetTime=")) == 0 && Data.length() > strlen("ThreadPoolResetTime="))
	{
		if (Data.length() < strlen("ThreadPoolResetTime=") + UINT16_MAX_STRING_LENGTH)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("ThreadPoolResetTime="), nullptr, 0);
			if (UnsignedResult >= SHORTEST_THREAD_POOL_RESET_TIME && UnsignedResult < ULONG_MAX)
				ParameterPointer->ThreadPoolResetTime = UnsignedResult * SECOND_TO_MILLISECOND;
		}
		else {
			goto PrintDataFormatError;
		}
	}

	if (IsFirstRead)
	{
		if (Data.compare(0, strlen("QueueLimitsResetTime="), ("QueueLimitsResetTime=")) == 0 && Data.length() > strlen("QueueLimitsResetTime="))
		{
			if (Data.length() < strlen("QueueLimitsResetTime=") + UINT16_MAX_STRING_LENGTH)
			{
				_set_errno(0);
				UnsignedResult = strtoul(Data.c_str() + strlen("QueueLimitsResetTime="), nullptr, 0);
				if (UnsignedResult > 0 && UnsignedResult < ULONG_MAX)
					Parameter.QueueResetTime = UnsignedResult * SECOND_TO_MILLISECOND;
			}
			else {
				goto PrintDataFormatError;
			}
		}
		else if (Data.compare(0, strlen("EDNSPayloadSize="), ("EDNSPayloadSize=")) == 0 && Data.length() > strlen("EDNSPayloadSize="))
		{
			if (Data.length() < strlen("EDNSPayloadSize=") + UINT16_MAX_STRING_LENGTH)
			{
				_set_errno(0);
				UnsignedResult = strtoul(Data.c_str() + strlen("EDNSPayloadSize="), nullptr, 0);
				if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult < ULONG_MAX))
					Parameter.EDNS_PayloadSize = UnsignedResult;
			}
			else {
				goto PrintDataFormatError;
			}
		}
	}

	if (Data.compare(0, strlen("IPv4PacketTTL="), ("IPv4PacketTTL=")) == 0 && Data.length() > strlen("IPv4PacketTTL="))
	{
	//Range
		if (Data.find(ASCII_MINUS) != std::string::npos && Data.length() > Data.find(ASCII_MINUS) + 1U)
		{
		//Mark beginning value.
			std::string ValueString(Data, strlen("IPv4PacketTTL="), Data.find(ASCII_MINUS) - strlen("IPv4PacketTTL="));
			_set_errno(0);
			UnsignedResult = strtoul(ValueString.c_str(), nullptr, 0);
			if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult <= UINT8_MAX))
			#if defined(PLATFORM_WIN)
				ParameterPointer->PacketHopLimits_IPv4_Begin = static_cast<DWORD>(UnsignedResult);
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				ParameterPointer->PacketHopLimits_IPv4_Begin = static_cast<int>(UnsignedResult);
			#endif
			else 
				goto PrintDataFormatError;

		//Mark end value.
			ValueString.clear();
			ValueString.append(Data, Data.find(ASCII_MINUS) + 1U, Data.length() - Data.find(ASCII_MINUS));
			_set_errno(0);
			UnsignedResult = strtoul(ValueString.c_str(), nullptr, 0);
			if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult <= UINT8_MAX))
			#if defined(PLATFORM_WIN)
				ParameterPointer->PacketHopLimits_IPv4_End = static_cast<DWORD>(UnsignedResult);
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				ParameterPointer->PacketHopLimits_IPv4_End = static_cast<int>(UnsignedResult);
			#endif
			else 
				goto PrintDataFormatError;

		//Range check
			if (ParameterPointer->PacketHopLimits_IPv4_Begin == 0)
				++ParameterPointer->PacketHopLimits_IPv4_Begin;
			if (ParameterPointer->PacketHopLimits_IPv4_Begin >= ParameterPointer->PacketHopLimits_IPv4_End)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv4 packet TTL range error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
				return false;
			}
		}
	//Value
		else {
			if (Data.length() < strlen("IPv4PacketTTL=") + UINT8_MAX_STRING_LENGTH)
			{
				_set_errno(0);
				UnsignedResult = strtoul(Data.c_str() + strlen("IPv4PacketTTL="), nullptr, 0);
				if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult <= UINT8_MAX))
				#if defined(PLATFORM_WIN)
					ParameterPointer->PacketHopLimits_IPv4_Begin = static_cast<DWORD>(UnsignedResult);
				#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
					ParameterPointer->PacketHopLimits_IPv4_Begin = static_cast<int>(UnsignedResult);
				#endif
				else 
					goto PrintDataFormatError;
			}
			else {
				goto PrintDataFormatError;
			}
		}
	}

#if defined(ENABLE_PCAP)
	else if (Data.compare(0, strlen("IPv4MainDNSTTL="), ("IPv4MainDNSTTL=")) == 0 && Data.length() > strlen("IPv4MainDNSTTL="))
	{
		if (!ReadHopLimitsData(AF_INET, Data, strlen("IPv4MainDNSTTL="), Parameter.Target_Server_IPv4_Multiple, IsFirstRead, FileIndex, Line))
			return false;
	}
	else if (Data.compare(0, strlen("IPv4AlternateDNSTTL="), ("IPv4AlternateDNSTTL=")) == 0 && Data.length() > strlen("IPv4AlternateDNSTTL="))
	{
		if (!ReadHopLimitsData(AF_INET, Data, strlen("IPv4AlternateDNSTTL="), Parameter.Target_Server_IPv4_Multiple, IsFirstRead, FileIndex, Line))
			return false;
	}
	else if (Data.compare(0, strlen("IPv6MainDNSHopLimits="), ("IPv6MainDNSHopLimits=")) == 0 && Data.length() > strlen("IPv6MainDNSHopLimits="))
	{
		if (!ReadHopLimitsData(AF_INET6, Data, strlen("IPv6MainDNSHopLimits="), Parameter.Target_Server_IPv6_Multiple, IsFirstRead, FileIndex, Line))
			return false;
	}
	else if (Data.compare(0, strlen("IPv6AlternateDNSHopLimits="), ("IPv6AlternateDNSHopLimits=")) == 0 && Data.length() > strlen("IPv6AlternateDNSHopLimits="))
	{
		if (!ReadHopLimitsData(AF_INET6, Data, strlen("IPv6AlternateDNSHopLimits="), Parameter.Target_Server_IPv6_Multiple, IsFirstRead, FileIndex, Line))
			return false;
	}
#endif

	else if (Data.compare(0, strlen("IPv6PacketHopLimits="), ("IPv6PacketHopLimits=")) == 0 && Data.length() > strlen("IPv6PacketHopLimits="))
	{
	//Range
		if (Data.find(ASCII_MINUS) != std::string::npos)
		{
		//Mark beginning value.
			std::string ValueString(Data, strlen("IPv6PacketHopLimits="), Data.find(ASCII_MINUS) - strlen("IPv6PacketHopLimits="));
			_set_errno(0);
			UnsignedResult = strtoul(ValueString.c_str(), nullptr, 0);
			if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult <= UINT8_MAX))
			#if defined(PLATFORM_WIN)
				ParameterPointer->PacketHopLimits_IPv6_Begin = static_cast<DWORD>(UnsignedResult);
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				ParameterPointer->PacketHopLimits_IPv6_Begin = static_cast<int>(UnsignedResult);
			#endif
			else 
				goto PrintDataFormatError;

		//Mark end value.
			ValueString.clear();
			ValueString.append(Data, Data.find(ASCII_MINUS) + 1U, Data.length() - Data.find(ASCII_MINUS));
			_set_errno(0);
			UnsignedResult = strtoul(ValueString.c_str(), nullptr, 0);
			if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult <= UINT8_MAX))
			#if defined(PLATFORM_WIN)
				ParameterPointer->PacketHopLimits_IPv6_End = static_cast<DWORD>(UnsignedResult);
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				ParameterPointer->PacketHopLimits_IPv6_End = static_cast<int>(UnsignedResult);
			#endif
			else 
				goto PrintDataFormatError;

		//Range check
			if (ParameterPointer->PacketHopLimits_IPv6_Begin == 0)
				++ParameterPointer->PacketHopLimits_IPv6_Begin;
			if (ParameterPointer->PacketHopLimits_IPv6_Begin >= ParameterPointer->PacketHopLimits_IPv6_End)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv6 packet Hop Limits range error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
				return false;
			}
		}
	//Value
		else {
			if (Data.length() < strlen("IPv6PacketHopLimits=") + UINT8_MAX_STRING_LENGTH)
			{
				_set_errno(0);
				UnsignedResult = strtoul(Data.c_str() + strlen("IPv6PacketHopLimits="), nullptr, 0);
				if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult <= UINT8_MAX))
				#if defined(PLATFORM_WIN)
					ParameterPointer->PacketHopLimits_IPv6_Begin = static_cast<DWORD>(UnsignedResult);
				#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
					ParameterPointer->PacketHopLimits_IPv6_Begin = static_cast<int>(UnsignedResult);
				#endif
				else 
					goto PrintDataFormatError;
			}
			else {
				goto PrintDataFormatError;
			}
		}
	}

#if defined(ENABLE_PCAP)
	else if (Data.compare(0, strlen("HopLimitsFluctuation="), ("HopLimitsFluctuation=")) == 0 && Data.length() > strlen("HopLimitsFluctuation="))
	{
		if (Data.length() < strlen("HopLimitsFluctuation=") + UINT8_MAX_STRING_LENGTH)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("HopLimitsFluctuation="), nullptr, 0);
			if (UnsignedResult > 0 && UnsignedResult < UINT8_MAX)
				ParameterPointer->HopLimitsFluctuation = static_cast<uint8_t>(UnsignedResult);
		}
		else {
			goto PrintDataFormatError;
		}
	}
#endif

	else if (Data.compare(0, strlen("ReliableOnceSocketTimeout="), ("ReliableOnceSocketTimeout=")) == 0 && 
		Data.length() > strlen("ReliableOnceSocketTimeout="))
	{
		if (Data.length() < strlen("ReliableOnceSocketTimeout=") + UINT32_MAX_STRING_LENGTH)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("ReliableOnceSocketTimeout="), nullptr, 0);
			if (UnsignedResult > SOCKET_MIN_TIMEOUT && UnsignedResult < ULONG_MAX)
			#if defined(PLATFORM_WIN)
				ParameterPointer->SocketTimeout_Reliable_Once = static_cast<DWORD>(UnsignedResult);
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			{
				ParameterPointer->SocketTimeout_Reliable_Once.tv_sec = UnsignedResult / SECOND_TO_MILLISECOND;
				ParameterPointer->SocketTimeout_Reliable_Once.tv_usec = UnsignedResult % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
			}
			#endif
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (Data.compare(0, strlen("ReliableSerialSocketTimeout="), ("ReliableSerialSocketTimeout=")) == 0 && 
		Data.length() > strlen("ReliableSerialSocketTimeout="))
	{
		if (Data.length() < strlen("ReliableSerialSocketTimeout=") + UINT32_MAX_STRING_LENGTH)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("ReliableSerialSocketTimeout="), nullptr, 0);
			if (UnsignedResult > SOCKET_MIN_TIMEOUT && UnsignedResult < ULONG_MAX)
			#if defined(PLATFORM_WIN)
				ParameterPointer->SocketTimeout_Reliable_Serial = static_cast<DWORD>(UnsignedResult);
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			{
				ParameterPointer->SocketTimeout_Reliable_Serial.tv_sec = UnsignedResult / SECOND_TO_MILLISECOND;
				ParameterPointer->SocketTimeout_Reliable_Serial.tv_usec = UnsignedResult % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
			}
			#endif
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (Data.compare(0, strlen("UnreliableOnceSocketTimeout="), ("UnreliableOnceSocketTimeout=")) == 0 && 
		Data.length() > strlen("UnreliableOnceSocketTimeout="))
	{
		if (Data.length() < strlen("UnreliableOnceSocketTimeout=") + UINT32_MAX_STRING_LENGTH)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("UnreliableOnceSocketTimeout="), nullptr, 0);
			if (UnsignedResult > SOCKET_MIN_TIMEOUT && UnsignedResult < ULONG_MAX)
			#if defined(PLATFORM_WIN)
				ParameterPointer->SocketTimeout_Unreliable_Once = static_cast<DWORD>(UnsignedResult);
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			{
				ParameterPointer->SocketTimeout_Unreliable_Once.tv_sec = UnsignedResult / SECOND_TO_MILLISECOND;
				ParameterPointer->SocketTimeout_Unreliable_Once.tv_usec = UnsignedResult % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
			}
			#endif
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (Data.compare(0, strlen("UnreliableSerialSocketTimeout="), ("UnreliableSerialSocketTimeout=")) == 0 && 
		Data.length() > strlen("UnreliableSerialSocketTimeout="))
	{
		if (Data.length() < strlen("UnreliableSerialSocketTimeout=") + UINT32_MAX_STRING_LENGTH)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("UnreliableSerialSocketTimeout="), nullptr, 0);
			if (UnsignedResult > SOCKET_MIN_TIMEOUT && UnsignedResult < ULONG_MAX)
			#if defined(PLATFORM_WIN)
				ParameterPointer->SocketTimeout_Unreliable_Serial = static_cast<DWORD>(UnsignedResult);
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			{
				ParameterPointer->SocketTimeout_Unreliable_Serial.tv_sec = UnsignedResult / SECOND_TO_MILLISECOND;
				ParameterPointer->SocketTimeout_Unreliable_Serial.tv_usec = UnsignedResult % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
			}
			#endif
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (IsFirstRead && Data.compare(0, strlen("TCPFastOpen="), ("TCPFastOpen=")) == 0 && Data.length() > strlen("TCPFastOpen="))
	{
		if (Data.length() < strlen("TCPFastOpen=") + UINT16_MAX_STRING_LENGTH)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("TCPFastOpen="), nullptr, 0);
			if (UnsignedResult > 0 && UnsignedResult < ULONG_MAX)
				Parameter.TCP_FastOpen = UnsignedResult;
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (Data.compare(0, strlen("ReceiveWaiting="), ("ReceiveWaiting=")) == 0 && Data.length() > strlen("ReceiveWaiting="))
	{
		if (Data.length() < strlen("ReceiveWaiting=") + UINT16_MAX_STRING_LENGTH)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("ReceiveWaiting="), nullptr, 0);
			if (UnsignedResult > 0 && UnsignedResult < ULONG_MAX)
				ParameterPointer->ReceiveWaiting = UnsignedResult;
		}
		else {
			goto PrintDataFormatError;
		}
	}

#if defined(ENABLE_PCAP)
	else if (Data.compare(0, strlen("ICMPTest="), ("ICMPTest=")) == 0 && Data.length() > strlen("ICMPTest="))
	{
		if (Data.length() < strlen("ICMPTest=") + UINT16_MAX_STRING_LENGTH)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("ICMPTest="), nullptr, 0);
			if (UnsignedResult >= SHORTEST_ICMP_TEST_TIME && UnsignedResult < ULONG_MAX)
				ParameterPointer->ICMP_Speed = UnsignedResult * SECOND_TO_MILLISECOND;
			else if (UnsignedResult > 0 && UnsignedResult < SHORTEST_ICMP_TEST_TIME)
				ParameterPointer->ICMP_Speed = SHORTEST_ICMP_TEST_TIME * SECOND_TO_MILLISECOND;
			else //ICMP Test disabled
				ParameterPointer->ICMP_Speed = 0;
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (Data.compare(0, strlen("DomainTest="), ("DomainTest=")) == 0 && Data.length() > strlen("DomainTest="))
	{
		if (Data.length() < strlen("DomainTest=") + UINT16_MAX_STRING_LENGTH)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("DomainTest="), nullptr, 0);
			if (UnsignedResult > SHORTEST_DOMAIN_TEST_INTERVAL_TIME && UnsignedResult < ULONG_MAX)
				ParameterPointer->DomainTest_Speed = UnsignedResult * SECOND_TO_MILLISECOND;
			else //Domain Test disabled
				ParameterPointer->DomainTest_Speed = 0;
		}
		else {
			goto PrintDataFormatError;
		}
	}
#endif

	if (IsFirstRead)
	{
		if (Data.compare(0, strlen("AlternateTimes="), ("AlternateTimes=")) == 0 && Data.length() > strlen("AlternateTimes="))
		{
			if (Data.length() < strlen("AlternateTimes=") + UINT16_MAX_STRING_LENGTH)
			{
				_set_errno(0);
				UnsignedResult = strtoul(Data.c_str() + strlen("AlternateTimes="), nullptr, 0);
				if (UnsignedResult > 0 && UnsignedResult < ULONG_MAX)
					Parameter.AlternateTimes = UnsignedResult;
			}
			else {
				goto PrintDataFormatError;
			}
		}
		else if (Data.compare(0, strlen("AlternateTimeRange="), ("AlternateTimeRange=")) == 0 && Data.length() > strlen("AlternateTimeRange="))
		{
			if (Data.length() < strlen("AlternateTimeRange=") + UINT16_MAX_STRING_LENGTH)
			{
				_set_errno(0);
				UnsignedResult = strtoul(Data.c_str() + strlen("AlternateTimeRange="), nullptr, 0);
				if (UnsignedResult >= SHORTEST_ALTERNATE_RANGE_TIME && UnsignedResult < ULONG_MAX)
					Parameter.AlternateTimeRange = UnsignedResult * SECOND_TO_MILLISECOND;
			}
			else {
				goto PrintDataFormatError;
			}
		}
		else if (Data.compare(0, strlen("AlternateResetTime="), ("AlternateResetTime=")) == 0 && Data.length() > strlen("AlternateResetTime="))
		{
			if (Data.length() < strlen("AlternateResetTime=") + UINT16_MAX_STRING_LENGTH)
			{
				_set_errno(0);
				UnsignedResult = strtoul(Data.c_str() + strlen("AlternateResetTime="), nullptr, 0);
				if (UnsignedResult >= SHORTEST_ALTERNATE_RESET_TIME && UnsignedResult < ULONG_MAX)
					Parameter.AlternateResetTime = UnsignedResult * SECOND_TO_MILLISECOND;
			}
			else {
				goto PrintDataFormatError;
			}
		}
	}

	if (Data.compare(0, strlen("MultipleRequestTimes="), ("MultipleRequestTimes=")) == 0 && Data.length() > strlen("MultipleRequestTimes="))
	{
		if (Data.length() < strlen("MultipleRequestTimes=") + UINT16_MAX_STRING_LENGTH)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("MultipleRequestTimes="), nullptr, 0);
			if (UnsignedResult > 0 && UnsignedResult < ULONG_MAX)
				ParameterPointer->MultipleRequestTimes = UnsignedResult;
		}
		else {
			goto PrintDataFormatError;
		}
	}

//[Switches] block
	if (Data.compare(0, strlen("DomainCaseConversion=1"), ("DomainCaseConversion=1")) == 0)
		ParameterPointer->DomainCaseConversion = true;

	if (IsFirstRead)
	{
		if (Data.compare(0, strlen("CompressionPointerMutation="), ("CompressionPointerMutation=")) == 0 && Data.length() > strlen("CompressionPointerMutation="))
		{
			if (Data.find(ASCII_ONE) != std::string::npos)
				Parameter.CPM_PointerToHeader = true;
			if (Data.find(ASCII_TWO) != std::string::npos)
				Parameter.CPM_PointerToRR = true;
			if (Data.find(ASCII_THREE) != std::string::npos)
				Parameter.CPM_PointerToAdditional = true;
			if (Parameter.CPM_PointerToHeader || Parameter.CPM_PointerToRR || Parameter.CPM_PointerToAdditional)
				Parameter.CompressionPointerMutation = true;
		}
		else if (Data.compare(0, strlen("EDNSLabel="), ("EDNSLabel=")) == 0)
		{
			CaseConvert(Data, true);

		//Process selection mode
			auto IsExclusionMode = true;
			if (Data.find(ASCII_MINUS) != std::string::npos)
			{
				if (Data.find(ASCII_PLUS) != std::string::npos)
					goto PrintDataFormatError;
				else 
					IsExclusionMode = false;
			}

		//Process mode check
			if (Data.compare(0, strlen("EDNSLABEL=1"), ("EDNSLABEL=1")) == 0 || 
				Data.compare(0, strlen("EDNSLABEL=ALL"), ("EDNSLABEL=ALL")) == 0)
			{
			//Enable all process
				Parameter.EDNS_Label = true;
				Parameter.EDNS_Switch_Local = true;
				Parameter.EDNS_Switch_SOCKS = true;
				Parameter.EDNS_Switch_HTTP_CONNECT = true;
				Parameter.EDNS_Switch_Direct = true;
			#if defined(ENABLE_LIBSODIUM)
				Parameter.EDNS_Switch_DNSCurve = true;
			#endif
				Parameter.EDNS_Switch_TCP = true;
				Parameter.EDNS_Switch_UDP = true;
			}

		//Local request process
			if (Data.find("LOCAL") != std::string::npos)
			{
				Parameter.EDNS_Label = true;
				Parameter.EDNS_Switch_Local = IsExclusionMode;
			}

		//SOCKS Proxy request process
			if (Data.find("SOCKS") != std::string::npos)
			{
				Parameter.EDNS_Label = true;
				Parameter.EDNS_Switch_SOCKS = IsExclusionMode;
			}

		//HTTP CONNECT Proxy request process
			if (Data.find("HTTP") != std::string::npos && Data.find("CONNECT") != std::string::npos && 
				Data.find("HTTP") < Data.find("CONNECT"))
			{
				Parameter.EDNS_Label = true;
				Parameter.EDNS_Switch_HTTP_CONNECT = IsExclusionMode;
			}

		//Direct request process
			if (Data.find("DIRECT") != std::string::npos)
			{
				Parameter.EDNS_Label = true;
				Parameter.EDNS_Switch_Direct = IsExclusionMode;
			}

		//DNSCurve request process
		#if defined(ENABLE_LIBSODIUM)
			if (Data.find("DNSCURVE") != std::string::npos || 
				Data.find("DNSCRYPT") != std::string::npos)
			{
				Parameter.EDNS_Label = true;
				Parameter.EDNS_Switch_DNSCurve = IsExclusionMode;
			}
		#endif

		//TCP request process
			if (Data.find("TCP") != std::string::npos)
			{
				Parameter.EDNS_Label = true;
				Parameter.EDNS_Switch_TCP = IsExclusionMode;
			}

		//UDP request process
			if (Data.find("UDP") != std::string::npos)
			{
				Parameter.EDNS_Label = true;
				Parameter.EDNS_Switch_UDP = IsExclusionMode;
			}
		}
		else if (Data.compare(0, strlen("EDNSClientSubnetRelay=1"), ("EDNSClientSubnetRelay=1")) == 0)
		{
			Parameter.EDNS_ClientSubnet_Relay = true;
		}
		else if (Data.compare(0, strlen("DNSSECRequest=1"), ("DNSSECRequest=1")) == 0)
		{
			Parameter.DNSSEC_Request = true;
		}
		else if (Data.compare(0, strlen("DNSSECForceRecord=1"), ("DNSSECForceRecord=1")) == 0)
		{
			Parameter.DNSSEC_ForceRecord = true;
		}
		else if (Data.compare(0, strlen("AlternateMultipleRequest=1"), ("AlternateMultipleRequest=1")) == 0)
		{
			Parameter.AlternateMultipleRequest = true;
		}
	}

	if (Data.compare(0, strlen("IPv4DoNotFragment=1"), ("IPv4DoNotFragment=1")) == 0)
	{
		ParameterPointer->DoNotFragment_IPv4 = true;
	}

#if defined(ENABLE_PCAP)
	else if (Data.compare(0, strlen("TCPDataFilter=1"), ("TCPDataFilter=1")) == 0)
	{
		ParameterPointer->PacketCheck_TCP = true;
	}
#endif

	else if (Data.compare(0, strlen("DNSDataFilter=1"), ("DNSDataFilter=1")) == 0)
	{
		ParameterPointer->PacketCheck_DNS = true;
	}
	else if (IsFirstRead && Data.compare(0, strlen("BlacklistFilter=1"), ("BlacklistFilter=1")) == 0)
	{
		Parameter.DataCheck_Blacklist = true;
	}

//[Data] block
	if (IsFirstRead)
	{
#if defined(ENABLE_PCAP)
		if (Data.compare(0, strlen("ICMPID="), ("ICMPID=")) == 0 && Data.length() > strlen("ICMPID="))
		{
			if (Data.length() < strlen("ICMPID=") + strlen(HEX_PREAMBLE_STRING) + UINT8_MAX_STRING_LENGTH)
			{
				_set_errno(0);
				UnsignedResult = strtoul(Data.c_str() + strlen("ICMPID="), nullptr, 0);
				if (UnsignedResult > 0 && UnsignedResult < ULONG_MAX)
					Parameter.ICMP_ID = htons(static_cast<uint16_t>(UnsignedResult));
			}
			else {
				goto PrintDataFormatError;
			}
		}
		else if (Data.compare(0, strlen("ICMPSequence="), ("ICMPSequence=")) == 0 && Data.length() > strlen("ICMPSequence="))
		{
			if (Data.length() < strlen("ICMPSequence=") + strlen(HEX_PREAMBLE_STRING) + UINT8_MAX_STRING_LENGTH)
			{
				_set_errno(0);
				UnsignedResult = strtoul(Data.c_str() + strlen("ICMPSequence="), nullptr, 0);
				if (UnsignedResult > 0 && UnsignedResult < ULONG_MAX)
					Parameter.ICMP_Sequence = htons(static_cast<uint16_t>(UnsignedResult));
			}
			else {
				goto PrintDataFormatError;
			}
		}
		else if (Data.compare(0, strlen("ICMPPaddingData="), ("ICMPPaddingData=")) == 0 && Data.length() > strlen("ICMPPaddingData="))
		{
			if (Data.length() > strlen("ICMPPaddingData=") + 17U && Data.length() < strlen("ICMPPaddingData=") + ICMP_PADDING_MAXSIZE - 1U)
			{
				Parameter.ICMP_PaddingLength = Data.length() - strlen("ICMPPaddingData=");
				memcpy_s(Parameter.ICMP_PaddingData, ICMP_PADDING_MAXSIZE, Data.c_str() + strlen("ICMPPaddingData="), Data.length() - strlen("ICMPPaddingData="));
			}
			else {
				goto PrintDataFormatError;
			}
		}
	}

	if (Data.compare(0, strlen("DomainTestProtocol="), ("DomainTestProtocol=")) == 0 && Data.length() > strlen("DomainTestProtocol="))
	{
		CaseConvert(Data, true);
		if (Data.find("TCP") != std::string::npos)
		{
			if (Data.find("UDP") != std::string::npos)
				ParameterPointer->DomainTest_Protocol = REQUEST_MODE_TEST::BOTH;
			else 
				ParameterPointer->DomainTest_Protocol = REQUEST_MODE_TEST::TCP;
		}
		else {
			ParameterPointer->DomainTest_Protocol = REQUEST_MODE_TEST::UDP;
		}
	}

	if (IsFirstRead)
	{
		if (Data.compare(0, strlen("DomainTestID="), ("DomainTestID=")) == 0 && Data.length() > strlen("DomainTestID="))
		{
			if (Data.length() < strlen("DomainTestID=") + strlen(HEX_PREAMBLE_STRING) + UINT8_MAX_STRING_LENGTH)
			{
				_set_errno(0);
				UnsignedResult = strtoul(Data.c_str() + strlen("DomainTestID="), nullptr, 0);
				if (UnsignedResult > 0 && UnsignedResult < ULONG_MAX)
					Parameter.DomainTest_ID = htons(static_cast<uint16_t>(UnsignedResult));
			}
			else {
				goto PrintDataFormatError;
			}
		}
		else if (Data.compare(0, strlen("DomainTestData="), ("DomainTestData=")) == 0 && Data.length() > strlen("DomainTestData="))
		{
			if (Data.length() > strlen("DomainTestData=") + DOMAIN_MINSIZE && Data.length() < strlen("DomainTestData=") + DOMAIN_DATA_MAXSIZE)
				memcpy_s(Parameter.DomainTest_Data, DOMAIN_MAXSIZE, Data.c_str() + strlen("DomainTestData="), Data.length() - strlen("DomainTestData="));
			else 
				goto PrintDataFormatError;
		}
	#endif
		if (Data.compare(0, strlen("LocalMachineServerName="), ("LocalMachineServerName=")) == 0 && Data.length() > strlen("LocalMachineServerName="))
		{
			if (Data.length() > strlen("LocalMachineServerName=") + DOMAIN_MINSIZE && Data.length() < strlen("LocalMachineServerName=") + DOMAIN_DATA_MAXSIZE)
			{
				std::unique_ptr<uint8_t[]> FQDN_String(new uint8_t[NI_MAXHOST + PADDING_RESERVED_BYTES]());
				memset(FQDN_String.get(), 0, NI_MAXHOST + PADDING_RESERVED_BYTES);
				Parameter.Local_FQDN_Length = Data.length() - strlen("LocalMachineServerName=");
				memcpy_s(FQDN_String.get(), NI_MAXHOST, Data.c_str() + strlen("LocalMachineServerName="), Parameter.Local_FQDN_Length);
				*Parameter.Local_FQDN_String = reinterpret_cast<const char *>(FQDN_String.get());
				memset(Parameter.Local_FQDN_Response, 0, DOMAIN_MAXSIZE);
				UnsignedResult = StringToPacketQuery(FQDN_String.get(), Parameter.Local_FQDN_Response);
				if (UnsignedResult > DOMAIN_MINSIZE)
				{
					Parameter.Local_FQDN_Length = UnsignedResult;
				}
				else {
					Parameter.Local_FQDN_Length = 0;
					memset(Parameter.Local_FQDN_Response, 0, DOMAIN_MAXSIZE);
					Parameter.Local_FQDN_String->clear();
				}
			}
			else {
				goto PrintDataFormatError;
			}
		}
	}

//[Proxy] block
	if (IsFirstRead)
	{
		if (Data.compare(0, strlen("SOCKSProxy=1"), ("SOCKSProxy=1")) == 0)
		{
			Parameter.SOCKS_Proxy = true;
		}
		else if (Data.compare(0, strlen("SOCKSVersion="), ("SOCKSVersion=")) == 0 && 
			Data.length() > strlen("SOCKSVersion="))
		{
			CaseConvert(Data, true);
			if (Data.find("4A") != std::string::npos) //SOCKS v4a
			{
				Parameter.SOCKS_Version = SOCKS_VERSION_CONFIG_4A;
			}
			else if (Data.find("4") != std::string::npos) //SOCKS v4
			{
				Parameter.SOCKS_Version = SOCKS_VERSION_4;
			}
			else if (Data.find("5") != std::string::npos) //SOCKS v5
			{
				Parameter.SOCKS_Version = SOCKS_VERSION_5;
			}
			else {
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::SOCKS, L"SOCKS version is not supported", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
				return false;
			}
		}
		else if (Data.compare(0, strlen("SOCKSProtocol="), ("SOCKSProtocol=")) == 0)
		{
			CaseConvert(Data, true);

		//Network layer
			if (Data.find("IPV6") != std::string::npos)
			{
				if (Data.find("IPV4") != std::string::npos)
					Parameter.SOCKS_Protocol_Network = REQUEST_MODE_NETWORK::BOTH;
				else 
					Parameter.SOCKS_Protocol_Network = REQUEST_MODE_NETWORK::IPV6;
			}
			else {
				Parameter.SOCKS_Protocol_Network = REQUEST_MODE_NETWORK::IPV4;
			}

		//Transport layer
			if (Data.find("FORCE") != std::string::npos)
				Parameter.SOCKS_Protocol_Transport = REQUEST_MODE_TRANSPORT::FORCE_UDP;
			else if (Data.find("UDP") != std::string::npos)
				Parameter.SOCKS_Protocol_Transport = REQUEST_MODE_TRANSPORT::UDP;
			else 
				Parameter.SOCKS_Protocol_Transport = REQUEST_MODE_TRANSPORT::TCP;
		}
		else if (Data.compare(0, strlen("SOCKSUDPNoHandshake=1"), ("SOCKSUDPNoHandshake=1")) == 0)
		{
			Parameter.SOCKS_UDP_NoHandshake = true;
		}
		else if (Data.compare(0, strlen("SOCKSProxyOnly=1"), ("SOCKSProxyOnly=1")) == 0)
		{
			Parameter.SOCKS_Only = true;
		}
		else if (Data.compare(0, strlen("SOCKSIPv4Address="), ("SOCKSIPv4Address=")) == 0 && 
			Data.length() > strlen("SOCKSIPv4Address="))
		{
			std::vector<DNS_SERVER_DATA> DNSServerDataTemp;
			if (!ReadMultipleAddresses(AF_INET, Data, strlen("SOCKSIPv4Address="), &DNSServerDataTemp, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line) || DNSServerDataTemp.empty())
				return false;
			else 
				Parameter.SOCKS_Address_IPv4 = DNSServerDataTemp.front().AddressData;
		}
		else if (Data.compare(0, strlen("SOCKSIPv6Address="), ("SOCKSIPv6Address=")) == 0 && 
			Data.length() > strlen("SOCKSIPv6Address="))
		{
			std::vector<DNS_SERVER_DATA> DNSServerDataTemp;
			if (!ReadMultipleAddresses(AF_INET6, Data, strlen("SOCKSIPv6Address="), &DNSServerDataTemp, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line) || DNSServerDataTemp.empty())
				return false;
			else 
				Parameter.SOCKS_Address_IPv6 = DNSServerDataTemp.front().AddressData;
		}
	}

	if (Data.compare(0, strlen("SOCKSTargetServer="), ("SOCKSTargetServer=")) == 0 && 
		Data.length() > strlen("SOCKSTargetServer="))
	{
		if (!Read_SOCKS_AddressDomain(Data, strlen("SOCKSTargetServer="), ParameterPointer, FileIndex, Line))
			return false;
	}
	else if (Data.compare(0, strlen("SOCKSUsername="), ("SOCKSUsername=")) == 0 && 
		Data.length() > strlen("SOCKSUsername="))
	{
		if (Data.length() > strlen("SOCKSUsername=") + SOCKS_USERNAME_PASSWORD_MAXNUM)
		{
			ParameterPointer->SOCKS_Username->clear();
			ParameterPointer->SOCKS_Username->append(Data, strlen("SOCKSUsername="), Data.length() - strlen("SOCKSUsername="));
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (Data.compare(0, strlen("SOCKSPassword="), ("SOCKSPassword=")) == 0 && 
		Data.length() > strlen("SOCKSPassword="))
	{
		if (Data.length() > strlen("SOCKSPassword=") + SOCKS_USERNAME_PASSWORD_MAXNUM)
		{
			ParameterPointer->SOCKS_Password->clear();
			ParameterPointer->SOCKS_Password->append(Data, strlen("SOCKSPassword="), Data.length() - strlen("SOCKSPassword="));
		}
		else {
			goto PrintDataFormatError;
		}
	}

	if (IsFirstRead)
	{
		if (Data.compare(0, strlen("HTTPCONNECTProxy=1"), ("HTTPCONNECTProxy=1")) == 0)
		{
			Parameter.HTTP_CONNECT_Proxy = true;
		}
		else if (Data.compare(0, strlen("HTTPCONNECTProtocol="), ("HTTPCONNECTProtocol=")) == 0)
		{
			CaseConvert(Data, true);
			if (Data.find("IPV6") != std::string::npos)
			{
				if (Data.find("IPV4") != std::string::npos)
					Parameter.HTTP_CONNECT_Protocol = REQUEST_MODE_NETWORK::BOTH;
				else 
					Parameter.HTTP_CONNECT_Protocol = REQUEST_MODE_NETWORK::IPV6;
			}
			else {
				Parameter.HTTP_CONNECT_Protocol = REQUEST_MODE_NETWORK::IPV4;
			}
		}
		else if (Data.compare(0, strlen("HTTPCONNECTProxyOnly=1"), ("HTTPCONNECTProxyOnly=1")) == 0)
		{
			Parameter.HTTP_CONNECT_Only = true;
		}
		else if (Data.compare(0, strlen("HTTPCONNECTIPv4Address="), ("HTTPCONNECTIPv4Address=")) == 0 && 
			Data.length() > strlen("HTTPCONNECTIPv4Address="))
		{
			std::vector<DNS_SERVER_DATA> DNSServerDataTemp;
			if (!ReadMultipleAddresses(AF_INET, Data, strlen("HTTPCONNECTIPv4Address="), &DNSServerDataTemp, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line) || DNSServerDataTemp.empty())
			{
				return false;
			}
			else {
				Parameter.HTTP_CONNECT_Address_IPv4 = DNSServerDataTemp.front().AddressData;
			#if defined(ENABLE_TLS)
			#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				Parameter.HTTP_CONNECT_TLS_AddressString_IPv4->clear();
				Parameter.HTTP_CONNECT_TLS_AddressString_IPv4->append(Data, strlen("HTTPCONNECTIPv4Address="), Data.length() - strlen("HTTPCONNECTIPv4Address="));
			#endif
			#endif
			}
		}
		else if (Data.compare(0, strlen("HTTPCONNECTIPv6Address="), ("HTTPCONNECTIPv6Address=")) == 0 && 
			Data.length() > strlen("HTTPCONNECTIPv6Address="))
		{
			std::vector<DNS_SERVER_DATA> DNSServerDataTemp;
			if (!ReadMultipleAddresses(AF_INET6, Data, strlen("HTTPCONNECTIPv6Address="), &DNSServerDataTemp, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line) || DNSServerDataTemp.empty())
			{
				return false;
			}
			else {
				Parameter.HTTP_CONNECT_Address_IPv6 = DNSServerDataTemp.front().AddressData;
			#if defined(ENABLE_TLS)
			#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				Parameter.HTTP_CONNECT_TLS_AddressString_IPv6->clear();
				Parameter.HTTP_CONNECT_TLS_AddressString_IPv6->append(Data, strlen("HTTPCONNECTIPv6Address="), Data.length() - strlen("HTTPCONNECTIPv6Address="));
			#endif
			#endif
			}
		}
	}

	if (Data.compare(0, strlen("HTTPCONNECTTargetServer="), ("HTTPCONNECTTargetServer=")) == 0 && 
		Data.length() > strlen("HTTPCONNECTTargetServer="))
	{
		ParameterPointer->HTTP_CONNECT_TargetDomain->clear();
		ParameterPointer->HTTP_CONNECT_TargetDomain->append(Data, strlen("HTTPCONNECTTargetServer="), Data.length() - strlen("HTTPCONNECTTargetServer="));
	}

#if defined(ENABLE_TLS)
	else if (IsFirstRead && Data.compare(0, strlen("HTTPCONNECTTLSHandshake=1"), ("HTTPCONNECTTLSHandshake=1")) == 0)
	{
		Parameter.HTTP_CONNECT_TLS_Handshake = true;
	}
	else if (Data.compare(0, strlen("HTTPCONNECTTLSVersion="), ("HTTPCONNECTTLSVersion=")) == 0 && 
		Data.length() > strlen("HTTPCONNECTTLSVersion="))
	{
		CaseConvert(Data, true);
		if (Data.compare(0, strlen("HTTPCONNECTTLSVERSION=1.2"), ("HTTPCONNECTTLSVERSION=1.2")) == 0) //TLS 1.2
			ParameterPointer->HTTP_CONNECT_TLS_Version = TLS_VERSION_SELECTION::VERSION_1_2;
		else if (Data.compare(0, strlen("HTTPCONNECTTLSVERSION=1.1"), ("HTTPCONNECTTLSVERSION=1.1")) == 0) //TLS 1.1
			ParameterPointer->HTTP_CONNECT_TLS_Version = TLS_VERSION_SELECTION::VERSION_1_1;
		else if (Data.compare(0, strlen("HTTPCONNECTTLSVERSION=1.0"), ("HTTPCONNECTTLSVERSION=1.0")) == 0) //TLS 1.0
			ParameterPointer->HTTP_CONNECT_TLS_Version = TLS_VERSION_SELECTION::VERSION_1_0;
		else //Auto-select
			ParameterPointer->HTTP_CONNECT_TLS_Version = TLS_VERSION_SELECTION::VERSION_AUTO;
	}
	else if (Data.compare(0, strlen("HTTPCONNECTTLSValidation=1"), ("HTTPCONNECTTLSValidation=1")) == 0)
	{
		ParameterPointer->HTTP_CONNECT_TLS_Validation = true;
	}
#endif

	if (IsFirstRead)
	{
	#if defined(ENABLE_TLS)
		if (Data.compare(0, strlen("HTTPCONNECTTLSServerNameIndication="), ("HTTPCONNECTTLSServerNameIndication=")) == 0 && 
			Data.length() > strlen("HTTPCONNECTTLSServerNameIndication=") + DOMAIN_MINSIZE)
		{
			Parameter.MBS_HTTP_CONNECT_TLS_SNI->clear();
			Parameter.MBS_HTTP_CONNECT_TLS_SNI->append(Data, strlen("HTTPCONNECTTLSServerNameIndication="), Data.length() - strlen("HTTPCONNECTTLSServerNameIndication="));
		}
	#if !defined(PLATFORM_WIN_XP)
		else if (Data.compare(0, strlen("HTTPCONNECTTLSALPN=1"), ("HTTPCONNECTTLSALPN=1")) == 0)
		{
			Parameter.HTTP_CONNECT_TLS_ALPN = true;
		}
		else 
	#endif
	#endif
		if (Data.compare(0, strlen("HTTPCONNECTVersion="), ("HTTPCONNECTVersion=")) == 0 && 
		Data.length() > strlen("HTTPCONNECTVersion="))
		{
			_set_errno(0);
			if (Data.length() > strlen("HTTPCONNECTVersion=") && Data.length() <= strlen("HTTPCONNECTVersion=") + HTTP_VERSION_MAXSIZE)
			{
				size_t Version_Major = 0, Version_Minor = 0;
				if (Data.find(ASCII_PERIOD) != std::string::npos)
				{
				//Get list data.
					std::vector<std::string> ListData;
					GetParameterListData(ListData, Data, strlen("HTTPCONNECTVersion="), Data.length(), ASCII_PERIOD, true, true);
					if (ListData.size() != HTTP_VERSION_SUPPORT_COUNT)
						goto PrintDataFormatError;

				//Convert major version.
					_set_errno(0);
					UnsignedResult = strtoul(ListData.front().c_str(), nullptr, 0);
					if ((UnsignedResult == 0 && errno == 0) || UnsignedResult < ULONG_MAX)
						Version_Major = UnsignedResult;
					else 
						goto PrintDataFormatError;

				//Convert minor version.
					_set_errno(0);
					UnsignedResult = strtoul(ListData.back().c_str(), nullptr, 0);
					if ((UnsignedResult == 0 && errno == 0) || UnsignedResult < ULONG_MAX)
						Version_Minor = UnsignedResult;
					else 
						goto PrintDataFormatError;
				}
				else if (Data.compare(0, strlen("HTTPCONNECTVersion=2"), ("HTTPCONNECTVersion=2")) == 0 && 
					Data.length() == strlen("HTTPCONNECTVersion=2")) //HTTP 2.x
				{
					Version_Major = 2U;
				}
				else if (Data.compare(0, strlen("HTTPCONNECTVersion=1"), ("HTTPCONNECTVersion=1")) == 0 && 
					Data.length() == strlen("HTTPCONNECTVersion=1")) //HTTP 1.x
				{
					Version_Major = 1U;
					Version_Minor = 1U;
				}

			//Mark to global list.
				if (Version_Major == 0)
				{
					Parameter.HTTP_CONNECT_Version = HTTP_VERSION_SELECTION::VERSION_AUTO;
				}
				else if (Version_Major == 1U) //HTTP 1.x
				{
					if (Version_Minor == 1U) //HTTP 1.1
					{
						Parameter.HTTP_CONNECT_Version = HTTP_VERSION_SELECTION::VERSION_1;
					}
					else { //HTTP 1.0 or other minor version
						PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HTTP_CONNECT, L"HTTP version is not supported", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
						return false;
					}
				}
				else if (Version_Major == 2U) //HTTP 2.x
				{
					Parameter.HTTP_CONNECT_Version = HTTP_VERSION_SELECTION::VERSION_2;
				}
				else {
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HTTP_CONNECT, L"HTTP version is not supported", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					return false;
				}
			}
			else {
				goto PrintDataFormatError;
			}
		}
	}

	if (Data.compare(0, strlen("HTTP CONNECT Header Field = "), ("HTTP CONNECT Header Field = ")) == 0 && 
		Data.length() > strlen("HTTP CONNECT Header Field = "))
	{
		if (Data.find(": ") == std::string::npos || Data.rfind(": ") == std::string::npos || Data.find(": ") != Data.rfind(": ") || 
		//These fields are prohibited by RFC 7231, Hypertext Transfer Protocol (HTTP/1.1): Semantics and Content(https://tools.ietf.org/html/rfc7231) and RFC 7540, Hypertext Transfer Protocol Version 2 (HTTP/2)(https://tools.ietf.org/html/rfc7540).
			Data.find("Connection: ") != std::string::npos || Data.find("Content-Length: ") != std::string::npos || Data.find("Proxy-Connection: ") != std::string::npos || 
			Data.find("Transfer-Encoding: ") != std::string::npos || Data.find("Upgrade: ") != std::string::npos)
		{
			goto PrintDataFormatError;
		}
		else {
			std::string HeaderField(Data, strlen("HTTP CONNECT Header Field = "), Data.find(": ") - strlen("HTTP CONNECT Header Field = "));
			ParameterPointer->HTTP_CONNECT_HeaderField->push_back(HeaderField);
			HeaderField.clear();
			HeaderField.append(Data, Data.find(": ") + strlen(": "), Data.length() - Data.find(": ") - strlen(": "));
			ParameterPointer->HTTP_CONNECT_HeaderField->push_back(HeaderField);
		}
	}
	else if (Data.compare(0, strlen("HTTPCONNECTProxyAuthorization="), ("HTTPCONNECTProxyAuthorization=")) == 0 && 
		Data.length() > strlen("HTTPCONNECTProxyAuthorization="))
	{
		std::unique_ptr<uint8_t[]> ProxyAuthorization(new uint8_t[BASE64_ENCODE_OUT_SIZE(Data.length() - strlen("HTTPCONNECTProxyAuthorization=")) + PADDING_RESERVED_BYTES]());
		memset(ProxyAuthorization.get(), 0, BASE64_ENCODE_OUT_SIZE(Data.length() - strlen("HTTPCONNECTProxyAuthorization=")) + PADDING_RESERVED_BYTES);
		Base64_Encode(reinterpret_cast<uint8_t *>(const_cast<char *>(Data.c_str() + strlen("HTTPCONNECTProxyAuthorization="))), Data.length() - strlen("HTTPCONNECTProxyAuthorization="), ProxyAuthorization.get(), BASE64_ENCODE_OUT_SIZE(Data.length() - strlen("HTTPCONNECTProxyAuthorization=")));
		*ParameterPointer->HTTP_CONNECT_ProxyAuthorization = ("Basic ");
		ParameterPointer->HTTP_CONNECT_ProxyAuthorization->append(reinterpret_cast<const char *>(ProxyAuthorization.get()));
	}

//[DNSCurve] block
#if defined(ENABLE_LIBSODIUM)
	if (IsFirstRead)
	{
		if (Data.compare(0, strlen("DNSCurve=1"), ("DNSCurve=1")) == 0)
		{
			Parameter.IsDNSCurve = true;
		}
		else if (Data.compare(0, strlen("DNSCurveProtocol="), ("DNSCurveProtocol=")) == 0)
		{
			CaseConvert(Data, true);

		//Network layer
			if (Data.find("IPV6") != std::string::npos)
			{
				if (Data.find("IPV4") != std::string::npos)
					DNSCurveParameter.DNSCurveProtocol_Network = REQUEST_MODE_NETWORK::BOTH;
				else 
					DNSCurveParameter.DNSCurveProtocol_Network = REQUEST_MODE_NETWORK::IPV6;
			}
			else {
				DNSCurveParameter.DNSCurveProtocol_Network = REQUEST_MODE_NETWORK::IPV4;
			}

		//Transport layer
			if (Data.find("FORCE") != std::string::npos)
				DNSCurveParameter.DNSCurveProtocol_Transport = REQUEST_MODE_TRANSPORT::FORCE_TCP;
			else if (Data.find("TCP") != std::string::npos)
				DNSCurveParameter.DNSCurveProtocol_Transport = REQUEST_MODE_TRANSPORT::TCP;
			else 
				DNSCurveParameter.DNSCurveProtocol_Transport = REQUEST_MODE_TRANSPORT::UDP;
		}
		else if (Data.compare(0, strlen("DNSCurvePayloadSize="), ("DNSCurvePayloadSize=")) == 0 && Data.length() > strlen("DNSCurvePayloadSize="))
		{
			if (Data.length() > strlen("DNSCurvePayloadSize=") + 2U)
			{
				_set_errno(0);
				UnsignedResult = strtoul(Data.c_str() + strlen("DNSCurvePayloadSize="), nullptr, 0);
				if (UnsignedResult > 0 && UnsignedResult < ULONG_MAX)
					DNSCurveParameter.DNSCurvePayloadSize = UnsignedResult;
			}
			else {
				goto PrintDataFormatError;
			}
		}
	}

	if (Data.compare(0, strlen("DNSCurveReliableSocketTimeout="), ("DNSCurveReliableSocketTimeout=")) == 0 && 
		Data.length() > strlen("DNSCurveReliableSocketTimeout="))
	{
		if (Data.length() < strlen("DNSCurveReliableSocketTimeout=") + UINT32_MAX_STRING_LENGTH)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("DNSCurveReliableSocketTimeout="), nullptr, 0);
			if (UnsignedResult > SOCKET_MIN_TIMEOUT && UnsignedResult < ULONG_MAX)
			#if defined(PLATFORM_WIN)
				DNSCurveParameterPointer->DNSCurve_SocketTimeout_Reliable = static_cast<DWORD>(UnsignedResult);
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			{
				DNSCurveParameterPointer->DNSCurve_SocketTimeout_Reliable.tv_sec = UnsignedResult / SECOND_TO_MILLISECOND;
				DNSCurveParameterPointer->DNSCurve_SocketTimeout_Reliable.tv_usec = UnsignedResult % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
			}
			#endif
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (Data.compare(0, strlen("DNSCurveUnreliableSocketTimeout="), ("DNSCurveUnreliableSocketTimeout=")) == 0 && 
		Data.length() > strlen("DNSCurveUnreliableSocketTimeout="))
	{
		if (Data.length() < strlen("DNSCurveUnreliableSocketTimeout=") + UINT32_MAX_STRING_LENGTH)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("DNSCurveUnreliableSocketTimeout="), nullptr, 0);
			if (UnsignedResult > SOCKET_MIN_TIMEOUT && UnsignedResult < ULONG_MAX)
			#if defined(PLATFORM_WIN)
				DNSCurveParameterPointer->DNSCurve_SocketTimeout_Unreliable = static_cast<DWORD>(UnsignedResult);
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			{
				DNSCurveParameterPointer->DNSCurve_SocketTimeout_Unreliable.tv_sec = UnsignedResult / SECOND_TO_MILLISECOND;
				DNSCurveParameterPointer->DNSCurve_SocketTimeout_Unreliable.tv_usec = UnsignedResult % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
			}
			#endif
		}
		else {
			goto PrintDataFormatError;
		}
	}

	if (IsFirstRead)
	{
		if (Data.compare(0, strlen("DNSCurveEncryption=1"), ("DNSCurveEncryption=1")) == 0)
			DNSCurveParameter.IsEncryption = true;
		else if (Data.compare(0, strlen("DNSCurveEncryptionOnly=1"), ("DNSCurveEncryptionOnly=1")) == 0)
			DNSCurveParameter.IsEncryptionOnly = true;
	}

	if (Data.compare(0, strlen("DNSCurveClientEphemeralKey=1"), ("DNSCurveClientEphemeralKey=1")) == 0)
	{
		DNSCurveParameter.IsClientEphemeralKey = true;
	}
	else if (Data.compare(0, strlen("DNSCurveKeyRecheckTime="), ("DNSCurveKeyRecheckTime=")) == 0 && Data.length() > strlen("DNSCurveKeyRecheckTime="))
	{
		if (Data.length() < strlen("DNSCurveKeyRecheckTime=") + UINT16_MAX_STRING_LENGTH)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("DNSCurveKeyRecheckTime="), nullptr, 0);
			if (UnsignedResult >= SHORTEST_DNSCURVE_RECHECK_TIME && UnsignedResult < ULONG_MAX)
				DNSCurveParameterPointer->KeyRecheckTime = UnsignedResult * SECOND_TO_MILLISECOND;
		}
		else {
			goto PrintDataFormatError;
		}
	}

//[DNSCurve Database] block
	if (IsFirstRead)
	{
		if (Data.compare(0, strlen("DNSCurve Database Name = "), ("DNSCurve Database Name = ")) == 0 && Data.length() > strlen("DNSCurve Database Name = "))
		{
		//Convert to wide string.
			if (!MBS_To_WCS_String(reinterpret_cast<const uint8_t *>(Data.c_str() + strlen("DNSCurve Database Name = ")), Data.length() - strlen("DNSCurve Database Name = "), *DNSCurveParameter.DatabaseName))
				goto PrintDataFormatError;

		//Mark database name.
		#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			DNSCurveParameter.MBS_DatabaseName->append(Data, strlen("DNSCurve Database Name = "), Data.length() - strlen("DNSCurve Database Name = "));
		#endif
		}
		else if (Data.compare(0, strlen("DNSCurveDatabaseIPv4MainDNS="), ("DNSCurveDatabaseIPv4MainDNS=")) == 0 && Data.length() > strlen("DNSCurveDatabaseIPv4MainDNS="))
		{
			DNSCurveParameter.Database_Target_Server_Main_IPv4->append(Data, strlen("DNSCurveDatabaseIPv4MainDNS="), Data.length() - strlen("DNSCurveDatabaseIPv4MainDNS="));
		}
		else if (Data.compare(0, strlen("DNSCurveDatabaseIPv4AlternateDNS="), ("DNSCurveDatabaseIPv4AlternateDNS=")) == 0 && Data.length() > strlen("DNSCurveDatabaseIPv4AlternateDNS="))
		{
			DNSCurveParameter.Database_Target_Server_Alternate_IPv4->append(Data, strlen("DNSCurveDatabaseIPv4AlternateDNS="), Data.length() - strlen("DNSCurveDatabaseIPv4AlternateDNS="));
		}
		else if (Data.compare(0, strlen("DNSCurveDatabaseIPv6MainDNS="), ("DNSCurveDatabaseIPv6MainDNS=")) == 0 && Data.length() > strlen("DNSCurveDatabaseIPv6MainDNS="))
		{
			DNSCurveParameter.Database_Target_Server_Main_IPv6->append(Data, strlen("DNSCurveDatabaseIPv6MainDNS="), Data.length() - strlen("DNSCurveDatabaseIPv6MainDNS="));
		}
		else if (Data.compare(0, strlen("DNSCurveDatabaseIPv6AlternateDNS="), ("DNSCurveDatabaseIPv6AlternateDNS=")) == 0 && Data.length() > strlen("DNSCurveDatabaseIPv6AlternateDNS="))
		{
			DNSCurveParameter.Database_Target_Server_Alternate_IPv6->append(Data, strlen("DNSCurveDatabaseIPv6AlternateDNS="), Data.length() - strlen("DNSCurveDatabaseIPv6AlternateDNS="));
		}
	}

//[DNSCurve Addresses] block
	if (IsFirstRead)
	{
		if (Data.compare(0, strlen("DNSCurveIPv4MainDNSAddress="), ("DNSCurveIPv4MainDNSAddress=")) == 0 && 
			Data.length() > strlen("DNSCurveIPv4MainDNSAddress="))
		{
			std::vector<DNS_SERVER_DATA> DNSServerDataTemp;
			if (!ReadMultipleAddresses(AF_INET, Data, strlen("DNSCurveIPv4MainDNSAddress="), &DNSServerDataTemp, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line) || DNSServerDataTemp.empty())
				return false;
			else 
				DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.AddressData = DNSServerDataTemp.front().AddressData;
		}
		else if (Data.compare(0, strlen("DNSCurveIPv4AlternateDNSAddress="), ("DNSCurveIPv4AlternateDNSAddress=")) == 0 && 
			Data.length() > strlen("DNSCurveIPv4AlternateDNSAddress="))
		{
			std::vector<DNS_SERVER_DATA> DNSServerDataTemp;
			if (!ReadMultipleAddresses(AF_INET, Data, strlen("DNSCurveIPv4AlternateDNSAddress="), &DNSServerDataTemp, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line) || DNSServerDataTemp.empty())
				return false;
			else 
				DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.AddressData = DNSServerDataTemp.front().AddressData;
		}
		else if (Data.compare(0, strlen("DNSCurveIPv6MainDNSAddress="), ("DNSCurveIPv6MainDNSAddress=")) == 0 && 
			Data.length() > strlen("DNSCurveIPv6MainDNSAddress="))
		{
			std::vector<DNS_SERVER_DATA> DNSServerDataTemp;
			if (!ReadMultipleAddresses(AF_INET6, Data, strlen("DNSCurveIPv6MainDNSAddress="), &DNSServerDataTemp, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line) || DNSServerDataTemp.empty())
				return false;
			else 
				DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.AddressData = DNSServerDataTemp.front().AddressData;
		}
		else if (Data.compare(0, strlen("DNSCurveIPv6AlternateDNSAddress="), ("DNSCurveIPv6AlternateDNSAddress=")) == 0 && 
			Data.length() > strlen("DNSCurveIPv6AlternateDNSAddress="))
		{
			std::vector<DNS_SERVER_DATA> DNSServerDataTemp;
			if (!ReadMultipleAddresses(AF_INET6, Data, strlen("DNSCurveIPv6AlternateDNSAddress="), &DNSServerDataTemp, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line) || DNSServerDataTemp.empty())
				return false;
			else 
				DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.AddressData = DNSServerDataTemp.front().AddressData;
		}
		else if (Data.compare(0, strlen("DNSCurveIPv4MainProviderName="), ("DNSCurveIPv4MainProviderName=")) == 0 && 
			Data.length() > strlen("DNSCurveIPv4MainProviderName="))
		{
			if (!ReadDNSCurveProviderName(Data, strlen("DNSCurveIPv4MainProviderName="), DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ProviderName, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
				return false;
		}
		else if (Data.compare(0, strlen("DNSCurveIPv4AlternateProviderName="), ("DNSCurveIPv4AlternateProviderName=")) == 0 && 
			Data.length() > strlen("DNSCurveIPv4AlternateProviderName="))
		{
			if (!ReadDNSCurveProviderName(Data, strlen("DNSCurveIPv4AlternateProviderName="), DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ProviderName, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
				return false;
		}
		else if (Data.compare(0, strlen("DNSCurveIPv6MainProviderName="), ("DNSCurveIPv6MainProviderName=")) == 0 && 
			Data.length() > strlen("DNSCurveIPv6MainProviderName="))
		{
			if (!ReadDNSCurveProviderName(Data, strlen("DNSCurveIPv6MainProviderName="), DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ProviderName, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
				return false;
		}
		else if (Data.compare(0, strlen("DNSCurveIPv6AlternateProviderName="), ("DNSCurveIPv6AlternateProviderName=")) == 0 && 
			Data.length() > strlen("DNSCurveIPv6AlternateProviderName="))
		{
			if (!ReadDNSCurveProviderName(Data, strlen("DNSCurveIPv6AlternateProviderName="), DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ProviderName, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
				return false;
		}
	}

//[DNSCurve Keys] block
	if (Data.compare(0, strlen("DNSCurveClientPublicKey="), ("DNSCurveClientPublicKey=")) == 0 && 
		Data.length() > strlen("DNSCurveClientPublicKey="))
	{
		if (!ReadDNSCurveKey(Data, strlen("DNSCurveClientPublicKey="), DNSCurveParameterPointer->Client_PublicKey, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
			return false;
	}
	else if (Data.compare(0, strlen("DNSCurveClientSecretKey="), ("DNSCurveClientSecretKey=")) == 0 && 
		Data.length() > strlen("DNSCurveClientSecretKey="))
	{
		if (!ReadDNSCurveKey(Data, strlen("DNSCurveClientSecretKey="), DNSCurveParameterPointer->Client_SecretKey, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
			return false;
	}
	else if (Data.compare(0, strlen("DNSCurveIPv4MainDNSPublicKey="), ("DNSCurveIPv4MainDNSPublicKey=")) == 0 && 
		Data.length() > strlen("DNSCurveIPv4MainDNSPublicKey="))
	{
		if (!ReadDNSCurveKey(Data, strlen("DNSCurveIPv4MainDNSPublicKey="), DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv4.ServerPublicKey, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
			return false;
	}
	else if (Data.compare(0, strlen("DNSCurveIPv4AlternateDNSPublicKey="), ("DNSCurveIPv4AlternateDNSPublicKey=")) == 0 && 
		Data.length() > strlen("DNSCurveIPv4AlternateDNSPublicKey="))
	{
		if (!ReadDNSCurveKey(Data, strlen("DNSCurveIPv4AlternateDNSPublicKey="), DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
			return false;
	}
	else if (Data.compare(0, strlen("DNSCurveIPv6MainDNSPublicKey="), ("DNSCurveIPv6MainDNSPublicKey=")) == 0 && 
		Data.length() > strlen("DNSCurveIPv6MainDNSPublicKey="))
	{
		if (!ReadDNSCurveKey(Data, strlen("DNSCurveIPv6MainDNSPublicKey="), DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv6.ServerPublicKey, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
			return false;
	}
	else if (Data.compare(0, strlen("DNSCurveIPv6AlternateDNSPublicKey="), ("DNSCurveIPv6AlternateDNSPublicKey=")) == 0 && 
		Data.length() > strlen("DNSCurveIPv6AlternateDNSPublicKey="))
	{
		if (!ReadDNSCurveKey(Data, strlen("DNSCurveIPv6AlternateDNSPublicKey="), DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
			return false;
	}
	else if (Data.compare(0, strlen("DNSCurveIPv4MainDNSFingerprint="), ("DNSCurveIPv4MainDNSFingerprint=")) == 0 && 
		Data.length() > strlen("DNSCurveIPv4MainDNSFingerprint="))
	{
		if (!ReadDNSCurveKey(Data, strlen("DNSCurveIPv4MainDNSFingerprint="), DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv4.ServerFingerprint, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
			return false;
	}
	else if (Data.compare(0, strlen("DNSCurveIPv4AlternateDNSFingerprint="), ("DNSCurveIPv4AlternateDNSFingerprint=")) == 0 && 
		Data.length() > strlen("DNSCurveIPv4AlternateDNSFingerprint="))
	{
		if (!ReadDNSCurveKey(Data, strlen("DNSCurveIPv4AlternateDNSFingerprint="), DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
			return false;
	}
	else if (Data.compare(0, strlen("DNSCurveIPv6MainDNSFingerprint="), ("DNSCurveIPv6MainDNSFingerprint=")) == 0 && 
		Data.length() > strlen("DNSCurveIPv6MainDNSFingerprint="))
	{
		if (!ReadDNSCurveKey(Data, strlen("DNSCurveIPv6MainDNSFingerprint="), DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv6.ServerFingerprint, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
			return false;
	}
	else if (Data.compare(0, strlen("DNSCurveIPv6AlternateDNSFingerprint="), ("DNSCurveIPv6AlternateDNSFingerprint=")) == 0 && 
		Data.length() > strlen("DNSCurveIPv6AlternateDNSFingerprint="))
	{
		if (!ReadDNSCurveKey(Data, strlen("DNSCurveIPv6AlternateDNSFingerprint="), DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
			return false;
	}

//[DNSCurve Magic Number] block
	if (Data.compare(0, strlen("DNSCurveIPv4MainReceiveMagicNumber="), ("DNSCurveIPv4MainReceiveMagicNumber=")) == 0 && 
		Data.length() > strlen("DNSCurveIPv4MainReceiveMagicNumber="))
	{
		if (!ReadDNSCurveMagicNumber(Data, strlen("DNSCurveIPv4MainReceiveMagicNumber="), DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber, FileIndex, Line))
			return false;
	}
	else if (Data.compare(0, strlen("DNSCurveIPv4AlternateReceiveMagicNumber="), ("DNSCurveIPv4AlternateReceiveMagicNumber=")) == 0 && 
		Data.length() > strlen("DNSCurveIPv4AlternateReceiveMagicNumber="))
	{
		if (!ReadDNSCurveMagicNumber(Data, strlen("DNSCurveIPv4AlternateReceiveMagicNumber="), DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber, FileIndex, Line))
			return false;
	}
	else if (Data.compare(0, strlen("DNSCurveIPv6MainReceiveMagicNumber="), ("DNSCurveIPv6MainReceiveMagicNumber=")) == 0 && 
		Data.length() > strlen("DNSCurveIPv6MainReceiveMagicNumber="))
	{
		if (!ReadDNSCurveMagicNumber(Data, strlen("DNSCurveIPv6MainReceiveMagicNumber="), DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber, FileIndex, Line))
			return false;
	}
	else if (Data.compare(0, strlen("DNSCurveIPv6AlternateReceiveMagicNumber="), ("DNSCurveIPv6AlternateReceiveMagicNumber=")) == 0 && 
		Data.length() > strlen("DNSCurveIPv6AlternateReceiveMagicNumber="))
	{
		if (!ReadDNSCurveMagicNumber(Data, strlen("DNSCurveIPv6AlternateReceiveMagicNumber="), DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber, FileIndex, Line))
			return false;
	}
	else if (Data.compare(0, strlen("DNSCurveIPv4MainDNSMagicNumber="), ("DNSCurveIPv4MainDNSMagicNumber=")) == 0 && 
		Data.length() > strlen("DNSCurveIPv4MainDNSMagicNumber="))
	{
		if (!ReadDNSCurveMagicNumber(Data, strlen("DNSCurveIPv4MainDNSMagicNumber="), DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv4.SendMagicNumber, FileIndex, Line))
			return false;
	}
	else if (Data.compare(0, strlen("DNSCurveIPv4AlternateDNSMagicNumber="), ("DNSCurveIPv4AlternateDNSMagicNumber=")) == 0 && 
		Data.length() > strlen("DNSCurveIPv4AlternateDNSMagicNumber="))
	{
		if (!ReadDNSCurveMagicNumber(Data, strlen("DNSCurveIPv4AlternateDNSMagicNumber="), DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber, FileIndex, Line))
			return false;
	}
	else if (Data.compare(0, strlen("DNSCurveIPv6MainDNSMagicNumber="), ("DNSCurveIPv6MainDNSMagicNumber=")) == 0 && 
		Data.length() > strlen("DNSCurveIPv6MainDNSMagicNumber="))
	{
		if (!ReadDNSCurveMagicNumber(Data, strlen("DNSCurveIPv6MainDNSMagicNumber="), DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv6.SendMagicNumber, FileIndex, Line))
			return false;
	}
	else if (Data.compare(0, strlen("DNSCurveIPv6AlternateDNSMagicNumber="), ("DNSCurveIPv6AlternateDNSMagicNumber=")) == 0 && 
		Data.length() > strlen("DNSCurveIPv6AlternateDNSMagicNumber="))
	{
		if (!ReadDNSCurveMagicNumber(Data, strlen("DNSCurveIPv6AlternateDNSMagicNumber="), DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber, FileIndex, Line))
			return false;
	}
#endif

	return true;

//Jump here to print data format error.
PrintDataFormatError:
	PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Data format error", errno, FileList_Config.at(FileIndex).FileName.c_str(), Line);
	return false;
}

//Read file names from data
bool ReadName_PathFile(
	std::string Data, 
	const size_t DataOffset, 
	const bool IsPath, 
	std::vector<std::wstring> * const ListData, 
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	std::vector<std::string> * const MBS_ListData, 
#endif
	const size_t FileIndex, 
	const size_t Line)
{
//Initialization
	std::vector<std::string> InnerListData;
	std::wstring WCS_NameString;
	GetParameterListData(InnerListData, Data, DataOffset, Data.length(), ASCII_VERTICAL, false, false);

//Read file path.
	if (IsPath)
	{
	//Mark all data in list.
		for (auto &StringIter:InnerListData)
		{
		//Path, file name check and add backslash or slash to the end.
		#if defined(PLATFORM_WIN)
			if (StringIter.find("\\\\") != std::string::npos)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Read file path error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
				return false;
			}
			else if (StringIter.back() != ASCII_BACKSLASH)
			{
				StringIter.append("\\");
			}
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			if (StringIter.find("//") != std::string::npos)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Read file path error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
				return false;
			}
			else if (StringIter.back() != ASCII_SLASH)
			{
				StringIter.append("/");
			}
		#endif

		//Convert to wide string.
			if (!MBS_To_WCS_String(reinterpret_cast<const uint8_t *>(StringIter.c_str()), StringIter.length(), WCS_NameString))
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Read file path error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Double backslash
		#if defined(PLATFORM_WIN)
			for (size_t Index = 0;Index < WCS_NameString.length();++Index)
			{
				if (WCS_NameString.at(Index) == (L'\\'))
				{
					WCS_NameString.insert(Index, L"\\");
					++Index;
				}
			}
		#endif

		//Mark to global list.
			for (auto InnerStringIter = GlobalRunningStatus.Path_Global->begin();InnerStringIter < GlobalRunningStatus.Path_Global->end();++InnerStringIter)
			{
				if (*InnerStringIter == WCS_NameString)
				{
					break;
				}
				else if (InnerStringIter + 1U == GlobalRunningStatus.Path_Global->end())
				{
					GlobalRunningStatus.Path_Global->push_back(WCS_NameString);
					break;
				}
			}

		#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			for (auto InnerStringIter = GlobalRunningStatus.MBS_Path_Global->begin();InnerStringIter < GlobalRunningStatus.MBS_Path_Global->end();++InnerStringIter)
			{
				if (*InnerStringIter == StringIter)
				{
					break;
				}
				else if (InnerStringIter + 1U == GlobalRunningStatus.MBS_Path_Global->end())
				{
					GlobalRunningStatus.MBS_Path_Global->push_back(StringIter);
					break;
				}
			}
		#endif
		}
	}
//Read file name.
	else {
	//Mark all data in list.
		for (const auto &StringIter:InnerListData)
		{
		//Convert to wide string.
			if (!MBS_To_WCS_String(reinterpret_cast<const uint8_t *>(StringIter.c_str()), StringIter.length(), WCS_NameString))
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Read file path error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Mark to global list.
			if (ListData->empty())
			{
				ListData->push_back(WCS_NameString);
			}
			else {
				for (auto InnerStringIter = ListData->begin();InnerStringIter != ListData->end();++InnerStringIter)
				{
					if (*InnerStringIter == WCS_NameString)
					{
						break;
					}
					else if (InnerStringIter + 1U == ListData->end())
					{
						ListData->push_back(WCS_NameString);
						break;
					}
				}
			}

		#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			if (MBS_ListData->empty())
			{
				MBS_ListData->push_back(StringIter);
			}
			else {
				for (auto InnerStringIter = MBS_ListData->begin();InnerStringIter != MBS_ListData->end();++InnerStringIter)
				{
					if (*InnerStringIter == StringIter)
					{
						break;
					}
					else if (InnerStringIter + 1U == MBS_ListData->end())
					{
						MBS_ListData->push_back(StringIter);
						break;
					}
				}
			}
		#endif
		}
	}

	return true;
}

//Read multiple addresses from data
bool ReadMultipleAddresses(
	const uint16_t Protocol, 
	std::string Data, 
	const size_t DataOffset, 
	std::vector<DNS_SERVER_DATA> * const DNSServerDataList, 
	const READ_TEXT_TYPE InputType, 
	const size_t FileIndex, 
	const size_t Line)
{
//Data server list check
	if (DNSServerDataList == nullptr)
	{
	#if defined(ENABLE_LIBSODIUM)
		if (InputType == READ_TEXT_TYPE::DNSCURVE_DATABASE || InputType == READ_TEXT_TYPE::DNSCURVE_MONITOR)
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::DNSCURVE, L"Data format error", 0, nullptr, 0);
		else 
	#endif
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Data format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);

		return false;
	}

//Initialization
	DNS_SERVER_DATA DNSServerDataTemp;
	memset(&DNSServerDataTemp, 0, sizeof(DNSServerDataTemp));
	uint8_t AddrBuffer[ADDRESS_STRING_MAXSIZE]{0};
	std::vector<std::string> ListData;
	ssize_t SignedResult = 0;
	size_t UnsignedResult = 0;
	GetParameterListData(ListData, Data, DataOffset, Data.length(), ASCII_VERTICAL, false, false);

//IPv6
	if (Protocol == AF_INET6)
	{
	//Mark all data in list.
		for (const auto &StringIter:ListData)
		{
			memset(&DNSServerDataTemp, 0, sizeof(DNSServerDataTemp));

		//IPv6 address and port check.
			if (StringIter.find(ASCII_BRACKETS_LEFT) == std::string::npos || StringIter.find(ASCII_BRACKETS_RIGHT) == std::string::npos || 
				StringIter.find("]:") == std::string::npos || StringIter.find(ASCII_BRACKETS_RIGHT) <= strlen("[") || 
				StringIter.find(ASCII_BRACKETS_RIGHT) < IPV6_SHORTEST_ADDR_STRING || StringIter.length() <= StringIter.find("]:") + strlen("]:"))
			{
			#if defined(ENABLE_LIBSODIUM)
				if (InputType == READ_TEXT_TYPE::DNSCURVE_DATABASE || InputType == READ_TEXT_TYPE::DNSCURVE_MONITOR)
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::DNSCURVE, L"IPv6 address format error", 0, nullptr, 0);
				else 
			#endif
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv6 address format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);

				return false;
			}

		//Convert IPv6 address.
			memset(AddrBuffer, 0, ADDRESS_STRING_MAXSIZE);
			memcpy_s(AddrBuffer, ADDRESS_STRING_MAXSIZE, StringIter.c_str() + strlen("["), StringIter.find(ASCII_BRACKETS_RIGHT) - strlen("["));
			if (!AddressStringToBinary(AF_INET6, AddrBuffer, &DNSServerDataTemp.AddressData.IPv6.sin6_addr, &SignedResult))
			{
			#if defined(ENABLE_LIBSODIUM)
				if (InputType == READ_TEXT_TYPE::DNSCURVE_DATABASE || InputType == READ_TEXT_TYPE::DNSCURVE_MONITOR)
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::DNSCURVE, L"IPv6 address format error", SignedResult, nullptr, 0);
				else 
			#endif
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv6 address format error", SignedResult, FileList_Config.at(FileIndex).FileName.c_str(), Line);

				return false;
			}

		//Convert IPv6 port.
			memset(AddrBuffer, 0, ADDRESS_STRING_MAXSIZE);
			memcpy_s(AddrBuffer, ADDRESS_STRING_MAXSIZE, StringIter.c_str() + StringIter.find("]:") + strlen("]:"), StringIter.length() - (StringIter.find("]:") + strlen("]:")));
			UnsignedResult = ServiceNameToBinary(AddrBuffer);
			if (UnsignedResult == 0)
			{
				_set_errno(0);
				UnsignedResult = strtoul(reinterpret_cast<const char *>(AddrBuffer), nullptr, 0);
				if (UnsignedResult == 0 || UnsignedResult >= ULONG_MAX)
				{
				#if defined(ENABLE_LIBSODIUM)
					if (InputType == READ_TEXT_TYPE::DNSCURVE_DATABASE || InputType == READ_TEXT_TYPE::DNSCURVE_MONITOR)
						PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::DNSCURVE, L"IPv6 address port error", errno, nullptr, 0);
					else 
				#endif
						PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv6 address port error", errno, FileList_Config.at(FileIndex).FileName.c_str(), Line);

					return false;
				}
			}
			DNSServerDataTemp.AddressData.IPv6.sin6_port = htons(static_cast<uint16_t>(UnsignedResult));

		//Mark to global list.
			DNSServerDataTemp.AddressData.Storage.ss_family = AF_INET6;
			if (DNSServerDataList->empty())
			{
				DNSServerDataList->push_back(DNSServerDataTemp);
			}
			else {
			//Check repeat items.
				for (const auto &DNSServerDataIter:*DNSServerDataList)
				{
					if (DNSServerDataTemp.AddressData.Storage.ss_family == DNSServerDataIter.AddressData.Storage.ss_family && 
						memcmp(&DNSServerDataTemp.AddressData.IPv6.sin6_addr, &DNSServerDataIter.AddressData.IPv6.sin6_addr, sizeof(in6_addr)) == 0 && 
						DNSServerDataTemp.AddressData.IPv6.sin6_port == DNSServerDataIter.AddressData.IPv6.sin6_port)
					{
					#if defined(ENABLE_LIBSODIUM)
						if (InputType == READ_TEXT_TYPE::DNSCURVE_DATABASE || InputType == READ_TEXT_TYPE::DNSCURVE_MONITOR)
							PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::DNSCURVE, L"DNS target error", 0, nullptr, 0);
						else 
					#endif
							PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"DNS target error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);

						return false;
					}
				}

				DNSServerDataList->push_back(DNSServerDataTemp);
			}
		}
	}
//IPv4
	else if (Protocol == AF_INET)
	{
	//Mark all data in list.
		for (const auto &StringIter:ListData)
		{
			memset(&DNSServerDataTemp, 0, sizeof(DNSServerDataTemp));

		//IPv4 address and port check.
			if (StringIter.find(ASCII_COLON) == std::string::npos || StringIter.find(ASCII_PERIOD) == std::string::npos || 
				StringIter.find(ASCII_COLON) < IPV4_SHORTEST_ADDR_STRING || StringIter.length() <= StringIter.find(ASCII_COLON) + strlen(":"))
			{
			#if defined(ENABLE_LIBSODIUM)
				if (InputType == READ_TEXT_TYPE::DNSCURVE_DATABASE || InputType == READ_TEXT_TYPE::DNSCURVE_MONITOR)
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::DNSCURVE, L"IPv4 address format error", 0, nullptr, 0);
				else 
			#endif
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv4 address format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);

				return false;
			}

		//Convert IPv4 address.
			memset(AddrBuffer, 0, ADDRESS_STRING_MAXSIZE);
			memcpy_s(AddrBuffer, ADDRESS_STRING_MAXSIZE, StringIter.c_str(), StringIter.find(ASCII_COLON));
			if (!AddressStringToBinary(AF_INET, AddrBuffer, &DNSServerDataTemp.AddressData.IPv4.sin_addr, &SignedResult))
			{
			#if defined(ENABLE_LIBSODIUM)
				if (InputType == READ_TEXT_TYPE::DNSCURVE_DATABASE || InputType == READ_TEXT_TYPE::DNSCURVE_MONITOR)
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::DNSCURVE, L"IPv4 address format error", SignedResult, nullptr, 0);
				else 
			#endif
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv4 address format error", SignedResult, FileList_Config.at(FileIndex).FileName.c_str(), Line);

				return false;
			}

		//Convert IPv4 port.
			memset(AddrBuffer, 0, ADDRESS_STRING_MAXSIZE);
			memcpy_s(AddrBuffer, ADDRESS_STRING_MAXSIZE, StringIter.c_str() + StringIter.find(ASCII_COLON) + strlen(":"), StringIter.length() - (StringIter.find(ASCII_COLON) + strlen(":")));
			UnsignedResult = ServiceNameToBinary(AddrBuffer);
			if (UnsignedResult == 0)
			{
				_set_errno(0);
				UnsignedResult = strtoul(reinterpret_cast<const char *>(AddrBuffer), nullptr, 0);
				if (UnsignedResult == 0 || UnsignedResult >= ULONG_MAX)
				{
				#if defined(ENABLE_LIBSODIUM)
					if (InputType == READ_TEXT_TYPE::DNSCURVE_DATABASE || InputType == READ_TEXT_TYPE::DNSCURVE_MONITOR)
						PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::DNSCURVE, L"IPv4 address port error", errno, nullptr, 0);
					else 
				#endif
						PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv4 address port error", errno, FileList_Config.at(FileIndex).FileName.c_str(), Line);

					return false;
				}
			}
			DNSServerDataTemp.AddressData.IPv4.sin_port = htons(static_cast<uint16_t>(UnsignedResult));

		//Mark to global list.
			DNSServerDataTemp.AddressData.Storage.ss_family = AF_INET;
			if (DNSServerDataList->empty())
			{
				DNSServerDataList->push_back(DNSServerDataTemp);
			}
			else {
			//Check repeat items.
				for (const auto &DNSServerDataIter:*DNSServerDataList)
				{
					if (DNSServerDataTemp.AddressData.Storage.ss_family == DNSServerDataIter.AddressData.Storage.ss_family && 
						DNSServerDataTemp.AddressData.IPv4.sin_addr.s_addr == DNSServerDataIter.AddressData.IPv4.sin_addr.s_addr && 
						DNSServerDataTemp.AddressData.IPv4.sin_port == DNSServerDataIter.AddressData.IPv4.sin_port)
					{
					#if defined(ENABLE_LIBSODIUM)
						if (InputType == READ_TEXT_TYPE::DNSCURVE_DATABASE || InputType == READ_TEXT_TYPE::DNSCURVE_MONITOR)
							PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::DNSCURVE, L"DNS target error", 0, nullptr, 0);
						else 
					#endif
							PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"DNS target error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);

						return false;
					}
				}

				DNSServerDataList->push_back(DNSServerDataTemp);
			}
		}
	}
	else {
	#if defined(ENABLE_LIBSODIUM)
		if (InputType == READ_TEXT_TYPE::DNSCURVE_DATABASE || InputType == READ_TEXT_TYPE::DNSCURVE_MONITOR)
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::DNSCURVE, L"Data format error", 0, nullptr, 0);
		else 
	#endif
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Data format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);

		return false;
	}

	return true;
}

//Read address or domain of SOCKS
bool Read_SOCKS_AddressDomain(
	std::string Data, 
	const size_t DataOffset, 
	CONFIGURATION_TABLE * const ParameterPointer, 
	const size_t FileIndex, 
	const size_t Line)
{
//Data check
	if (Data.find(ASCII_COLON) == std::string::npos)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Data length error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Initialization
	uint8_t AddrBuffer[ADDRESS_STRING_MAXSIZE]{0};
	ssize_t SignedResult = 0;
	size_t UnsignedResult = 0;

//IPv6
	if (Data.find(ASCII_BRACKETS_LEFT) != std::string::npos || Data.find(ASCII_BRACKETS_RIGHT) != std::string::npos)
	{
		if (Data.find("]:") == std::string::npos || Data.find(ASCII_BRACKETS_RIGHT) <= DataOffset + strlen("[") || 
			Data.find(ASCII_BRACKETS_RIGHT) < DataOffset + IPV6_SHORTEST_ADDR_STRING || Data.length() <= Data.find("]:") + strlen("]:"))
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv6 address format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
		else {
		//Convert IPv6 address.
			memcpy_s(AddrBuffer, ADDRESS_STRING_MAXSIZE, Data.c_str() + DataOffset + strlen("["), Data.find(ASCII_BRACKETS_RIGHT) - (DataOffset + strlen("[")));
			if (!AddressStringToBinary(AF_INET6, AddrBuffer, &ParameterPointer->SOCKS_TargetServer.IPv6.sin6_addr, &SignedResult))
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv6 address format error", SignedResult, FileList_Config.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Convert IPv6 port.
			memset(AddrBuffer, 0, ADDRESS_STRING_MAXSIZE);
			memcpy_s(AddrBuffer, ADDRESS_STRING_MAXSIZE, Data.c_str() + Data.find("]:") + strlen("]:"), Data.length() - (Data.find("]:") + strlen("]:")));
			UnsignedResult = ServiceNameToBinary(AddrBuffer);
			if (UnsignedResult == 0)
			{
				_set_errno(0);
				UnsignedResult = strtoul(reinterpret_cast<const char *>(AddrBuffer), nullptr, 0);
				if (UnsignedResult == 0 || UnsignedResult >= ULONG_MAX)
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv6 address port error", errno, FileList_Config.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
			}

			ParameterPointer->SOCKS_TargetServer.IPv6.sin6_port = htons(static_cast<uint16_t>(UnsignedResult));
			ParameterPointer->SOCKS_TargetServer.Storage.ss_family = AF_INET6;
		}
	}
	else {
	//Format error
		if (Data.find(ASCII_PERIOD) == std::string::npos)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv6 address format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
			return false;
		}

	//Scan data.
		auto IsDomain = false;
		for (UnsignedResult = DataOffset;UnsignedResult < Data.length();++UnsignedResult)
		{
			if ((Data.at(UnsignedResult) >= ASCII_UPPERCASE_A && Data.at(UnsignedResult) <= ASCII_UPPERCASE_Z) || 
				(Data.at(UnsignedResult) >= ASCII_LOWERCASE_A && Data.at(UnsignedResult) <= ASCII_LOWERCASE_Z))
			{
				IsDomain = true;
				break;
			}
		}

	//Domain
		if (IsDomain)
		{
		//Convert domain.
			ParameterPointer->SOCKS_TargetDomain->clear();
			ParameterPointer->SOCKS_TargetDomain->append(Data, DataOffset, Data.find(ASCII_COLON) - DataOffset);

		//Convert port.
			memcpy_s(AddrBuffer, ADDRESS_STRING_MAXSIZE, Data.c_str() + Data.find(ASCII_COLON) + strlen(":"), Data.length() - (Data.find(ASCII_COLON) + strlen(":")));
			UnsignedResult = ServiceNameToBinary(AddrBuffer);
			if (UnsignedResult == 0)
			{
				_set_errno(0);
				UnsignedResult = strtoul(reinterpret_cast<const char *>(AddrBuffer), nullptr, 0);
				if (UnsignedResult == 0 || UnsignedResult >= ULONG_MAX)
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv4 address port error", errno, FileList_Config.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
			}

			ParameterPointer->SOCKS_TargetDomain_Port = htons(static_cast<uint16_t>(UnsignedResult));
		}
	//IPv4
		else {
		//IPv4 address and port check.
			if (Data.find(ASCII_COLON) == std::string::npos || Data.find(ASCII_PERIOD) == std::string::npos || 
				Data.find(ASCII_COLON) < DataOffset + IPV4_SHORTEST_ADDR_STRING || Data.length() <= Data.find(ASCII_COLON) + strlen(":"))
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv4 address format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Convert IPv4 address.
			memcpy_s(AddrBuffer, ADDRESS_STRING_MAXSIZE, Data.c_str() + DataOffset, Data.find(ASCII_COLON) - DataOffset);
			if (!AddressStringToBinary(AF_INET, AddrBuffer, &ParameterPointer->SOCKS_TargetServer.IPv4.sin_addr, &SignedResult))
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv4 address format error", SignedResult, FileList_Config.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Convert IPv4 port.
			memset(AddrBuffer, 0, ADDRESS_STRING_MAXSIZE);
			memcpy_s(AddrBuffer, ADDRESS_STRING_MAXSIZE, Data.c_str() + Data.find(ASCII_COLON) + strlen(":"), Data.length() - (Data.find(ASCII_COLON) + strlen(":")));
			UnsignedResult = ServiceNameToBinary(AddrBuffer);
			if (UnsignedResult == 0)
			{
				_set_errno(0);
				UnsignedResult = strtoul(reinterpret_cast<const char *>(AddrBuffer), nullptr, 0);
				if (UnsignedResult == 0 || UnsignedResult >= ULONG_MAX)
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv4 address port error", errno, FileList_Config.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
			}

			ParameterPointer->SOCKS_TargetServer.IPv4.sin_port = htons(static_cast<uint16_t>(UnsignedResult));
			ParameterPointer->SOCKS_TargetServer.Storage.ss_family = AF_INET;
		}
	}

	return true;
}

//Read TTL or Hop Limits from data
#if defined(ENABLE_PCAP)
bool ReadHopLimitsData(
	const uint16_t Protocol, 
	std::string Data, 
	const size_t DataOffset, 
	std::vector<DNS_SERVER_DATA> * const DNSServerDataList, 
	const bool IsFirstRead, 
	const size_t FileIndex, 
	const size_t Line)
{
//DNS server list check
	if (DNSServerDataList == nullptr)
		return false;
	else if (DNSServerDataList->empty() && 
		((Protocol == AF_INET6 && Parameter.Target_Server_Main_IPv6.AddressData.Storage.ss_family == 0) || 
		(Protocol == AF_INET && Parameter.Target_Server_Main_IPv4.AddressData.Storage.ss_family == 0)))
			return true;

//Initialization
	std::vector<std::string> ListData;
	GetParameterListData(ListData, Data, DataOffset, Data.length(), ASCII_VERTICAL, false, false);
	size_t UnsignedResult = 0;

//Mark all data in list.
	for (const auto &StringIter:ListData)
	{
		_set_errno(0);
		UnsignedResult = strtoul(StringIter.c_str(), nullptr, 0);
		if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult < UINT8_MAX))
		{
			if (Protocol == AF_INET6)
			{
			//Monitor mode
				if (!IsFirstRead)
				{
					if (ParameterHopLimitsIndex[NETWORK_LAYER_TYPE_IPV6] == 0)
						Parameter.Target_Server_Main_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_Assign = static_cast<uint8_t>(UnsignedResult);
					else if (ParameterHopLimitsIndex[NETWORK_LAYER_TYPE_IPV6] == 1U)
						Parameter.Target_Server_Alternate_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_Assign = static_cast<uint8_t>(UnsignedResult);
					else if (!DNSServerDataList->empty() && ParameterHopLimitsIndex[NETWORK_LAYER_TYPE_IPV6] - 2U < DNSServerDataList->size())
						DNSServerDataList->at(ParameterHopLimitsIndex[NETWORK_LAYER_TYPE_IPV6] - 2U).ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_Assign = static_cast<uint8_t>(UnsignedResult);
					else 
						goto PrintDataFormatError;

					++ParameterHopLimitsIndex[NETWORK_LAYER_TYPE_IPV6];
				}
			//Normal mode
				else if (!DNSServerDataList->empty() && ParameterHopLimitsIndex[NETWORK_LAYER_TYPE_IPV6] < DNSServerDataList->size())
				{
					DNSServerDataList->at(ParameterHopLimitsIndex[NETWORK_LAYER_TYPE_IPV6]).ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_Assign = static_cast<uint8_t>(UnsignedResult);
					++ParameterHopLimitsIndex[NETWORK_LAYER_TYPE_IPV6];
				}
				else {
					goto PrintDataFormatError;
				}
			}
			else if (Protocol == AF_INET)
			{
			//Monitor mode
				if (!IsFirstRead)
				{
					if (ParameterHopLimitsIndex[NETWORK_LAYER_TYPE_IPV4] == 0)
						Parameter.Target_Server_Main_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_Assign = static_cast<uint8_t>(UnsignedResult);
					else if (ParameterHopLimitsIndex[NETWORK_LAYER_TYPE_IPV4] == 1U)
						Parameter.Target_Server_Alternate_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_Assign = static_cast<uint8_t>(UnsignedResult);
					else if (!DNSServerDataList->empty() && ParameterHopLimitsIndex[NETWORK_LAYER_TYPE_IPV4] - 2U < DNSServerDataList->size())
						DNSServerDataList->at(ParameterHopLimitsIndex[NETWORK_LAYER_TYPE_IPV4] - 2U).ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_Assign = static_cast<uint8_t>(UnsignedResult);
					else 
						goto PrintDataFormatError;

					++ParameterHopLimitsIndex[NETWORK_LAYER_TYPE_IPV4];
				}
			//Normal mode
				else if (!DNSServerDataList->empty() && ParameterHopLimitsIndex[NETWORK_LAYER_TYPE_IPV4] < DNSServerDataList->size())
				{
					DNSServerDataList->at(ParameterHopLimitsIndex[NETWORK_LAYER_TYPE_IPV4]).ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_Assign = static_cast<uint8_t>(UnsignedResult);
					++ParameterHopLimitsIndex[NETWORK_LAYER_TYPE_IPV4];
				}
				else {
					goto PrintDataFormatError;
				}
			}
			else {
				goto PrintDataFormatError;
			}
		}
		else {
			goto PrintDataFormatError;
		}
	}

	return true;

//Jump here to print data format error.
PrintDataFormatError:
	PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Data format error", errno, FileList_Config.at(FileIndex).FileName.c_str(), Line);
	return false;
}
#endif

//Read database
#if defined(ENABLE_LIBSODIUM)
void ReadDNSCurveDatabaseData(
	std::string Data, 
	const READ_TEXT_TYPE InputType, 
	const size_t FileIndex, 
	const size_t Line)
{
//Initialization
	DNSCURVE_CONFIGURATION_TABLE *DNSCurveParameterPointer = nullptr;
	if (InputType == READ_TEXT_TYPE::DNSCURVE_DATABASE)
		DNSCurveParameterPointer = &DNSCurveParameter;
	else if (InputType == READ_TEXT_TYPE::DNSCURVE_MONITOR)
		DNSCurveParameterPointer = &DNSCurveParameterModificating;
	if (DNSCurveParameterPointer == nullptr || DNSCurveParameterPointer->Database_LineData == nullptr)
		return;

//File title check
//The title data is <Name,"Full name","Description","Location","Coordinates",URL,Version,DNSSEC validation,No logs,Namecoin,Resolver address,Provider name,Provider public key,Provider public key TXT record>.
	if (Data.compare(0, strlen("Name,"), ("Name,")) == 0 || Data.find(",\"Full name\",") != std::string::npos || Data.find(",\"Description\",") != std::string::npos || 
		Data.find(",\"Location\",") != std::string::npos || Data.find(",\"Coordinates\",") != std::string::npos || Data.find(",URL,") != std::string::npos || 
		Data.find(",Version,") != std::string::npos || Data.find(",DNSSEC validation,") != std::string::npos || Data.find(",No logs,") != std::string::npos || 
		Data.find(",Namecoin,") != std::string::npos || Data.find(",Resolver address,") != std::string::npos || Data.find(",Provider name,") != std::string::npos || 
		Data.find(",Provider public key,") != std::string::npos || Data.find(",Provider public key TXT record,") != std::string::npos)
			return;

//Remove all commas in data.
	auto IsDataItem = false;
	for (size_t Index = 1U;Index < Data.length();++Index)
	{
		if (!IsDataItem && Data.at(Index) == ASCII_QUOTATION_MARK && Data.at(Index - 1U) == ASCII_COMMA) //",\""
		{
			IsDataItem = true;
		}
		else if (IsDataItem && Data.at(Index) == ASCII_COMMA)
		{
			if (Data.at(Index - 1U) == ASCII_QUOTATION_MARK) //"\","
				IsDataItem = false;
			else 
				Data.erase(Index, 1U);
		}
	}

//Mark all list data.
	std::vector<std::string> LineDataTemp;
	GetParameterListData(LineDataTemp, Data, 0, Data.length(), ASCII_COMMA, false, true);
	if (LineDataTemp.size() < DNSCRYPT_DATABASE_ITEM_MINNUM)
		PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::DNSCURVE, L"Data format error", 0, FileList_DNSCurveDatabase.at(FileIndex).FileName.c_str(), Line);
	else 
		DNSCurveParameterPointer->Database_LineData->push_back(LineDataTemp);

	return;
}

//Read database item data
bool ReadDNSCurveDatabaseItem(
	const READ_TEXT_TYPE InputType)
{
//Initialization
	DNSCURVE_CONFIGURATION_TABLE *DNSCurveParameterPointer = nullptr;
	if (InputType == READ_TEXT_TYPE::DNSCURVE_DATABASE)
		DNSCurveParameterPointer = &DNSCurveParameter;
	else if (InputType == READ_TEXT_TYPE::DNSCURVE_MONITOR)
		DNSCurveParameterPointer = &DNSCurveParameterModificating;
	if (DNSCurveParameterPointer == nullptr || DNSCurveParameterPointer->Database_LineData == nullptr)
		return false;

//Read all list database data.
	auto IsIPv6_Main = false, IsIPv6_Alternate = false, IsIPv4_Main = false, IsIPv4_Alternate = false;
	for (auto StringIter:*DNSCurveParameterPointer->Database_LineData)
	{
		if (StringIter.size() >= DNSCRYPT_DATABASE_ITEM_MINNUM && 
			!StringIter.at(DNSCRYPT_DATABASE_ADDRESS_LOCATION).empty() && //DNSCurve Address location
			!StringIter.at(DNSCRYPT_DATABASE_PROVIDER_NAME_LOCATION).empty() && //Provider Name location
			!StringIter.at(DNSCRYPT_DATABASE_PROVIDER_KEY_LOCATION).empty()) //Provider Public Key location
		{
		//IPv6 Main
			if (!IsIPv6_Main && DNSCurveParameter.Database_Target_Server_Main_IPv6 != nullptr && StringIter.front() == *DNSCurveParameter.Database_Target_Server_Main_IPv6)
			{
			//Set default port.
				if (StringIter.at(DNSCRYPT_DATABASE_ADDRESS_LOCATION).find("]:") == std::string::npos)
					StringIter.at(DNSCRYPT_DATABASE_ADDRESS_LOCATION).append(DNSCURVE_DEFAULT_PORT_STRING);

			//DNSCurve Address location, Provider Name location and Provider Public Key location
				std::vector<DNS_SERVER_DATA> DNSServerDataTemp;
				if (!ReadMultipleAddresses(AF_INET6, StringIter.at(DNSCRYPT_DATABASE_ADDRESS_LOCATION).c_str(), 0, &DNSServerDataTemp, InputType, 0, 0) || 
					DNSServerDataTemp.empty() || 
					(InputType == READ_TEXT_TYPE::DNSCURVE_DATABASE && 
					!ReadDNSCurveProviderName(StringIter.at(DNSCRYPT_DATABASE_PROVIDER_NAME_LOCATION).c_str(), 0, DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ProviderName, InputType, 0, 0)) || 
					!ReadDNSCurveKey(StringIter.at(DNSCRYPT_DATABASE_PROVIDER_KEY_LOCATION).c_str(), 0, DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv6.ServerPublicKey, InputType, 0, 0))
				{
					std::wstring Message;
					DNSCurvePrintLog(DNSCURVE_SERVER_TYPE::MAIN_IPV6, Message);
					if (!Message.empty())
					{
						Message.append(L"Data format error");
						PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::DNSCURVE, Message.c_str(), 0, nullptr, 0);
					}
					else {
						PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::DNSCURVE, L"Data format error", 0, nullptr, 0);
					}

					return false;
				}
				else {
					DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv6.AddressData = DNSServerDataTemp.front().AddressData;
					IsIPv6_Main = true;
				}
			}
		//IPv6 Alternate
			else if (!IsIPv6_Alternate && DNSCurveParameter.Database_Target_Server_Alternate_IPv6 != nullptr && StringIter.front() == *DNSCurveParameter.Database_Target_Server_Alternate_IPv6)
			{
			//Set default port.
				if (StringIter.at(DNSCRYPT_DATABASE_ADDRESS_LOCATION).find("]:") == std::string::npos)
					StringIter.at(DNSCRYPT_DATABASE_ADDRESS_LOCATION).append(DNSCURVE_DEFAULT_PORT_STRING);

			//DNSCurve Address location, Provider Name location and Provider Public Key location
				std::vector<DNS_SERVER_DATA> DNSServerDataTemp;
				if (!ReadMultipleAddresses(AF_INET6, StringIter.at(DNSCRYPT_DATABASE_ADDRESS_LOCATION).c_str(), 0, &DNSServerDataTemp, InputType, 0, 0) || 
					DNSServerDataTemp.empty() || 
					(InputType == READ_TEXT_TYPE::DNSCURVE_DATABASE && 
					!ReadDNSCurveProviderName(StringIter.at(DNSCRYPT_DATABASE_PROVIDER_NAME_LOCATION).c_str(), 0, DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ProviderName, InputType, 0, 0)) || 
					!ReadDNSCurveKey(StringIter.at(DNSCRYPT_DATABASE_PROVIDER_KEY_LOCATION).c_str(), 0, DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey, InputType, 0, 0))
				{
					std::wstring Message;
					DNSCurvePrintLog(DNSCURVE_SERVER_TYPE::ALTERNATE_IPV6, Message);
					if (!Message.empty())
					{
						Message.append(L"Data format error");
						PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::DNSCURVE, Message.c_str(), 0, nullptr, 0);
					}
					else {
						PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::DNSCURVE, L"Data format error", 0, nullptr, 0);
					}

					return false;
				}
				else {
					DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv6.AddressData = DNSServerDataTemp.front().AddressData;
					IsIPv6_Alternate = true;
				}
			}
		//IPv4 Main
			else if (!IsIPv4_Main && DNSCurveParameter.Database_Target_Server_Main_IPv4 != nullptr && StringIter.front() == *DNSCurveParameter.Database_Target_Server_Main_IPv4)
			{
			//Set default port.
				if (StringIter.at(DNSCRYPT_DATABASE_ADDRESS_LOCATION).find(ASCII_COLON) == std::string::npos)
					StringIter.at(DNSCRYPT_DATABASE_ADDRESS_LOCATION).append(DNSCURVE_DEFAULT_PORT_STRING);

			//DNSCurve Address location, Provider Name location and Provider Public Key location
				std::vector<DNS_SERVER_DATA> DNSServerDataTemp;
				if (!ReadMultipleAddresses(AF_INET, StringIter.at(DNSCRYPT_DATABASE_ADDRESS_LOCATION).c_str(), 0, &DNSServerDataTemp, InputType, 0, 0) || 
					DNSServerDataTemp.empty() || 
					(InputType == READ_TEXT_TYPE::DNSCURVE_DATABASE && 
					!ReadDNSCurveProviderName(StringIter.at(DNSCRYPT_DATABASE_PROVIDER_NAME_LOCATION).c_str(), 0, DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ProviderName, InputType, 0, 0)) || 
					!ReadDNSCurveKey(StringIter.at(DNSCRYPT_DATABASE_PROVIDER_KEY_LOCATION).c_str(), 0, DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv4.ServerPublicKey, InputType, 0, 0))
				{
					std::wstring Message;
					DNSCurvePrintLog(DNSCURVE_SERVER_TYPE::MAIN_IPV4, Message);
					if (!Message.empty())
					{
						Message.append(L"Data format error");
						PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::DNSCURVE, Message.c_str(), 0, nullptr, 0);
					}
					else {
						PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::DNSCURVE, L"Data format error", 0, nullptr, 0);
					}

					return false;
				}
				else {
					DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv4.AddressData = DNSServerDataTemp.front().AddressData;
					IsIPv4_Main = true;
				}
			}
		//IPv4 Alternate
			else if (!IsIPv4_Alternate && DNSCurveParameter.Database_Target_Server_Alternate_IPv4 != nullptr && StringIter.front() == *DNSCurveParameter.Database_Target_Server_Alternate_IPv4)
			{
			//Set default port.
				if (StringIter.at(DNSCRYPT_DATABASE_ADDRESS_LOCATION).find(ASCII_COLON) == std::string::npos)
					StringIter.at(DNSCRYPT_DATABASE_ADDRESS_LOCATION).append(DNSCURVE_DEFAULT_PORT_STRING);

			//DNSCurve Address location, Provider Name location and Provider Public Key location
				std::vector<DNS_SERVER_DATA> DNSServerDataTemp;
				if (!ReadMultipleAddresses(AF_INET, StringIter.at(DNSCRYPT_DATABASE_ADDRESS_LOCATION).c_str(), 0, &DNSServerDataTemp, InputType, 0, 0) || 
					DNSServerDataTemp.empty() || 
					(InputType == READ_TEXT_TYPE::DNSCURVE_DATABASE && 
					!ReadDNSCurveProviderName(StringIter.at(DNSCRYPT_DATABASE_PROVIDER_NAME_LOCATION).c_str(), 0, DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ProviderName, InputType, 0, 0)) || 
					!ReadDNSCurveKey(StringIter.at(DNSCRYPT_DATABASE_PROVIDER_KEY_LOCATION).c_str(), 0, DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey, InputType, 0, 0))
				{
					std::wstring Message;
					DNSCurvePrintLog(DNSCURVE_SERVER_TYPE::ALTERNATE_IPV4, Message);
					if (!Message.empty())
					{
						Message.append(L"Data format error");
						PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::DNSCURVE, Message.c_str(), 0, nullptr, 0);
					}
					else {
						PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::DNSCURVE, L"Data format error", 0, nullptr, 0);
					}

					return false;
				}
				else {
					DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv4.AddressData = DNSServerDataTemp.front().AddressData;
					IsIPv4_Alternate = true;
				}
			}

		//Completed check
			if (IsIPv6_Main && IsIPv6_Alternate && IsIPv4_Main && IsIPv4_Alternate)
				break;
		}
	}

	return true;
}

//Read Provider Name of DNSCurve server
bool ReadDNSCurveProviderName(
	std::string Data, 
	const size_t DataOffset, 
	uint8_t * const ProviderNameData, 
	const READ_TEXT_TYPE InputType, 
	const size_t FileIndex, 
	const size_t Line)
{
	sodium_memzero(ProviderNameData, DOMAIN_MAXSIZE);
	if (Data.length() > DataOffset + DOMAIN_MINSIZE && Data.length() < DataOffset + DOMAIN_DATA_MAXSIZE)
	{
		for (auto Index = DataOffset;Index < Data.length() - DataOffset;++Index)
		{
			for (size_t InnerIndex = 0;InnerIndex < strnlen_s(reinterpret_cast<const char *>(GlobalRunningStatus.DomainTable), DOMAIN_MAXSIZE);++InnerIndex)
			{
				if (InnerIndex + 1U == strnlen_s(reinterpret_cast<const char *>(GlobalRunningStatus.DomainTable), DOMAIN_MAXSIZE) && Data.at(Index) != *(GlobalRunningStatus.DomainTable + InnerIndex))
				{
					if (InputType == READ_TEXT_TYPE::DNSCURVE_DATABASE || InputType == READ_TEXT_TYPE::DNSCURVE_MONITOR)
						PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::DNSCURVE, L"DNSCurve Provider Name error", 0, nullptr, 0);
					else 
						PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"DNSCurve Provider Name error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);

					return false;
				}

				if (Data.at(Index) == *(GlobalRunningStatus.DomainTable + InnerIndex))
					break;
			}
		}

		memcpy_s(ProviderNameData, DOMAIN_MAXSIZE, Data.c_str() + DataOffset, Data.length() - DataOffset);
	}
	else {
		if (InputType == READ_TEXT_TYPE::DNSCURVE_DATABASE || InputType == READ_TEXT_TYPE::DNSCURVE_MONITOR)
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::DNSCURVE, L"Data length error", 0, nullptr, 0);
		else 
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Data length error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);

		return false;
	}

	return true;
}

//Read DNSCurve secret keys, public keys and fingerprints
bool ReadDNSCurveKey(
	std::string Data, 
	const size_t DataOffset, 
	uint8_t * const KeyData, 
	const READ_TEXT_TYPE InputType, 
	const size_t FileIndex, 
	const size_t Line)
{
	memset(KeyData, 0, crypto_box_SECRETKEYBYTES);

//Initialization
	const char *ResultPointer = nullptr;
	size_t ResultLength = 0;

//Convert hex format to binary.
	if (Data.length() > DataOffset + crypto_box_PUBLICKEYBYTES * 2U && Data.length() < DataOffset + crypto_box_PUBLICKEYBYTES * 3U)
	{
		uint8_t AddrBuffer[ADDRESS_STRING_MAXSIZE]{0};
		if (sodium_hex2bin(AddrBuffer, ADDRESS_STRING_MAXSIZE, Data.c_str() + DataOffset, Data.length() - DataOffset, (": "), &ResultLength, &ResultPointer) == 0 && 
			ResultPointer != nullptr && ResultLength == crypto_box_PUBLICKEYBYTES)
		{
			memcpy_s(KeyData, crypto_box_SECRETKEYBYTES, AddrBuffer, crypto_box_PUBLICKEYBYTES);
		}
		else {
			if (InputType == READ_TEXT_TYPE::DNSCURVE_DATABASE || InputType == READ_TEXT_TYPE::DNSCURVE_MONITOR)
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::DNSCURVE, L"DNSCurve Key format error", 0, nullptr, 0);
			else 
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"DNSCurve Key format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);

			return false;
		}
	}
	else {
		if (InputType == READ_TEXT_TYPE::DNSCURVE_DATABASE || InputType == READ_TEXT_TYPE::DNSCURVE_MONITOR)
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::DNSCURVE, L"Data length error", 0, nullptr, 0);
		else 
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Data length error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);

		return false;
	}

	return true;
}

//Read DNSCurve magic number
bool ReadDNSCurveMagicNumber(
	std::string Data, 
	const size_t DataOffset, 
	uint8_t * const MagicNumber, 
	const size_t FileIndex, 
	const size_t Line)
{
	memset(MagicNumber, 0, DNSCURVE_MAGIC_QUERY_LEN);

//Binary format
	if (Data.find(HEX_PREAMBLE_STRING) == DataOffset && Data.length() == DataOffset + DNSCURVE_MAGIC_QUERY_HEX_LEN + strlen(HEX_PREAMBLE_STRING))
	{
		const char *ResultPointer = nullptr;
		size_t ResultLength = 0;

	//Convert hex format to binary.
		if (sodium_hex2bin(MagicNumber, DNSCURVE_MAGIC_QUERY_LEN, Data.c_str() + DataOffset + strlen(HEX_PREAMBLE_STRING), DNSCURVE_MAGIC_QUERY_HEX_LEN, nullptr, &ResultLength, &ResultPointer) != 0 || 
			ResultLength != DNSCURVE_MAGIC_QUERY_LEN || ResultPointer == nullptr)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Data length error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
	}
//ASCII format
	else if (Data.length() == DataOffset + DNSCURVE_MAGIC_QUERY_LEN)
	{
		memcpy_s(MagicNumber, DNSCURVE_MAGIC_QUERY_LEN, Data.c_str() + DataOffset, DNSCURVE_MAGIC_QUERY_LEN);
	}
	else {
		PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Data length error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

	return true;
}
#endif

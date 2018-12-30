// This code is part of Pcap_DNSProxy
// Pcap_DNSProxy, a local DNS server based on WinPcap and LibPcap
// Copyright (C) 2012-2019 Chengr28
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

//Local variables
extern std::array<size_t, NETWORK_LAYER_PARTNUM> ParameterHopLimitsIndex;

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
		Parameter.ListenPort->push_back(hton16(IPPORT_DNS));
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
	if (IsFirstRead)
	{
	//Move Alternate to Main.
	//IPv6
		if (Parameter.Target_Server_Local_Main_IPv6.Storage.ss_family == 0 && Parameter.Target_Server_Local_Alternate_IPv6.Storage.ss_family != 0)
		{
			Parameter.Target_Server_Local_Main_IPv6 = Parameter.Target_Server_Local_Alternate_IPv6;
			memset(&Parameter.Target_Server_Local_Alternate_IPv6, 0, sizeof(Parameter.Target_Server_Local_Alternate_IPv6));
		}
	//IPv4
		if (Parameter.Target_Server_Local_Main_IPv4.Storage.ss_family == 0 && Parameter.Target_Server_Local_Alternate_IPv4.Storage.ss_family != 0)
		{
			Parameter.Target_Server_Local_Main_IPv4 = Parameter.Target_Server_Local_Alternate_IPv4;
			memset(&Parameter.Target_Server_Local_Alternate_IPv4, 0, sizeof(Parameter.Target_Server_Local_Alternate_IPv4));
		}

	//Local Hosts, Local Routin, and Local Force Request check
		if (
		//Pass, Local request disabled
//			(!Parameter.IsLocalHosts && !Parameter.IsLocalRouting && !Parameter.IsLocalForce) || 
		//Pass, Local Hosts only
//			(Parameter.IsLocalHosts && !Parameter.IsLocalRouting && !Parameter.IsLocalForce) || 
		//Pass, Local Routing only
//			(!Parameter.IsLocalHosts && Parameter.IsLocalRouting && !Parameter.IsLocalForce) || 
		//Failed, Local Force Request only, no any matched Local request.
			(!Parameter.IsLocalHosts && !Parameter.IsLocalRouting && Parameter.IsLocalForce) || 
		//Failed, Local Hosts + Local Routing, no need to enable Local Hosts.
			(Parameter.IsLocalHosts && Parameter.IsLocalRouting && !Parameter.IsLocalForce) || 
		//Pass, Local Hosts + Local Force Request, enforce Local Hosts results from Local DNS.
//			(Parameter.IsLocalHosts && !Parameter.IsLocalRouting && Parameter.IsLocalForce) || 
		//Failed, Local Routing + Local Force Request, no any rules to enforce.
			(!Parameter.IsLocalHosts && Parameter.IsLocalRouting && Parameter.IsLocalForce) || 
		//Pass, Local Hosts + Local Routing + Local Force Request, send all request to Local DNS first and then:
		//Request in Local Hosts, stop next step and return result.
		//Request not in Local Hosts, go next Local Routing step.
//			(Parameter.IsLocalHosts && Parameter.IsLocalRouting && Parameter.IsLocalForce) || 
			((Parameter.IsLocalHosts || Parameter.IsLocalRouting || Parameter.IsLocalForce) && 
			Parameter.Target_Server_Local_Main_IPv6.Storage.ss_family == 0 && Parameter.Target_Server_Local_Main_IPv4.Storage.ss_family == 0))
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Local request options error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
			return false;
		}
	}

	//Local Protocol
	//IPv6
	if (Parameter.Target_Server_Local_Main_IPv6.Storage.ss_family == 0 && ParameterPointer->LocalProtocol_Network == REQUEST_MODE_NETWORK::IPV6)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NOTICE, L"IPv6 Request Mode require IPv6 DNS server", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
		ParameterPointer->LocalProtocol_Network = REQUEST_MODE_NETWORK::BOTH;
	}
	//IPv4
	else if (Parameter.Target_Server_Local_Main_IPv4.Storage.ss_family == 0 && ParameterPointer->LocalProtocol_Network == REQUEST_MODE_NETWORK::IPV4)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NOTICE, L"IPv4 Request Mode require IPv4 DNS server", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
		ParameterPointer->LocalProtocol_Network = REQUEST_MODE_NETWORK::BOTH;
	}

	if (IsFirstRead)
	{
//[Addresses] block
	//Listen Address list check
	//IPv6
		if (Parameter.ListenAddress_IPv6->empty())
		{
			delete Parameter.ListenAddress_IPv6;
			Parameter.ListenAddress_IPv6 = nullptr;
		}
	//IPv4
		if (Parameter.ListenAddress_IPv4->empty())
		{
			delete Parameter.ListenAddress_IPv4;
			Parameter.ListenAddress_IPv4 = nullptr;
		}

	//EDNS Client Subnet Address check
	//IPv6
		if (Parameter.LocalMachineSubnet_IPv6->first.ss_family == 0)
		{
			delete Parameter.LocalMachineSubnet_IPv6;
			Parameter.LocalMachineSubnet_IPv6 = nullptr;
		}
		else if (!Parameter.EDNS_Label)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NOTICE, L"EDNS Client Subnet require EDNS Label", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);

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
	//IPv4
		if (Parameter.LocalMachineSubnet_IPv4->first.ss_family == 0)
		{
			delete Parameter.LocalMachineSubnet_IPv4;
			Parameter.LocalMachineSubnet_IPv4 = nullptr;
		}
		else if (!Parameter.EDNS_Label)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NOTICE, L"EDNS Client Subnet require EDNS Label", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);

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
	//DNS target check
		if (Parameter.Target_Server_Main_IPv6.AddressData.Storage.ss_family == 0 && Parameter.Target_Server_Main_IPv4.AddressData.Storage.ss_family == 0)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"DNS target error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
			return false;
		}
	//Protocol
	//IPv6
		else if (Parameter.Target_Server_Main_IPv6.AddressData.Storage.ss_family == 0 && Parameter.RequestMode_Network == REQUEST_MODE_NETWORK::IPV6)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NOTICE, L"IPv6 Request Mode require IPv6 DNS server", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
			Parameter.RequestMode_Network = REQUEST_MODE_NETWORK::BOTH;
		}
	//IPv4
		else if (Parameter.Target_Server_Main_IPv4.AddressData.Storage.ss_family == 0 && Parameter.RequestMode_Network == REQUEST_MODE_NETWORK::IPV4)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NOTICE, L"IPv4 Request Mode require IPv4 DNS server", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
			Parameter.RequestMode_Network = REQUEST_MODE_NETWORK::BOTH;
		}
	}

//Direct Request check
	if ((ParameterPointer->DirectRequest_Protocol == REQUEST_MODE_DIRECT::IPV6 && Parameter.Target_Server_Main_IPv6.AddressData.Storage.ss_family == 0) || 
		(ParameterPointer->DirectRequest_Protocol == REQUEST_MODE_DIRECT::IPV4 && Parameter.Target_Server_Main_IPv4.AddressData.Storage.ss_family == 0))
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
			(ParameterPointer->Target_Server_Main_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_StaticLoad > 0 && 
			(static_cast<const size_t>(ParameterPointer->Target_Server_Main_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_StaticLoad) + static_cast<const size_t>(ParameterPointer->HopLimitsFluctuation) > UINT8_MAX || 
			static_cast<const ssize_t>(ParameterPointer->Target_Server_Main_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_StaticLoad) < static_cast<const ssize_t>(ParameterPointer->HopLimitsFluctuation) + 1)) || 
			(ParameterPointer->Target_Server_Alternate_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_StaticLoad > 0 && 
			(static_cast<const size_t>(ParameterPointer->Target_Server_Alternate_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_StaticLoad) + static_cast<const size_t>(ParameterPointer->HopLimitsFluctuation) > UINT8_MAX || 
			static_cast<const ssize_t>(ParameterPointer->Target_Server_Alternate_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_StaticLoad) < static_cast<const ssize_t>(ParameterPointer->HopLimitsFluctuation) + 1)) || 
		//IPv4
			(ParameterPointer->Target_Server_Main_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_StaticLoad > 0 && 
			(static_cast<const size_t>(ParameterPointer->Target_Server_Main_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_StaticLoad) + static_cast<const size_t>(ParameterPointer->HopLimitsFluctuation) > UINT8_MAX || 
			static_cast<const ssize_t>(ParameterPointer->Target_Server_Main_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_StaticLoad) < static_cast<const ssize_t>(ParameterPointer->HopLimitsFluctuation) + 1)) || 
			(ParameterPointer->Target_Server_Alternate_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_StaticLoad > 0 && 
			(static_cast<const size_t>(ParameterPointer->Target_Server_Alternate_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_StaticLoad) + static_cast<const size_t>(ParameterPointer->HopLimitsFluctuation) > UINT8_MAX || 
			static_cast<const ssize_t>(ParameterPointer->Target_Server_Alternate_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_StaticLoad) < static_cast<const ssize_t>(ParameterPointer->HopLimitsFluctuation) + 1)))
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Hop Limits Fluctuation error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
			return false;
		}

	//Hop Limits and TTL check in multiple list
	//IPv6
		if (Parameter.Target_Server_IPv6_Multiple != nullptr)
		{
			for (const auto &DNSServerDataItem:*Parameter.Target_Server_IPv6_Multiple)
			{
				if (DNSServerDataItem.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_StaticLoad > 0 && 
					(static_cast<const size_t>(DNSServerDataItem.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_StaticLoad) + static_cast<const size_t>(ParameterPointer->HopLimitsFluctuation) > UINT8_MAX || 
					static_cast<const ssize_t>(DNSServerDataItem.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_StaticLoad) < static_cast<const ssize_t>(ParameterPointer->HopLimitsFluctuation) + 1))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Hop Limits Fluctuation error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					return false;
				}
			}
		}
	//IPv4
		if (Parameter.Target_Server_IPv4_Multiple != nullptr)
		{
			for (const auto &DNSServerDataItem:*Parameter.Target_Server_IPv4_Multiple)
			{
				if (DNSServerDataItem.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_StaticLoad > 0 && 
					(static_cast<const size_t>(DNSServerDataItem.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_StaticLoad) + static_cast<const size_t>(ParameterPointer->HopLimitsFluctuation) > UINT8_MAX || 
					static_cast<const ssize_t>(DNSServerDataItem.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_StaticLoad) < static_cast<const ssize_t>(ParameterPointer->HopLimitsFluctuation) + 1))
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
			Parameter.DNSSEC_Request = true;
		}

	//EDNS Label check
		if (!Parameter.EDNS_Label)
		{
		//EDNS Client Subnet Relay check
			if (Parameter.EDNS_ClientSubnet_Relay)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NOTICE, L"EDNS Client Subnet require EDNS Label", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);

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

		//DNSSEC check
			if (Parameter.DNSSEC_Request)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NOTICE, L"DNSSEC Request require EDNS Label", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);

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
	#if defined(ENABLE_PCAP)
	//ICMP ID check
		if (Parameter.ICMP_ID == 0)
			GenerateRandomBuffer(&Parameter.ICMP_ID, sizeof(Parameter.ICMP_ID), nullptr, 0, 0);

	//Domain Test ID check
		if (Parameter.DomainTest_ID == 0)
			GenerateRandomBuffer(&Parameter.DomainTest_ID, sizeof(Parameter.DomainTest_ID), nullptr, 0, 0);

	//Domain Test domain name check
		if (CheckEmptyBuffer(Parameter.DomainTest_Data, DOMAIN_MAXSIZE))
		{
			delete[] Parameter.DomainTest_Data;
			Parameter.DomainTest_Data = nullptr;
		}
	#endif

	//Default Local DNS server name
		if (Parameter.Local_FQDN_Length == 0)
		{
			Parameter.Local_FQDN_Length = StringToPacketQuery(reinterpret_cast<const uint8_t *>(DEFAULT_LOCAL_SERVER_NAME), Parameter.Local_FQDN_Response, DOMAIN_MAXSIZE);
			*Parameter.Local_FQDN_String = DEFAULT_LOCAL_SERVER_NAME;
		}

	//Set Local DNS server PTR response.
	//macOS: LLMNR protocol is powered by mDNS with DNS PTR records.
	#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_WIN))
		if (Parameter.LocalServer_Length == 0)
		{
		//Make DNS PTR response packet.
			reinterpret_cast<dns_record_ptr *>(Parameter.LocalServer_Response)->Pointer = hton16(DNS_POINTER_QUERY);
			reinterpret_cast<dns_record_ptr *>(Parameter.LocalServer_Response)->Classes = hton16(DNS_CLASS_INTERNET);
			if (Parameter.HostsDefaultTTL > 0)
				reinterpret_cast<dns_record_ptr *>(Parameter.LocalServer_Response)->TTL = hton32(Parameter.HostsDefaultTTL);
			else 
				reinterpret_cast<dns_record_ptr *>(Parameter.LocalServer_Response)->TTL = hton32(DEFAULT_HOSTS_TTL);
			reinterpret_cast<dns_record_ptr *>(Parameter.LocalServer_Response)->Type = hton16(DNS_TYPE_PTR);
			reinterpret_cast<dns_record_ptr *>(Parameter.LocalServer_Response)->Length = hton16(static_cast<const uint16_t>(Parameter.Local_FQDN_Length));
			Parameter.LocalServer_Length += sizeof(dns_record_ptr);

		//Copy to global buffer.
			memcpy_s(Parameter.LocalServer_Response + Parameter.LocalServer_Length, PACKET_NORMAL_MAXSIZE - Parameter.LocalServer_Length, Parameter.Local_FQDN_Response, Parameter.Local_FQDN_Length);
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
		//SOCKS target check
			if (Parameter.SOCKS_Address_IPv6.Storage.ss_family == 0 && Parameter.SOCKS_Address_IPv4.Storage.ss_family == 0)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::SOCKS, L"SOCKS address error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
				return false;
			}
		//SOCKS Protocl
		//IPv6
			else if (Parameter.SOCKS_Address_IPv6.Storage.ss_family == 0 && Parameter.SOCKS_Protocol_Network == REQUEST_MODE_NETWORK::IPV6)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NOTICE, L"IPv6 Request Mode require IPv6 DNS server", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
				Parameter.SOCKS_Protocol_Network = REQUEST_MODE_NETWORK::BOTH;
			}
		//IPv4
			else if (Parameter.SOCKS_Address_IPv4.Storage.ss_family == 0 && Parameter.SOCKS_Protocol_Network == REQUEST_MODE_NETWORK::IPV4)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NOTICE, L"IPv4 Request Mode require IPv4 DNS server", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
				Parameter.SOCKS_Protocol_Network = REQUEST_MODE_NETWORK::BOTH;
			}

		//Only SOCKS version 5 support client authentication.
			if (Parameter.SOCKS_Version != SOCKS_VERSION_5)
			{
			#if defined(ENABLE_LIBSODIUM)
				sodium_free(Parameter.SOCKS_Password);
			#else
				delete[] Parameter.SOCKS_Password;
			#endif
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
		if (Parameter.SOCKS_Version == SOCKS_VERSION_5 && Parameter.SOCKS_UsernameLength == 0 && Parameter.SOCKS_PasswordLength > 0)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::SOCKS, L"SOCKS username and password error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
			return false;
		}
	}
	else if (IsFirstRead)
	{
		delete Parameter.SOCKS_TargetDomain;
	#if defined(ENABLE_LIBSODIUM)
		sodium_free(Parameter.SOCKS_Username);
		sodium_free(Parameter.SOCKS_Password);
	#else
		delete[] Parameter.SOCKS_Username;
		delete[] Parameter.SOCKS_Password;
	#endif

		Parameter.SOCKS_TargetDomain = nullptr;
		Parameter.SOCKS_Username = nullptr;
		Parameter.SOCKS_Password = nullptr;
	}

//HTTP CONNECT Proxy check
	if (Parameter.HTTP_CONNECT_Proxy)
	{
		if (IsFirstRead)
		{
		//HTTP CONNECT target check
			if (Parameter.HTTP_CONNECT_Address_IPv6.Storage.ss_family == 0 && Parameter.HTTP_CONNECT_Address_IPv4.Storage.ss_family == 0)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HTTP_CONNECT, L"HTTP CONNECT address error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
				return false;
			}
		//HTTP Protocol
		//IPv6
			else if (Parameter.HTTP_CONNECT_Address_IPv6.Storage.ss_family == 0 && Parameter.HTTP_CONNECT_Protocol == REQUEST_MODE_NETWORK::IPV6)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NOTICE, L"IPv6 Request Mode require IPv6 DNS server", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
				Parameter.HTTP_CONNECT_Protocol = REQUEST_MODE_NETWORK::BOTH;
			}
		//HTTP Protocol
		//IPv4
			else if (Parameter.HTTP_CONNECT_Address_IPv4.Storage.ss_family == 0 && Parameter.HTTP_CONNECT_Protocol == REQUEST_MODE_NETWORK::IPV4)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NOTICE, L"IPv4 Request Mode require IPv4 DNS server", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
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
						if (IsLiteralFlag && StringIter.compare(0, strlen(":"), ":") == 0)
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
				delete Parameter.HTTP_CONNECT_TLS_SNI_MBS;
			#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				delete Parameter.HTTP_CONNECT_TLS_AddressString_IPv6;
				delete Parameter.HTTP_CONNECT_TLS_AddressString_IPv4;
			#endif
				Parameter.HTTP_CONNECT_TLS_SNI = nullptr;
				Parameter.HTTP_CONNECT_TLS_SNI_MBS = nullptr;
			#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				Parameter.HTTP_CONNECT_TLS_AddressString_IPv6 = nullptr;
				Parameter.HTTP_CONNECT_TLS_AddressString_IPv4 = nullptr;

			//Free all OpenSSL libraries.
				if (GlobalRunningStatus.IsInitialized_OpenSSL)
				{
					OpenSSL_LibraryInit(false);
					GlobalRunningStatus.IsInitialized_OpenSSL = false;
				}
			#endif
			}
			else {
			#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			//HTTP CONNECT IPv6/IPv4 address check
				if (Parameter.HTTP_CONNECT_TLS_AddressString_IPv6->empty() && Parameter.HTTP_CONNECT_TLS_AddressString_IPv4->empty())
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HTTP_CONNECT, L"HTTP CONNECT address error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					return false;
				}
			#endif

			//Mark TLS Server Name Indication/SNI.
				if (Parameter.HTTP_CONNECT_TLS_SNI_MBS != nullptr && !Parameter.HTTP_CONNECT_TLS_SNI_MBS->empty())
				{
					if (!MBS_To_WCS_String(reinterpret_cast<const uint8_t *>(Parameter.HTTP_CONNECT_TLS_SNI_MBS->c_str()), Parameter.HTTP_CONNECT_TLS_SNI_MBS->length(), *Parameter.HTTP_CONNECT_TLS_SNI))
					{
						PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"Convert multiple byte or wide char string error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
						delete Parameter.HTTP_CONNECT_TLS_SNI;
						delete Parameter.HTTP_CONNECT_TLS_SNI_MBS;
						Parameter.HTTP_CONNECT_TLS_SNI = nullptr;
						Parameter.HTTP_CONNECT_TLS_SNI_MBS = nullptr;
					}
				}
				else {
					delete Parameter.HTTP_CONNECT_TLS_SNI;
					delete Parameter.HTTP_CONNECT_TLS_SNI_MBS;
					Parameter.HTTP_CONNECT_TLS_SNI = nullptr;
					Parameter.HTTP_CONNECT_TLS_SNI_MBS = nullptr;
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
				Parameter.HTTP_CONNECT_TLS_SNI_MBS == nullptr || Parameter.HTTP_CONNECT_TLS_SNI_MBS->empty()) && 
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
	#if defined(ENABLE_LIBSODIUM)
		sodium_free(Parameter.HTTP_CONNECT_ProxyAuthorization);
	#else
		delete[] Parameter.HTTP_CONNECT_ProxyAuthorization;
	#endif
	#if defined(ENABLE_TLS)
		delete Parameter.HTTP_CONNECT_TLS_SNI;
		delete Parameter.HTTP_CONNECT_TLS_SNI_MBS;
	#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		delete Parameter.HTTP_CONNECT_TLS_AddressString_IPv6;
		delete Parameter.HTTP_CONNECT_TLS_AddressString_IPv4;
	#endif
	#endif

		Parameter.HTTP_CONNECT_TargetDomain = nullptr;
		Parameter.HTTP_CONNECT_HeaderField = nullptr;
		Parameter.HTTP_CONNECT_ProxyAuthorization = nullptr;
	#if defined(ENABLE_TLS)
		Parameter.HTTP_CONNECT_TLS_SNI = nullptr;
		Parameter.HTTP_CONNECT_TLS_SNI_MBS = nullptr;
	#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		Parameter.HTTP_CONNECT_TLS_AddressString_IPv6 = nullptr;
		Parameter.HTTP_CONNECT_TLS_AddressString_IPv4 = nullptr;

	//Free all OpenSSL libraries.
		if (GlobalRunningStatus.IsInitialized_OpenSSL)
		{
			OpenSSL_LibraryInit(false);
			GlobalRunningStatus.IsInitialized_OpenSSL = false;
		}
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
		//Move Alternate to Main.
		//IPv6
			if (DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.AddressData.Storage.ss_family == 0 && DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.AddressData.Storage.ss_family != 0)
			{
				DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6 = DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6;
				memset(&DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6, 0, sizeof(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6));
			}
		//IPv4
			if (DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.AddressData.Storage.ss_family == 0 && DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.AddressData.Storage.ss_family != 0)
			{
				DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4 = DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4;
				memset(&DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4, 0, sizeof(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4));
			}

		//DNSCurve target check
			if (DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.AddressData.Storage.ss_family == 0 && DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.AddressData.Storage.ss_family == 0)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"DNSCurve target error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
				return false;
			}

		//DNSCurve Protocol
		//IPv6
			if (DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.AddressData.Storage.ss_family == 0 && DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_NETWORK::IPV6)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NOTICE, L"IPv6 Request Mode require IPv6 DNS server", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
				DNSCurveParameter.DNSCurveProtocol_Network = REQUEST_MODE_NETWORK::BOTH;
			}
		//IPv4
			else if (DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.AddressData.Storage.ss_family == 0 && DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_NETWORK::IPV4)
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
				sodium_is_zero(DNSCurveParameterPointer->Client_SecretKey, crypto_box_SECRETKEYBYTES) == 0)
			{
				if (!DNSCurve_VerifyKeypair(DNSCurveParameterPointer->Client_PublicKey, DNSCurveParameterPointer->Client_SecretKey))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::DNSCURVE, L"Client keypair error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);

					memset(DNSCurveParameterPointer->Client_PublicKey, 0, crypto_box_PUBLICKEYBYTES);
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
				memset(DNSCurveParameterPointer->Client_PublicKey, 0, crypto_box_PUBLICKEYBYTES);
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
			if ((DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.AddressData.Storage.ss_family != 0 && 
				DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.AddressData.Storage.ss_family != 0 && 
				memcmp(&DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.AddressData.IPv6.sin6_addr, &DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.AddressData.IPv6.sin6_addr, sizeof(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.AddressData.IPv6.sin6_addr)) == 0 && 
				DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.AddressData.IPv6.sin6_port == DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.AddressData.IPv6.sin6_port) || 
				(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.AddressData.Storage.ss_family != 0 && 
				DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.AddressData.Storage.ss_family != 0 && 
				DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.AddressData.IPv4.sin_addr.s_addr == DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.AddressData.IPv4.sin_addr.s_addr && 
				DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.AddressData.IPv4.sin_port == DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.AddressData.IPv4.sin_port))
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"DNSCurve target error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
				return false;
			}

		//Encryption options check
			if (DNSCurveParameter.IsEncryptionOnly && !DNSCurveParameter.IsEncryption)
			{
				DNSCurveParameter.IsEncryption = true;
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"DNSCurve encryption options error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
			}
		}

	//IPv6 Main
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

	//IPv6 Alternate
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

	//IPv4 Main
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

	//IPv4 Alternate
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
				else if (DNSCurveParameter.DNSCurvePayloadSize >= PACKET_NORMAL_MAXSIZE - DNSCRYPT_HEADER_RESERVED_LEN)
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NOTICE, L"DNSCurve Payload Size is too large", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					DNSCurveParameter.DNSCurvePayloadSize = EDNS_PACKET_MINSIZE;
				}
			}

		//IPv6 Main
			if (DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.AddressData.Storage.ss_family != 0 && 
				CheckEmptyBuffer(DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
					memcpy_s(DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCRYPT_RECEIVE_MAGIC, DNSCURVE_MAGIC_QUERY_LEN);

		//IPv6 Alternate
			if (DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.AddressData.Storage.ss_family != 0 && 
				CheckEmptyBuffer(DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
					memcpy_s(DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCRYPT_RECEIVE_MAGIC, DNSCURVE_MAGIC_QUERY_LEN);

		//IPv4 Main
			if (DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.AddressData.Storage.ss_family != 0 && 
				CheckEmptyBuffer(DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
					memcpy_s(DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCRYPT_RECEIVE_MAGIC, DNSCURVE_MAGIC_QUERY_LEN);

		//IPv4 Alternate
			if (DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.AddressData.Storage.ss_family != 0 && 
				CheckEmptyBuffer(DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
					memcpy_s(DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCRYPT_RECEIVE_MAGIC, DNSCURVE_MAGIC_QUERY_LEN);

		//DNSCurve keys recheck time
			if (DNSCurveParameterPointer->KeyRecheckTime == 0)
				DNSCurveParameterPointer->KeyRecheckTime = DNSCURVE_DEFAULT_RECHECK_TIME * SECOND_TO_MILLISECOND;
		}
	}
	else if (IsFirstRead)
	{
	//[DNSCurve Addresses] block
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ProviderName;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ProviderName;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ProviderName;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ProviderName;
	//[DNSCurve Keys] block
		delete[] DNSCurveParameter.Client_PublicKey;
		sodium_free(DNSCurveParameter.Client_SecretKey);
		sodium_free(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.PrecomputationKey);
		sodium_free(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey);
		sodium_free(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.PrecomputationKey);
		sodium_free(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey);
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ServerPublicKey;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ServerPublicKey;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ServerFingerprint;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ServerFingerprint;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint;
	//[DNSCurve Magic Number] block
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.SendMagicNumber;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.SendMagicNumber;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber;

		DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ProviderName = nullptr;
		DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ProviderName = nullptr;
		DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ProviderName = nullptr;
		DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ProviderName = nullptr;
		DNSCurveParameter.Client_PublicKey = nullptr;
		DNSCurveParameter.Client_SecretKey = nullptr;
		DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.PrecomputationKey = nullptr;
		DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey = nullptr;
		DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.PrecomputationKey = nullptr;
		DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey = nullptr;
		DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ServerPublicKey = nullptr;
		DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey = nullptr;
		DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ServerPublicKey = nullptr;
		DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey = nullptr;
		DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ServerFingerprint = nullptr;
		DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint = nullptr;
		DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ServerFingerprint = nullptr;
		DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint = nullptr;
		DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.SendMagicNumber = nullptr;
		DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber = nullptr;
		DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.SendMagicNumber = nullptr;
		DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber = nullptr;
		DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber = nullptr;
		DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber = nullptr;
		DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber = nullptr;
		DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber = nullptr;
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
		return hton16(IPPORT_TCPMUX);
	else if (Buffer == ("ECHO"))
		return hton16(IPPORT_ECHO);
	else if (Buffer == ("DISCARD"))
		return hton16(IPPORT_DISCARD);
	else if (Buffer == ("SYSTAT"))
		return hton16(IPPORT_SYSTAT);
	else if (Buffer == ("DAYTIME"))
		return hton16(IPPORT_DAYTIME);
	else if (Buffer == ("NETSTAT"))
		return hton16(IPPORT_NETSTAT);
	else if (Buffer == ("QOTD"))
		return hton16(IPPORT_QOTD);
	else if (Buffer == ("MSP"))
		return hton16(IPPORT_MSP);
	else if (Buffer == ("CHARGEN"))
		return hton16(IPPORT_CHARGEN);
	else if (Buffer == ("FTPDATA"))
		return hton16(IPPORT_FTP_DATA);
	else if (Buffer == ("FTP"))
		return hton16(IPPORT_FTP);
	else if (Buffer == ("SSH"))
		return hton16(IPPORT_SSH);
	else if (Buffer == ("TELNET"))
		return hton16(IPPORT_TELNET);
	else if (Buffer == ("SMTP"))
		return hton16(IPPORT_SMTP);
	else if (Buffer == ("TIMESERVER"))
		return hton16(IPPORT_TIMESERVER);
	else if (Buffer == ("RAP"))
		return hton16(IPPORT_RAP);
	else if (Buffer == ("RLP"))
		return hton16(IPPORT_RLP);
	else if (Buffer == ("NAMESERVER"))
		return hton16(IPPORT_NAMESERVER);
	else if (Buffer == ("WHOIS"))
		return hton16(IPPORT_WHOIS);
	else if (Buffer == ("TACACS"))
		return hton16(IPPORT_TACACS);
	else if (Buffer == ("DNS"))
		return hton16(IPPORT_DNS);
	else if (Buffer == ("XNSAUTH"))
		return hton16(IPPORT_XNSAUTH);
	else if (Buffer == ("MTP"))
		return hton16(IPPORT_MTP);
	else if (Buffer == ("BOOTPS"))
		return hton16(IPPORT_BOOTPS);
	else if (Buffer == ("BOOTPC"))
		return hton16(IPPORT_BOOTPC);
	else if (Buffer == ("TFTP"))
		return hton16(IPPORT_TFTP);
	else if (Buffer == ("RJE"))
		return hton16(IPPORT_RJE);
	else if (Buffer == ("FINGER"))
		return hton16(IPPORT_FINGER);
	else if (Buffer == ("HTTP"))
		return hton16(IPPORT_HTTP);
	else if (Buffer == ("HTTPBACKUP"))
		return hton16(IPPORT_HTTPBACKUP);
	else if (Buffer == ("TTYLINK"))
		return hton16(IPPORT_TTYLINK);
	else if (Buffer == ("SUPDUP"))
		return hton16(IPPORT_SUPDUP);
	else if (Buffer == ("POP3"))
		return hton16(IPPORT_POP3);
	else if (Buffer == ("SUNRPC"))
		return hton16(IPPORT_SUNRPC);
	else if (Buffer == ("SQL"))
		return hton16(IPPORT_SQL);
	else if (Buffer == ("NTP"))
		return hton16(IPPORT_NTP);
	else if (Buffer == ("EPMAP"))
		return hton16(IPPORT_EPMAP);
	else if (Buffer == ("NETBIOS_NS"))
		return hton16(IPPORT_NETBIOS_NS);
	else if (Buffer == ("NETBIOS_DGM"))
		return hton16(IPPORT_NETBIOS_DGM);
	else if (Buffer == ("NETBIOS_SSN"))
		return hton16(IPPORT_NETBIOS_SSN);
	else if (Buffer == ("IMAP"))
		return hton16(IPPORT_IMAP);
	else if (Buffer == ("BFTP"))
		return hton16(IPPORT_BFTP);
	else if (Buffer == ("SGMP"))
		return hton16(IPPORT_SGMP);
	else if (Buffer == ("SQLSRV"))
		return hton16(IPPORT_SQLSRV);
	else if (Buffer == ("DMSP"))
		return hton16(IPPORT_DMSP);
	else if (Buffer == ("SNMP"))
		return hton16(IPPORT_SNMP);
	else if (Buffer == ("SNMP_TRAP"))
		return hton16(IPPORT_SNMP_TRAP);
	else if (Buffer == ("ATRTMP"))
		return hton16(IPPORT_ATRTMP);
	else if (Buffer == ("ATHBP"))
		return hton16(IPPORT_ATHBP);
	else if (Buffer == ("QMTP"))
		return hton16(IPPORT_QMTP);
	else if (Buffer == ("IPX"))
		return hton16(IPPORT_IPX);
	else if (Buffer == ("IMAP3"))
		return hton16(IPPORT_IMAP3);
	else if (Buffer == ("BGMP"))
		return hton16(IPPORT_BGMP);
	else if (Buffer == ("TSP"))
		return hton16(IPPORT_TSP);
	else if (Buffer == ("IMMP"))
		return hton16(IPPORT_IMMP);
	else if (Buffer == ("ODMR"))
		return hton16(IPPORT_ODMR);
	else if (Buffer == ("RPC2PORTMAP"))
		return hton16(IPPORT_RPC2PORTMAP);
	else if (Buffer == ("CLEARCASE"))
		return hton16(IPPORT_CLEARCASE);
	else if (Buffer == ("HPALARMMGR"))
		return hton16(IPPORT_HPALARMMGR);
	else if (Buffer == ("ARNS"))
		return hton16(IPPORT_ARNS);
	else if (Buffer == ("AURP"))
		return hton16(IPPORT_AURP);
	else if (Buffer == ("LDAP"))
		return hton16(IPPORT_LDAP);
	else if (Buffer == ("UPS"))
		return hton16(IPPORT_UPS);
	else if (Buffer == ("SLP"))
		return hton16(IPPORT_SLP);
	else if (Buffer == ("HTTPS"))
		return hton16(IPPORT_HTTPS);
	else if (Buffer == ("SNPP"))
		return hton16(IPPORT_SNPP);
	else if (Buffer == ("MICROSOFTDS"))
		return hton16(IPPORT_MICROSOFT_DS);
	else if (Buffer == ("KPASSWD"))
		return hton16(IPPORT_KPASSWD);
	else if (Buffer == ("TCPNETHASPSRV"))
		return hton16(IPPORT_TCPNETHASPSRV);
	else if (Buffer == ("RETROSPECT"))
		return hton16(IPPORT_RETROSPECT);
	else if (Buffer == ("ISAKMP"))
		return hton16(IPPORT_ISAKMP);
	else if (Buffer == ("BIFFUDP"))
		return hton16(IPPORT_BIFFUDP);
	else if (Buffer == ("WHOSERVER"))
		return hton16(IPPORT_WHOSERVER);
	else if (Buffer == ("SYSLOG"))
		return hton16(IPPORT_SYSLOG);
	else if (Buffer == ("ROUTERSERVER"))
		return hton16(IPPORT_ROUTESERVER);
	else if (Buffer == ("NCP"))
		return hton16(IPPORT_NCP);
	else if (Buffer == ("COURIER"))
		return hton16(IPPORT_COURIER);
	else if (Buffer == ("COMMERCE"))
		return hton16(IPPORT_COMMERCE);
	else if (Buffer == ("RTSP"))
		return hton16(IPPORT_RTSP);
	else if (Buffer == ("NNTP"))
		return hton16(IPPORT_NNTP);
	else if (Buffer == ("HTTPRPCEPMAP"))
		return hton16(IPPORT_HTTPRPCEPMAP);
	else if (Buffer == ("IPP"))
		return hton16(IPPORT_IPP);
	else if (Buffer == ("LDAPS"))
		return hton16(IPPORT_LDAPS);
	else if (Buffer == ("MSDP"))
		return hton16(IPPORT_MSDP);
	else if (Buffer == ("AODV"))
		return hton16(IPPORT_AODV);
	else if (Buffer == ("FTPSDATA"))
		return hton16(IPPORT_FTPSDATA);
	else if (Buffer == ("FTPS"))
		return hton16(IPPORT_FTPS);
	else if (Buffer == ("NAS"))
		return hton16(IPPORT_NAS);
	else if (Buffer == ("TELNETS"))
		return hton16(IPPORT_TELNETS);

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
		return hton16(DNS_TYPE_A);
	else if (Buffer == ("NS"))
		return hton16(DNS_TYPE_NS);
	else if (Buffer == ("MD"))
		return hton16(DNS_TYPE_MD);
	else if (Buffer == ("MF"))
		return hton16(DNS_TYPE_MF);
	else if (Buffer == ("CNAME"))
		return hton16(DNS_TYPE_CNAME);
	else if (Buffer == ("SOA"))
		return hton16(DNS_TYPE_SOA);
	else if (Buffer == ("MB"))
		return hton16(DNS_TYPE_MB);
	else if (Buffer == ("MG"))
		return hton16(DNS_TYPE_MG);
	else if (Buffer == ("MR"))
		return hton16(DNS_TYPE_MR);
	else if (Buffer == ("PTR"))
		return hton16(DNS_TYPE_PTR);
	else if (Buffer == ("NULL"))
		return hton16(DNS_TYPE_NULL);
	else if (Buffer == ("WKS"))
		return hton16(DNS_TYPE_WKS);
	else if (Buffer == ("HINFO"))
		return hton16(DNS_TYPE_HINFO);
	else if (Buffer == ("MINFO"))
		return hton16(DNS_TYPE_MINFO);
	else if (Buffer == ("MX"))
		return hton16(DNS_TYPE_MX);
	else if (Buffer == ("TXT"))
		return hton16(DNS_TYPE_TEXT);
	else if (Buffer == ("RP"))
		return hton16(DNS_TYPE_RP);
	else if (Buffer == ("AFSDB"))
		return hton16(DNS_TYPE_AFSDB);
	else if (Buffer == ("X25"))
		return hton16(DNS_TYPE_X25);
	else if (Buffer == ("ISDN"))
		return hton16(DNS_TYPE_ISDN);
	else if (Buffer == ("RT"))
		return hton16(DNS_TYPE_RT);
	else if (Buffer == ("NSAP"))
		return hton16(DNS_TYPE_NSAP);
	else if (Buffer == ("NSAPPTR"))
		return hton16(DNS_TYPE_NSAPPTR);
	else if (Buffer == ("SIG"))
		return hton16(DNS_TYPE_SIG);
	else if (Buffer == ("KEY"))
		return hton16(DNS_TYPE_KEY);
	else if (Buffer == ("AAAA"))
		return hton16(DNS_TYPE_AAAA);
	else if (Buffer == ("PX"))
		return hton16(DNS_TYPE_PX);
	else if (Buffer == ("GPOS"))
		return hton16(DNS_TYPE_GPOS);
	else if (Buffer == ("LOC"))
		return hton16(DNS_TYPE_LOC);
	else if (Buffer == ("NXT"))
		return hton16(DNS_TYPE_NXT);
	else if (Buffer == ("EID"))
		return hton16(DNS_TYPE_EID);
	else if (Buffer == ("NIMLOC"))
		return hton16(DNS_TYPE_NIMLOC);
	else if (Buffer == ("SRV"))
		return hton16(DNS_TYPE_SRV);
	else if (Buffer == ("ATMA"))
		return hton16(DNS_TYPE_ATMA);
	else if (Buffer == ("NAPTR"))
		return hton16(DNS_TYPE_NAPTR);
	else if (Buffer == ("KX"))
		return hton16(DNS_TYPE_KX);
	else if (Buffer == ("CERT"))
		return hton16(DNS_TYPE_CERT);
	else if (Buffer == ("A6"))
		return hton16(DNS_TYPE_A6);
	else if (Buffer == ("DNAME"))
		return hton16(DNS_TYPE_DNAME);
	else if (Buffer == ("SINK"))
		return hton16(DNS_TYPE_SINK);
	else if (Buffer == ("OPT"))
		return hton16(DNS_TYPE_OPT);
	else if (Buffer == ("APL"))
		return hton16(DNS_TYPE_APL);
	else if (Buffer == ("DS"))
		return hton16(DNS_TYPE_DS);
	else if (Buffer == ("SSHFP"))
		return hton16(DNS_TYPE_SSHFP);
	else if (Buffer == ("IPSECKEY"))
		return hton16(DNS_TYPE_IPSECKEY);
	else if (Buffer == ("RRSIG"))
		return hton16(DNS_TYPE_RRSIG);
	else if (Buffer == ("NSEC"))
		return hton16(DNS_TYPE_NSEC);
	else if (Buffer == ("DNSKEY"))
		return hton16(DNS_TYPE_DNSKEY);
	else if (Buffer == ("DHCID"))
		return hton16(DNS_TYPE_DHCID);
	else if (Buffer == ("NSEC3"))
		return hton16(DNS_TYPE_NSEC3);
	else if (Buffer == ("NSEC3PARAM"))
		return hton16(DNS_TYPE_NSEC3PARAM);
	else if (Buffer == ("TLSA"))
		return hton16(DNS_TYPE_TLSA);
	else if (Buffer == ("HIP"))
		return hton16(DNS_TYPE_HIP);
	else if (Buffer == ("NINFO"))
		return hton16(DNS_TYPE_NINFO);
	else if (Buffer == ("RKEY"))
		return hton16(DNS_TYPE_RKEY);
	else if (Buffer == ("TALINK"))
		return hton16(DNS_TYPE_TALINK);
	else if (Buffer == ("CDS"))
		return hton16(DNS_TYPE_CDS);
	else if (Buffer == ("CDNSKEY"))
		return hton16(DNS_TYPE_CDNSKEY);
	else if (Buffer == ("OPENPGPKEY"))
		return hton16(DNS_TYPE_OPENPGPKEY);
	else if (Buffer == ("SPF"))
		return hton16(DNS_TYPE_SPF);
	else if (Buffer == ("UINFO"))
		return hton16(DNS_TYPE_UINFO);
	else if (Buffer == ("UID"))
		return hton16(DNS_TYPE_UID);
	else if (Buffer == ("GID"))
		return hton16(DNS_TYPE_GID);
	else if (Buffer == ("UNSPEC"))
		return hton16(DNS_TYPE_UNSPEC);
	else if (Buffer == ("NID"))
		return hton16(DNS_TYPE_NID);
	else if (Buffer == ("L32"))
		return hton16(DNS_TYPE_L32);
	else if (Buffer == ("L64"))
		return hton16(DNS_TYPE_L64);
	else if (Buffer == ("LP"))
		return hton16(DNS_TYPE_LP);
	else if (Buffer == ("EUI48"))
		return hton16(DNS_TYPE_EUI48);
	else if (Buffer == ("EUI64"))
		return hton16(DNS_TYPE_EUI64);
	else if (Buffer == ("ADDRS"))
		return hton16(DNS_TYPE_ADDRS);
	else if (Buffer == ("TKEY"))
		return hton16(DNS_TYPE_TKEY);
	else if (Buffer == ("TSIG"))
		return hton16(DNS_TYPE_TSIG);
	else if (Buffer == ("IXFR"))
		return hton16(DNS_TYPE_IXFR);
	else if (Buffer == ("AXFR"))
		return hton16(DNS_TYPE_AXFR);
	else if (Buffer == ("MAILB"))
		return hton16(DNS_TYPE_MAILB);
	else if (Buffer == ("MAILA"))
		return hton16(DNS_TYPE_MAILA);
	else if (Buffer == ("ANY"))
		return hton16(DNS_TYPE_ANY);
	else if (Buffer == ("URI"))
		return hton16(DNS_TYPE_URI);
	else if (Buffer == ("CAA"))
		return hton16(DNS_TYPE_CAA);
	else if (Buffer == ("TA"))
		return hton16(DNS_TYPE_TA);
	else if (Buffer == ("DLV"))
		return hton16(DNS_TYPE_DLV);
	else if (Buffer == ("RESERVED"))
		return hton16(DNS_TYPE_RESERVED);

//No match.
	return 0;
}

//Read parameter data from files
bool ReadParameterData_Whole(
	std::string Data, 
	const size_t FileIndex, 
	const bool IsFirstRead, 
	const size_t Line)
{
//Remove spaces, horizontal tab/HT, check comments(Number Sign/NS and double slashs) and check minimum length of ipfilter items.
//Remove comments(Number Sign/NS and double slashs) and check minimum length of configuration items.
//Additional Path, Hosts File Name, IPFilter File Name, HTTP CONNECT Header Field and DNSCurve Database Name must not be removed spaces or horizontal tab/HT.
	if (Data.compare(0, strlen("#"), "#") == 0 || Data.compare(0, strlen("/"), "/") == 0)
	{
		return true;
	}
	else if (Data.compare(0, strlen("Additional Path = "), "Additional Path = ") != 0 && 
		Data.compare(0, strlen("IPFilter File Name = "), "IPFilter File Name = ") != 0 && 
		Data.compare(0, strlen("Hosts File Name ="), "Hosts File Name =") != 0 && 
		Data.compare(0, strlen("HTTP CONNECT Header Field = "), "HTTP CONNECT Header Field = ") != 0 && 
		Data.compare(0, strlen("ICMP PaddingData = "), "ICMP PaddingData = ") != 0
	#if defined(ENABLE_LIBSODIUM)
		&& Data.compare(0, strlen("DNSCurve Database Name = "), "DNSCurve Database Name = ") != 0
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
	auto IsPassRemainingBlock = false;
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
	if (!ReadParameterData_Base(Data, FileIndex, IsFirstRead, Line, ParameterPointer, IsPassRemainingBlock))
		return false;
	else if (IsPassRemainingBlock)
		return true;

//[Log] block
	if (!ReadParameterData_Log(Data, FileIndex, /* IsFirstRead, */ Line, ParameterPointer, IsPassRemainingBlock))
		return false;
	else if (IsPassRemainingBlock)
		return true;

//[Listen] block
	if (!ReadParameterData_Listen(Data, FileIndex, IsFirstRead, Line, ParameterPointer, IsPassRemainingBlock))
		return false;
	else if (IsPassRemainingBlock)
		return true;

//[DNS] block
	if (!ReadParameterData_DNS(Data, FileIndex, IsFirstRead, Line, ParameterPointer, IsPassRemainingBlock))
		return false;
	else if (IsPassRemainingBlock)
		return true;

//[Local DNS] block
	if (!ReadParameterData_Local_DNS(Data, /* FileIndex, */ IsFirstRead, /* Line, */ ParameterPointer, IsPassRemainingBlock))
		return false;
	else if (IsPassRemainingBlock)
		return true;

//[Addresses] block
	if (!ReadParameterData_Addresses(Data, FileIndex, IsFirstRead, Line, /* ParameterPointer, */ IsPassRemainingBlock))
		return false;
	else if (IsPassRemainingBlock)
		return true;

//[Values] block
	if (!ReadParameterData_Values(Data, FileIndex, IsFirstRead, Line, ParameterPointer, IsPassRemainingBlock))
		return false;
	else if (IsPassRemainingBlock)
		return true;

//[Switches] block
	if (!ReadParameterData_Switches(Data, FileIndex, IsFirstRead, Line, ParameterPointer, IsPassRemainingBlock))
		return false;
	else if (IsPassRemainingBlock)
		return true;

//[Data] block
	if (!ReadParameterData_Data(Data, FileIndex, IsFirstRead, Line, ParameterPointer, IsPassRemainingBlock))
		return false;
	else if (IsPassRemainingBlock)
		return true;

//[Proxy] block
	if (!ReadParameterData_Proxy(Data, FileIndex, IsFirstRead, Line, ParameterPointer, IsPassRemainingBlock))
		return false;
	else if (IsPassRemainingBlock)
		return true;

#if defined(ENABLE_LIBSODIUM)
//[DNSCurve] block
	if (!ReadParameterData_DNSCurve_Main(Data, FileIndex, IsFirstRead, Line, /* ParameterPointer, */ DNSCurveParameterPointer, IsPassRemainingBlock))
		return false;
	else if (IsPassRemainingBlock)
		return true;

//[DNSCurve Database] block
	if (!ReadParameterData_DNSCurve_Database(Data, FileIndex, IsFirstRead, Line, /* ParameterPointer, DNSCurveParameterPointer, */ IsPassRemainingBlock))
		return false;
	else if (IsPassRemainingBlock)
		return true;

//[DNSCurve Addresses] block
	if (!ReadParameterData_DNSCurve_Addresses(Data, FileIndex, IsFirstRead, Line, /* ParameterPointer, DNSCurveParameterPointer, */ IsPassRemainingBlock))
		return false;
	else if (IsPassRemainingBlock)
		return true;

//[DNSCurve Keys] block
	if (!ReadParameterData_DNSCurve_Keys(Data, FileIndex, /* IsFirstRead, */ Line, /* ParameterPointer, */ DNSCurveParameterPointer, IsPassRemainingBlock))
		return false;
	else if (IsPassRemainingBlock)
		return true;

//[DNSCurve Magic Number] block
	if (!ReadParameterData_DNSCurve_MagicNumber(Data, FileIndex, /* IsFirstRead, */ Line, /* ParameterPointer, */ DNSCurveParameterPointer, IsPassRemainingBlock))
		return false;
	else if (IsPassRemainingBlock)
		return true;
#endif

	return true;
}

//Read parameter data from files(Base block)
bool ReadParameterData_Base(
	const std::string &Data, 
	const size_t FileIndex, 
	const bool IsFirstRead, 
	const size_t Line, 
	CONFIGURATION_TABLE * const ParameterPointer, 
	bool &IsFoundParameter)
{
	size_t UnsignedResult = 0;

//[Base] block
	if (Data.compare(0, strlen("Version="), "Version=") == 0)
	{
		if (Data.length() > strlen("Version=") && Data.length() < strlen("Version=") + CONFIG_VERSION_MAXSIZE && //Version = x.x(x)
			Data.find(ASCII_PERIOD) != std::string::npos && Data.find(ASCII_MINUS) == std::string::npos)
		{
		//Get list data.
			std::vector<std::string> ListData;
			ReadSupport_GetParameterListData(ListData, Data, strlen("Version="), Data.length(), ASCII_PERIOD, true, true);
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

		//Mark parameter found.
			IsFoundParameter = true;
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (Data.compare(0, strlen("FileRefreshTime="), "FileRefreshTime=") == 0 && Data.length() > strlen("FileRefreshTime="))
	{
		if (Data.length() < strlen("FileRefreshTime=") + UINT16_STRING_MAXLEN && 
			Data.find(ASCII_MINUS) == std::string::npos)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("FileRefreshTime="), nullptr, 0);
			if (UnsignedResult >= SHORTEST_FILE_REFRESH_TIME && UnsignedResult < ULONG_MAX)
			{
				ParameterPointer->FileRefreshTime = UnsignedResult * SECOND_TO_MILLISECOND;
				IsFoundParameter = true;
			}
		}
		else {
			goto PrintDataFormatError;
		}
	}

	if (IsFirstRead)
	{
		if (Data.compare(0, strlen("LargeBufferSize="), "LargeBufferSize=") == 0 && Data.length() > strlen("LargeBufferSize="))
		{
			if (Data.length() < strlen("LargeBufferSize=") + UINT16_STRING_MAXLEN && 
				Data.find(ASCII_MINUS) == std::string::npos)
			{
				_set_errno(0);
				UnsignedResult = strtoul(Data.c_str() + strlen("LargeBufferSize="), nullptr, 0);
				if (UnsignedResult >= PACKET_NORMAL_MAXSIZE && UnsignedResult < ULONG_MAX)
				{
					Parameter.LargeBufferSize = UnsignedResult;
					IsFoundParameter = true;
				}
			}
			else {
				goto PrintDataFormatError;
			}
		}
		else if (Data.compare(0, strlen("Additional Path = "), "Additional Path = ") == 0 && Data.length() > strlen("Additional Path = "))
		{
		#if defined(PLATFORM_WIN)
			if (!ReadSupport_PathFileName(Data, strlen("Additional Path = "), true, GlobalRunningStatus.Path_Global, FileIndex, Line))
		#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			if (!ReadSupport_PathFileName(Data, strlen("Additional Path = "), true, GlobalRunningStatus.Path_Global, GlobalRunningStatus.Path_Global_MBS, FileIndex, Line))
		#endif
				return false;

		//Mark parameter found.
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("Hosts File Name = "), "Hosts File Name = ") == 0 && Data.length() > strlen("Hosts File Name = "))
		{
		#if defined(PLATFORM_WIN)
			if (!ReadSupport_PathFileName(Data, strlen("Hosts File Name = "), false, GlobalRunningStatus.FileList_Hosts, FileIndex, Line))
		#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			if (!ReadSupport_PathFileName(Data, strlen("Hosts File Name = "), false, GlobalRunningStatus.FileList_Hosts, GlobalRunningStatus.FileList_Hosts_MBS, FileIndex, Line))
		#endif
				return false;

		//Mark parameter found.
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("IPFilter File Name = "), "IPFilter File Name = ") == 0 && Data.length() > strlen("IPFilter File Name = "))
		{
		#if defined(PLATFORM_WIN)
			if (!ReadSupport_PathFileName(Data, strlen("IPFilter File Name = "), false, GlobalRunningStatus.FileList_IPFilter, FileIndex, Line))
		#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			if (!ReadSupport_PathFileName(Data, strlen("IPFilter File Name = "), false, GlobalRunningStatus.FileList_IPFilter, GlobalRunningStatus.FileList_IPFilter_MBS, FileIndex, Line))
		#endif
				return false;

		//Mark parameter found.
			IsFoundParameter = true;
		}
	}

	return true;

//Jump here to print data format error.
PrintDataFormatError:
	PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Data format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
	return false;
}

//Read parameter data from files(Log block)
bool ReadParameterData_Log(
	const std::string &Data, 
	const size_t FileIndex, 
//	const bool IsFirstRead, 
	const size_t Line, 
	CONFIGURATION_TABLE * const ParameterPointer, 
	bool &IsFoundParameter)
{
	size_t UnsignedResult = 0;

//[Log] block
	if (Data.compare(0, strlen("PrintLogLevel="), "PrintLogLevel=") == 0)
	{
		if (Data.length() == strlen("PrintLogLevel=") + NULL_TERMINATE_LENGTH && 
			Data.find(ASCII_MINUS) == std::string::npos)
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

		//Mark parameter found.
			IsFoundParameter = true;
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (Data.compare(0, strlen("LogMaximumSize="), "LogMaximumSize=") == 0 && Data.length() > strlen("LogMaximumSize="))
	{
	//Format check
		if (Data.find(ASCII_MINUS) != std::string::npos)
			goto PrintDataFormatError;

	//Convert number.
		std::string InnerData(Data);
		CaseConvert(InnerData, true);
		if (InnerData.find("KB") != std::string::npos)
		{
			InnerData.erase(InnerData.length() - strlen("KB"), strlen("KB"));

		//Mark bytes.
			_set_errno(0);
			UnsignedResult = strtoul(InnerData.c_str() + strlen("LogMaximumSize="), nullptr, 0);
			if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult < ULONG_MAX))
				ParameterPointer->LogMaxSize = UnsignedResult * KIBIBYTE_TIMES;
			else 
				goto PrintDataFormatError;
		}
		else if (InnerData.find("MB") != std::string::npos)
		{
			InnerData.erase(InnerData.length() - strlen("MB"), strlen("MB"));

		//Mark bytes.
			_set_errno(0);
			UnsignedResult = strtoul(InnerData.c_str() + strlen("LogMaximumSize="), nullptr, 0);
			if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult < ULONG_MAX))
				ParameterPointer->LogMaxSize = UnsignedResult * MEBIBYTE_TIMES;
			else 
				goto PrintDataFormatError;
		}
		else if (InnerData.find("GB") != std::string::npos)
		{
			InnerData.erase(InnerData.length() - strlen("GB"), strlen("GB"));

		//Mark bytes.
			_set_errno(0);
			UnsignedResult = strtoul(InnerData.c_str() + strlen("LogMaximumSize="), nullptr, 0);
			if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult < ULONG_MAX))
				ParameterPointer->LogMaxSize = UnsignedResult * GIBIBYTE_TIMES;
			else 
				goto PrintDataFormatError;
		}
		else {
		//Check number.
			for (auto StringIter = InnerData.begin() + strlen("LogMaximumSize=");StringIter != InnerData.end();++StringIter)
			{
				if (*StringIter < ASCII_ZERO || *StringIter > ASCII_NINE)
					goto PrintDataFormatError;
			}

		//Mark bytes.
			_set_errno(0);
			UnsignedResult = strtoul(InnerData.c_str() + strlen("LogMaximumSize="), nullptr, 0);
			if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult < ULONG_MAX))
				ParameterPointer->LogMaxSize = UnsignedResult;
			else 
				goto PrintDataFormatError;
		}

	//Mark parameter found.
		IsFoundParameter = true;
	}

	return true;

//Jump here to print data format error.
PrintDataFormatError:
	PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Data format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
	return false;
}

//Read parameter data from files(Listen block)
bool ReadParameterData_Listen(
	const std::string &Data, 
	const size_t FileIndex, 
	const bool IsFirstRead, 
	const size_t Line, 
	CONFIGURATION_TABLE * const ParameterPointer, 
	bool &IsFoundParameter)
{
	size_t UnsignedResult = 0;

//[Listen] block
	if (IsFirstRead)
	{
		if (Data.compare(0, strlen("ProcessUnique=1"), "ProcessUnique=1") == 0)
		{
			Parameter.IsProcessUnique = true;
			IsFoundParameter = true;
		}

	#if defined(ENABLE_PCAP)
		else if (Data.compare(0, strlen("PcapCapture=1"), "PcapCapture=1") == 0)
		{
			Parameter.IsPcapCapture = true;
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("PcapDevicesBlacklist="), "PcapDevicesBlacklist=") == 0)
		{
			ReadSupport_GetParameterListData(*Parameter.PcapDevicesBlacklist, Data, strlen("PcapDevicesBlacklist="), Data.length(), ASCII_VERTICAL, true, false);
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("PcapReadingTimeout="), "PcapReadingTimeout=") == 0)
		{
			if (Data.length() < strlen("PcapReadingTimeout=") + UINT16_STRING_MAXLEN && 
				Data.find(ASCII_MINUS) == std::string::npos)
			{
				_set_errno(0);
				UnsignedResult = strtoul(Data.c_str() + strlen("PcapReadingTimeout="), nullptr, 0);
				if (UnsignedResult > PCAP_CAPTURE_MIN_TIMEOUT && UnsignedResult < ULONG_MAX)
				{
					Parameter.PcapReadingTimeout = UnsignedResult;
					IsFoundParameter = true;
				}
			}
			else {
				goto PrintDataFormatError;
			}
		}
	#endif
		else if (Data.compare(0, strlen("ListenProtocol="), "ListenProtocol=") == 0 && Data.length() > strlen("ListenProtocol="))
		{
			std::string InnerData(Data);
			CaseConvert(InnerData, true);

		//Network layer
			if (InnerData.find("IPV6") != std::string::npos && InnerData.find("IPV4") == std::string::npos)
				Parameter.ListenProtocol_Network = LISTEN_PROTOCOL_NETWORK::IPV6;
			else if (InnerData.find("IPV4") != std::string::npos && InnerData.find("IPV6") == std::string::npos)
				Parameter.ListenProtocol_Network = LISTEN_PROTOCOL_NETWORK::IPV4;
			else 
				Parameter.ListenProtocol_Network = LISTEN_PROTOCOL_NETWORK::BOTH;

		//Transport layer
			if (InnerData.find("TCP") != std::string::npos && InnerData.find("UDP") == std::string::npos)
				Parameter.ListenProtocol_Transport = LISTEN_PROTOCOL_TRANSPORT::TCP;
			else if (InnerData.find("UDP") != std::string::npos && InnerData.find("TCP") == std::string::npos)
				Parameter.ListenProtocol_Transport = LISTEN_PROTOCOL_TRANSPORT::UDP;
			else 
				Parameter.ListenProtocol_Transport = LISTEN_PROTOCOL_TRANSPORT::BOTH;

		//Mark parameter found.
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("ListenPort="), "ListenPort=") == 0 && Data.length() > strlen("ListenPort="))
		{
		//Format check
			if (Data.find(ASCII_MINUS) != std::string::npos)
				goto PrintDataFormatError;

		//Get list data.
			std::vector<std::string> ListData;
			ReadSupport_GetParameterListData(ListData, Data, strlen("ListenPort="), Data.length(), ASCII_VERTICAL, false, false);
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

			//Register to global list.
				Parameter.ListenPort->push_back(hton16(static_cast<const uint16_t>(UnsignedResult)));
			}

		//Mark parameter found.
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("OperationMode="), "OperationMode=") == 0 && Data.length() > strlen("OperationMode="))
		{
			std::string InnerData(Data);
			CaseConvert(InnerData, true);
			if (InnerData.find("SERVER") != std::string::npos)
			{
				Parameter.OperationMode = LISTEN_MODE::SERVER;
				IsFoundParameter = true;
			}
			else if (InnerData.find("CUSTOM") != std::string::npos)
			{
				Parameter.OperationMode = LISTEN_MODE::CUSTOM;
				IsFoundParameter = true;
			}
			else if (InnerData.find("PROXY") != std::string::npos)
			{
				Parameter.OperationMode = LISTEN_MODE::PROXY;
				IsFoundParameter = true;
			}
//			else if (InnerData.find("PRIVATE") != std::string::npos)
			else {
				Parameter.OperationMode = LISTEN_MODE::PRIVATE;
				IsFoundParameter = true;
			}
		}
	}

	if (Data.compare(0, strlen("IPFilterType="), "IPFilterType=") == 0 && Data.length() > strlen("IPFilterType="))
	{
		std::string InnerData(Data);
		CaseConvert(InnerData, true);
		if (InnerData.compare(0, strlen("IPFILTERTYPE=PERMIT"), "IPFILTERTYPE=PERMIT") == 0)
		{
			ParameterPointer->IsIPFilterTypePermit = true;
			IsFoundParameter = true;
		}
	}
	else if (Data.compare(0, strlen("IPFilterLevel<"), "IPFilterLevel<") == 0 && Data.length() > strlen("IPFilterLevel<"))
	{
		if (Data.length() < strlen("IPFilterLevel<") + UINT8_STRING_MAXLEN && 
			Data.find(ASCII_MINUS) == std::string::npos)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("IPFilterLevel<"), nullptr, 0);
			if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult <= UINT16_MAX))
			{
				ParameterPointer->IPFilterLevel = UnsignedResult;
				IsFoundParameter = true;
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
	else if (Data.compare(0, strlen("AcceptType="), "AcceptType=") == 0 && Data.length() > strlen("AcceptType="))
	{
		if (Data.find(ASCII_COLON) == std::string::npos || 
			Data.find(ASCII_MINUS) != std::string::npos)
		{
			goto PrintDataFormatError;
		}
		else {
			std::string InnerData(Data);
			CaseConvert(InnerData, true);

		//Permit or Deny mode check
			if (InnerData.find("PERMIT:") != std::string::npos)
				ParameterPointer->IsAcceptTypePermit = true;
			else 
				ParameterPointer->IsAcceptTypePermit = false;

		//Get list data.
			std::vector<std::string> ListData;
			ReadSupport_GetParameterListData(ListData, InnerData, InnerData.find(ASCII_COLON) + 1U, InnerData.length(), ASCII_VERTICAL, false, false);
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
				ParameterPointer->AcceptTypeList->push_back(static_cast<const uint16_t>(UnsignedResult));
			}

		//Mark parameter found.
			IsFoundParameter = true;
		}
	}

	return true;

//Jump here to print data format error.
PrintDataFormatError:
	PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Data format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
	return false;
}

//Read parameter data from files(DNS block)
bool ReadParameterData_DNS(
	const std::string &Data, 
	const size_t FileIndex, 
	const bool IsFirstRead, 
	const size_t Line, 
	CONFIGURATION_TABLE * const ParameterPointer, 
	bool &IsFoundParameter)
{
	size_t UnsignedResult = 0;

//[DNS] block
	if (IsFirstRead && Data.compare(0, strlen("OutgoingProtocol="), "OutgoingProtocol=") == 0 && Data.length() > strlen("OutgoingProtocol="))
	{
		std::string InnerData(Data);
		CaseConvert(InnerData, true);

	//Network layer
		if (InnerData.find("IPV6") != std::string::npos && InnerData.find("IPV4") == std::string::npos)
			Parameter.RequestMode_Network = REQUEST_MODE_NETWORK::IPV6;
		else if (InnerData.find("IPV4") != std::string::npos && InnerData.find("IPV6") == std::string::npos)
			Parameter.RequestMode_Network = REQUEST_MODE_NETWORK::IPV4;
		else 
			Parameter.RequestMode_Network = REQUEST_MODE_NETWORK::BOTH;

	//Transport layer
		if (InnerData.find("FORCE") != std::string::npos)
		{
			if (InnerData.find("TCP") != std::string::npos)
				Parameter.RequestMode_Transport = REQUEST_MODE_TRANSPORT::FORCE_TCP;
			else 
				Parameter.RequestMode_Transport = REQUEST_MODE_TRANSPORT::FORCE_UDP;
		}
		else if (InnerData.find("TCP") != std::string::npos)
		{
			Parameter.RequestMode_Transport = REQUEST_MODE_TRANSPORT::TCP;
		}
		else {
			Parameter.RequestMode_Transport = REQUEST_MODE_TRANSPORT::UDP;
		}

	//According type
		if (InnerData.find("TYPE") != std::string::npos)
			Parameter.RequestMode_IsAccordingType = true;

	//Mark parameter found.
		IsFoundParameter = true;
	}
	else if (Data.compare(0, strlen("DirectRequest="), "DirectRequest=") == 0 && Data.length() > strlen("DirectRequest="))
	{
		if (Data.compare(0, strlen("DirectRequest=1"), "DirectRequest=1") == 0)
		{
			ParameterPointer->DirectRequest_Protocol = REQUEST_MODE_DIRECT::BOTH;
		}
		else {
			std::string InnerData(Data);
			CaseConvert(InnerData, true);

		//Network layer
			if (InnerData.find("IPV6") != std::string::npos && InnerData.find("IPV4") != std::string::npos)
				ParameterPointer->DirectRequest_Protocol = REQUEST_MODE_DIRECT::BOTH;
			else if (InnerData.find("IPV6") != std::string::npos)
				ParameterPointer->DirectRequest_Protocol = REQUEST_MODE_DIRECT::IPV6;
			else if (InnerData.find("IPV4") != std::string::npos)
				ParameterPointer->DirectRequest_Protocol = REQUEST_MODE_DIRECT::IPV4;
		}

	//Mark parameter found.
		IsFoundParameter = true;
	}

	if (IsFirstRead)
	{
		if (Data.compare(0, strlen("CacheType="), "CacheType=") == 0 && Data.length() > strlen("CacheType="))
		{
			std::string InnerData(Data);
			CaseConvert(InnerData, true);
			if (InnerData.find("QUEUE") != std::string::npos && InnerData.find("TIMER") != std::string::npos)
			{
				Parameter.DNS_CacheType = DNS_CACHE_TYPE::BOTH;
				IsFoundParameter = true;
			}
			else if (InnerData.find("TIMER") != std::string::npos)
			{
				Parameter.DNS_CacheType = DNS_CACHE_TYPE::TIMER;
				IsFoundParameter = true;
			}
			else if (InnerData.find("QUEUE") != std::string::npos)
			{
				Parameter.DNS_CacheType = DNS_CACHE_TYPE::QUEUE;
				IsFoundParameter = true;
			}
		}
		else if (Data.compare(0, strlen("CacheParameter="), "CacheParameter=")== 0 && Data.length() > strlen("CacheParameter="))
		{
		//Format check
			if (Data.find(ASCII_MINUS) != std::string::npos)
				goto PrintDataFormatError;

		//Convert number.
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("CacheParameter="), nullptr, 0);
			if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult < ULONG_MAX))
				Parameter.DNS_CacheParameter = UnsignedResult;
			else 
				goto PrintDataFormatError;

		//Mark parameter found.
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("CacheSingleIPv4AddressPrefix="), "CacheSingleIPv4AddressPrefix=") == 0 && Data.length() > strlen("CacheSingleIPv4AddressPrefix="))
		{
		//Format check
			if (Data.find(ASCII_MINUS) != std::string::npos)
				goto PrintDataFormatError;

		//Convert number.
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("CacheSingleIPv4AddressPrefix="), nullptr, 0);
			if (UnsignedResult > 0 && UnsignedResult <= sizeof(in_addr) * BYTES_TO_BITS)
			{
				Parameter.DNS_CacheSinglePrefix_IPv4 = UnsignedResult;
				IsFoundParameter = true;
			}
			else if (UnsignedResult != 0)
			{
				goto PrintDataFormatError;
			}
		}
		else if (Data.compare(0, strlen("CacheSingleIPv6AddressPrefix="), "CacheSingleIPv6AddressPrefix=") == 0 && Data.length() > strlen("CacheSingleIPv6AddressPrefix="))
		{
		//Format check
			if (Data.find(ASCII_MINUS) != std::string::npos)
				goto PrintDataFormatError;

		//Convert number.
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("CacheSingleIPv6AddressPrefix="), nullptr, 0);
			if (UnsignedResult > 0 && UnsignedResult <= sizeof(in6_addr) * BYTES_TO_BITS)
			{
				Parameter.DNS_CacheSinglePrefix_IPv6 = UnsignedResult;
				IsFoundParameter = true;
			}
			else if (UnsignedResult != 0)
			{
				goto PrintDataFormatError;
			}
		}
	}

	if (Data.compare(0, strlen("DefaultTTL="), "DefaultTTL=") == 0 && Data.length() > strlen("DefaultTTL="))
	{
		if (Data.length() < strlen("DefaultTTL=") + UINT16_STRING_MAXLEN && 
			Data.find(ASCII_MINUS) == std::string::npos)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("DefaultTTL="), nullptr, 0);
			if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult < ULONG_MAX))
			{
				ParameterPointer->HostsDefaultTTL = static_cast<const uint32_t>(UnsignedResult);
				IsFoundParameter = true;
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

	return true;

//Jump here to print data format error.
PrintDataFormatError:
	PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Data format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
	return false;
}

//Read parameter data from files(Local DNS block)
bool ReadParameterData_Local_DNS(
	const std::string &Data, 
//	const size_t FileIndex, 
	const bool IsFirstRead, 
//	const size_t Line, 
	CONFIGURATION_TABLE * const ParameterPointer, 
	bool &IsFoundParameter)
{
//[Local DNS] block
	if (Data.compare(0, strlen("LocalProtocol="), "LocalProtocol=") == 0)
	{
		std::string InnerData(Data);
		CaseConvert(InnerData, true);

	//Network layer
		if (InnerData.find("IPV6") != std::string::npos && InnerData.find("IPV4") == std::string::npos)
			ParameterPointer->LocalProtocol_Network = REQUEST_MODE_NETWORK::IPV6;
		else if (InnerData.find("IPV4") != std::string::npos && InnerData.find("IPV6") == std::string::npos)
			ParameterPointer->LocalProtocol_Network = REQUEST_MODE_NETWORK::IPV4;
		else 
			ParameterPointer->LocalProtocol_Network = REQUEST_MODE_NETWORK::BOTH;

	//Transport layer
		if (InnerData.find("FORCE") != std::string::npos)
		{
			if (InnerData.find("TCP") != std::string::npos)
				ParameterPointer->LocalProtocol_Transport = REQUEST_MODE_TRANSPORT::FORCE_TCP;
			else 
				ParameterPointer->LocalProtocol_Transport = REQUEST_MODE_TRANSPORT::FORCE_UDP;
		}
		else if (InnerData.find("TCP") != std::string::npos)
		{
			ParameterPointer->LocalProtocol_Transport = REQUEST_MODE_TRANSPORT::TCP;
		}
		else {
			ParameterPointer->LocalProtocol_Transport = REQUEST_MODE_TRANSPORT::UDP;
		}

	//According type
		if (InnerData.find("TYPE") != std::string::npos)
			ParameterPointer->LocalProtocol_IsAccordingType = true;

	//Mark parameter found.
		IsFoundParameter = true;
	}

	if (IsFirstRead)
	{
		if (Data.compare(0, strlen("LocalHosts=1"), "LocalHosts=1") == 0)
		{
			Parameter.IsLocalHosts = true;
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("LocalRouting=1"), "LocalRouting=1") == 0)
		{
			Parameter.IsLocalRouting = true;
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("LocalForceRequest=1"), "LocalForceRequest=1") == 0)
		{
			Parameter.IsLocalForce = true;
			IsFoundParameter = true;
		}
	}

	return true;

/* No need error report label.
//Jump here to print data format error.
PrintDataFormatError:
	PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Data format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
	return false;
*/
}

//Read parameter data from files(Addresses block)
bool ReadParameterData_Addresses(
	const std::string &Data, 
	const size_t FileIndex, 
	const bool IsFirstRead, 
	const size_t Line, 
//	CONFIGURATION_TABLE * const ParameterPointer, 
	bool &IsFoundParameter)
{
//[Addresses] block
	if (IsFirstRead)
	{
		if (Data.compare(0, strlen("IPv4ListenAddress="), "IPv4ListenAddress=") == 0 && 
			Data.length() > strlen("IPv4ListenAddress="))
		{
		//Get list data.
			std::vector<DNS_SERVER_DATA> DNSServerDataTemp;
			if (!ReadSupport_MultipleAddresses(AF_INET, Data, strlen("IPv4ListenAddress="), &DNSServerDataTemp, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
				return false;

		//Register to global list.
			for (const auto &DNSServerDataItem:DNSServerDataTemp)
				Parameter.ListenAddress_IPv4->push_back(DNSServerDataItem.AddressData.Storage);

		//Mark parameter found.
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("IPv4EDNSClientSubnetAddress="), "IPv4EDNSClientSubnetAddress=") == 0 && 
			Data.length() > strlen("IPv4EDNSClientSubnetAddress="))
		{
			if (!ReadSupport_AddressPrefixData(AF_INET, Data, strlen("IPv4EDNSClientSubnetAddress="), Parameter.LocalMachineSubnet_IPv4, FileList_Config, FileIndex, Line))
				return false;

		//Mark parameter found.
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("IPv4MainDNSAddress="), "IPv4MainDNSAddress=") == 0 && 
			Data.length() > strlen("IPv4MainDNSAddress="))
		{
			if (!ReadSupport_MultipleAddresses(AF_INET, Data, strlen("IPv4MainDNSAddress="), Parameter.Target_Server_IPv4_Multiple, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
				return false;

		//Mark parameter found.
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("IPv4AlternateDNSAddress="), "IPv4AlternateDNSAddress=") == 0 && 
			Data.length() > strlen("IPv4AlternateDNSAddress="))
		{
			if (!ReadSupport_MultipleAddresses(AF_INET, Data, strlen("IPv4AlternateDNSAddress="), Parameter.Target_Server_IPv4_Multiple, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
				return false;

		//Mark parameter found.
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("IPv4LocalMainDNSAddress="), "IPv4LocalMainDNSAddress=") == 0 && 
			Data.length() > strlen("IPv4LocalMainDNSAddress="))
		{
			std::vector<DNS_SERVER_DATA> DNSServerDataTemp;
			if (!ReadSupport_MultipleAddresses(AF_INET, Data, strlen("IPv4LocalMainDNSAddress="), &DNSServerDataTemp, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line) || DNSServerDataTemp.empty())
			{
				return false;
			}
			else {
				Parameter.Target_Server_Local_Main_IPv4 = DNSServerDataTemp.front().AddressData;
				IsFoundParameter = true;
			}
		}
		else if (Data.compare(0, strlen("IPv4LocalAlternateDNSAddress="), "IPv4LocalAlternateDNSAddress=") == 0 && 
			Data.length() > strlen("IPv4LocalAlternateDNSAddress="))
		{
			std::vector<DNS_SERVER_DATA> DNSServerDataTemp;
			if (!ReadSupport_MultipleAddresses(AF_INET, Data, strlen("IPv4LocalAlternateDNSAddress="), &DNSServerDataTemp, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line) || DNSServerDataTemp.empty())
			{
				return false;
			}
			else {
				Parameter.Target_Server_Local_Alternate_IPv4 = DNSServerDataTemp.front().AddressData;
				IsFoundParameter = true;
			}
		}
		else if (Data.compare(0, strlen("IPv6ListenAddress="), "IPv6ListenAddress=") == 0 && 
			Data.length() > strlen("IPv6ListenAddress="))
		{
		//Get list data.
			std::vector<DNS_SERVER_DATA> DNSServerDataTemp;
			if (!ReadSupport_MultipleAddresses(AF_INET6, Data, strlen("IPv6ListenAddress="), &DNSServerDataTemp, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
				return false;

		//Register to global list.
			for (const auto &DNSServerDataItem:DNSServerDataTemp)
				Parameter.ListenAddress_IPv6->push_back(DNSServerDataItem.AddressData.Storage);

		//Mark parameter found.
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("IPv6EDNSClientSubnetAddress="), "IPv6EDNSClientSubnetAddress=") == 0 && 
			Data.length() > strlen("IPv6EDNSClientSubnetAddress="))
		{
			if (!ReadSupport_AddressPrefixData(AF_INET6, Data, strlen("IPv6EDNSClientSubnetAddress="), Parameter.LocalMachineSubnet_IPv6, FileList_Config, FileIndex, Line))
				return false;

		//Mark parameter found.
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("IPv6MainDNSAddress="), "IPv6MainDNSAddress=") == 0 && 
			Data.length() > strlen("IPv6MainDNSAddress="))
		{
			if (!ReadSupport_MultipleAddresses(AF_INET6, Data, strlen("IPv6MainDNSAddress="), Parameter.Target_Server_IPv6_Multiple, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
				return false;

		//Mark parameter found.
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("IPv6AlternateDNSAddress="), "IPv6AlternateDNSAddress=") == 0 && 
			Data.length() > strlen("IPv6AlternateDNSAddress="))
		{
			if (!ReadSupport_MultipleAddresses(AF_INET6, Data, strlen("IPv6AlternateDNSAddress="), Parameter.Target_Server_IPv6_Multiple, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
				return false;

		//Mark parameter found.
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("IPv6LocalMainDNSAddress="), "IPv6LocalMainDNSAddress=") == 0 && 
			Data.length() > strlen("IPv6LocalMainDNSAddress="))
		{
			std::vector<DNS_SERVER_DATA> DNSServerDataTemp;
			if (!ReadSupport_MultipleAddresses(AF_INET6, Data, strlen("IPv6LocalMainDNSAddress="), &DNSServerDataTemp, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line) || DNSServerDataTemp.empty())
			{
				return false;
			}
			else {
				Parameter.Target_Server_Local_Main_IPv6 = DNSServerDataTemp.front().AddressData;
				IsFoundParameter = true;
			}
		}
		else if (Data.compare(0, strlen("IPv6LocalAlternateDNSAddress="), "IPv6LocalAlternateDNSAddress=") == 0 && 
			Data.length() > strlen("IPv6LocalAlternateDNSAddress="))
		{
			std::vector<DNS_SERVER_DATA> DNSServerDataTemp;
			if (!ReadSupport_MultipleAddresses(AF_INET6, Data, strlen("IPv6LocalAlternateDNSAddress="), &DNSServerDataTemp, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line) || DNSServerDataTemp.empty())
			{
				return false;
			}
			else {
				Parameter.Target_Server_Local_Alternate_IPv6 = DNSServerDataTemp.front().AddressData;
				IsFoundParameter = true;
			}
		}
	}

	return true;

/* No need error report label.
//Jump here to print data format error.
PrintDataFormatError:
	PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Data format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
	return false;
*/
}

//Read parameter data from files(Values block)
bool ReadParameterData_Values(
	const std::string &Data, 
	const size_t FileIndex, 
	const bool IsFirstRead, 
	const size_t Line, 
	CONFIGURATION_TABLE * const ParameterPointer, 
	bool &IsFoundParameter)
{
	size_t UnsignedResult = 0;

//[Values] block
	if (IsFirstRead)
	{
		if (Data.compare(0, strlen("ThreadPoolBaseNumber="), "ThreadPoolBaseNumber=") == 0 && Data.length() > strlen("ThreadPoolBaseNumber="))
		{
			if (Data.length() < strlen("ThreadPoolBaseNumber=") + UINT32_STRING_MAXLEN - 1U && 
				Data.find(ASCII_MINUS) == std::string::npos)
			{
				_set_errno(0);
				UnsignedResult = strtoul(Data.c_str() + strlen("ThreadPoolBaseNumber="), nullptr, 0);
				if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult <= THREAD_POOL_MAXNUM))
				{
					Parameter.ThreadPoolBaseNum = UnsignedResult;
					IsFoundParameter = true;
				}
			}
			else {
				goto PrintDataFormatError;
			}
		}
		else if (Data.compare(0, strlen("ThreadPoolMaximumNumber="), "ThreadPoolMaximumNumber=") == 0 && Data.length() > strlen("ThreadPoolMaximumNumber="))
		{
			if (Data.length() < strlen("ThreadPoolMaximumNumber=") + UINT32_STRING_MAXLEN - 1U && 
				Data.find(ASCII_MINUS) == std::string::npos)
			{
				_set_errno(0);
				UnsignedResult = strtoul(Data.c_str() + strlen("ThreadPoolMaximumNumber="), nullptr, 0);
				if (UnsignedResult >= THREAD_POOL_MINNUM && UnsignedResult <= THREAD_POOL_MAXNUM)
				{
					Parameter.ThreadPoolMaxNum = UnsignedResult;
					IsFoundParameter = true;
				}
			}
			else {
				goto PrintDataFormatError;
			}
		}
	}

	if (Data.compare(0, strlen("ThreadPoolResetTime="), "ThreadPoolResetTime=") == 0 && Data.length() > strlen("ThreadPoolResetTime="))
	{
		if (Data.length() < strlen("ThreadPoolResetTime=") + UINT16_STRING_MAXLEN && 
			Data.find(ASCII_MINUS) == std::string::npos)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("ThreadPoolResetTime="), nullptr, 0);
			if (UnsignedResult >= SHORTEST_THREAD_POOL_RESET_TIME && UnsignedResult < ULONG_MAX)
			{
				ParameterPointer->ThreadPoolResetTime = UnsignedResult * SECOND_TO_MILLISECOND;
				IsFoundParameter = true;
			}
		}
		else {
			goto PrintDataFormatError;
		}
	}

	if (IsFirstRead)
	{
		if (Data.compare(0, strlen("QueueLimitsResetTime="), "QueueLimitsResetTime=") == 0 && Data.length() > strlen("QueueLimitsResetTime="))
		{
			if (Data.length() < strlen("QueueLimitsResetTime=") + UINT16_STRING_MAXLEN && 
				Data.find(ASCII_MINUS) == std::string::npos)
			{
				_set_errno(0);
				UnsignedResult = strtoul(Data.c_str() + strlen("QueueLimitsResetTime="), nullptr, 0);
				if (UnsignedResult >= SHORTEST_QUEUE_RESET_TIME && UnsignedResult < ULONG_MAX)
				{
					Parameter.QueueResetTime = UnsignedResult * SECOND_TO_MILLISECOND;
					IsFoundParameter = true;
				}
			}
			else {
				goto PrintDataFormatError;
			}
		}
		else if (Data.compare(0, strlen("EDNSPayloadSize="), "EDNSPayloadSize=") == 0 && Data.length() > strlen("EDNSPayloadSize="))
		{
			if (Data.length() < strlen("EDNSPayloadSize=") + UINT16_STRING_MAXLEN && 
				Data.find(ASCII_MINUS) == std::string::npos)
			{
				_set_errno(0);
				UnsignedResult = strtoul(Data.c_str() + strlen("EDNSPayloadSize="), nullptr, 0);
				if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult < ULONG_MAX))
				{
					Parameter.EDNS_PayloadSize = UnsignedResult;
					IsFoundParameter = true;
				}
			}
			else {
				goto PrintDataFormatError;
			}
		}
	}

	if (Data.compare(0, strlen("IPv4PacketTTL="), "IPv4PacketTTL=") == 0 && Data.length() > strlen("IPv4PacketTTL="))
	{
	//Range
		if (Data.find(ASCII_MINUS) != std::string::npos && Data.length() > Data.find(ASCII_MINUS) + 1U)
		{
		//Mark beginning value.
			std::string ValueString(Data, strlen("IPv4PacketTTL="), Data.find(ASCII_MINUS) - strlen("IPv4PacketTTL="));
			if (ValueString.find(ASCII_MINUS) != std::string::npos)
				goto PrintDataFormatError;

		//Convert number(Part 1).
			_set_errno(0);
			UnsignedResult = strtoul(ValueString.c_str(), nullptr, 0);
			if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult <= UINT8_MAX))
			#if defined(PLATFORM_WIN)
				ParameterPointer->PacketHopLimits_IPv4_Begin = static_cast<const DWORD>(UnsignedResult);
			#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				ParameterPointer->PacketHopLimits_IPv4_Begin = static_cast<const int>(UnsignedResult);
			#endif
			else 
				goto PrintDataFormatError;

		//Mark end value.
			ValueString.clear();
			ValueString.append(Data, Data.find(ASCII_MINUS) + 1U, Data.length() - Data.find(ASCII_MINUS));
			if (ValueString.find(ASCII_MINUS) != std::string::npos)
				goto PrintDataFormatError;

		//Convert number(Part 2).
			_set_errno(0);
			UnsignedResult = strtoul(ValueString.c_str(), nullptr, 0);
			if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult <= UINT8_MAX))
			#if defined(PLATFORM_WIN)
				ParameterPointer->PacketHopLimits_IPv4_End = static_cast<const DWORD>(UnsignedResult);
			#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				ParameterPointer->PacketHopLimits_IPv4_End = static_cast<const int>(UnsignedResult);
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
			if (Data.length() < strlen("IPv4PacketTTL=") + UINT8_STRING_MAXLEN && 
				Data.find(ASCII_MINUS) == std::string::npos)
			{
				_set_errno(0);
				UnsignedResult = strtoul(Data.c_str() + strlen("IPv4PacketTTL="), nullptr, 0);
				if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult <= UINT8_MAX))
				#if defined(PLATFORM_WIN)
					ParameterPointer->PacketHopLimits_IPv4_Begin = static_cast<const DWORD>(UnsignedResult);
				#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
					ParameterPointer->PacketHopLimits_IPv4_Begin = static_cast<const int>(UnsignedResult);
				#endif
				else 
					goto PrintDataFormatError;
			}
			else {
				goto PrintDataFormatError;
			}
		}

	//Mark parameter found.
		IsFoundParameter = true;
	}

#if defined(ENABLE_PCAP)
	else if (Data.compare(0, strlen("IPv4MainDNSTTL="), "IPv4MainDNSTTL=") == 0 && Data.length() > strlen("IPv4MainDNSTTL="))
	{
		if (!ReadSupport_HopLimitsData(AF_INET, Data, strlen("IPv4MainDNSTTL="), Parameter.Target_Server_IPv4_Multiple, IsFirstRead, FileIndex, Line))
			return false;

	//Mark parameter found.
		IsFoundParameter = true;
	}
	else if (Data.compare(0, strlen("IPv4AlternateDNSTTL="), "IPv4AlternateDNSTTL=") == 0 && Data.length() > strlen("IPv4AlternateDNSTTL="))
	{
		if (!ReadSupport_HopLimitsData(AF_INET, Data, strlen("IPv4AlternateDNSTTL="), Parameter.Target_Server_IPv4_Multiple, IsFirstRead, FileIndex, Line))
			return false;

	//Mark parameter found.
		IsFoundParameter = true;
	}
	else if (Data.compare(0, strlen("IPv6MainDNSHopLimits="), "IPv6MainDNSHopLimits=") == 0 && Data.length() > strlen("IPv6MainDNSHopLimits="))
	{
		if (!ReadSupport_HopLimitsData(AF_INET6, Data, strlen("IPv6MainDNSHopLimits="), Parameter.Target_Server_IPv6_Multiple, IsFirstRead, FileIndex, Line))
			return false;

	//Mark parameter found.
		IsFoundParameter = true;
	}
	else if (Data.compare(0, strlen("IPv6AlternateDNSHopLimits="), "IPv6AlternateDNSHopLimits=") == 0 && Data.length() > strlen("IPv6AlternateDNSHopLimits="))
	{
		if (!ReadSupport_HopLimitsData(AF_INET6, Data, strlen("IPv6AlternateDNSHopLimits="), Parameter.Target_Server_IPv6_Multiple, IsFirstRead, FileIndex, Line))
			return false;

	//Mark parameter found.
		IsFoundParameter = true;
	}
#endif

	else if (Data.compare(0, strlen("IPv6PacketHopLimits="), "IPv6PacketHopLimits=") == 0 && Data.length() > strlen("IPv6PacketHopLimits="))
	{
	//Range
		if (Data.find(ASCII_MINUS) != std::string::npos)
		{
		//Mark beginning value.
			std::string ValueString(Data, strlen("IPv6PacketHopLimits="), Data.find(ASCII_MINUS) - strlen("IPv6PacketHopLimits="));
			if (ValueString.find(ASCII_MINUS) != std::string::npos)
				goto PrintDataFormatError;

		//Convert number(Part 1).
			_set_errno(0);
			UnsignedResult = strtoul(ValueString.c_str(), nullptr, 0);
			if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult <= UINT8_MAX))
			#if defined(PLATFORM_WIN)
				ParameterPointer->PacketHopLimits_IPv6_Begin = static_cast<const DWORD>(UnsignedResult);
			#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				ParameterPointer->PacketHopLimits_IPv6_Begin = static_cast<const int>(UnsignedResult);
			#endif
			else 
				goto PrintDataFormatError;

		//Mark end value.
			ValueString.clear();
			ValueString.append(Data, Data.find(ASCII_MINUS) + 1U, Data.length() - Data.find(ASCII_MINUS));
			if (ValueString.find(ASCII_MINUS) != std::string::npos)
				goto PrintDataFormatError;

		//Convert number(Part 2).
			_set_errno(0);
			UnsignedResult = strtoul(ValueString.c_str(), nullptr, 0);
			if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult <= UINT8_MAX))
			#if defined(PLATFORM_WIN)
				ParameterPointer->PacketHopLimits_IPv6_End = static_cast<const DWORD>(UnsignedResult);
			#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				ParameterPointer->PacketHopLimits_IPv6_End = static_cast<const int>(UnsignedResult);
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
			if (Data.length() < strlen("IPv6PacketHopLimits=") + UINT8_STRING_MAXLEN)
			{
				_set_errno(0);
				UnsignedResult = strtoul(Data.c_str() + strlen("IPv6PacketHopLimits="), nullptr, 0);
				if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult <= UINT8_MAX))
				#if defined(PLATFORM_WIN)
					ParameterPointer->PacketHopLimits_IPv6_Begin = static_cast<const DWORD>(UnsignedResult);
				#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
					ParameterPointer->PacketHopLimits_IPv6_Begin = static_cast<const int>(UnsignedResult);
				#endif
				else 
					goto PrintDataFormatError;
			}
			else {
				goto PrintDataFormatError;
			}
		}

	//Mark parameter found.
		IsFoundParameter = true;
	}

#if defined(ENABLE_PCAP)
	else if (Data.compare(0, strlen("HopLimitsFluctuation="), "HopLimitsFluctuation=") == 0 && Data.length() > strlen("HopLimitsFluctuation="))
	{
		if (Data.length() < strlen("HopLimitsFluctuation=") + UINT8_STRING_MAXLEN && 
			Data.find(ASCII_MINUS) == std::string::npos)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("HopLimitsFluctuation="), nullptr, 0);
			if (UnsignedResult > 0 && UnsignedResult < UINT8_MAX)
			{
				ParameterPointer->HopLimitsFluctuation = static_cast<const uint8_t>(UnsignedResult);
				IsFoundParameter = true;
			}
		}
		else {
			goto PrintDataFormatError;
		}
	}
#endif

	else if (Data.compare(0, strlen("ReliableOnceSocketTimeout="), "ReliableOnceSocketTimeout=") == 0 && 
		Data.length() > strlen("ReliableOnceSocketTimeout="))
	{
		if (Data.length() < strlen("ReliableOnceSocketTimeout=") + UINT32_STRING_MAXLEN && 
			Data.find(ASCII_MINUS) == std::string::npos)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("ReliableOnceSocketTimeout="), nullptr, 0);
			if (UnsignedResult > SOCKET_TIMEOUT_MIN && UnsignedResult < ULONG_MAX)
			{
			#if defined(PLATFORM_WIN)
				ParameterPointer->SocketTimeout_Reliable_Once = static_cast<const DWORD>(UnsignedResult);
			#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				ParameterPointer->SocketTimeout_Reliable_Once.tv_sec = UnsignedResult / SECOND_TO_MILLISECOND;
				ParameterPointer->SocketTimeout_Reliable_Once.tv_usec = UnsignedResult % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
			#endif
				IsFoundParameter = true;
			}
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (Data.compare(0, strlen("ReliableSerialSocketTimeout="), "ReliableSerialSocketTimeout=") == 0 && 
		Data.length() > strlen("ReliableSerialSocketTimeout="))
	{
		if (Data.length() < strlen("ReliableSerialSocketTimeout=") + UINT32_STRING_MAXLEN && 
			Data.find(ASCII_MINUS) == std::string::npos)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("ReliableSerialSocketTimeout="), nullptr, 0);
			if (UnsignedResult > SOCKET_TIMEOUT_MIN && UnsignedResult < ULONG_MAX)
			{
			#if defined(PLATFORM_WIN)
				ParameterPointer->SocketTimeout_Reliable_Serial = static_cast<const DWORD>(UnsignedResult);
			#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				ParameterPointer->SocketTimeout_Reliable_Serial.tv_sec = UnsignedResult / SECOND_TO_MILLISECOND;
				ParameterPointer->SocketTimeout_Reliable_Serial.tv_usec = UnsignedResult % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
			#endif
				IsFoundParameter = true;
			}
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (Data.compare(0, strlen("UnreliableOnceSocketTimeout="), "UnreliableOnceSocketTimeout=") == 0 && 
		Data.length() > strlen("UnreliableOnceSocketTimeout="))
	{
		if (Data.length() < strlen("UnreliableOnceSocketTimeout=") + UINT32_STRING_MAXLEN && 
			Data.find(ASCII_MINUS) == std::string::npos)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("UnreliableOnceSocketTimeout="), nullptr, 0);
			if (UnsignedResult > SOCKET_TIMEOUT_MIN && UnsignedResult < ULONG_MAX)
			{
			#if defined(PLATFORM_WIN)
				ParameterPointer->SocketTimeout_Unreliable_Once = static_cast<const DWORD>(UnsignedResult);
			#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				ParameterPointer->SocketTimeout_Unreliable_Once.tv_sec = UnsignedResult / SECOND_TO_MILLISECOND;
				ParameterPointer->SocketTimeout_Unreliable_Once.tv_usec = UnsignedResult % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
			#endif
				IsFoundParameter = true;
			}
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (Data.compare(0, strlen("UnreliableSerialSocketTimeout="), "UnreliableSerialSocketTimeout=") == 0 && 
		Data.length() > strlen("UnreliableSerialSocketTimeout="))
	{
		if (Data.length() < strlen("UnreliableSerialSocketTimeout=") + UINT32_STRING_MAXLEN && 
			Data.find(ASCII_MINUS) == std::string::npos)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("UnreliableSerialSocketTimeout="), nullptr, 0);
			if (UnsignedResult > SOCKET_TIMEOUT_MIN && UnsignedResult < ULONG_MAX)
			{
			#if defined(PLATFORM_WIN)
				ParameterPointer->SocketTimeout_Unreliable_Serial = static_cast<const DWORD>(UnsignedResult);
			#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				ParameterPointer->SocketTimeout_Unreliable_Serial.tv_sec = UnsignedResult / SECOND_TO_MILLISECOND;
				ParameterPointer->SocketTimeout_Unreliable_Serial.tv_usec = UnsignedResult % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
			#endif
				IsFoundParameter = true;
			}
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (IsFirstRead && Data.compare(0, strlen("TCPFastOpen="), "TCPFastOpen=") == 0 && Data.length() > strlen("TCPFastOpen="))
	{
		if (Data.length() < strlen("TCPFastOpen=") + UINT16_STRING_MAXLEN && 
			Data.find(ASCII_MINUS) == std::string::npos)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("TCPFastOpen="), nullptr, 0);
			if (UnsignedResult > 0 && UnsignedResult < ULONG_MAX)
			{
				Parameter.TCP_FastOpen = UnsignedResult;
				IsFoundParameter = true;
			}
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (Data.compare(0, strlen("ReceiveWaiting="), "ReceiveWaiting=") == 0 && Data.length() > strlen("ReceiveWaiting="))
	{
		if (Data.length() < strlen("ReceiveWaiting=") + UINT16_STRING_MAXLEN && 
			Data.find(ASCII_MINUS) == std::string::npos)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("ReceiveWaiting="), nullptr, 0);
			if (UnsignedResult > 0 && UnsignedResult < ULONG_MAX)
			{
				ParameterPointer->ReceiveWaiting = UnsignedResult;
				IsFoundParameter = true;
			}
		}
		else {
			goto PrintDataFormatError;
		}
	}

#if defined(ENABLE_PCAP)
	else if (Data.compare(0, strlen("ICMPTest="), "ICMPTest=") == 0 && Data.length() > strlen("ICMPTest="))
	{
		if (Data.length() < strlen("ICMPTest=") + UINT16_STRING_MAXLEN && 
			Data.find(ASCII_MINUS) == std::string::npos)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("ICMPTest="), nullptr, 0);
			if (UnsignedResult >= SHORTEST_ICMP_TEST_TIME && UnsignedResult < ULONG_MAX)
				ParameterPointer->ICMP_Speed = UnsignedResult * SECOND_TO_MILLISECOND;
			else if (UnsignedResult > 0 && UnsignedResult < SHORTEST_ICMP_TEST_TIME)
				ParameterPointer->ICMP_Speed = SHORTEST_ICMP_TEST_TIME * SECOND_TO_MILLISECOND;
			else //ICMP Test disabled
				ParameterPointer->ICMP_Speed = 0;

		//Mark parameter found.
			IsFoundParameter = true;
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (Data.compare(0, strlen("DomainTest="), "DomainTest=") == 0 && Data.length() > strlen("DomainTest="))
	{
		if (Data.length() < strlen("DomainTest=") + UINT16_STRING_MAXLEN && 
			Data.find(ASCII_MINUS) == std::string::npos)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("DomainTest="), nullptr, 0);
			if (UnsignedResult >= SHORTEST_DOMAIN_TEST_INTERVAL_TIME && UnsignedResult < ULONG_MAX)
				ParameterPointer->DomainTest_Speed = UnsignedResult * SECOND_TO_MILLISECOND;
			else if (UnsignedResult > 0 && UnsignedResult < SHORTEST_DOMAIN_TEST_INTERVAL_TIME)
				ParameterPointer->DomainTest_Speed = SHORTEST_DOMAIN_TEST_INTERVAL_TIME * SECOND_TO_MILLISECOND;
			else //Domain Test disabled
				ParameterPointer->DomainTest_Speed = 0;

		//Mark parameter found.
			IsFoundParameter = true;
		}
		else {
			goto PrintDataFormatError;
		}
	}
#endif

	if (IsFirstRead)
	{
		if (Data.compare(0, strlen("AlternateTimes="), "AlternateTimes=") == 0 && Data.length() > strlen("AlternateTimes="))
		{
			if (Data.length() < strlen("AlternateTimes=") + UINT16_STRING_MAXLEN && 
				Data.find(ASCII_MINUS) == std::string::npos)
			{
				_set_errno(0);
				UnsignedResult = strtoul(Data.c_str() + strlen("AlternateTimes="), nullptr, 0);
				if (UnsignedResult > 0 && UnsignedResult < ULONG_MAX)
				{
					Parameter.AlternateTimes = UnsignedResult;
					IsFoundParameter = true;
				}
			}
			else {
				goto PrintDataFormatError;
			}
		}
		else if (Data.compare(0, strlen("AlternateTimeRange="), "AlternateTimeRange=") == 0 && Data.length() > strlen("AlternateTimeRange="))
		{
			if (Data.length() < strlen("AlternateTimeRange=") + UINT16_STRING_MAXLEN && 
				Data.find(ASCII_MINUS) == std::string::npos)
			{
				_set_errno(0);
				UnsignedResult = strtoul(Data.c_str() + strlen("AlternateTimeRange="), nullptr, 0);
				if (UnsignedResult >= SHORTEST_ALTERNATE_RANGE_TIME && UnsignedResult < ULONG_MAX)
				{
					Parameter.AlternateTimeRange = UnsignedResult * SECOND_TO_MILLISECOND;
					IsFoundParameter = true;
				}
			}
			else {
				goto PrintDataFormatError;
			}
		}
		else if (Data.compare(0, strlen("AlternateResetTime="), "AlternateResetTime=") == 0 && Data.length() > strlen("AlternateResetTime="))
		{
			if (Data.length() < strlen("AlternateResetTime=") + UINT16_STRING_MAXLEN && 
				Data.find(ASCII_MINUS) == std::string::npos)
			{
				_set_errno(0);
				UnsignedResult = strtoul(Data.c_str() + strlen("AlternateResetTime="), nullptr, 0);
				if (UnsignedResult >= SHORTEST_ALTERNATE_RESET_TIME && UnsignedResult < ULONG_MAX)
				{
					Parameter.AlternateResetTime = UnsignedResult * SECOND_TO_MILLISECOND;
					IsFoundParameter = true;
				}
			}
			else {
				goto PrintDataFormatError;
			}
		}
	}

	if (Data.compare(0, strlen("MultipleRequestTimes="), "MultipleRequestTimes=") == 0 && Data.length() > strlen("MultipleRequestTimes="))
	{
		if (Data.length() < strlen("MultipleRequestTimes=") + UINT16_STRING_MAXLEN && 
			Data.find(ASCII_MINUS) == std::string::npos)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("MultipleRequestTimes="), nullptr, 0);
			if (UnsignedResult > 0 && UnsignedResult < ULONG_MAX)
			{
				ParameterPointer->MultipleRequestTimes = UnsignedResult;
				IsFoundParameter = true;
			}
		}
		else {
			goto PrintDataFormatError;
		}
	}

	return true;

//Jump here to print data format error.
PrintDataFormatError:
	PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Data format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
	return false;
}

//Read parameter data from files(Switches block)
bool ReadParameterData_Switches(
	const std::string &Data, 
	const size_t FileIndex, 
	const bool IsFirstRead, 
	const size_t Line, 
	CONFIGURATION_TABLE * const ParameterPointer, 
	bool &IsFoundParameter)
{
//[Switches] block
	if (Data.compare(0, strlen("DomainCaseConversion=1"), "DomainCaseConversion=1") == 0)
	{
		ParameterPointer->DomainCaseConversion = true;
		IsFoundParameter = true;
	}

	if (IsFirstRead)
	{
		if (Data.compare(0, strlen("CompressionPointerMutation="), "CompressionPointerMutation=") == 0 && Data.length() > strlen("CompressionPointerMutation="))
		{
			if (Data.find(ASCII_ONE) != std::string::npos)
				Parameter.CPM_PointerToHeader = true;
			if (Data.find(ASCII_TWO) != std::string::npos)
				Parameter.CPM_PointerToRR = true;
			if (Data.find(ASCII_THREE) != std::string::npos)
				Parameter.CPM_PointerToAdditional = true;
			if (Parameter.CPM_PointerToHeader || Parameter.CPM_PointerToRR || Parameter.CPM_PointerToAdditional)
				Parameter.CompressionPointerMutation = true;

		//Mark parameter found.
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("EDNSLabel="), "EDNSLabel=") == 0)
		{
			std::string InnerData(Data);
			CaseConvert(InnerData, true);

		//Process selection mode
			auto IsExclusionMode = true;
			if (InnerData.find(ASCII_MINUS) != std::string::npos)
			{
				if (InnerData.find(ASCII_PLUS) != std::string::npos)
					goto PrintDataFormatError;
				else 
					IsExclusionMode = false;
			}

		//Process mode check
			if (InnerData.compare(0, strlen("EDNSLABEL=1"), "EDNSLABEL=1") == 0 || 
				InnerData.compare(0, strlen("EDNSLABEL=ALL"), "EDNSLABEL=ALL") == 0)
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
			if (InnerData.find("LOCAL") != std::string::npos)
			{
				Parameter.EDNS_Label = true;
				Parameter.EDNS_Switch_Local = IsExclusionMode;
			}

		//SOCKS Proxy request process
			if (InnerData.find("SOCKS") != std::string::npos)
			{
				Parameter.EDNS_Label = true;
				Parameter.EDNS_Switch_SOCKS = IsExclusionMode;
			}

		//HTTP CONNECT Proxy request process
			if (InnerData.find("HTTP") != std::string::npos && 
				InnerData.find("CONNECT") != std::string::npos && 
				InnerData.find("HTTP") < InnerData.find("CONNECT"))
			{
				Parameter.EDNS_Label = true;
				Parameter.EDNS_Switch_HTTP_CONNECT = IsExclusionMode;
			}

		//Direct request process
			if (InnerData.find("DIRECT") != std::string::npos)
			{
				Parameter.EDNS_Label = true;
				Parameter.EDNS_Switch_Direct = IsExclusionMode;
			}

		//DNSCurve request process
		#if defined(ENABLE_LIBSODIUM)
			if (InnerData.find("DNSCURVE") != std::string::npos || 
				InnerData.find("DNSCRYPT") != std::string::npos)
			{
				Parameter.EDNS_Label = true;
				Parameter.EDNS_Switch_DNSCurve = IsExclusionMode;
			}
		#endif

		//TCP request process
			if (InnerData.find("TCP") != std::string::npos)
			{
				Parameter.EDNS_Label = true;
				Parameter.EDNS_Switch_TCP = IsExclusionMode;
			}

		//UDP request process
			if (InnerData.find("UDP") != std::string::npos)
			{
				Parameter.EDNS_Label = true;
				Parameter.EDNS_Switch_UDP = IsExclusionMode;
			}

		//Mark parameter found.
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("EDNSClientSubnetRelay=1"), "EDNSClientSubnetRelay=1") == 0)
		{
			Parameter.EDNS_ClientSubnet_Relay = true;
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("DNSSECRequest=1"), "DNSSECRequest=1") == 0)
		{
			Parameter.DNSSEC_Request = true;
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("DNSSECForceRecord=1"), "DNSSECForceRecord=1") == 0)
		{
			Parameter.DNSSEC_ForceRecord = true;
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("AlternateMultipleRequest=1"), "AlternateMultipleRequest=1") == 0)
		{
			Parameter.AlternateMultipleRequest = true;
			IsFoundParameter = true;
		}
	}

	if (Data.compare(0, strlen("IPv4DoNotFragment=1"), "IPv4DoNotFragment=1") == 0)
	{
		ParameterPointer->DoNotFragment_IPv4 = true;
		IsFoundParameter = true;
	}

#if defined(ENABLE_PCAP)
	else if (Data.compare(0, strlen("TCPDataFilter=1"), "TCPDataFilter=1") == 0)
	{
		ParameterPointer->PacketCheck_TCP = true;
		IsFoundParameter = true;
	}
#endif

	else if (Data.compare(0, strlen("DNSDataFilter=1"), "DNSDataFilter=1") == 0)
	{
		ParameterPointer->PacketCheck_DNS = true;
		IsFoundParameter = true;
	}
	else if (IsFirstRead && Data.compare(0, strlen("BlacklistFilter=1"), "BlacklistFilter=1") == 0)
	{
		Parameter.DataCheck_Blacklist = true;
		IsFoundParameter = true;
	}
	else if (Data.compare(0, strlen("ResourceRecordSetTTLFilter=1"), "ResourceRecordSetTTLFilter=1") == 0)
	{
		ParameterPointer->DataCheck_RRSetTTL = true;
		IsFoundParameter = true;
	}

	return true;

//Jump here to print data format error.
PrintDataFormatError:
	PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Data format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
	return false;
}

//Read parameter data from files(Data block)
bool ReadParameterData_Data(
	const std::string &Data, 
	const size_t FileIndex, 
	const bool IsFirstRead, 
	const size_t Line, 
	CONFIGURATION_TABLE * const ParameterPointer, 
	bool &IsFoundParameter)
{
	size_t UnsignedResult = 0;

//[Data] block
	if (IsFirstRead)
	{
	#if defined(ENABLE_PCAP)
		if (Data.compare(0, strlen("ICMPID="), "ICMPID=") == 0 && Data.length() > strlen("ICMPID="))
		{
			if (Data.length() <= strlen("ICMPID=") + strlen(HEX_PREAMBLE_STRING) + UINT8_STRING_MAXLEN && 
				Data.find(ASCII_MINUS) == std::string::npos)
			{
				_set_errno(0);
				UnsignedResult = strtoul(Data.c_str() + strlen("ICMPID="), nullptr, 0);
				if (UnsignedResult > 0 && UnsignedResult < ULONG_MAX)
				{
					Parameter.ICMP_ID = hton16(static_cast<const uint16_t>(UnsignedResult));
					IsFoundParameter = true;
				}
			}
			else {
				goto PrintDataFormatError;
			}
		}
		else if (Data.compare(0, strlen("ICMPSequence="), "ICMPSequence=") == 0 && Data.length() > strlen("ICMPSequence="))
		{
			if (Data.length() <= strlen("ICMPSequence=") + strlen(HEX_PREAMBLE_STRING) + UINT8_STRING_MAXLEN && 
				Data.find(ASCII_MINUS) == std::string::npos)
			{
				_set_errno(0);
				UnsignedResult = strtoul(Data.c_str() + strlen("ICMPSequence="), nullptr, 0);
				if (UnsignedResult > 0 && UnsignedResult < ULONG_MAX)
				{
					Parameter.ICMP_Sequence = hton16(static_cast<const uint16_t>(UnsignedResult));
					IsFoundParameter = true;
				}
			}
			else {
				goto PrintDataFormatError;
			}
		}
		else if (Data.compare(0, strlen("ICMP PaddingData = "), "ICMP PaddingData = ") == 0 && Data.length() > strlen("ICMP PaddingData = "))
		{
			if (Data.length() > strlen("ICMP PaddingData = ") + ICMP_PADDING_MINSIZE && Data.length() < strlen("ICMP PaddingData = ") + ICMP_PADDING_MAXSIZE - 1U)
			{
				memcpy_s(Parameter.ICMP_PaddingData, ICMP_PADDING_MAXSIZE, Data.c_str() + strlen("ICMP PaddingData = "), Data.length() - strlen("ICMP PaddingData = "));
				Parameter.ICMP_PaddingLength = Data.length() - strlen("ICMP PaddingData = ");

			//Mark parameter found.
				IsFoundParameter = true;
			}
			else {
				goto PrintDataFormatError;
			}
		}
	}

	if (Data.compare(0, strlen("DomainTestProtocol="), "DomainTestProtocol=") == 0 && Data.length() > strlen("DomainTestProtocol="))
	{
		std::string InnerData(Data);
		CaseConvert(InnerData, true);

	//Transport layer
		if (InnerData.find("TCP") != std::string::npos && InnerData.find("UDP") == std::string::npos)
			ParameterPointer->DomainTest_Protocol = REQUEST_MODE_TEST::TCP;
		else if (InnerData.find("UDP") != std::string::npos && InnerData.find("TCP") == std::string::npos)
			ParameterPointer->DomainTest_Protocol = REQUEST_MODE_TEST::UDP;
		else 
			ParameterPointer->DomainTest_Protocol = REQUEST_MODE_TEST::BOTH;

	//Mark parameter found.
		IsFoundParameter = true;
	}

	if (IsFirstRead)
	{
		if (Data.compare(0, strlen("DomainTestID="), "DomainTestID=") == 0 && Data.length() > strlen("DomainTestID="))
		{
			if (Data.length() <= strlen("DomainTestID=") + strlen(HEX_PREAMBLE_STRING) + UINT8_STRING_MAXLEN && 
				Data.find(ASCII_MINUS) == std::string::npos)
			{
				_set_errno(0);
				UnsignedResult = strtoul(Data.c_str() + strlen("DomainTestID="), nullptr, 0);
				if (UnsignedResult > 0 && UnsignedResult < ULONG_MAX)
				{
					Parameter.DomainTest_ID = hton16(static_cast<const uint16_t>(UnsignedResult));
					IsFoundParameter = true;
				}
			}
			else {
				goto PrintDataFormatError;
			}
		}
		else if (Data.compare(0, strlen("DomainTestData="), "DomainTestData=") == 0 && Data.length() > strlen("DomainTestData="))
		{
			if (Data.length() > strlen("DomainTestData=") + DOMAIN_MINSIZE && Data.length() < strlen("DomainTestData=") + DOMAIN_DATA_MAXSIZE)
				memcpy_s(Parameter.DomainTest_Data, DOMAIN_MAXSIZE, Data.c_str() + strlen("DomainTestData="), Data.length() - strlen("DomainTestData="));
			else 
				goto PrintDataFormatError;

		//Mark parameter found.
			IsFoundParameter = true;
		}
	#endif
		if (Data.compare(0, strlen("LocalMachineServerName="), "LocalMachineServerName=") == 0 && Data.length() > strlen("LocalMachineServerName="))
		{
			if (Data.length() > strlen("LocalMachineServerName=") + DOMAIN_MINSIZE && Data.length() < strlen("LocalMachineServerName=") + DOMAIN_DATA_MAXSIZE)
			{
				const auto FQDN_String = std::make_unique<uint8_t[]>(NI_MAXHOST + MEMORY_RESERVED_BYTES);
				memset(FQDN_String.get(), 0, NI_MAXHOST + MEMORY_RESERVED_BYTES);
				Parameter.Local_FQDN_Length = Data.length() - strlen("LocalMachineServerName=");
				memcpy_s(FQDN_String.get(), NI_MAXHOST, Data.c_str() + strlen("LocalMachineServerName="), Parameter.Local_FQDN_Length);
				*Parameter.Local_FQDN_String = reinterpret_cast<const char *>(FQDN_String.get());
				memset(Parameter.Local_FQDN_Response, 0, DOMAIN_MAXSIZE);
				UnsignedResult = StringToPacketQuery(FQDN_String.get(), Parameter.Local_FQDN_Response, DOMAIN_MAXSIZE);
				if (UnsignedResult > DOMAIN_MINSIZE && UnsignedResult < DOMAIN_MAXSIZE)
				{
					Parameter.Local_FQDN_Length = UnsignedResult;
				}
				else {
					Parameter.Local_FQDN_Length = 0;
					memset(Parameter.Local_FQDN_Response, 0, DOMAIN_MAXSIZE);
					Parameter.Local_FQDN_String->clear();
				}

			//Mark parameter found.
				IsFoundParameter = true;
			}
			else {
				goto PrintDataFormatError;
			}
		}
	}

	return true;

//Jump here to print data format error.
PrintDataFormatError:
	PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Data format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
	return false;
}

//Read parameter data from files(Proxy block)
bool ReadParameterData_Proxy(
	const std::string &Data, 
	const size_t FileIndex, 
	const bool IsFirstRead, 
	const size_t Line, 
	CONFIGURATION_TABLE * const ParameterPointer, 
	bool &IsFoundParameter)
{
	size_t UnsignedResult = 0;

//[Proxy] block
	if (IsFirstRead)
	{
		if (Data.compare(0, strlen("SOCKSProxy=1"), "SOCKSProxy=1") == 0)
		{
			Parameter.SOCKS_Proxy = true;
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("SOCKSVersion="), "SOCKSVersion=") == 0 && 
			Data.length() > strlen("SOCKSVersion="))
		{
			std::string InnerData(Data);
			CaseConvert(InnerData, true);
			if (InnerData.find("4A") != std::string::npos) //SOCKS v4a
			{
				Parameter.SOCKS_Version = SOCKS_VERSION_CONFIG_4A;
			}
			else if (InnerData.find("4") != std::string::npos) //SOCKS v4
			{
				Parameter.SOCKS_Version = SOCKS_VERSION_4;
			}
			else if (InnerData.find("5") != std::string::npos) //SOCKS v5
			{
				Parameter.SOCKS_Version = SOCKS_VERSION_5;
			}
			else {
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::SOCKS, L"SOCKS version is not supported", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
				return false;
			}

		//Mark parameter found.
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("SOCKSProtocol="), "SOCKSProtocol=") == 0)
		{
			std::string InnerData(Data);
			CaseConvert(InnerData, true);

		//Network layer
			if (InnerData.find("IPV6") != std::string::npos && InnerData.find("IPV4") == std::string::npos)
				Parameter.SOCKS_Protocol_Network = REQUEST_MODE_NETWORK::IPV6;
			else if (InnerData.find("IPV4") != std::string::npos && InnerData.find("IPV6") == std::string::npos)
				Parameter.SOCKS_Protocol_Network = REQUEST_MODE_NETWORK::IPV4;
			else 
				Parameter.SOCKS_Protocol_Network = REQUEST_MODE_NETWORK::BOTH;

		//Transport layer
			if (InnerData.find("FORCE") != std::string::npos)
			{
				if (InnerData.find("UDP") != std::string::npos)
					Parameter.SOCKS_Protocol_Transport = REQUEST_MODE_TRANSPORT::FORCE_UDP;
				else 
					Parameter.SOCKS_Protocol_Transport = REQUEST_MODE_TRANSPORT::FORCE_TCP;
			}
			else if (InnerData.find("UDP") != std::string::npos)
			{
				Parameter.SOCKS_Protocol_Transport = REQUEST_MODE_TRANSPORT::UDP;
			}
			else {
				Parameter.SOCKS_Protocol_Transport = REQUEST_MODE_TRANSPORT::TCP;
			}

		//According type
			if (InnerData.find("TYPE") != std::string::npos)
				Parameter.SOCKS_Protocol_IsAccordingType = true;

		//Mark parameter found.
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("SOCKSUDPNoHandshake=1"), "SOCKSUDPNoHandshake=1") == 0)
		{
			Parameter.SOCKS_UDP_NoHandshake = true;
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("SOCKSProxyOnly=1"), "SOCKSProxyOnly=1") == 0)
		{
			Parameter.SOCKS_Only = true;
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("SOCKSIPv4Address="), "SOCKSIPv4Address=") == 0 && 
			Data.length() > strlen("SOCKSIPv4Address="))
		{
			std::vector<DNS_SERVER_DATA> DNSServerDataTemp;
			if (!ReadSupport_MultipleAddresses(AF_INET, Data, strlen("SOCKSIPv4Address="), &DNSServerDataTemp, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line) || DNSServerDataTemp.empty())
			{
				return false;
			}
			else {
				Parameter.SOCKS_Address_IPv4 = DNSServerDataTemp.front().AddressData;
				IsFoundParameter = true;
			}
		}
		else if (Data.compare(0, strlen("SOCKSIPv6Address="), "SOCKSIPv6Address=") == 0 && 
			Data.length() > strlen("SOCKSIPv6Address="))
		{
			std::vector<DNS_SERVER_DATA> DNSServerDataTemp;
			if (!ReadSupport_MultipleAddresses(AF_INET6, Data, strlen("SOCKSIPv6Address="), &DNSServerDataTemp, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line) || DNSServerDataTemp.empty())
			{
				return false;
			}
			else {
				Parameter.SOCKS_Address_IPv6 = DNSServerDataTemp.front().AddressData;
				IsFoundParameter = true;
			}
		}
	}

	if (Data.compare(0, strlen("SOCKSTargetServer="), "SOCKSTargetServer=") == 0 && 
		Data.length() > strlen("SOCKSTargetServer="))
	{
		if (!ReadSupport_SOCKS_AddressDomain(Data, strlen("SOCKSTargetServer="), ParameterPointer, FileIndex, Line))
			return false;

	//Mark parameter found.
		IsFoundParameter = true;
	}
	else if (Data.compare(0, strlen("SOCKSUsername="), "SOCKSUsername=") == 0 && 
		Data.length() > strlen("SOCKSUsername="))
	{
		if (Data.length() < strlen("SOCKSUsername=") + SOCKS_USERNAME_PASSWORD_MAXNUM)
		{
			memcpy_s(ParameterPointer->SOCKS_Username, SOCKS_USERNAME_PASSWORD_MAXNUM, Data.c_str() + strlen("SOCKSUsername="), Data.length() - strlen("SOCKSUsername="));
			ParameterPointer->SOCKS_UsernameLength = Data.length() - strlen("SOCKSUsername=");

		//Mark parameter found.
			IsFoundParameter = true;
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (Data.compare(0, strlen("SOCKSPassword="), "SOCKSPassword=") == 0 && 
		Data.length() > strlen("SOCKSPassword="))
	{
		if (Data.length() < strlen("SOCKSPassword=") + SOCKS_USERNAME_PASSWORD_MAXNUM)
		{
			memcpy_s(ParameterPointer->SOCKS_Password, SOCKS_USERNAME_PASSWORD_MAXNUM, Data.c_str() + strlen("SOCKSPassword="), Data.length() - strlen("SOCKSPassword="));
			ParameterPointer->SOCKS_PasswordLength = Data.length() - strlen("SOCKSPassword=");

		//Mark parameter found.
			IsFoundParameter = true;
		}
		else {
			goto PrintDataFormatError;
		}
	}

	if (IsFirstRead)
	{
		if (Data.compare(0, strlen("HTTPCONNECTProxy=1"), "HTTPCONNECTProxy=1") == 0)
		{
			Parameter.HTTP_CONNECT_Proxy = true;
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("HTTPCONNECTProtocol="), "HTTPCONNECTProtocol=") == 0)
		{
			std::string InnerData(Data);
			CaseConvert(InnerData, true);

		//Network layer
			if (InnerData.find("IPV6") != std::string::npos && InnerData.find("IPV4") == std::string::npos)
				Parameter.HTTP_CONNECT_Protocol = REQUEST_MODE_NETWORK::IPV6;
			else if (InnerData.find("IPV4") != std::string::npos && InnerData.find("IPV6") == std::string::npos)
				Parameter.HTTP_CONNECT_Protocol = REQUEST_MODE_NETWORK::IPV4;
			else 
				Parameter.HTTP_CONNECT_Protocol = REQUEST_MODE_NETWORK::BOTH;

		//According type
			if (InnerData.find("TYPE") != std::string::npos)
				Parameter.HTTP_CONNECT_IsAccordingType = true;

		//Mark parameter found.
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("HTTPCONNECTProxyOnly=1"), "HTTPCONNECTProxyOnly=1") == 0)
		{
			Parameter.HTTP_CONNECT_Only = true;
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("HTTPCONNECTIPv4Address="), "HTTPCONNECTIPv4Address=") == 0 && 
			Data.length() > strlen("HTTPCONNECTIPv4Address="))
		{
			std::vector<DNS_SERVER_DATA> DNSServerDataTemp;
			if (!ReadSupport_MultipleAddresses(AF_INET, Data, strlen("HTTPCONNECTIPv4Address="), &DNSServerDataTemp, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line) || DNSServerDataTemp.empty())
			{
				return false;
			}
			else {
				Parameter.HTTP_CONNECT_Address_IPv4 = DNSServerDataTemp.front().AddressData;
			#if defined(ENABLE_TLS)
			#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				Parameter.HTTP_CONNECT_TLS_AddressString_IPv4->clear();
				Parameter.HTTP_CONNECT_TLS_AddressString_IPv4->append(Data, strlen("HTTPCONNECTIPv4Address="), Data.length() - strlen("HTTPCONNECTIPv4Address="));
			#endif
			#endif
				IsFoundParameter = true;
			}
		}
		else if (Data.compare(0, strlen("HTTPCONNECTIPv6Address="), "HTTPCONNECTIPv6Address=") == 0 && 
			Data.length() > strlen("HTTPCONNECTIPv6Address="))
		{
			std::vector<DNS_SERVER_DATA> DNSServerDataTemp;
			if (!ReadSupport_MultipleAddresses(AF_INET6, Data, strlen("HTTPCONNECTIPv6Address="), &DNSServerDataTemp, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line) || DNSServerDataTemp.empty())
			{
				return false;
			}
			else {
				Parameter.HTTP_CONNECT_Address_IPv6 = DNSServerDataTemp.front().AddressData;
			#if defined(ENABLE_TLS)
			#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				Parameter.HTTP_CONNECT_TLS_AddressString_IPv6->clear();
				Parameter.HTTP_CONNECT_TLS_AddressString_IPv6->append(Data, strlen("HTTPCONNECTIPv6Address="), Data.length() - strlen("HTTPCONNECTIPv6Address="));
			#endif
			#endif
				IsFoundParameter = true;
			}
		}
	}

	if (Data.compare(0, strlen("HTTPCONNECTTargetServer="), "HTTPCONNECTTargetServer=") == 0 && 
		Data.length() > strlen("HTTPCONNECTTargetServer="))
	{
		ParameterPointer->HTTP_CONNECT_TargetDomain->clear();
		ParameterPointer->HTTP_CONNECT_TargetDomain->append(Data, strlen("HTTPCONNECTTargetServer="), Data.length() - strlen("HTTPCONNECTTargetServer="));

	//Mark parameter found.
		IsFoundParameter = true;
	}

#if defined(ENABLE_TLS)
	else if (IsFirstRead && Data.compare(0, strlen("HTTPCONNECTTLSHandshake=1"), "HTTPCONNECTTLSHandshake=1") == 0)
	{
		Parameter.HTTP_CONNECT_TLS_Handshake = true;
		IsFoundParameter = true;
	}
	else if (Data.compare(0, strlen("HTTPCONNECTTLSVersion="), "HTTPCONNECTTLSVersion=") == 0 && 
		Data.length() > strlen("HTTPCONNECTTLSVersion="))
	{
		std::string InnerData(Data);
		CaseConvert(InnerData, true);
		if (InnerData.compare(0, strlen("HTTPCONNECTTLSVERSION=1.3"), "HTTPCONNECTTLSVERSION=1.3") == 0) //TLS 1.3
			ParameterPointer->HTTP_CONNECT_TLS_Version = TLS_VERSION_SELECTION::VERSION_1_3;
		else if (InnerData.compare(0, strlen("HTTPCONNECTTLSVERSION=1.2"), "HTTPCONNECTTLSVERSION=1.2") == 0) //TLS 1.2
			ParameterPointer->HTTP_CONNECT_TLS_Version = TLS_VERSION_SELECTION::VERSION_1_2;
		else if (InnerData.compare(0, strlen("HTTPCONNECTTLSVERSION=1.1"), "HTTPCONNECTTLSVERSION=1.1") == 0) //TLS 1.1
			ParameterPointer->HTTP_CONNECT_TLS_Version = TLS_VERSION_SELECTION::VERSION_1_1;
		else if (InnerData.compare(0, strlen("HTTPCONNECTTLSVERSION=1.0"), "HTTPCONNECTTLSVERSION=1.0") == 0) //TLS 1.0
			ParameterPointer->HTTP_CONNECT_TLS_Version = TLS_VERSION_SELECTION::VERSION_1_0;
		else //Auto-select
			ParameterPointer->HTTP_CONNECT_TLS_Version = TLS_VERSION_SELECTION::VERSION_AUTO;

	//Mark parameter found.
		IsFoundParameter = true;
	}
	else if (Data.compare(0, strlen("HTTPCONNECTTLSValidation=1"), "HTTPCONNECTTLSValidation=1") == 0)
	{
		ParameterPointer->HTTP_CONNECT_TLS_Validation = true;
		IsFoundParameter = true;
	}
#endif

	if (IsFirstRead)
	{
	#if defined(ENABLE_TLS)
		if (Data.compare(0, strlen("HTTPCONNECTTLSServerNameIndication="), "HTTPCONNECTTLSServerNameIndication=") == 0 && 
			Data.length() > strlen("HTTPCONNECTTLSServerNameIndication=") + DOMAIN_MINSIZE)
		{
			Parameter.HTTP_CONNECT_TLS_SNI_MBS->clear();
			Parameter.HTTP_CONNECT_TLS_SNI_MBS->append(Data, strlen("HTTPCONNECTTLSServerNameIndication="), Data.length() - strlen("HTTPCONNECTTLSServerNameIndication="));

		//Mark parameter found.
			IsFoundParameter = true;
		}
	#if !defined(PLATFORM_WIN_XP)
		else if (Data.compare(0, strlen("HTTPCONNECTTLSALPN=1"), "HTTPCONNECTTLSALPN=1") == 0)
		{
			Parameter.HTTP_CONNECT_TLS_ALPN = true;
			IsFoundParameter = true;
		}
		else 
	#endif
	#endif
		if (Data.compare(0, strlen("HTTPCONNECTVersion="), "HTTPCONNECTVersion=") == 0 && 
		Data.length() > strlen("HTTPCONNECTVersion="))
		{
			if (Data.length() > strlen("HTTPCONNECTVersion=") && Data.length() <= strlen("HTTPCONNECTVersion=") + HTTP_VERSION_MAXSIZE && 
				Data.find(ASCII_MINUS) == std::string::npos)
			{
				size_t Version_Major = 0, Version_Minor = 0;
				if (Data.find(ASCII_PERIOD) != std::string::npos)
				{
				//Get list data.
					std::vector<std::string> ListData;
					ReadSupport_GetParameterListData(ListData, Data, strlen("HTTPCONNECTVersion="), Data.length(), ASCII_PERIOD, true, true);
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
				else if (Data.compare(0, strlen("HTTPCONNECTVersion=2"), "HTTPCONNECTVersion=2") == 0 && 
					Data.length() == strlen("HTTPCONNECTVersion=2")) //HTTP 2.x
				{
					Version_Major = 2U;
				}
				else if (Data.compare(0, strlen("HTTPCONNECTVersion=1"), "HTTPCONNECTVersion=1") == 0 && 
					Data.length() == strlen("HTTPCONNECTVersion=1")) //HTTP 1.x
				{
					Version_Major = 1U;
					Version_Minor = 1U;
				}

			//Register to global list.
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

			//Mark parameter found.
				IsFoundParameter = true;
			}
			else {
				goto PrintDataFormatError;
			}
		}
	}

	if (Data.compare(0, strlen("HTTP CONNECT Header Field = "), "HTTP CONNECT Header Field = ") == 0 && 
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

		//Mark parameter found.
		//This parameter can be written over times.
//			IsFoundParameter = true;
		}
	}
	else if (Data.compare(0, strlen("HTTPCONNECTProxyAuthorization="), "HTTPCONNECTProxyAuthorization=") == 0 && 
		Data.length() > strlen("HTTPCONNECTProxyAuthorization="))
	{
		if (Data.length() < HTTP_AUTHORIZATION_MAXSIZE)
		{
		//Mark fixed part.
			memcpy_s(ParameterPointer->HTTP_CONNECT_ProxyAuthorization, strlen("Basic "), "Basic ", strlen("Basic "));
			ParameterPointer->HTTP_CONNECT_ProxyAuthorizationLength = strlen("Basic ");

		//Convert string to base64.
		#if defined(ENABLE_LIBSODIUM)
			if (sodium_bin2base64(
					reinterpret_cast<char *>(ParameterPointer->HTTP_CONNECT_ProxyAuthorization) + ParameterPointer->HTTP_CONNECT_ProxyAuthorizationLength, 
					HTTP_AUTHORIZATION_MAXSIZE - ParameterPointer->HTTP_CONNECT_ProxyAuthorizationLength, 
					reinterpret_cast<const uint8_t *>(Data.c_str() + strlen("HTTPCONNECTProxyAuthorization=")), 
					Data.length() - strlen("HTTPCONNECTProxyAuthorization="), 
					sodium_base64_VARIANT_ORIGINAL) == nullptr)
						goto PrintDataFormatError;
			else 
				ParameterPointer->HTTP_CONNECT_ProxyAuthorizationLength = strnlen_s(reinterpret_cast<const char *>(ParameterPointer->HTTP_CONNECT_ProxyAuthorization), HTTP_AUTHORIZATION_MAXSIZE);
		#else
			ParameterPointer->HTTP_CONNECT_ProxyAuthorizationLength = Base64_Encode(
				reinterpret_cast<uint8_t *>(const_cast<char *>(Data.c_str() + strlen("HTTPCONNECTProxyAuthorization="))), 
				Data.length() - strlen("HTTPCONNECTProxyAuthorization="), 
				ParameterPointer->HTTP_CONNECT_ProxyAuthorization + ParameterPointer->HTTP_CONNECT_ProxyAuthorizationLength, 
				HTTP_AUTHORIZATION_MAXSIZE - ParameterPointer->HTTP_CONNECT_ProxyAuthorizationLength);
			if (ParameterPointer->HTTP_CONNECT_ProxyAuthorizationLength == 0)
				goto PrintDataFormatError;
			else 
				ParameterPointer->HTTP_CONNECT_ProxyAuthorizationLength += strlen("Basic ");
		#endif

		//Mark parameter found.
			IsFoundParameter = true;
		}
		else {
			goto PrintDataFormatError;
		}
	}

	return true;

//Jump here to print data format error.
PrintDataFormatError:
	PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Data format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
	return false;
}

#if defined(ENABLE_LIBSODIUM)
//Read parameter data from files(DNSCurve block)
bool ReadParameterData_DNSCurve_Main(
	const std::string &Data, 
	const size_t FileIndex, 
	const bool IsFirstRead, 
	const size_t Line, 
//	CONFIGURATION_TABLE * const ParameterPointer, 
	DNSCURVE_CONFIGURATION_TABLE * const DNSCurveParameterPointer, 
	bool &IsFoundParameter)
{
	size_t UnsignedResult = 0;

//[DNSCurve] block
	if (IsFirstRead)
	{
		if (Data.compare(0, strlen("DNSCurve=1"), "DNSCurve=1") == 0)
		{
			Parameter.IsDNSCurve = true;
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("DNSCurveProtocol="), "DNSCurveProtocol=") == 0)
		{
			std::string InnerData(Data);
			CaseConvert(InnerData, true);

		//Network layer
			if (InnerData.find("IPV6") != std::string::npos && InnerData.find("IPV4") == std::string::npos)
				DNSCurveParameter.DNSCurveProtocol_Network = REQUEST_MODE_NETWORK::IPV6;
			else if (InnerData.find("IPV4") != std::string::npos && InnerData.find("IPV6") == std::string::npos)
				DNSCurveParameter.DNSCurveProtocol_Network = REQUEST_MODE_NETWORK::IPV4;
			else 
				DNSCurveParameter.DNSCurveProtocol_Network = REQUEST_MODE_NETWORK::BOTH;

		//Transport layer
			if (InnerData.find("FORCE") != std::string::npos)
			{
				if (InnerData.find("TCP") != std::string::npos)
					DNSCurveParameter.DNSCurveProtocol_Transport = REQUEST_MODE_TRANSPORT::FORCE_TCP;
				else 
					DNSCurveParameter.DNSCurveProtocol_Transport = REQUEST_MODE_TRANSPORT::FORCE_UDP;
			}
			else if (InnerData.find("TCP") != std::string::npos)
			{
				DNSCurveParameter.DNSCurveProtocol_Transport = REQUEST_MODE_TRANSPORT::TCP;
			}
			else {
				DNSCurveParameter.DNSCurveProtocol_Transport = REQUEST_MODE_TRANSPORT::UDP;
			}

		//According type
			if (InnerData.find("TYPE") != std::string::npos)
				DNSCurveParameter.DNSCurveProtocol_IsAccordingType = true;

		//Mark parameter found.
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("DNSCurvePayloadSize="), "DNSCurvePayloadSize=") == 0 && Data.length() > strlen("DNSCurvePayloadSize="))
		{
			if (Data.length() > strlen("DNSCurvePayloadSize=") + 2U && 
				Data.find(ASCII_MINUS) == std::string::npos)
			{
				_set_errno(0);
				UnsignedResult = strtoul(Data.c_str() + strlen("DNSCurvePayloadSize="), nullptr, 0);
				if (UnsignedResult > 0 && UnsignedResult < ULONG_MAX)
				{
					DNSCurveParameter.DNSCurvePayloadSize = UnsignedResult;
					IsFoundParameter = true;
				}
			}
			else {
				goto PrintDataFormatError;
			}
		}
	}

	if (Data.compare(0, strlen("DNSCurveReliableSocketTimeout="), "DNSCurveReliableSocketTimeout=") == 0 && 
		Data.length() > strlen("DNSCurveReliableSocketTimeout="))
	{
		if (Data.length() < strlen("DNSCurveReliableSocketTimeout=") + UINT32_STRING_MAXLEN && 
			Data.find(ASCII_MINUS) == std::string::npos)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("DNSCurveReliableSocketTimeout="), nullptr, 0);
			if (UnsignedResult > SOCKET_TIMEOUT_MIN && UnsignedResult < ULONG_MAX)
			{
			#if defined(PLATFORM_WIN)
				DNSCurveParameterPointer->DNSCurve_SocketTimeout_Reliable = static_cast<const DWORD>(UnsignedResult);
			#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				DNSCurveParameterPointer->DNSCurve_SocketTimeout_Reliable.tv_sec = UnsignedResult / SECOND_TO_MILLISECOND;
				DNSCurveParameterPointer->DNSCurve_SocketTimeout_Reliable.tv_usec = UnsignedResult % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
			#endif
				IsFoundParameter = true;
			}
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (Data.compare(0, strlen("DNSCurveUnreliableSocketTimeout="), "DNSCurveUnreliableSocketTimeout=") == 0 && 
		Data.length() > strlen("DNSCurveUnreliableSocketTimeout="))
	{
		if (Data.length() < strlen("DNSCurveUnreliableSocketTimeout=") + UINT32_STRING_MAXLEN && 
			Data.find(ASCII_MINUS) == std::string::npos)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("DNSCurveUnreliableSocketTimeout="), nullptr, 0);
			if (UnsignedResult > SOCKET_TIMEOUT_MIN && UnsignedResult < ULONG_MAX)
			{
			#if defined(PLATFORM_WIN)
				DNSCurveParameterPointer->DNSCurve_SocketTimeout_Unreliable = static_cast<const DWORD>(UnsignedResult);
			#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				DNSCurveParameterPointer->DNSCurve_SocketTimeout_Unreliable.tv_sec = UnsignedResult / SECOND_TO_MILLISECOND;
				DNSCurveParameterPointer->DNSCurve_SocketTimeout_Unreliable.tv_usec = UnsignedResult % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
			#endif
				IsFoundParameter = true;
			}
		}
		else {
			goto PrintDataFormatError;
		}
	}

	if (IsFirstRead)
	{
		if (Data.compare(0, strlen("DNSCurveEncryption=1"), "DNSCurveEncryption=1") == 0)
		{
			DNSCurveParameter.IsEncryption = true;
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("DNSCurveEncryptionOnly=1"), "DNSCurveEncryptionOnly=1") == 0)
		{
			DNSCurveParameter.IsEncryptionOnly = true;
			IsFoundParameter = true;
		}
	}

	if (Data.compare(0, strlen("DNSCurveClientEphemeralKey=1"), "DNSCurveClientEphemeralKey=1") == 0)
	{
		DNSCurveParameter.IsClientEphemeralKey = true;
		IsFoundParameter = true;
	}
	else if (Data.compare(0, strlen("DNSCurveKeyRecheckTime="), "DNSCurveKeyRecheckTime=") == 0 && Data.length() > strlen("DNSCurveKeyRecheckTime="))
	{
		if (Data.length() < strlen("DNSCurveKeyRecheckTime=") + UINT16_STRING_MAXLEN && 
			Data.find(ASCII_MINUS) == std::string::npos)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("DNSCurveKeyRecheckTime="), nullptr, 0);
			if (UnsignedResult >= DNSCURVE_SHORTEST_RECHECK_TIME && UnsignedResult < ULONG_MAX)
			{
				DNSCurveParameterPointer->KeyRecheckTime = UnsignedResult * SECOND_TO_MILLISECOND;
				IsFoundParameter = true;
			}
		}
		else {
			goto PrintDataFormatError;
		}
	}

	return true;

//Jump here to print data format error.
PrintDataFormatError:
	PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Data format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
	return false;
}

//Read parameter data from files(DNSCurve Database block)
bool ReadParameterData_DNSCurve_Database(
	const std::string &Data, 
	const size_t FileIndex, 
	const bool IsFirstRead, 
	const size_t Line, 
//	CONFIGURATION_TABLE * const ParameterPointer, 
//	DNSCURVE_CONFIGURATION_TABLE * const DNSCurveParameterPointer, 
	bool &IsFoundParameter)
{
//[DNSCurve Database] block
	if (IsFirstRead)
	{
		if (Data.compare(0, strlen("DNSCurve Database Name = "), "DNSCurve Database Name = ") == 0 && Data.length() > strlen("DNSCurve Database Name = "))
		{
		//Convert to wide string.
			if (!MBS_To_WCS_String(reinterpret_cast<const uint8_t *>(Data.c_str() + strlen("DNSCurve Database Name = ")), Data.length() - strlen("DNSCurve Database Name = "), *DNSCurveParameter.DatabaseName))
				goto PrintDataFormatError;

		//Mark database name.
		#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			DNSCurveParameter.DatabaseName_MBS->append(Data, strlen("DNSCurve Database Name = "), Data.length() - strlen("DNSCurve Database Name = "));
		#endif

		//Mark parameter found.
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("DNSCurveDatabaseIPv4MainDNS="), "DNSCurveDatabaseIPv4MainDNS=") == 0 && Data.length() > strlen("DNSCurveDatabaseIPv4MainDNS="))
		{
			DNSCurveParameter.Database_Target_Server_Main_IPv4->append(Data, strlen("DNSCurveDatabaseIPv4MainDNS="), Data.length() - strlen("DNSCurveDatabaseIPv4MainDNS="));
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("DNSCurveDatabaseIPv4AlternateDNS="), "DNSCurveDatabaseIPv4AlternateDNS=") == 0 && Data.length() > strlen("DNSCurveDatabaseIPv4AlternateDNS="))
		{
			DNSCurveParameter.Database_Target_Server_Alternate_IPv4->append(Data, strlen("DNSCurveDatabaseIPv4AlternateDNS="), Data.length() - strlen("DNSCurveDatabaseIPv4AlternateDNS="));
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("DNSCurveDatabaseIPv6MainDNS="), "DNSCurveDatabaseIPv6MainDNS=") == 0 && Data.length() > strlen("DNSCurveDatabaseIPv6MainDNS="))
		{
			DNSCurveParameter.Database_Target_Server_Main_IPv6->append(Data, strlen("DNSCurveDatabaseIPv6MainDNS="), Data.length() - strlen("DNSCurveDatabaseIPv6MainDNS="));
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("DNSCurveDatabaseIPv6AlternateDNS="), "DNSCurveDatabaseIPv6AlternateDNS=") == 0 && Data.length() > strlen("DNSCurveDatabaseIPv6AlternateDNS="))
		{
			DNSCurveParameter.Database_Target_Server_Alternate_IPv6->append(Data, strlen("DNSCurveDatabaseIPv6AlternateDNS="), Data.length() - strlen("DNSCurveDatabaseIPv6AlternateDNS="));
			IsFoundParameter = true;
		}
	}

	return true;

//Jump here to print data format error.
PrintDataFormatError:
	PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Data format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
	return false;
}

//Read parameter data from files(DNSCurve Addresses block)
bool ReadParameterData_DNSCurve_Addresses(
	const std::string &Data, 
	const size_t FileIndex, 
	const bool IsFirstRead, 
	const size_t Line, 
//	CONFIGURATION_TABLE * const ParameterPointer, 
//	DNSCURVE_CONFIGURATION_TABLE * const DNSCurveParameterPointer, 
	bool &IsFoundParameter)
{
//[DNSCurve Addresses] block
	if (IsFirstRead)
	{
		if (Data.compare(0, strlen("DNSCurveIPv4MainDNSAddress="), "DNSCurveIPv4MainDNSAddress=") == 0 && 
			Data.length() > strlen("DNSCurveIPv4MainDNSAddress="))
		{
			std::vector<DNS_SERVER_DATA> DNSServerDataTemp;
			if (!ReadSupport_MultipleAddresses(AF_INET, Data, strlen("DNSCurveIPv4MainDNSAddress="), &DNSServerDataTemp, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line) || DNSServerDataTemp.empty())
			{
				return false;
			}
			else {
				DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.AddressData = DNSServerDataTemp.front().AddressData;
				IsFoundParameter = true;
			}
		}
		else if (Data.compare(0, strlen("DNSCurveIPv4AlternateDNSAddress="), "DNSCurveIPv4AlternateDNSAddress=") == 0 && 
			Data.length() > strlen("DNSCurveIPv4AlternateDNSAddress="))
		{
			std::vector<DNS_SERVER_DATA> DNSServerDataTemp;
			if (!ReadSupport_MultipleAddresses(AF_INET, Data, strlen("DNSCurveIPv4AlternateDNSAddress="), &DNSServerDataTemp, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line) || DNSServerDataTemp.empty())
			{
				return false;
			}
			else {
				DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.AddressData = DNSServerDataTemp.front().AddressData;
				IsFoundParameter = true;
			}
		}
		else if (Data.compare(0, strlen("DNSCurveIPv6MainDNSAddress="), "DNSCurveIPv6MainDNSAddress=") == 0 && 
			Data.length() > strlen("DNSCurveIPv6MainDNSAddress="))
		{
			std::vector<DNS_SERVER_DATA> DNSServerDataTemp;
			if (!ReadSupport_MultipleAddresses(AF_INET6, Data, strlen("DNSCurveIPv6MainDNSAddress="), &DNSServerDataTemp, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line) || DNSServerDataTemp.empty())
			{
				return false;
			}
			else {
				DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.AddressData = DNSServerDataTemp.front().AddressData;
				IsFoundParameter = true;
			}
		}
		else if (Data.compare(0, strlen("DNSCurveIPv6AlternateDNSAddress="), "DNSCurveIPv6AlternateDNSAddress=") == 0 && 
			Data.length() > strlen("DNSCurveIPv6AlternateDNSAddress="))
		{
			std::vector<DNS_SERVER_DATA> DNSServerDataTemp;
			if (!ReadSupport_MultipleAddresses(AF_INET6, Data, strlen("DNSCurveIPv6AlternateDNSAddress="), &DNSServerDataTemp, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line) || DNSServerDataTemp.empty())
			{
				return false;
			}
			else {
				DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.AddressData = DNSServerDataTemp.front().AddressData;
				IsFoundParameter = true;
			}
		}
		else if (Data.compare(0, strlen("DNSCurveIPv4MainProviderName="), "DNSCurveIPv4MainProviderName=") == 0 && 
			Data.length() > strlen("DNSCurveIPv4MainProviderName="))
		{
			if (!ReadSupport_DNSCurveProviderName(Data, strlen("DNSCurveIPv4MainProviderName="), DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ProviderName, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
				return false;

		//Mark parameter found.
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("DNSCurveIPv4AlternateProviderName="), "DNSCurveIPv4AlternateProviderName=") == 0 && 
			Data.length() > strlen("DNSCurveIPv4AlternateProviderName="))
		{
			if (!ReadSupport_DNSCurveProviderName(Data, strlen("DNSCurveIPv4AlternateProviderName="), DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ProviderName, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
				return false;

		//Mark parameter found.
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("DNSCurveIPv6MainProviderName="), "DNSCurveIPv6MainProviderName=") == 0 && 
			Data.length() > strlen("DNSCurveIPv6MainProviderName="))
		{
			if (!ReadSupport_DNSCurveProviderName(Data, strlen("DNSCurveIPv6MainProviderName="), DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ProviderName, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
				return false;

		//Mark parameter found.
			IsFoundParameter = true;
		}
		else if (Data.compare(0, strlen("DNSCurveIPv6AlternateProviderName="), "DNSCurveIPv6AlternateProviderName=") == 0 && 
			Data.length() > strlen("DNSCurveIPv6AlternateProviderName="))
		{
			if (!ReadSupport_DNSCurveProviderName(Data, strlen("DNSCurveIPv6AlternateProviderName="), DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ProviderName, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
				return false;

		//Mark parameter found.
			IsFoundParameter = true;
		}
	}

	return true;

/* No need error report label.
//Jump here to print data format error.
PrintDataFormatError:
	PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Data format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
	return false;
*/
}

//Read parameter data from files(DNSCurve Keys block)
bool ReadParameterData_DNSCurve_Keys(
	const std::string &Data, 
	const size_t FileIndex, 
//	const bool IsFirstRead, 
	const size_t Line, 
//	CONFIGURATION_TABLE * const ParameterPointer, 
	DNSCURVE_CONFIGURATION_TABLE * const DNSCurveParameterPointer, 
	bool &IsFoundParameter)
{
//[DNSCurve Keys] block
	if (Data.compare(0, strlen("DNSCurveClientPublicKey="), "DNSCurveClientPublicKey=") == 0 && 
		Data.length() > strlen("DNSCurveClientPublicKey="))
	{
		if (!ReadSupport_DNSCurveKey(Data, strlen("DNSCurveClientPublicKey="), DNSCurveParameterPointer->Client_PublicKey, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
			return false;

	//Mark parameter found.
		IsFoundParameter = true;
	}
	else if (Data.compare(0, strlen("DNSCurveClientSecretKey="), "DNSCurveClientSecretKey=") == 0 && 
		Data.length() > strlen("DNSCurveClientSecretKey="))
	{
		if (!ReadSupport_DNSCurveKey(Data, strlen("DNSCurveClientSecretKey="), DNSCurveParameterPointer->Client_SecretKey, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
			return false;

	//Mark parameter found.
		IsFoundParameter = true;
	}
	else if (Data.compare(0, strlen("DNSCurveIPv4MainDNSPublicKey="), "DNSCurveIPv4MainDNSPublicKey=") == 0 && 
		Data.length() > strlen("DNSCurveIPv4MainDNSPublicKey="))
	{
		if (!ReadSupport_DNSCurveKey(Data, strlen("DNSCurveIPv4MainDNSPublicKey="), DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv4.ServerPublicKey, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
			return false;

	//Mark parameter found.
		IsFoundParameter = true;
	}
	else if (Data.compare(0, strlen("DNSCurveIPv4AlternateDNSPublicKey="), "DNSCurveIPv4AlternateDNSPublicKey=") == 0 && 
		Data.length() > strlen("DNSCurveIPv4AlternateDNSPublicKey="))
	{
		if (!ReadSupport_DNSCurveKey(Data, strlen("DNSCurveIPv4AlternateDNSPublicKey="), DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
			return false;

	//Mark parameter found.
		IsFoundParameter = true;
	}
	else if (Data.compare(0, strlen("DNSCurveIPv6MainDNSPublicKey="), "DNSCurveIPv6MainDNSPublicKey=") == 0 && 
		Data.length() > strlen("DNSCurveIPv6MainDNSPublicKey="))
	{
		if (!ReadSupport_DNSCurveKey(Data, strlen("DNSCurveIPv6MainDNSPublicKey="), DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv6.ServerPublicKey, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
			return false;

	//Mark parameter found.
		IsFoundParameter = true;
	}
	else if (Data.compare(0, strlen("DNSCurveIPv6AlternateDNSPublicKey="), "DNSCurveIPv6AlternateDNSPublicKey=") == 0 && 
		Data.length() > strlen("DNSCurveIPv6AlternateDNSPublicKey="))
	{
		if (!ReadSupport_DNSCurveKey(Data, strlen("DNSCurveIPv6AlternateDNSPublicKey="), DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
			return false;

	//Mark parameter found.
		IsFoundParameter = true;
	}
	else if (Data.compare(0, strlen("DNSCurveIPv4MainDNSFingerprint="), "DNSCurveIPv4MainDNSFingerprint=") == 0 && 
		Data.length() > strlen("DNSCurveIPv4MainDNSFingerprint="))
	{
		if (!ReadSupport_DNSCurveKey(Data, strlen("DNSCurveIPv4MainDNSFingerprint="), DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv4.ServerFingerprint, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
			return false;

	//Mark parameter found.
		IsFoundParameter = true;
	}
	else if (Data.compare(0, strlen("DNSCurveIPv4AlternateDNSFingerprint="), "DNSCurveIPv4AlternateDNSFingerprint=") == 0 && 
		Data.length() > strlen("DNSCurveIPv4AlternateDNSFingerprint="))
	{
		if (!ReadSupport_DNSCurveKey(Data, strlen("DNSCurveIPv4AlternateDNSFingerprint="), DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
			return false;

	//Mark parameter found.
		IsFoundParameter = true;
	}
	else if (Data.compare(0, strlen("DNSCurveIPv6MainDNSFingerprint="), "DNSCurveIPv6MainDNSFingerprint=") == 0 && 
		Data.length() > strlen("DNSCurveIPv6MainDNSFingerprint="))
	{
		if (!ReadSupport_DNSCurveKey(Data, strlen("DNSCurveIPv6MainDNSFingerprint="), DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv6.ServerFingerprint, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
			return false;

	//Mark parameter found.
		IsFoundParameter = true;
	}
	else if (Data.compare(0, strlen("DNSCurveIPv6AlternateDNSFingerprint="), "DNSCurveIPv6AlternateDNSFingerprint=") == 0 && 
		Data.length() > strlen("DNSCurveIPv6AlternateDNSFingerprint="))
	{
		if (!ReadSupport_DNSCurveKey(Data, strlen("DNSCurveIPv6AlternateDNSFingerprint="), DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint, READ_TEXT_TYPE::PARAMETER_NORMAL, FileIndex, Line))
			return false;

	//Mark parameter found.
		IsFoundParameter = true;
	}

	return true;

/* No need error report label.
//Jump here to print data format error.
PrintDataFormatError:
	PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Data format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
	return false;
*/
}

//Read parameter data from files(DNSCurve Magic Number block)
bool ReadParameterData_DNSCurve_MagicNumber(
	const std::string &Data, 
	const size_t FileIndex, 
//	const bool IsFirstRead, 
	const size_t Line, 
//	CONFIGURATION_TABLE * const ParameterPointer, 
	DNSCURVE_CONFIGURATION_TABLE * const DNSCurveParameterPointer, 
	bool &IsFoundParameter)
{
//[DNSCurve Magic Number] block
	if (Data.compare(0, strlen("DNSCurveIPv4MainReceiveMagicNumber="), "DNSCurveIPv4MainReceiveMagicNumber=") == 0 && 
		Data.length() > strlen("DNSCurveIPv4MainReceiveMagicNumber="))
	{
		if (!ReadSupport_DNSCurveMagicNumber(Data, strlen("DNSCurveIPv4MainReceiveMagicNumber="), DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber, FileIndex, Line))
			return false;

	//Mark parameter found.
		IsFoundParameter = true;
	}
	else if (Data.compare(0, strlen("DNSCurveIPv4AlternateReceiveMagicNumber="), "DNSCurveIPv4AlternateReceiveMagicNumber=") == 0 && 
		Data.length() > strlen("DNSCurveIPv4AlternateReceiveMagicNumber="))
	{
		if (!ReadSupport_DNSCurveMagicNumber(Data, strlen("DNSCurveIPv4AlternateReceiveMagicNumber="), DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber, FileIndex, Line))
			return false;

	//Mark parameter found.
		IsFoundParameter = true;
	}
	else if (Data.compare(0, strlen("DNSCurveIPv6MainReceiveMagicNumber="), "DNSCurveIPv6MainReceiveMagicNumber=") == 0 && 
		Data.length() > strlen("DNSCurveIPv6MainReceiveMagicNumber="))
	{
		if (!ReadSupport_DNSCurveMagicNumber(Data, strlen("DNSCurveIPv6MainReceiveMagicNumber="), DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber, FileIndex, Line))
			return false;

	//Mark parameter found.
		IsFoundParameter = true;
	}
	else if (Data.compare(0, strlen("DNSCurveIPv6AlternateReceiveMagicNumber="), "DNSCurveIPv6AlternateReceiveMagicNumber=") == 0 && 
		Data.length() > strlen("DNSCurveIPv6AlternateReceiveMagicNumber="))
	{
		if (!ReadSupport_DNSCurveMagicNumber(Data, strlen("DNSCurveIPv6AlternateReceiveMagicNumber="), DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber, FileIndex, Line))
			return false;

	//Mark parameter found.
		IsFoundParameter = true;
	}
	else if (Data.compare(0, strlen("DNSCurveIPv4MainDNSMagicNumber="), "DNSCurveIPv4MainDNSMagicNumber=") == 0 && 
		Data.length() > strlen("DNSCurveIPv4MainDNSMagicNumber="))
	{
		if (!ReadSupport_DNSCurveMagicNumber(Data, strlen("DNSCurveIPv4MainDNSMagicNumber="), DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv4.SendMagicNumber, FileIndex, Line))
			return false;

	//Mark parameter found.
		IsFoundParameter = true;
	}
	else if (Data.compare(0, strlen("DNSCurveIPv4AlternateDNSMagicNumber="), "DNSCurveIPv4AlternateDNSMagicNumber=") == 0 && 
		Data.length() > strlen("DNSCurveIPv4AlternateDNSMagicNumber="))
	{
		if (!ReadSupport_DNSCurveMagicNumber(Data, strlen("DNSCurveIPv4AlternateDNSMagicNumber="), DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber, FileIndex, Line))
			return false;

	//Mark parameter found.
		IsFoundParameter = true;
	}
	else if (Data.compare(0, strlen("DNSCurveIPv6MainDNSMagicNumber="), "DNSCurveIPv6MainDNSMagicNumber=") == 0 && 
		Data.length() > strlen("DNSCurveIPv6MainDNSMagicNumber="))
	{
		if (!ReadSupport_DNSCurveMagicNumber(Data, strlen("DNSCurveIPv6MainDNSMagicNumber="), DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv6.SendMagicNumber, FileIndex, Line))
			return false;

	//Mark parameter found.
		IsFoundParameter = true;
	}
	else if (Data.compare(0, strlen("DNSCurveIPv6AlternateDNSMagicNumber="), "DNSCurveIPv6AlternateDNSMagicNumber=") == 0 && 
		Data.length() > strlen("DNSCurveIPv6AlternateDNSMagicNumber="))
	{
		if (!ReadSupport_DNSCurveMagicNumber(Data, strlen("DNSCurveIPv6AlternateDNSMagicNumber="), DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber, FileIndex, Line))
			return false;

	//Mark parameter found.
		IsFoundParameter = true;
	}

	return true;

/* No need error report label.
//Jump here to print data format error.
PrintDataFormatError:
	PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Data format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
	return false;
*/
}
#endif

//Read file names from data
bool ReadSupport_PathFileName(
	std::string Data, 
	const size_t DataOffset, 
	const bool IsPath, 
	std::vector<std::wstring> * const ListData, 
#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	std::vector<std::string> * const ListData_MBS, 
#endif
	const size_t FileIndex, 
	const size_t Line)
{
//Initialization
	std::vector<std::string> InnerListData;
	std::wstring WCS_NameString;
	ReadSupport_GetParameterListData(InnerListData, Data, DataOffset, Data.length(), ASCII_VERTICAL, false, false);

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
		#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
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

		//Register to global list(WCS).
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

		//Register to global list(MBS).
		#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			for (auto InnerStringIter = GlobalRunningStatus.Path_Global_MBS->begin();InnerStringIter < GlobalRunningStatus.Path_Global_MBS->end();++InnerStringIter)
			{
				if (*InnerStringIter == StringIter)
				{
					break;
				}
				else if (InnerStringIter + 1U == GlobalRunningStatus.Path_Global_MBS->end())
				{
					GlobalRunningStatus.Path_Global_MBS->push_back(StringIter);
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

		//Register to global list(WCS).
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

		//Register to global list(MBS).
		#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			if (ListData_MBS->empty())
			{
				ListData_MBS->push_back(StringIter);
			}
			else {
				for (auto InnerStringIter = ListData_MBS->begin();InnerStringIter != ListData_MBS->end();++InnerStringIter)
				{
					if (*InnerStringIter == StringIter)
					{
						break;
					}
					else if (InnerStringIter + 1U == ListData_MBS->end())
					{
						ListData_MBS->push_back(StringIter);
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
bool ReadSupport_MultipleAddresses(
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
	std::array<uint8_t, ADDRESS_STRING_MAXSIZE + MEMORY_RESERVED_BYTES> AddrBuffer{};
	std::vector<std::string> ListData;
	ssize_t SignedResult = 0;
	size_t UnsignedResult = 0;
	ReadSupport_GetParameterListData(ListData, Data, DataOffset, Data.length(), ASCII_VERTICAL, false, false);

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
				StringIter.find(ASCII_BRACKETS_RIGHT) < ADDRESS_STRING_IPV6_MINSIZE || StringIter.length() <= StringIter.find("]:") + strlen("]:"))
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
			AddrBuffer.fill(0);
			memcpy_s(AddrBuffer.data(), ADDRESS_STRING_MAXSIZE, StringIter.c_str() + strlen("["), StringIter.find(ASCII_BRACKETS_RIGHT) - strlen("["));
			if (!AddressStringToBinary(AF_INET6, AddrBuffer.data(), &DNSServerDataTemp.AddressData.IPv6.sin6_addr, &SignedResult))
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
			AddrBuffer.fill(0);
			memcpy_s(AddrBuffer.data(), ADDRESS_STRING_MAXSIZE, StringIter.c_str() + StringIter.find("]:") + strlen("]:"), StringIter.length() - (StringIter.find("]:") + strlen("]:")));
			if (strstr(reinterpret_cast<const char *>(AddrBuffer.data()), "-") != nullptr)
			{
			#if defined(ENABLE_LIBSODIUM)
				if (InputType == READ_TEXT_TYPE::DNSCURVE_DATABASE || InputType == READ_TEXT_TYPE::DNSCURVE_MONITOR)
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::DNSCURVE, L"IPv6 address format error", 0, nullptr, 0);
				else 
			#endif
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv6 address format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);

				return false;
			}

		//Convert type.
			UnsignedResult = ServiceNameToBinary(AddrBuffer.data());
			if (UnsignedResult == 0)
			{
				_set_errno(0);
				UnsignedResult = strtoul(reinterpret_cast<const char *>(AddrBuffer.data()), nullptr, 0);
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
			DNSServerDataTemp.AddressData.IPv6.sin6_port = hton16(static_cast<const uint16_t>(UnsignedResult));

		//Register to global list.
			DNSServerDataTemp.AddressData.Storage.ss_family = AF_INET6;
			if (DNSServerDataList->empty())
			{
				DNSServerDataList->push_back(DNSServerDataTemp);
			}
			else {
			//Check repeat items.
				for (const auto &DNSServerDataItem:*DNSServerDataList)
				{
					if (DNSServerDataTemp.AddressData.Storage.ss_family == DNSServerDataItem.AddressData.Storage.ss_family && 
						memcmp(&DNSServerDataTemp.AddressData.IPv6.sin6_addr, &DNSServerDataItem.AddressData.IPv6.sin6_addr, sizeof(DNSServerDataTemp.AddressData.IPv6.sin6_addr)) == 0 && 
						DNSServerDataTemp.AddressData.IPv6.sin6_port == DNSServerDataItem.AddressData.IPv6.sin6_port)
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
				StringIter.find(ASCII_COLON) < ADDRESS_STRING_IPV4_MINSIZE || StringIter.length() <= StringIter.find(ASCII_COLON) + strlen(":"))
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
			AddrBuffer.fill(0);
			memcpy_s(AddrBuffer.data(), ADDRESS_STRING_MAXSIZE, StringIter.c_str(), StringIter.find(ASCII_COLON));
			if (!AddressStringToBinary(AF_INET, AddrBuffer.data(), &DNSServerDataTemp.AddressData.IPv4.sin_addr, &SignedResult))
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
			AddrBuffer.fill(0);
			memcpy_s(AddrBuffer.data(), ADDRESS_STRING_MAXSIZE, StringIter.c_str() + StringIter.find(ASCII_COLON) + strlen(":"), StringIter.length() - (StringIter.find(ASCII_COLON) + strlen(":")));
			if (strstr(reinterpret_cast<const char *>(AddrBuffer.data()), "-") != nullptr)
			{
			#if defined(ENABLE_LIBSODIUM)
				if (InputType == READ_TEXT_TYPE::DNSCURVE_DATABASE || InputType == READ_TEXT_TYPE::DNSCURVE_MONITOR)
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::DNSCURVE, L"IPv4 address format error", 0, nullptr, 0);
				else 
			#endif
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv4 address format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);

				return false;
			}

		//Convert type.
			UnsignedResult = ServiceNameToBinary(AddrBuffer.data());
			if (UnsignedResult == 0)
			{
				_set_errno(0);
				UnsignedResult = strtoul(reinterpret_cast<const char *>(AddrBuffer.data()), nullptr, 0);
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
			DNSServerDataTemp.AddressData.IPv4.sin_port = hton16(static_cast<const uint16_t>(UnsignedResult));

		//Register to global list.
			DNSServerDataTemp.AddressData.Storage.ss_family = AF_INET;
			if (DNSServerDataList->empty())
			{
				DNSServerDataList->push_back(DNSServerDataTemp);
			}
			else {
			//Check repeat items.
				for (const auto &DNSServerDataItem:*DNSServerDataList)
				{
					if (DNSServerDataTemp.AddressData.Storage.ss_family == DNSServerDataItem.AddressData.Storage.ss_family && 
						DNSServerDataTemp.AddressData.IPv4.sin_addr.s_addr == DNSServerDataItem.AddressData.IPv4.sin_addr.s_addr && 
						DNSServerDataTemp.AddressData.IPv4.sin_port == DNSServerDataItem.AddressData.IPv4.sin_port)
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
bool ReadSupport_SOCKS_AddressDomain(
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
	std::array<uint8_t, ADDRESS_STRING_MAXSIZE + MEMORY_RESERVED_BYTES> AddrBuffer{};
	ssize_t SignedResult = 0;
	size_t UnsignedResult = 0;

//IPv6
	if (Data.find(ASCII_BRACKETS_LEFT) != std::string::npos || Data.find(ASCII_BRACKETS_RIGHT) != std::string::npos)
	{
		if (Data.find("]:") == std::string::npos || Data.find(ASCII_BRACKETS_RIGHT) <= DataOffset + strlen("[") || 
			Data.find(ASCII_BRACKETS_RIGHT) < DataOffset + ADDRESS_STRING_IPV6_MINSIZE || Data.length() <= Data.find("]:") + strlen("]:"))
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv6 address format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
		else {
		//Convert IPv6 address.
			memcpy_s(AddrBuffer.data(), ADDRESS_STRING_MAXSIZE, Data.c_str() + DataOffset + strlen("["), Data.find(ASCII_BRACKETS_RIGHT) - (DataOffset + strlen("[")));
			if (!AddressStringToBinary(AF_INET6, AddrBuffer.data(), &ParameterPointer->SOCKS_TargetServer.IPv6.sin6_addr, &SignedResult))
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv6 address format error", SignedResult, FileList_Config.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Convert IPv6 port.
			AddrBuffer.fill(0);
			memcpy_s(AddrBuffer.data(), ADDRESS_STRING_MAXSIZE, Data.c_str() + Data.find("]:") + strlen("]:"), Data.length() - (Data.find("]:") + strlen("]:")));
			if (strstr(reinterpret_cast<const char *>(AddrBuffer.data()), "-") != nullptr)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv6 address format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Convert type.
			UnsignedResult = ServiceNameToBinary(AddrBuffer.data());
			if (UnsignedResult == 0)
			{
				_set_errno(0);
				UnsignedResult = strtoul(reinterpret_cast<const char *>(AddrBuffer.data()), nullptr, 0);
				if (UnsignedResult == 0 || UnsignedResult >= ULONG_MAX)
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv6 address port error", errno, FileList_Config.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
			}

			ParameterPointer->SOCKS_TargetServer.IPv6.sin6_port = hton16(static_cast<const uint16_t>(UnsignedResult));
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
			memcpy_s(AddrBuffer.data(), ADDRESS_STRING_MAXSIZE, Data.c_str() + Data.find(ASCII_COLON) + strlen(":"), Data.length() - (Data.find(ASCII_COLON) + strlen(":")));
			if (strstr(reinterpret_cast<const char *>(AddrBuffer.data()), "-") != nullptr)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv4 address format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Convert type.
			UnsignedResult = ServiceNameToBinary(AddrBuffer.data());
			if (UnsignedResult == 0)
			{
				_set_errno(0);
				UnsignedResult = strtoul(reinterpret_cast<const char *>(AddrBuffer.data()), nullptr, 0);
				if (UnsignedResult == 0 || UnsignedResult >= ULONG_MAX)
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv4 address port error", errno, FileList_Config.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
			}

			ParameterPointer->SOCKS_TargetDomain_Port = hton16(static_cast<const uint16_t>(UnsignedResult));
		}
	//IPv4
		else {
		//IPv4 address and port check.
			if (Data.find(ASCII_COLON) == std::string::npos || Data.find(ASCII_PERIOD) == std::string::npos || 
				Data.find(ASCII_COLON) < DataOffset + ADDRESS_STRING_IPV4_MINSIZE || Data.length() <= Data.find(ASCII_COLON) + strlen(":"))
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv4 address format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Convert IPv4 address.
			memcpy_s(AddrBuffer.data(), ADDRESS_STRING_MAXSIZE, Data.c_str() + DataOffset, Data.find(ASCII_COLON) - DataOffset);
			if (!AddressStringToBinary(AF_INET, AddrBuffer.data(), &ParameterPointer->SOCKS_TargetServer.IPv4.sin_addr, &SignedResult))
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv4 address format error", SignedResult, FileList_Config.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Convert IPv4 port.
			AddrBuffer.fill(0);
			memcpy_s(AddrBuffer.data(), ADDRESS_STRING_MAXSIZE, Data.c_str() + Data.find(ASCII_COLON) + strlen(":"), Data.length() - (Data.find(ASCII_COLON) + strlen(":")));
			if (strstr(reinterpret_cast<const char *>(AddrBuffer.data()), "-") != nullptr)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv4 address format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Convert type.
			UnsignedResult = ServiceNameToBinary(AddrBuffer.data());
			if (UnsignedResult == 0)
			{
				_set_errno(0);
				UnsignedResult = strtoul(reinterpret_cast<const char *>(AddrBuffer.data()), nullptr, 0);
				if (UnsignedResult == 0 || UnsignedResult >= ULONG_MAX)
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv4 address port error", errno, FileList_Config.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
			}

			ParameterPointer->SOCKS_TargetServer.IPv4.sin_port = hton16(static_cast<const uint16_t>(UnsignedResult));
			ParameterPointer->SOCKS_TargetServer.Storage.ss_family = AF_INET;
		}
	}

	return true;
}

//Read TTL or Hop Limits from data
#if defined(ENABLE_PCAP)
bool ReadSupport_HopLimitsData(
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

//Format check
	if (Data.find(ASCII_MINUS) != std::string::npos)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Data format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Initialization
	std::vector<std::string> ListData;
	ReadSupport_GetParameterListData(ListData, Data, DataOffset, Data.length(), ASCII_VERTICAL, false, false);
	size_t UnsignedResult = 0;

//Mark all data in list.
	for (const auto &StringIter:ListData)
	{
	//Convert number.
		_set_errno(0);
		UnsignedResult = strtoul(StringIter.c_str(), nullptr, 0);
		if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult < UINT8_MAX))
		{
			if (Protocol == AF_INET6)
			{
			//Monitor mode
				if (!IsFirstRead)
				{
					if (ParameterHopLimitsIndex.at(NETWORK_LAYER_TYPE_IPV6) == 0)
						Parameter.Target_Server_Main_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_StaticLoad = static_cast<const uint8_t>(UnsignedResult);
					else if (ParameterHopLimitsIndex.at(NETWORK_LAYER_TYPE_IPV6) == 1U)
						Parameter.Target_Server_Alternate_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_StaticLoad = static_cast<const uint8_t>(UnsignedResult);
					else if (!DNSServerDataList->empty() && ParameterHopLimitsIndex.at(NETWORK_LAYER_TYPE_IPV6) - 2U < DNSServerDataList->size())
						DNSServerDataList->at(ParameterHopLimitsIndex.at(NETWORK_LAYER_TYPE_IPV6) - 2U).ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_StaticLoad = static_cast<const uint8_t>(UnsignedResult);
					else 
						goto PrintDataFormatError;

					++ParameterHopLimitsIndex.at(NETWORK_LAYER_TYPE_IPV6);
				}
			//Normal mode
				else if (!DNSServerDataList->empty() && ParameterHopLimitsIndex.at(NETWORK_LAYER_TYPE_IPV6) < DNSServerDataList->size())
				{
					DNSServerDataList->at(ParameterHopLimitsIndex.at(NETWORK_LAYER_TYPE_IPV6)).ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_StaticLoad = static_cast<const uint8_t>(UnsignedResult);
					++ParameterHopLimitsIndex.at(NETWORK_LAYER_TYPE_IPV6);
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
					if (ParameterHopLimitsIndex.at(NETWORK_LAYER_TYPE_IPV4) == 0)
						Parameter.Target_Server_Main_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_StaticLoad = static_cast<const uint8_t>(UnsignedResult);
					else if (ParameterHopLimitsIndex.at(NETWORK_LAYER_TYPE_IPV4) == 1U)
						Parameter.Target_Server_Alternate_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_StaticLoad = static_cast<const uint8_t>(UnsignedResult);
					else if (!DNSServerDataList->empty() && ParameterHopLimitsIndex.at(NETWORK_LAYER_TYPE_IPV4) - 2U < DNSServerDataList->size())
						DNSServerDataList->at(ParameterHopLimitsIndex.at(NETWORK_LAYER_TYPE_IPV4) - 2U).ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_StaticLoad = static_cast<const uint8_t>(UnsignedResult);
					else 
						goto PrintDataFormatError;

					++ParameterHopLimitsIndex.at(NETWORK_LAYER_TYPE_IPV4);
				}
			//Normal mode
				else if (!DNSServerDataList->empty() && ParameterHopLimitsIndex.at(NETWORK_LAYER_TYPE_IPV4) < DNSServerDataList->size())
				{
					DNSServerDataList->at(ParameterHopLimitsIndex.at(NETWORK_LAYER_TYPE_IPV4)).ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_StaticLoad = static_cast<const uint8_t>(UnsignedResult);
					++ParameterHopLimitsIndex.at(NETWORK_LAYER_TYPE_IPV4);
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
	PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Data format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
	return false;
}
#endif

//Read Address Prefix Block data
bool ReadSupport_AddressPrefixData(
	const uint16_t Protocol, 
	std::string OriginalData, 
	const size_t DataOffset, 
	ADDRESS_PREFIX_BLOCK * const AddressPrefix, 
	const std::vector<FILE_DATA> &FileList, 
	const size_t FileIndex, 
	const size_t Line)
{
	std::string Data(OriginalData, DataOffset);

//Check data format.
	if (Data.find("/") == std::string::npos || Data.rfind("/") < ADDRESS_STRING_IPV6_MINSIZE || Data.at(Data.length() - 1U) == ASCII_SLASH)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Address Prefix Block format error", 0, FileList.at(FileIndex).FileName.c_str(), Line);
		return false;
	}
	for (const auto &StringIter:Data)
	{
		if (StringIter < ASCII_PERIOD || (StringIter > ASCII_COLON && StringIter < ASCII_UPPERCASE_A) || 
			(StringIter > ASCII_UPPERCASE_F && StringIter < ASCII_LOWERCASE_A) || StringIter > ASCII_LOWERCASE_F)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Address Prefix Block format error", 0, FileList.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
	}

//Initialization
	std::array<uint8_t, ADDRESS_STRING_MAXSIZE + MEMORY_RESERVED_BYTES> AddrBuffer{};
	memcpy_s(AddrBuffer.data(), ADDRESS_STRING_MAXSIZE, Data.c_str(), Data.find("/"));
	Data.erase(0, Data.find("/") + 1U);
	ssize_t SignedResult = 0;
	size_t UnsignedResult = 0;

//IPv6
	if (Protocol == AF_INET6)
	{
	//Prefix check and convert address.
		if (Data.find(ASCII_MINUS) != std::string::npos || 
			!AddressStringToBinary(AF_INET6, AddrBuffer.data(), &reinterpret_cast<sockaddr_in6 *>(&AddressPrefix->first)->sin6_addr, &SignedResult))
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv6 address format error", SignedResult, FileList.at(FileIndex).FileName.c_str(), Line);
			return false;
		}

	//Mark network prefix.
		_set_errno(0);
		UnsignedResult = strtoul(Data.c_str(), nullptr, 0);
		if (UnsignedResult == 0 || UnsignedResult > sizeof(in6_addr) * BYTES_TO_BITS)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv6 prefix error", errno, FileList.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
		else {
			AddressPrefix->second = UnsignedResult;

		//Mark prefix block.
			in6_addr BinaryAddr;
			memset(&BinaryAddr, 0, sizeof(BinaryAddr));
			if (AddressPrefixReplacing(AF_INET6, &reinterpret_cast<const sockaddr_in6 *>(&AddressPrefix->first)->sin6_addr, &BinaryAddr, AddressPrefix->second))
				memcpy_s(&reinterpret_cast<sockaddr_in6 *>(&AddressPrefix->first)->sin6_addr, sizeof(BinaryAddr), &BinaryAddr, sizeof(BinaryAddr));
			else 
				return false;
		}

		AddressPrefix->first.ss_family = AF_INET6;
	}
//IPv4
	else if (Protocol == AF_INET)
	{
	//Prefix check and convert address.
		if (Data.find(ASCII_MINUS) != std::string::npos || 
			!AddressStringToBinary(AF_INET, AddrBuffer.data(), &reinterpret_cast<sockaddr_in *>(&AddressPrefix->first)->sin_addr, &SignedResult))
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv4 address format error", SignedResult, FileList.at(FileIndex).FileName.c_str(), Line);
			return false;
		}

	//Mark network prefix.
		_set_errno(0);
		UnsignedResult = strtoul(Data.c_str(), nullptr, 0);
		if (UnsignedResult == 0 || UnsignedResult > sizeof(in_addr) * BYTES_TO_BITS)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv4 prefix error", errno, FileList.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
		else {
			AddressPrefix->second = UnsignedResult;

		//Mark prefix block.
			in_addr BinaryAddr;
			memset(&BinaryAddr, 0, sizeof(BinaryAddr));
			if (AddressPrefixReplacing(AF_INET, &reinterpret_cast<const sockaddr_in *>(&AddressPrefix->first)->sin_addr, &BinaryAddr, AddressPrefix->second))
				memcpy_s(&reinterpret_cast<sockaddr_in *>(&AddressPrefix->first)->sin_addr, sizeof(BinaryAddr), &BinaryAddr, sizeof(BinaryAddr));
			else 
				return false;
		}

		AddressPrefix->first.ss_family = AF_INET;
	}
	else {
		PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Data format error", 0, FileList.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

	return true;
}

#if defined(ENABLE_LIBSODIUM)
//Read DNSCurve database
void ReadSupport_DNSCurveDatabaseData(
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

//CSV title check
//The title data is <Name,"Full name","Description","Location","Coordinates",URL,Version,DNSSEC validation,No logs,Namecoin,Resolver address,Provider name,Provider public key,Provider public key TXT record>.
	if (Data.compare(0, strlen("Name,"), "Name,") == 0 || 
		Data.find(",\"Full name\",") != std::string::npos || 
		Data.find(",\"Description\",") != std::string::npos || 
		Data.find(",\"Location\",") != std::string::npos || 
		Data.find(",\"Coordinates\",") != std::string::npos || 
		Data.find(",URL,") != std::string::npos || 
		Data.find(",Version,") != std::string::npos || 
		Data.find(",DNSSEC validation,") != std::string::npos || 
		Data.find(",No logs,") != std::string::npos || 
		Data.find(",Namecoin,") != std::string::npos || 
		Data.find(",Resolver address,") != std::string::npos || 
		Data.find(",Provider name,") != std::string::npos || 
		Data.find(",Provider public key,") != std::string::npos || 
		Data.find(",Provider public key TXT record,") != std::string::npos)
			return;

//Remove all commas in sub item.
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
	ReadSupport_GetParameterListData(LineDataTemp, Data, 0, Data.length(), ASCII_COMMA, false, true);
	if (LineDataTemp.size() < DNSCRYPT_DATABASE_ITEM_MIN)
		PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::DNSCURVE, L"Data format error", 0, FileList_DNSCurveDatabase.at(FileIndex).FileName.c_str(), Line);
	else 
		DNSCurveParameterPointer->Database_LineData->push_back(LineDataTemp);

	return;
}

//Read DNSCurve database item data
bool ReadSupport_DNSCurveDatabaseItem(
	const READ_TEXT_TYPE InputType)
{
//Initialization
	DNSCURVE_CONFIGURATION_TABLE *DNSCurveParameterPointer = nullptr;
	if (InputType == READ_TEXT_TYPE::DNSCURVE_DATABASE)
	{
	//Move Alternate to Main
		DNSCurveParameterPointer = &DNSCurveParameter;

	//IPv6
		if (DNSCurveParameter.Database_Target_Server_Main_IPv6 != nullptr && DNSCurveParameter.Database_Target_Server_Alternate_IPv6 != nullptr && 
			DNSCurveParameter.Database_Target_Server_Main_IPv6->empty() && !DNSCurveParameter.Database_Target_Server_Alternate_IPv6->empty())
		{
			*DNSCurveParameter.Database_Target_Server_Main_IPv6 = *DNSCurveParameter.Database_Target_Server_Alternate_IPv6;
			DNSCurveParameter.Database_Target_Server_Alternate_IPv6->clear();
			DNSCurveParameter.Database_Target_Server_Alternate_IPv6->shrink_to_fit();
		}

	//IPv4
		if (DNSCurveParameter.Database_Target_Server_Main_IPv4 != nullptr && DNSCurveParameter.Database_Target_Server_Alternate_IPv4 != nullptr && 
			DNSCurveParameter.Database_Target_Server_Main_IPv4->empty() && !DNSCurveParameter.Database_Target_Server_Alternate_IPv4->empty())
		{
			*DNSCurveParameter.Database_Target_Server_Main_IPv4 = *DNSCurveParameter.Database_Target_Server_Alternate_IPv4;
			DNSCurveParameter.Database_Target_Server_Alternate_IPv4->clear();
			DNSCurveParameter.Database_Target_Server_Alternate_IPv4->shrink_to_fit();
		}
	}
	else if (InputType == READ_TEXT_TYPE::DNSCURVE_MONITOR)
	{
		DNSCurveParameterPointer = &DNSCurveParameterModificating;
	}

//Pointer check
	if (DNSCurveParameterPointer == nullptr || DNSCurveParameterPointer->Database_LineData == nullptr)
		return false;

//Read all list database data.
	auto IsIPv6_Main = false, IsIPv6_Alternate = false, IsIPv4_Main = false, IsIPv4_Alternate = false;
	for (auto StringIter:*DNSCurveParameterPointer->Database_LineData)
	{
		if (StringIter.size() >= DNSCRYPT_DATABASE_ITEM_MIN && 
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
				if (!ReadSupport_MultipleAddresses(AF_INET6, StringIter.at(DNSCRYPT_DATABASE_ADDRESS_LOCATION).c_str(), 0, &DNSServerDataTemp, InputType, 0, 0) || 
					DNSServerDataTemp.empty() || 
					(InputType == READ_TEXT_TYPE::DNSCURVE_DATABASE && 
					!ReadSupport_DNSCurveProviderName(StringIter.at(DNSCRYPT_DATABASE_PROVIDER_NAME_LOCATION).c_str(), 0, DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ProviderName, InputType, 0, 0)) || 
					!ReadSupport_DNSCurveKey(StringIter.at(DNSCRYPT_DATABASE_PROVIDER_KEY_LOCATION).c_str(), 0, DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv6.ServerPublicKey, InputType, 0, 0))
				{
					std::wstring Message;
					PrintLog_DNSCurve(DNSCURVE_SERVER_TYPE::MAIN_IPV6, Message);
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
				if (!ReadSupport_MultipleAddresses(AF_INET6, StringIter.at(DNSCRYPT_DATABASE_ADDRESS_LOCATION).c_str(), 0, &DNSServerDataTemp, InputType, 0, 0) || 
					DNSServerDataTemp.empty() || 
					(InputType == READ_TEXT_TYPE::DNSCURVE_DATABASE && 
					!ReadSupport_DNSCurveProviderName(StringIter.at(DNSCRYPT_DATABASE_PROVIDER_NAME_LOCATION).c_str(), 0, DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ProviderName, InputType, 0, 0)) || 
					!ReadSupport_DNSCurveKey(StringIter.at(DNSCRYPT_DATABASE_PROVIDER_KEY_LOCATION).c_str(), 0, DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey, InputType, 0, 0))
				{
					std::wstring Message;
					PrintLog_DNSCurve(DNSCURVE_SERVER_TYPE::ALTERNATE_IPV6, Message);
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
				if (!ReadSupport_MultipleAddresses(AF_INET, StringIter.at(DNSCRYPT_DATABASE_ADDRESS_LOCATION).c_str(), 0, &DNSServerDataTemp, InputType, 0, 0) || 
					DNSServerDataTemp.empty() || 
					(InputType == READ_TEXT_TYPE::DNSCURVE_DATABASE && 
					!ReadSupport_DNSCurveProviderName(StringIter.at(DNSCRYPT_DATABASE_PROVIDER_NAME_LOCATION).c_str(), 0, DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ProviderName, InputType, 0, 0)) || 
					!ReadSupport_DNSCurveKey(StringIter.at(DNSCRYPT_DATABASE_PROVIDER_KEY_LOCATION).c_str(), 0, DNSCurveParameterPointer->DNSCurve_Target_Server_Main_IPv4.ServerPublicKey, InputType, 0, 0))
				{
					std::wstring Message;
					PrintLog_DNSCurve(DNSCURVE_SERVER_TYPE::MAIN_IPV4, Message);
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
				if (!ReadSupport_MultipleAddresses(AF_INET, StringIter.at(DNSCRYPT_DATABASE_ADDRESS_LOCATION).c_str(), 0, &DNSServerDataTemp, InputType, 0, 0) || 
					DNSServerDataTemp.empty() || 
					(InputType == READ_TEXT_TYPE::DNSCURVE_DATABASE && 
					!ReadSupport_DNSCurveProviderName(StringIter.at(DNSCRYPT_DATABASE_PROVIDER_NAME_LOCATION).c_str(), 0, DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ProviderName, InputType, 0, 0)) || 
					!ReadSupport_DNSCurveKey(StringIter.at(DNSCRYPT_DATABASE_PROVIDER_KEY_LOCATION).c_str(), 0, DNSCurveParameterPointer->DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey, InputType, 0, 0))
				{
					std::wstring Message;
					PrintLog_DNSCurve(DNSCURVE_SERVER_TYPE::ALTERNATE_IPV4, Message);
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

//Read DNSCurve Provider Name of DNSCurve server
bool ReadSupport_DNSCurveProviderName(
	std::string Data, 
	const size_t DataOffset, 
	uint8_t * const ProviderNameData, 
	const READ_TEXT_TYPE InputType, 
	const size_t FileIndex, 
	const size_t Line)
{
	memset(ProviderNameData, 0, DOMAIN_MAXSIZE);

//Provider Name format check
	if (Data.length() > DataOffset + DOMAIN_MINSIZE && Data.length() < DataOffset + DOMAIN_DATA_MAXSIZE)
	{
		for (auto Index = DataOffset;Index < Data.length() - DataOffset;++Index)
		{
			for (size_t InnerIndex = 0;InnerIndex < strnlen_s(reinterpret_cast<const char *>(GlobalRunningStatus.DomainTable_Upper), DOMAIN_MAXSIZE);++InnerIndex)
			{
			//Provider Name length check
				if (InnerIndex + 1U == strnlen_s(reinterpret_cast<const char *>(GlobalRunningStatus.DomainTable_Upper), DOMAIN_MAXSIZE) && Data.at(Index) != *(GlobalRunningStatus.DomainTable_Upper + InnerIndex))
				{
					if (InputType == READ_TEXT_TYPE::DNSCURVE_DATABASE || InputType == READ_TEXT_TYPE::DNSCURVE_MONITOR)
						PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::DNSCURVE, L"DNSCurve Provider Name error", 0, nullptr, 0);
					else 
						PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"DNSCurve Provider Name error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);

					return false;
				}

			//Provider Name character check
				if (Data.at(Index) == *(GlobalRunningStatus.DomainTable_Upper + InnerIndex))
					break;
			}
		}

	//Copy Provider Name to buffer.
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
bool ReadSupport_DNSCurveKey(
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
		std::array<uint8_t, ADDRESS_STRING_MAXSIZE + MEMORY_RESERVED_BYTES> AddrBuffer{};
		if (sodium_hex2bin(
				AddrBuffer.data(), 
				ADDRESS_STRING_MAXSIZE, 
				Data.c_str() + DataOffset, 
				Data.length() - DataOffset, 
				(": "), 
				&ResultLength, 
				&ResultPointer) == 0 && 
			ResultPointer != nullptr && ResultLength == crypto_box_PUBLICKEYBYTES)
		{
			memcpy_s(KeyData, crypto_box_SECRETKEYBYTES, AddrBuffer.data(), crypto_box_PUBLICKEYBYTES);
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
bool ReadSupport_DNSCurveMagicNumber(
	std::string Data, 
	const size_t DataOffset, 
	uint8_t * const MagicNumber, 
	const size_t FileIndex, 
	const size_t Line)
{
	memset(MagicNumber, 0, DNSCURVE_MAGIC_QUERY_LEN);

//Hex format
	if (Data.find(HEX_PREAMBLE_STRING) == DataOffset && Data.length() == DataOffset + DNSCURVE_MAGIC_QUERY_HEX_LEN + strlen(HEX_PREAMBLE_STRING))
	{
		const char *ResultPointer = nullptr;
		size_t ResultLength = 0;

	//Convert hex format to binary.
		if (sodium_hex2bin(
				MagicNumber, 
				DNSCURVE_MAGIC_QUERY_LEN, 
				Data.c_str() + DataOffset + strlen(HEX_PREAMBLE_STRING), 
				DNSCURVE_MAGIC_QUERY_HEX_LEN, 
				nullptr, 
				&ResultLength, 
				&ResultPointer) != 0 || 
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

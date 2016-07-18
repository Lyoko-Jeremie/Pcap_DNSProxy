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


#include "Configuration.h"

//Check parameter list and set default values
bool ParameterCheckAndSetting(
	const bool IsFirstRead, 
	const size_t FileIndex)
{
//Initialization
	CONFIGURATION_TABLE *ParameterPTR = nullptr;
#if defined(ENABLE_LIBSODIUM)
	DNSCURVE_CONFIGURATION_TABLE *DNSCurveParameterPTR = nullptr;
#endif
	if (IsFirstRead)
	{
		ParameterPTR = &Parameter;
	#if defined(ENABLE_LIBSODIUM)
		DNSCurveParameterPTR = &DNSCurveParameter;
	#endif
	}
	else {
		ParameterPTR = &ParameterModificating;
	#if defined(ENABLE_LIBSODIUM)
		DNSCurveParameterPTR = &DNSCurveParameterModificating;
	#endif
	}

//[Base] block
//Version check
	if (ParameterPTR->Version > CONFIG_VERSION)
	{
		PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"Configuration file version error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
		return false;
	}
	else if (ParameterPTR->Version < CONFIG_VERSION)
	{
		PrintError(LOG_LEVEL_3, LOG_MESSAGE_NOTICE, L"Configuration file is not the latest version", 0, nullptr, 0);
	}

//Log maximum size check
	if (ParameterPTR->LogMaxSize < DEFAULT_LOG_MINSIZE || ParameterPTR->LogMaxSize > DEFAULT_FILE_MAXSIZE)
	{
		PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"Log file size error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
		return false;
	}

//[Listen] block
//Pcap Capture check
	if (
	#if defined(ENABLE_PCAP)
		!Parameter.PcapCapture && 
	#endif
	//Direct Request mode
		ParameterPTR->DirectRequest == DIRECT_REQUEST_MODE_NONE && 
	//SOCKS request mode
		!Parameter.SOCKS_Proxy && 
	//HTTP request mode
		!Parameter.HTTP_Proxy
	//DNSCurve request mode
	#if defined(ENABLE_LIBSODIUM)
		&& !Parameter.DNSCurve
	#endif
	//TCP request mode
		&& Parameter.RequestMode_Transport != REQUEST_MODE_TCP)
	{
		PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"Pcap Capture error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
		return false;
	}

	if (IsFirstRead)
	{
	//[DNS] block part 1
	//DNS cache check
		if (Parameter.CacheType > 0 && Parameter.CacheParameter == 0)
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"DNS Cache error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
			return false;
		}

	//[Local DNS] block
	//Local options check
		if (((Parameter.LocalMain || Parameter.LocalHosts || Parameter.LocalRouting) && 
			Parameter.Target_Server_Local_IPv4.Storage.ss_family == 0 && Parameter.Target_Server_Local_IPv6.Storage.ss_family) || 
			(Parameter.LocalHosts && (Parameter.LocalMain || Parameter.LocalRouting)) || 
			(Parameter.LocalRouting && !Parameter.LocalMain))
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"Local Main / Local Hosts / Local Routing error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
			return false;
		}

	//[Addresses] block
	//DNS Main and Alternate targets check
		if (Parameter.ListenAddress_IPv6->empty())
		{
			delete Parameter.ListenAddress_IPv6;
			Parameter.ListenAddress_IPv6 = nullptr;
		}
		if (Parameter.ListenAddress_IPv4->empty())
		{
			delete Parameter.ListenAddress_IPv4;
			Parameter.ListenAddress_IPv4 = nullptr;
		}
		if (Parameter.LocalhostSubnet_IPv6->first.ss_family == 0)
		{
			delete Parameter.LocalhostSubnet_IPv6;
			Parameter.LocalhostSubnet_IPv6 = nullptr;
		}
		if (Parameter.LocalhostSubnet_IPv4->first.ss_family == 0)
		{
			delete Parameter.LocalhostSubnet_IPv4;
			Parameter.LocalhostSubnet_IPv4 = nullptr;
		}

	//IPv6 multiple list
		if (!Parameter.Target_Server_IPv6_Multi->empty())
		{
			Parameter.AlternateMultiRequest = true;

		//Copy DNS Server Data when Main or Alternate data are empty.
			if (Parameter.Target_Server_IPv6.AddressData.Storage.ss_family == 0)
			{
			#if defined(ENABLE_PCAP)
				uint8_t HopLimitTemp = 0;
				if (Parameter.Target_Server_IPv6.HopLimitData.HopLimit > 0)
					HopLimitTemp = Parameter.Target_Server_IPv6.HopLimitData.HopLimit;
			#endif
				Parameter.Target_Server_IPv6 = Parameter.Target_Server_IPv6_Multi->front();
			#if defined(ENABLE_PCAP)
				Parameter.Target_Server_IPv6.HopLimitData.HopLimit = HopLimitTemp;
			#endif
				Parameter.Target_Server_IPv6_Multi->erase(Parameter.Target_Server_IPv6_Multi->begin());
			}

			if (Parameter.Target_Server_Alternate_IPv6.AddressData.Storage.ss_family == 0 && !Parameter.Target_Server_IPv6_Multi->empty())
			{
			#if defined(ENABLE_PCAP)
				uint8_t HopLimitTemp = 0;
				if (Parameter.Target_Server_Alternate_IPv6.HopLimitData.HopLimit > 0)
					HopLimitTemp = Parameter.Target_Server_Alternate_IPv6.HopLimitData.HopLimit;
			#endif
				Parameter.Target_Server_Alternate_IPv6 = Parameter.Target_Server_IPv6_Multi->front();
			#if defined(ENABLE_PCAP)
				Parameter.Target_Server_Alternate_IPv6.HopLimitData.HopLimit = HopLimitTemp;
			#endif
				Parameter.Target_Server_IPv6_Multi->erase(Parameter.Target_Server_IPv6_Multi->begin());
			}

		//Multi DNS Server check
			if (Parameter.Target_Server_IPv6_Multi->empty())
			{
				delete Parameter.Target_Server_IPv6_Multi;
				Parameter.Target_Server_IPv6_Multi = nullptr;
			}
		}
		else {
			delete Parameter.Target_Server_IPv6_Multi;
			Parameter.Target_Server_IPv6_Multi = nullptr;
		}

	//IPv4 multiple list
		if (!Parameter.Target_Server_IPv4_Multi->empty())
		{
			Parameter.AlternateMultiRequest = true;

		//Copy DNS Server Data when Main or Alternate data are empty.
			if (Parameter.Target_Server_IPv4.AddressData.Storage.ss_family == 0)
			{
			#if defined(ENABLE_PCAP)
				uint8_t TTLTemp = 0;
				if (Parameter.Target_Server_IPv4.HopLimitData.TTL > 0)
					TTLTemp = Parameter.Target_Server_IPv4.HopLimitData.TTL;
			#endif
				Parameter.Target_Server_IPv4 = Parameter.Target_Server_IPv4_Multi->front();
			#if defined(ENABLE_PCAP)
				Parameter.Target_Server_IPv4.HopLimitData.TTL = TTLTemp;
			#endif
				Parameter.Target_Server_IPv4_Multi->erase(Parameter.Target_Server_IPv4_Multi->begin());
			}

			if (Parameter.Target_Server_Alternate_IPv4.AddressData.Storage.ss_family == 0 && !Parameter.Target_Server_IPv4_Multi->empty())
			{
			#if defined(ENABLE_PCAP)
				uint8_t TTLTemp = 0;
				if (Parameter.Target_Server_Alternate_IPv4.HopLimitData.TTL > 0)
					TTLTemp = Parameter.Target_Server_Alternate_IPv4.HopLimitData.TTL;
			#endif
				Parameter.Target_Server_Alternate_IPv4 = Parameter.Target_Server_IPv4_Multi->front();
			#if defined(ENABLE_PCAP)
				Parameter.Target_Server_Alternate_IPv4.HopLimitData.TTL = TTLTemp;
			#endif
				Parameter.Target_Server_IPv4_Multi->erase(Parameter.Target_Server_IPv4_Multi->begin());
			}

		//Multi DNS Server check
			if (Parameter.Target_Server_IPv4_Multi->empty())
			{
				delete Parameter.Target_Server_IPv4_Multi;
				Parameter.Target_Server_IPv4_Multi = nullptr;
			}
		}
		else {
			delete Parameter.Target_Server_IPv4_Multi;
			Parameter.Target_Server_IPv4_Multi = nullptr;
		}

	//IPv6
		if (Parameter.Target_Server_IPv6.AddressData.Storage.ss_family == 0 && Parameter.Target_Server_Alternate_IPv6.AddressData.Storage.ss_family > 0)
		{
			Parameter.Target_Server_IPv6 = Parameter.Target_Server_Alternate_IPv6;
			memset(&Parameter.Target_Server_Alternate_IPv6, 0, sizeof(Parameter.Target_Server_Alternate_IPv6));
		}
	//IPv4
		if (Parameter.Target_Server_IPv4.AddressData.Storage.ss_family == 0 && Parameter.Target_Server_Alternate_IPv4.AddressData.Storage.ss_family > 0)
		{
			Parameter.Target_Server_IPv4 = Parameter.Target_Server_Alternate_IPv4;
			memset(&Parameter.Target_Server_Alternate_IPv4, 0, sizeof(Parameter.Target_Server_Alternate_IPv4));
		}
	//IPv6 Local
		if (Parameter.Target_Server_Local_IPv6.Storage.ss_family == 0 && Parameter.Target_Server_Alternate_Local_IPv6.Storage.ss_family > 0)
		{
			Parameter.Target_Server_Local_IPv6 = Parameter.Target_Server_Alternate_Local_IPv6;
			memset(&Parameter.Target_Server_Alternate_Local_IPv6, 0, sizeof(Parameter.Target_Server_Alternate_Local_IPv6));
		}
	//IPv4 Local
		if (Parameter.Target_Server_Local_IPv4.Storage.ss_family == 0 && Parameter.Target_Server_Alternate_Local_IPv4.Storage.ss_family > 0)
		{
			Parameter.Target_Server_Local_IPv4 = Parameter.Target_Server_Alternate_Local_IPv4;
			memset(&Parameter.Target_Server_Alternate_Local_IPv4, 0, sizeof(Parameter.Target_Server_Alternate_Local_IPv4));
		}
	//Check repeating items.
		if ((Parameter.Target_Server_IPv4.AddressData.Storage.ss_family == 0 && Parameter.Target_Server_IPv6.AddressData.Storage.ss_family == 0) || 
			(Parameter.Target_Server_IPv4.AddressData.Storage.ss_family > 0 && Parameter.Target_Server_Alternate_IPv4.AddressData.Storage.ss_family > 0 && 
			Parameter.Target_Server_IPv4.AddressData.IPv4.sin_addr.s_addr == Parameter.Target_Server_Alternate_IPv4.AddressData.IPv4.sin_addr.s_addr && 
			Parameter.Target_Server_IPv4.AddressData.IPv4.sin_port == Parameter.Target_Server_Alternate_IPv4.AddressData.IPv4.sin_port) || 
			(Parameter.Target_Server_Local_IPv4.Storage.ss_family > 0 && Parameter.Target_Server_Alternate_Local_IPv4.Storage.ss_family > 0 && 
			Parameter.Target_Server_Local_IPv4.IPv4.sin_addr.s_addr == Parameter.Target_Server_Alternate_Local_IPv4.IPv4.sin_addr.s_addr && 
			Parameter.Target_Server_Local_IPv4.IPv4.sin_port == Parameter.Target_Server_Alternate_Local_IPv4.IPv4.sin_port) || 
			(Parameter.Target_Server_IPv6.AddressData.Storage.ss_family > 0 && Parameter.Target_Server_Alternate_IPv6.AddressData.Storage.ss_family > 0 && 
			memcmp(&Parameter.Target_Server_IPv6.AddressData.IPv6.sin6_addr, &Parameter.Target_Server_Alternate_IPv6.AddressData.IPv6.sin6_addr, sizeof(Parameter.Target_Server_IPv6.AddressData.IPv6.sin6_addr)) == 0 && 
			Parameter.Target_Server_IPv6.AddressData.IPv6.sin6_port == Parameter.Target_Server_Alternate_IPv6.AddressData.IPv6.sin6_port) || 
			(Parameter.Target_Server_Local_IPv6.Storage.ss_family > 0 && Parameter.Target_Server_Alternate_Local_IPv6.Storage.ss_family > 0 && 
			memcmp(&Parameter.Target_Server_Local_IPv6.IPv6.sin6_addr, &Parameter.Target_Server_Alternate_Local_IPv6.IPv6.sin6_addr, sizeof(Parameter.Target_Server_Local_IPv6.IPv6.sin6_addr)) == 0 && 
			Parameter.Target_Server_Local_IPv6.IPv6.sin6_port == Parameter.Target_Server_Alternate_Local_IPv6.IPv6.sin6_port))
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"DNS target error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
			return false;
		}
	}

//Hop Limit or TTL Fluctuations check
#if defined(ENABLE_PCAP)
	if (ParameterPTR->HopLimitFluctuation > 0)
	{
		if (
		//IPv6
			(ParameterPTR->Target_Server_IPv6.HopLimitData.HopLimit > 0 && 
			((size_t)ParameterPTR->Target_Server_IPv6.HopLimitData.HopLimit + (size_t)ParameterPTR->HopLimitFluctuation > UINT8_MAX || 
			(ssize_t)ParameterPTR->Target_Server_IPv6.HopLimitData.HopLimit < (ssize_t)ParameterPTR->HopLimitFluctuation + 1)) || 
			(ParameterPTR->Target_Server_Alternate_IPv6.HopLimitData.HopLimit > 0 && 
			((size_t)ParameterPTR->Target_Server_Alternate_IPv6.HopLimitData.HopLimit + (size_t)ParameterPTR->HopLimitFluctuation > UINT8_MAX || 
			(ssize_t)ParameterPTR->Target_Server_Alternate_IPv6.HopLimitData.HopLimit < (ssize_t)ParameterPTR->HopLimitFluctuation + 1)) || 
		//IPv4
			(ParameterPTR->Target_Server_IPv4.HopLimitData.TTL > 0 && 
			((size_t)ParameterPTR->Target_Server_IPv4.HopLimitData.TTL + (size_t)ParameterPTR->HopLimitFluctuation > UINT8_MAX || 
			(ssize_t)ParameterPTR->Target_Server_IPv4.HopLimitData.TTL < (ssize_t)ParameterPTR->HopLimitFluctuation + 1)) || 
			(ParameterPTR->Target_Server_Alternate_IPv4.HopLimitData.TTL > 0 && 
			((size_t)ParameterPTR->Target_Server_Alternate_IPv4.HopLimitData.TTL + (size_t)ParameterPTR->HopLimitFluctuation > UINT8_MAX || 
			(ssize_t)ParameterPTR->Target_Server_Alternate_IPv4.HopLimitData.TTL < (ssize_t)ParameterPTR->HopLimitFluctuation + 1)))
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"Hop Limit Fluctuations error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0); //Hop Limit and TTL must between 1 and 255.
			return false;
		}
	}
#endif

//[DNS] block part 2
//Direct Request check
	if ((ParameterPTR->DirectRequest == DIRECT_REQUEST_MODE_IPV6 && Parameter.Target_Server_IPv6.AddressData.Storage.ss_family == 0) || 
		(ParameterPTR->DirectRequest == DIRECT_REQUEST_MODE_IPV4 && Parameter.Target_Server_IPv4.AddressData.Storage.ss_family == 0))
	{
		PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"Direct Request error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
		return false;
	}

	if (IsFirstRead)
	{
	//[Values] block
	//EDNS Payload Size check
		if (Parameter.EDNSPayloadSize < DNS_PACKET_MAXSIZE_TRADITIONAL)
		{
			if (Parameter.EDNSPayloadSize > 0)
				PrintError(LOG_LEVEL_3, LOG_MESSAGE_NOTICE, L"EDNS Payload Size must longer than traditional DNS packet minimum supported size(512 bytes)", 0, nullptr, 0);
			Parameter.EDNSPayloadSize = EDNS_PACKET_MINSIZE;
		}
		else if (Parameter.EDNSPayloadSize >= PACKET_MAXSIZE - sizeof(ipv6_hdr) - sizeof(udp_hdr))
		{
			PrintError(LOG_LEVEL_3, LOG_MESSAGE_NOTICE, L"EDNS Payload Size is too long", 0, nullptr, 0);
			Parameter.EDNSPayloadSize = EDNS_PACKET_MINSIZE;
		}
	}

	//Multi Request Times check
	if (ParameterPTR->MultiRequestTimes < 1U)
		++ParameterPTR->MultiRequestTimes;
	if ((Parameter.Target_Server_IPv4_Multi != nullptr && (Parameter.Target_Server_IPv4_Multi->size() + 2U) * ParameterPTR->MultiRequestTimes > MULTI_REQUEST_MAXNUM) || 
		(Parameter.Target_Server_IPv4_Multi == nullptr && ParameterPTR->MultiRequestTimes * 2U > MULTI_REQUEST_MAXNUM))
	{
		PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"IPv4 total request number error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
		return false;
	}
	if ((Parameter.Target_Server_IPv6_Multi != nullptr && (Parameter.Target_Server_IPv6_Multi->size() + 2U) * ParameterPTR->MultiRequestTimes > MULTI_REQUEST_MAXNUM) || 
		(Parameter.Target_Server_IPv6_Multi == nullptr && ParameterPTR->MultiRequestTimes * 2U > MULTI_REQUEST_MAXNUM))
	{
		PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"IPv6 total request number error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
		return false;
	}

//[Values] block
	if (IsFirstRead)
	{
	//Thread pool check
		if (Parameter.ThreadPoolMaxNum < Parameter.ThreadPoolBaseNum)
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"Thread pool number error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
			return false;
		}
	}

//[Switches] block
#if defined(ENABLE_PCAP)
	if (ParameterPTR->HeaderCheck_TCP) //TCP Mode option check
	{
		if (!Parameter.PcapCapture)
			PrintError(LOG_LEVEL_3, LOG_MESSAGE_NOTICE, L"TCP Data Filter require Pcap Cpature", 0, nullptr, 0);

		ParameterPTR->HeaderCheck_TCP = false;
	}
	if (ParameterPTR->HeaderCheck_IPv4) //IPv4 Data Filter option check
	{
		if (Parameter.Target_Server_IPv4.AddressData.Storage.ss_family == 0)
			PrintError(LOG_LEVEL_3, LOG_MESSAGE_NOTICE, L"IPv4 Data Filter require IPv4 DNS server", 0, nullptr, 0);
		if (!Parameter.PcapCapture)
			PrintError(LOG_LEVEL_3, LOG_MESSAGE_NOTICE, L"IPv4 Data Filter require Pcap Cpature", 0, nullptr, 0);

		ParameterPTR->HeaderCheck_IPv4 = false;
	}
#endif

	if (IsFirstRead)
	{
	//Alternate Multi request check
		if (Parameter.AlternateMultiRequest && 
			Parameter.Target_Server_Alternate_IPv4.AddressData.Storage.ss_family == 0 && Parameter.Target_Server_Alternate_IPv6.AddressData.Storage.ss_family == 0 && 
			Parameter.Target_Server_Alternate_Local_IPv4.Storage.ss_family == 0 && Parameter.Target_Server_Alternate_Local_IPv6.Storage.ss_family == 0
		#if defined(ENABLE_LIBSODIUM)
			&& Parameter.DNSCurve && DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.AddressData.Storage.ss_family == 0 && DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.AddressData.Storage.ss_family == 0
		#endif
			)
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"Alternate Multi request error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
			return false;
		}
	}

//[Proxy] block
//SOCKS Proxy check
	if (Parameter.SOCKS_Proxy)
	{
		if (IsFirstRead)
		{
		//SOCKS IPv4/IPv6 address check
			if (Parameter.SOCKS_Address_IPv6.Storage.ss_family == 0 && Parameter.SOCKS_Address_IPv4.Storage.ss_family == 0)
			{
				PrintError(LOG_LEVEL_1, LOG_ERROR_SOCKS, L"SOCKS address error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
				return false;
			}
			else if ((Parameter.SOCKS_Address_IPv6.Storage.ss_family == 0 && Parameter.SOCKS_Protocol_Network == REQUEST_MODE_IPV6) || 
				(Parameter.SOCKS_Address_IPv4.Storage.ss_family == 0 && Parameter.SOCKS_Protocol_Network == REQUEST_MODE_IPV4))
			{
				Parameter.SOCKS_Protocol_Network = REQUEST_MODE_NETWORK_BOTH;
			}

		//Only SOCKS version 5 support client authentication.
			if (Parameter.SOCKS_Version != SOCKS_VERSION_5)
			{
				delete Parameter.SOCKS_Password;
				Parameter.SOCKS_Password = nullptr;
			}

		//SOCKS UDP support check
			if (Parameter.SOCKS_Protocol_Transport == REQUEST_MODE_UDP && (Parameter.SOCKS_Version == SOCKS_VERSION_4 || Parameter.SOCKS_Version == SOCKS_VERSION_CONFIG_4A))
			{
				PrintError(LOG_LEVEL_1, LOG_ERROR_SOCKS, L"SOCKS version 4 and 4a are not support UDP relay", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
				Parameter.SOCKS_Protocol_Transport = REQUEST_MODE_TCP;
			}

		//SOCKS UDP no handshake check
			if (Parameter.SOCKS_Protocol_Transport != REQUEST_MODE_UDP)
				Parameter.SOCKS_UDP_NoHandshake = false;
		}

	//SOCKS Target Server check
		if (ParameterPTR->SOCKS_TargetServer.Storage.ss_family == 0 && ParameterPTR->SOCKS_TargetDomain->empty())
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_SOCKS, L"SOCKS target server error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
			return false;
		}

	//SOCKS IPv6 support check
		if (ParameterPTR->SOCKS_TargetServer.Storage.ss_family != AF_INET && 
			(Parameter.SOCKS_Version == SOCKS_VERSION_4 || (Parameter.SOCKS_Version == SOCKS_VERSION_CONFIG_4A && ParameterPTR->SOCKS_TargetDomain->empty())))
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_SOCKS, L"SOCKS version 4 and 4a are not support IPv6 target server", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
			return false;
		}

	//SOCKS domain support check
		if (!ParameterPTR->SOCKS_TargetDomain->empty() && Parameter.SOCKS_Version == SOCKS_VERSION_4)
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_SOCKS, L"SOCKS version 4 is not support domain target server", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
			return false;
		}

	//SOCKS Username and password check
		if (Parameter.SOCKS_Version == SOCKS_VERSION_5 && Parameter.SOCKS_Username->empty() && !Parameter.SOCKS_Password->empty())
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_SOCKS, L"SOCKS username and password error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
			return false;
		}
	}
	else {
		delete Parameter.SOCKS_TargetDomain;
		delete Parameter.SOCKS_Username;
		delete Parameter.SOCKS_Password;

		Parameter.SOCKS_TargetDomain = nullptr;
		Parameter.SOCKS_Username = nullptr;
		Parameter.SOCKS_Password = nullptr;
	}

//HTTP Proxy check
	if (Parameter.HTTP_Proxy)
	{
		if (IsFirstRead)
		{
		//HTTP IPv4/IPv6 address check
			if (Parameter.HTTP_Address_IPv6.Storage.ss_family == 0 && Parameter.HTTP_Address_IPv4.Storage.ss_family == 0)
			{
				PrintError(LOG_LEVEL_1, LOG_ERROR_HTTP, L"HTTP address error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
				return false;
			}
			else if ((Parameter.HTTP_Address_IPv6.Storage.ss_family == 0 && Parameter.HTTP_Protocol == REQUEST_MODE_IPV6) || 
				(Parameter.HTTP_Address_IPv4.Storage.ss_family == 0 && Parameter.HTTP_Protocol == REQUEST_MODE_IPV4))
			{
				Parameter.HTTP_Protocol = REQUEST_MODE_NETWORK_BOTH;
			}
		}

	//SOCKS Target Server check
		if (ParameterPTR->HTTP_TargetDomain->empty())
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_HTTP, L"HTTP target server error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
			return false;
		}

	//HTTP version check
		if (ParameterPTR->HTTP_Version->empty())
			ParameterPTR->HTTP_Version->append(DEFAULT_HTTP_VERSION);
	}
	else {
		delete Parameter.HTTP_TargetDomain;
		delete Parameter.HTTP_Version;
		delete Parameter.HTTP_HeaderField;
		delete Parameter.HTTP_ProxyAuthorization;

		Parameter.HTTP_TargetDomain = nullptr;
		Parameter.HTTP_Version = nullptr;
		Parameter.HTTP_HeaderField = nullptr;
		Parameter.HTTP_ProxyAuthorization = nullptr;
	}

//[DNSCurve] block
#if defined(ENABLE_LIBSODIUM)
	if (Parameter.DNSCurve)
	{
	//Client keys check
		if (DNSCurveParameter.IsEncryption && !DNSCurveParameter.ClientEphemeralKey && 
			DNSCurveParameterPTR->Client_PublicKey != nullptr && DNSCurveParameterPTR->Client_SecretKey != nullptr)
		{
			if (!CheckEmptyBuffer(DNSCurveParameterPTR->Client_PublicKey, crypto_box_PUBLICKEYBYTES) && 
				!CheckEmptyBuffer(DNSCurveParameterPTR->Client_SecretKey, crypto_box_SECRETKEYBYTES))
			{
				if (!DNSCurveVerifyKeypair(DNSCurveParameterPTR->Client_PublicKey, DNSCurveParameterPTR->Client_SecretKey))
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_DNSCURVE, L"Client keypair error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);

					sodium_memzero(DNSCurveParameterPTR->Client_PublicKey, crypto_box_PUBLICKEYBYTES);
					sodium_memzero(DNSCurveParameterPTR->Client_SecretKey, crypto_box_SECRETKEYBYTES);
					crypto_box_keypair(DNSCurveParameterPTR->Client_PublicKey, DNSCurveParameterPTR->Client_SecretKey);
				}
			}
			else {
				sodium_memzero(DNSCurveParameterPTR->Client_PublicKey, crypto_box_PUBLICKEYBYTES);
				sodium_memzero(DNSCurveParameterPTR->Client_SecretKey, crypto_box_SECRETKEYBYTES);
				crypto_box_keypair(DNSCurveParameterPTR->Client_PublicKey, DNSCurveParameterPTR->Client_SecretKey);
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
		//DNSCurve targets check
			if (DNSCurveParameter.DNSCurve_Target_Server_IPv6.AddressData.Storage.ss_family == 0 && DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.AddressData.Storage.ss_family > 0)
			{
				DNSCurveParameter.DNSCurve_Target_Server_IPv6 = DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6;
				sodium_memzero(&DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6, sizeof(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6));
			}
			if (DNSCurveParameter.DNSCurve_Target_Server_IPv4.AddressData.Storage.ss_family == 0 && DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.AddressData.Storage.ss_family > 0)
			{
				DNSCurveParameter.DNSCurve_Target_Server_IPv4 = DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4;
				sodium_memzero(&DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4, sizeof(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4));
			}

			if ((DNSCurveParameter.DNSCurve_Target_Server_IPv4.AddressData.Storage.ss_family == 0 && 
				DNSCurveParameter.DNSCurve_Target_Server_IPv6.AddressData.Storage.ss_family == 0) || 
			//Check repeating items.
				(DNSCurveParameter.DNSCurve_Target_Server_IPv4.AddressData.Storage.ss_family > 0 && 
				DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.AddressData.Storage.ss_family > 0 && 
				DNSCurveParameter.DNSCurve_Target_Server_IPv4.AddressData.IPv4.sin_addr.s_addr == DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.AddressData.IPv4.sin_addr.s_addr) || 
				(DNSCurveParameter.DNSCurve_Target_Server_IPv6.AddressData.Storage.ss_family > 0 && 
				DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.AddressData.Storage.ss_family > 0 && 
				memcmp(&DNSCurveParameter.DNSCurve_Target_Server_IPv6.AddressData.IPv6.sin6_addr, &DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.AddressData.IPv6.sin6_addr, sizeof(DNSCurveParameter.DNSCurve_Target_Server_IPv6.AddressData.IPv6.sin6_addr)) == 0))
			{
				PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"DNSCurve target error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
				return false;
			}

		//Eencryption options check
			if (DNSCurveParameter.IsEncryptionOnly && !DNSCurveParameter.IsEncryption)
			{
				DNSCurveParameter.IsEncryption = true;
				PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"DNSCurve encryption options error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
			}
		}

	//Main(IPv6)
		if (DNSCurveParameter.IsEncryption && DNSCurveParameter.DNSCurve_Target_Server_IPv6.AddressData.Storage.ss_family > 0)
		{
		//Empty Server Fingerprint
			if (CheckEmptyBuffer(DNSCurveParameterPTR->DNSCurve_Target_Server_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES))
			{
			//Encryption Only mode check
				if (DNSCurveParameter.IsEncryptionOnly && 
					CheckEmptyBuffer(DNSCurveParameterPTR->DNSCurve_Target_Server_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"DNSCurve Encryption Only mode error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					return false;
				}

			//Empty Provider Name
				if (CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_IPv6.ProviderName, DOMAIN_MAXSIZE))
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"DNSCurve empty Provider Name error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					return false;
				}

			//Empty Public Key
				if (CheckEmptyBuffer(DNSCurveParameterPTR->DNSCurve_Target_Server_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES))
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"DNSCurve empty Public Key error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					return false;
				}
			}
			else if (!DNSCurveParameter.ClientEphemeralKey)
			{
				if (crypto_box_beforenm(
						DNSCurveParameterPTR->DNSCurve_Target_Server_IPv6.PrecomputationKey, 
						DNSCurveParameterPTR->DNSCurve_Target_Server_IPv6.ServerFingerprint, 
						DNSCurveParameterPTR->Client_SecretKey) == LIBSODIUM_ERROR)
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_DNSCURVE, L"Key calculating error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					return false;
				}
			}
		}
		else if (IsFirstRead)
		{
			delete[] DNSCurveParameter.DNSCurve_Target_Server_IPv6.ProviderName;
			sodium_free(DNSCurveParameter.DNSCurve_Target_Server_IPv6.PrecomputationKey);
			delete[] DNSCurveParameter.DNSCurve_Target_Server_IPv6.ServerPublicKey;
			delete[] DNSCurveParameter.DNSCurve_Target_Server_IPv6.ReceiveMagicNumber;
			delete[] DNSCurveParameter.DNSCurve_Target_Server_IPv6.SendMagicNumber;

			DNSCurveParameter.DNSCurve_Target_Server_IPv6.ProviderName = nullptr;
			DNSCurveParameter.DNSCurve_Target_Server_IPv6.PrecomputationKey = nullptr;
			DNSCurveParameter.DNSCurve_Target_Server_IPv6.ServerPublicKey = nullptr;
			DNSCurveParameter.DNSCurve_Target_Server_IPv6.ReceiveMagicNumber = nullptr;
			DNSCurveParameter.DNSCurve_Target_Server_IPv6.SendMagicNumber = nullptr;
		}

	//Main(IPv4)
		if (DNSCurveParameter.IsEncryption && DNSCurveParameter.DNSCurve_Target_Server_IPv4.AddressData.Storage.ss_family > 0)
		{
		//Empty Server Fingerprint
			if (CheckEmptyBuffer(DNSCurveParameterPTR->DNSCurve_Target_Server_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES))
			{
			//Encryption Only mode check
				if (DNSCurveParameter.IsEncryptionOnly && 
					CheckEmptyBuffer(DNSCurveParameterPTR->DNSCurve_Target_Server_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"DNSCurve Encryption Only mode error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					return false;
				}

			//Empty Provider Name
				if (CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_IPv4.ProviderName, DOMAIN_MAXSIZE))
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"DNSCurve empty Provider Name error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					return false;
				}

			//Empty Public Key
				if (CheckEmptyBuffer(DNSCurveParameterPTR->DNSCurve_Target_Server_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES))
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"DNSCurve empty Public Key error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					return false;
				}
			}
			else if (!DNSCurveParameter.ClientEphemeralKey)
			{
				if (crypto_box_beforenm(
						DNSCurveParameterPTR->DNSCurve_Target_Server_IPv4.PrecomputationKey, 
						DNSCurveParameterPTR->DNSCurve_Target_Server_IPv4.ServerFingerprint, 
						DNSCurveParameterPTR->Client_SecretKey) == LIBSODIUM_ERROR)
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_DNSCURVE, L"Key calculating error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					return false;
				}
			}
		}
		else if (IsFirstRead)
		{
			delete[] DNSCurveParameter.DNSCurve_Target_Server_IPv4.ProviderName;
			sodium_free(DNSCurveParameter.DNSCurve_Target_Server_IPv4.PrecomputationKey);
			delete[] DNSCurveParameter.DNSCurve_Target_Server_IPv4.ServerPublicKey;
			delete[] DNSCurveParameter.DNSCurve_Target_Server_IPv4.ReceiveMagicNumber;
			delete[] DNSCurveParameter.DNSCurve_Target_Server_IPv4.SendMagicNumber;

			DNSCurveParameter.DNSCurve_Target_Server_IPv4.ProviderName = nullptr;
			DNSCurveParameter.DNSCurve_Target_Server_IPv4.PrecomputationKey = nullptr;
			DNSCurveParameter.DNSCurve_Target_Server_IPv4.ServerPublicKey = nullptr;
			DNSCurveParameter.DNSCurve_Target_Server_IPv4.ReceiveMagicNumber = nullptr;
			DNSCurveParameter.DNSCurve_Target_Server_IPv4.SendMagicNumber = nullptr;
		}

	//Alternate(IPv6)
		if (DNSCurveParameter.IsEncryption && DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.AddressData.Storage.ss_family > 0)
		{
		//Empty Server Fingerprint
			if (CheckEmptyBuffer(DNSCurveParameterPTR->DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES))
			{
			//Encryption Only mode check
				if (DNSCurveParameter.IsEncryptionOnly && 
					CheckEmptyBuffer(DNSCurveParameterPTR->DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"DNSCurve Encryption Only mode error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					return false;
				}

			//Empty Provider Name
				if (CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ProviderName, DOMAIN_MAXSIZE))
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"DNSCurve empty Provider Name error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					return false;
				}

			//Empty Public Key
				if (CheckEmptyBuffer(DNSCurveParameterPTR->DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES))
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"DNSCurve empty Public Key error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					return false;
				}
			}
			else if (!DNSCurveParameter.ClientEphemeralKey)
			{
				if (crypto_box_beforenm(
						DNSCurveParameterPTR->DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey, 
						DNSCurveParameterPTR->DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint, 
						DNSCurveParameterPTR->Client_SecretKey) == LIBSODIUM_ERROR)
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_DNSCURVE, L"Key calculating error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					return false;
				}
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
		if (DNSCurveParameter.IsEncryption && DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.AddressData.Storage.ss_family > 0)
		{
		//Empty Server Fingerprint
			if (CheckEmptyBuffer(DNSCurveParameterPTR->DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES))
			{
			//Encryption Only mode check
				if (DNSCurveParameter.IsEncryptionOnly && 
					CheckEmptyBuffer(DNSCurveParameterPTR->DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"DNSCurve Encryption Only mode error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					return false;
				}

			//Empty Provider Name
				if (CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ProviderName, DOMAIN_MAXSIZE))
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"DNSCurve empty Provider Name error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					return false;
				}

			//Empty Public Key
				if (CheckEmptyBuffer(DNSCurveParameterPTR->DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES))
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"DNSCurve empty Public Key error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					return false;
				}
			}
			else if (!DNSCurveParameter.ClientEphemeralKey)
			{
				if (crypto_box_beforenm(
						DNSCurveParameterPTR->DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey, 
						DNSCurveParameterPTR->DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint, 
						DNSCurveParameterPTR->Client_SecretKey) == LIBSODIUM_ERROR)
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_DNSCURVE, L"Key calculating error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
					return false;
				}
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
	}
	else if (IsFirstRead)
	{
		delete[] DNSCurveParameter.DNSCurve_Target_Server_IPv4.ProviderName;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ProviderName;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_IPv6.ProviderName;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ProviderName;
	//DNSCurve Keys
		delete[] DNSCurveParameter.Client_PublicKey;
		sodium_free(DNSCurveParameter.Client_SecretKey);
		sodium_free(DNSCurveParameter.DNSCurve_Target_Server_IPv4.PrecomputationKey);
		sodium_free(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey);
		sodium_free(DNSCurveParameter.DNSCurve_Target_Server_IPv6.PrecomputationKey);
		sodium_free(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey);
		delete[] DNSCurveParameter.DNSCurve_Target_Server_IPv4.ServerPublicKey;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_IPv6.ServerPublicKey;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_IPv4.ServerFingerprint;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_IPv6.ServerFingerprint;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint;
	//DNSCurve Magic Numbers
		delete[] DNSCurveParameter.DNSCurve_Target_Server_IPv4.ReceiveMagicNumber;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_IPv6.ReceiveMagicNumber;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_IPv4.SendMagicNumber;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_IPv6.SendMagicNumber;
		delete[] DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber;

		DNSCurveParameter.DNSCurve_Target_Server_IPv4.ProviderName = nullptr, DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ProviderName = nullptr, DNSCurveParameter.DNSCurve_Target_Server_IPv6.ProviderName = nullptr, DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ProviderName = nullptr;
		DNSCurveParameter.Client_PublicKey = nullptr, DNSCurveParameter.Client_SecretKey = nullptr;
		DNSCurveParameter.DNSCurve_Target_Server_IPv4.PrecomputationKey = nullptr, DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey = nullptr, DNSCurveParameter.DNSCurve_Target_Server_IPv6.PrecomputationKey = nullptr, DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey = nullptr;
		DNSCurveParameter.DNSCurve_Target_Server_IPv4.ServerPublicKey = nullptr, DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey = nullptr, DNSCurveParameter.DNSCurve_Target_Server_IPv6.ServerPublicKey = nullptr, DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey = nullptr;
		DNSCurveParameter.DNSCurve_Target_Server_IPv4.ServerFingerprint = nullptr, DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint = nullptr, DNSCurveParameter.DNSCurve_Target_Server_IPv6.ServerFingerprint = nullptr, DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint = nullptr;
		DNSCurveParameter.DNSCurve_Target_Server_IPv4.SendMagicNumber = nullptr, DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber = nullptr, DNSCurveParameter.DNSCurve_Target_Server_IPv6.SendMagicNumber = nullptr, DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber = nullptr;
		DNSCurveParameter.DNSCurve_Target_Server_IPv4.ReceiveMagicNumber = nullptr, DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber = nullptr, DNSCurveParameter.DNSCurve_Target_Server_IPv6.ReceiveMagicNumber = nullptr, DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber = nullptr;
	}
#endif

//Default settings
	if (IsFirstRead)
	{
	//[Listen] block
	//Listen Port
		if (Parameter.ListenPort->empty())
		{
			PrintError(LOG_LEVEL_3, LOG_MESSAGE_NOTICE, L"Listen Port is empty, set to standard DNS port(53)", 0, nullptr, 0);
			Parameter.ListenPort->push_back(htons(IPPORT_DNS));
		}

	//[DNS] block part 1
	//Protocol(IPv6)
		if (Parameter.Target_Server_IPv6.AddressData.Storage.ss_family == 0 && Parameter.RequestMode_Network == REQUEST_MODE_IPV6)
		{
			PrintError(LOG_LEVEL_3, LOG_MESSAGE_NOTICE, L"IPv6 Request Mode require IPv6 DNS server", 0, nullptr, 0);
			Parameter.RequestMode_Network = REQUEST_MODE_NETWORK_BOTH;
		}
	}

	//Local Protocol(IPv6)
	if (Parameter.Target_Server_Local_IPv6.Storage.ss_family == 0 && ParameterPTR->LocalProtocol_Network == REQUEST_MODE_IPV6)
	{
		PrintError(LOG_LEVEL_3, LOG_MESSAGE_NOTICE, L"IPv6 Request Mode require IPv6 DNS server", 0, nullptr, 0);
		ParameterPTR->LocalProtocol_Network = REQUEST_MODE_NETWORK_BOTH;
	}

	if (IsFirstRead)
	{
	//[DNSCurve] block
	//DNSCurve Protocol(IPv6)
	#if defined(ENABLE_LIBSODIUM)
		if (DNSCurveParameter.DNSCurve_Target_Server_IPv6.AddressData.Storage.ss_family == 0 && DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV6)
		{
			PrintError(LOG_LEVEL_3, LOG_MESSAGE_NOTICE, L"IPv6 Request Mode require IPv6 DNS server", 0, nullptr, 0);
			DNSCurveParameter.DNSCurveProtocol_Network = REQUEST_MODE_NETWORK_BOTH;
		}
	#endif

	//[DNS] block part 2
	//Protocol(IPv6)
		if (Parameter.Target_Server_IPv4.AddressData.Storage.ss_family == 0 && Parameter.RequestMode_Network == REQUEST_MODE_IPV4)
		{
			PrintError(LOG_LEVEL_3, LOG_MESSAGE_NOTICE, L"IPv4 Request Mode require IPv4 DNS server", 0, nullptr, 0);
			Parameter.RequestMode_Network = REQUEST_MODE_NETWORK_BOTH;
		}
	}

	//Local Protocol(IPv4)
	if (Parameter.Target_Server_Local_IPv4.Storage.ss_family == 0 && ParameterPTR->LocalProtocol_Network == REQUEST_MODE_IPV4)
	{
		PrintError(LOG_LEVEL_3, LOG_MESSAGE_NOTICE, L"IPv4 Request Mode require IPv4 DNS server", 0, nullptr, 0);
		ParameterPTR->LocalProtocol_Network = REQUEST_MODE_NETWORK_BOTH;
	}

	if (IsFirstRead)
	{
	//[DNSCurve] block
	//DNSCurve Protocol(IPv4)
	#if defined(ENABLE_LIBSODIUM)
		if (DNSCurveParameter.DNSCurve_Target_Server_IPv4.AddressData.Storage.ss_family == 0 && DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV4)
		{
			PrintError(LOG_LEVEL_3, LOG_MESSAGE_NOTICE, L"IPv4 Request Mode require IPv4 DNS server", 0, nullptr, 0);
			DNSCurveParameter.DNSCurveProtocol_Network = REQUEST_MODE_NETWORK_BOTH;
		}
	#endif

	//[Switches] block
	//EDNS Label
		if (Parameter.DNSSEC_ForceValidation && (!Parameter.EDNS_Label || !Parameter.DNSSEC_Request || !Parameter.DNSSEC_Validation))
		{
			PrintError(LOG_LEVEL_3, LOG_MESSAGE_NOTICE, L"DNSSEC Force Validation require EDNS Label, DNSSEC Request and DNSSEC Validation", 0, nullptr, 0);
			Parameter.EDNS_Label = true;
			Parameter.DNSSEC_Request = true;
			Parameter.DNSSEC_Validation = true;
		}

	//DNSSEC Validation
		if (Parameter.DNSSEC_Validation && (!Parameter.EDNS_Label || !Parameter.DNSSEC_Request))
		{
			PrintError(LOG_LEVEL_3, LOG_MESSAGE_NOTICE, L"DNSSEC Validation require EDNS Label and DNSSEC Request", 0, nullptr, 0);
			Parameter.EDNS_Label = true;
			Parameter.DNSSEC_Request = true;
		}

	//EDNS Client Subnet
		if (!Parameter.EDNS_Label)
		{
			if (Parameter.EDNS_ClientSubnet_Relay)
			{
				PrintError(LOG_LEVEL_3, LOG_MESSAGE_NOTICE, L"EDNS Client Subnet require EDNS Label", 0, nullptr, 0);
				Parameter.EDNS_Label = true;
			}
			if (Parameter.DNSSEC_Request)
			{
				PrintError(LOG_LEVEL_3, LOG_MESSAGE_NOTICE, L"DNSSEC Request require EDNS Label", 0, nullptr, 0);
				Parameter.EDNS_Label = true;
			}
		}
		else {
		//Compression Pointer Mutation
			if (Parameter.CompressionPointerMutation)
			{
				PrintError(LOG_LEVEL_3, LOG_MESSAGE_NOTICE, L"Compression Pointer Mutation require EDNS Label is OFF", 0, nullptr, 0);
				Parameter.CompressionPointerMutation = false;
			}
		}

	//[Data] block
	//Domain Test
	#if defined(ENABLE_PCAP)
		if (CheckEmptyBuffer(Parameter.DomainTest_Data, DOMAIN_MAXSIZE))
		{
			delete[] Parameter.DomainTest_Data;
			Parameter.DomainTest_Data = nullptr;
		}
	#endif

	//Default Local DNS server name
		if (Parameter.LocalFQDN_Length <= 0)
		{
			Parameter.LocalFQDN_Length = CharToDNSQuery((const uint8_t *)DEFAULT_LOCAL_SERVERNAME, Parameter.LocalFQDN_Response);
			*Parameter.LocalFQDN_String = DEFAULT_LOCAL_SERVERNAME;
		}

	//Set Local DNS server PTR response.
	//LLMNR protocol of Mac OS X powered by mDNS with PTR records
	#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
		if (Parameter.LocalServer_Length == 0)
		{
		//Make PTR response packet.
			((pdns_record_ptr)Parameter.LocalServer_Response)->PTR = htons(DNS_POINTER_QUERY);
			((pdns_record_ptr)Parameter.LocalServer_Response)->Classes = htons(DNS_CLASS_IN);
			((pdns_record_ptr)Parameter.LocalServer_Response)->TTL = htonl(Parameter.HostsDefaultTTL);
			((pdns_record_ptr)Parameter.LocalServer_Response)->Type = htons(DNS_RECORD_PTR);
			((pdns_record_ptr)Parameter.LocalServer_Response)->Length = htons((uint16_t)Parameter.LocalFQDN_Length);
			Parameter.LocalServer_Length += sizeof(dns_record_ptr);

		//Copy to global buffer.
			memcpy_s(Parameter.LocalServer_Response + Parameter.LocalServer_Length, DOMAIN_MAXSIZE + sizeof(dns_record_ptr) + sizeof(dns_record_opt) - Parameter.LocalServer_Length, Parameter.LocalFQDN_Response, Parameter.LocalFQDN_Length);
			Parameter.LocalServer_Length += Parameter.LocalFQDN_Length;
		}
	#endif
	}

//[DNSCurve] block
#if defined(ENABLE_LIBSODIUM)
	if (Parameter.DNSCurve && DNSCurveParameter.IsEncryption)
	{
		if (IsFirstRead)
		{
		//DNSCurve PayloadSize check
			if (DNSCurveParameter.DNSCurvePayloadSize < DNS_PACKET_MAXSIZE_TRADITIONAL)
			{
				if (DNSCurveParameter.DNSCurvePayloadSize > 0)
					PrintError(LOG_LEVEL_3, LOG_MESSAGE_NOTICE, L"DNSCurve Payload Size must longer than traditional DNS packet minimum supported size(512 bytes)", 0, nullptr, 0);
				DNSCurveParameter.DNSCurvePayloadSize = DNS_PACKET_MAXSIZE_TRADITIONAL;
			}
			else if (DNSCurveParameter.DNSCurvePayloadSize + DNSCRYPT_RESERVE_HEADER_LEN >= PACKET_MAXSIZE)
			{
				PrintError(LOG_LEVEL_3, LOG_MESSAGE_NOTICE, L"DNSCurve Payload Size is too long", 0, nullptr, 0);
				DNSCurveParameter.DNSCurvePayloadSize = EDNS_PACKET_MINSIZE;
			}
		}

	//Main(IPv6)
		if (DNSCurveParameter.DNSCurve_Target_Server_IPv6.AddressData.Storage.ss_family > 0 && 
			CheckEmptyBuffer(DNSCurveParameterPTR->DNSCurve_Target_Server_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				memcpy_s(DNSCurveParameterPTR->DNSCurve_Target_Server_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCRYPT_RECEIVE_MAGIC, DNSCURVE_MAGIC_QUERY_LEN);

	//Main(IPv4)
		if (DNSCurveParameter.DNSCurve_Target_Server_IPv4.AddressData.Storage.ss_family > 0 && 
			CheckEmptyBuffer(DNSCurveParameterPTR->DNSCurve_Target_Server_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				memcpy_s(DNSCurveParameterPTR->DNSCurve_Target_Server_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCRYPT_RECEIVE_MAGIC, DNSCURVE_MAGIC_QUERY_LEN);

	//Alternate(IPv6)
		if (DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.AddressData.Storage.ss_family > 0 && 
			CheckEmptyBuffer(DNSCurveParameterPTR->DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				memcpy_s(DNSCurveParameterPTR->DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCRYPT_RECEIVE_MAGIC, DNSCURVE_MAGIC_QUERY_LEN);

	//Alternate(IPv4)
		if (DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.AddressData.Storage.ss_family > 0 && 
			CheckEmptyBuffer(DNSCurveParameterPTR->DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				memcpy_s(DNSCurveParameterPTR->DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCRYPT_RECEIVE_MAGIC, DNSCURVE_MAGIC_QUERY_LEN);

	//DNSCurve keys recheck time
		if (DNSCurveParameterPTR->KeyRecheckTime == 0)
			DNSCurveParameterPTR->KeyRecheckTime = DEFAULT_DNSCURVE_RECHECK_TIME * SECOND_TO_MILLISECOND;
	}
#endif

//[Listen] block
//Sort AcceptTypeList.
	if (!ParameterPTR->AcceptTypeList->empty())
		std::sort(ParameterPTR->AcceptTypeList->begin(), ParameterPTR->AcceptTypeList->end());

	return true;
}

//Convert service name to port
uint16_t ServiceNameToBinary(
	const uint8_t *OriginalBuffer)
{
	std::string Buffer((const char *)OriginalBuffer);
	CaseConvert(true, Buffer);

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
	const uint8_t *OriginalBuffer)
{
	std::string Buffer((const char *)OriginalBuffer);
	CaseConvert(true, Buffer);

//DNS type name
	if (Buffer == ("A"))
		return htons(DNS_RECORD_A);
	else if (Buffer == ("NS"))
		return htons(DNS_RECORD_NS);
	else if (Buffer == ("MD"))
		return htons(DNS_RECORD_MD);
	else if (Buffer == ("MF"))
		return htons(DNS_RECORD_MF);
	else if (Buffer == ("CNAME"))
		return htons(DNS_RECORD_CNAME);
	else if (Buffer == ("SOA"))
		return htons(DNS_RECORD_SOA);
	else if (Buffer == ("MB"))
		return htons(DNS_RECORD_MB);
	else if (Buffer == ("MG"))
		return htons(DNS_RECORD_MG);
	else if (Buffer == ("MR"))
		return htons(DNS_RECORD_MR);
	else if (Buffer == ("PTR"))
		return htons(DNS_RECORD_PTR);
	else if (Buffer == ("NULL"))
		return htons(DNS_RECORD_NULL);
	else if (Buffer == ("WKS"))
		return htons(DNS_RECORD_WKS);
	else if (Buffer == ("HINFO"))
		return htons(DNS_RECORD_HINFO);
	else if (Buffer == ("MINFO"))
		return htons(DNS_RECORD_MINFO);
	else if (Buffer == ("MX"))
		return htons(DNS_RECORD_MX);
	else if (Buffer == ("TXT"))
		return htons(DNS_RECORD_TXT);
	else if (Buffer == ("RP"))
		return htons(DNS_RECORD_RP);
	else if (Buffer == ("SIG"))
		return htons(DNS_RECORD_SIG);
	else if (Buffer == ("AFSDB"))
		return htons(DNS_RECORD_AFSDB);
	else if (Buffer == ("X25"))
		return htons(DNS_RECORD_X25);
	else if (Buffer == ("ISDN"))
		return htons(DNS_RECORD_ISDN);
	else if (Buffer == ("RT"))
		return htons(DNS_RECORD_RT);
	else if (Buffer == ("NSAP"))
		return htons(DNS_RECORD_NSAP);
	else if (Buffer == ("NSAPPTR"))
		return htons(DNS_RECORD_NSAP_PTR);
	else if (Buffer == ("SIG"))
		return htons(DNS_RECORD_SIG);
	else if (Buffer == ("KEY"))
		return htons(DNS_RECORD_KEY);
	else if (Buffer == ("AAAA"))
		return htons(DNS_RECORD_AAAA);
	else if (Buffer == ("PX"))
		return htons(DNS_RECORD_PX);
	else if (Buffer == ("GPOS"))
		return htons(DNS_RECORD_GPOS);
	else if (Buffer == ("LOC"))
		return htons(DNS_RECORD_LOC);
	else if (Buffer == ("NXT"))
		return htons(DNS_RECORD_NXT);
	else if (Buffer == ("EID"))
		return htons(DNS_RECORD_EID);
	else if (Buffer == ("NIMLOC"))
		return htons(DNS_RECORD_NIMLOC);
	else if (Buffer == ("SRV"))
		return htons(DNS_RECORD_SRV);
	else if (Buffer == ("ATMA"))
		return htons(DNS_RECORD_ATMA);
	else if (Buffer == ("NAPTR"))
		return htons(DNS_RECORD_NAPTR);
	else if (Buffer == ("KX"))
		return htons(DNS_RECORD_KX);
	else if (Buffer == ("CERT"))
		return htons(DNS_RECORD_CERT);
	else if (Buffer == ("A6"))
		return htons(DNS_RECORD_A6);
	else if (Buffer == ("DNAME"))
		return htons(DNS_RECORD_DNAME);
	else if (Buffer == ("SINK"))
		return htons(DNS_RECORD_SINK);
	else if (Buffer == ("OPT"))
		return htons(DNS_RECORD_OPT);
	else if (Buffer == ("APL"))
		return htons(DNS_RECORD_APL);
	else if (Buffer == ("DS"))
		return htons(DNS_RECORD_DS);
	else if (Buffer == ("SSHFP"))
		return htons(DNS_RECORD_SSHFP);
	else if (Buffer == ("IPSECKEY"))
		return htons(DNS_RECORD_IPSECKEY);
	else if (Buffer == ("RRSIG"))
		return htons(DNS_RECORD_RRSIG);
	else if (Buffer == ("NSEC"))
		return htons(DNS_RECORD_NSEC);
	else if (Buffer == ("DNSKEY"))
		return htons(DNS_RECORD_DNSKEY);
	else if (Buffer == ("DHCID"))
		return htons(DNS_RECORD_DHCID);
	else if (Buffer == ("NSEC3"))
		return htons(DNS_RECORD_NSEC3);
	else if (Buffer == ("NSEC3PARAM"))
		return htons(DNS_RECORD_NSEC3PARAM);
	else if (Buffer == ("TLSA"))
		return htons(DNS_RECORD_TLSA);
	else if (Buffer == ("HIP"))
		return htons(DNS_RECORD_HIP);
	else if (Buffer == ("HINFO"))
		return htons(DNS_RECORD_HINFO);
	else if (Buffer == ("RKEY"))
		return htons(DNS_RECORD_RKEY);
	else if (Buffer == ("TALINK"))
		return htons(DNS_RECORD_TALINK);
	else if (Buffer == ("CDS"))
		return htons(DNS_RECORD_CDS);
	else if (Buffer == ("CDNSKEY"))
		return htons(DNS_RECORD_CDNSKEY);
	else if (Buffer == ("OPENPGPKEY"))
		return htons(DNS_RECORD_OPENPGPKEY);
	else if (Buffer == ("SPF"))
		return htons(DNS_RECORD_SPF);
	else if (Buffer == ("UINFO"))
		return htons(DNS_RECORD_UINFO);
	else if (Buffer == ("UID"))
		return htons(DNS_RECORD_UID);
	else if (Buffer == ("GID"))
		return htons(DNS_RECORD_GID);
	else if (Buffer == ("UNSPEC"))
		return htons(DNS_RECORD_UNSPEC);
	else if (Buffer == ("NID"))
		return htons(DNS_RECORD_NID);
	else if (Buffer == ("L32"))
		return htons(DNS_RECORD_L32);
	else if (Buffer == ("L64"))
		return htons(DNS_RECORD_L64);
	else if (Buffer == ("LP"))
		return htons(DNS_RECORD_LP);
	else if (Buffer == ("EUI48"))
		return htons(DNS_RECORD_EUI48);
	else if (Buffer == ("EUI64"))
		return htons(DNS_RECORD_EUI64);
	else if (Buffer == ("TKEY"))
		return htons(DNS_RECORD_TKEY);
	else if (Buffer == ("TSIG"))
		return htons(DNS_RECORD_TSIG);
	else if (Buffer == ("IXFR"))
		return htons(DNS_RECORD_IXFR);
	else if (Buffer == ("AXFR"))
		return htons(DNS_RECORD_AXFR);
	else if (Buffer == ("MAILB"))
		return htons(DNS_RECORD_MAILB);
	else if (Buffer == ("MAILA"))
		return htons(DNS_RECORD_MAILA);
	else if (Buffer == ("ANY"))
		return htons(DNS_RECORD_ANY);
	else if (Buffer == ("URI"))
		return htons(DNS_RECORD_URI);
	else if (Buffer == ("CAA"))
		return htons(DNS_RECORD_CAA);
	else if (Buffer == ("TA"))
		return htons(DNS_RECORD_TA);
	else if (Buffer == ("DLV"))
		return htons(DNS_RECORD_DLV);
	else if (Buffer == ("RESERVED"))
		return htons(DNS_RECORD_RESERVED);

//No match.
	return 0;
}

//Read parameter data from files
bool ReadParameterData(
	std::string Data, 
	const size_t FileIndex, 
	const bool IsFirstRead, 
	const size_t Line, 
	bool &IsLabelComments)
{
//Delete delete spaces, horizontal tab/HT, check comments(Number Sign/NS and double slashs) and check minimum length of ipfilter items.
//Delete comments(Number Sign/NS and double slashs) and check minimum length of configuration items.
	if (Data.find(ASCII_HASHTAG) == 0 || Data.find(ASCII_SLASH) == 0)
		return true;
	else if (Data.find("HTTP Header Field = ") != 0 && Data.find("Additional Path = ") != 0 && 
		Data.find("Hosts File Name =") != 0 && Data.find("IPFilter File Name = ") != 0)
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

//Multi-line comments check
	if (Data.find("HTTP Header Field = ") != 0 && !ReadMultiLineComments(Data, IsLabelComments))
		return true;

//Initialization
	CONFIGURATION_TABLE *ParameterPTR = nullptr;
#if defined(ENABLE_LIBSODIUM)
	DNSCURVE_CONFIGURATION_TABLE *DNSCurveParameterPTR = nullptr;
#endif
	ssize_t SignedResult = 0;
	size_t UnsignedResult = 0;
	if (IsFirstRead)
	{
		ParameterPTR = &Parameter;
	#if defined(ENABLE_LIBSODIUM)
		DNSCurveParameterPTR = &DNSCurveParameter;
	#endif
	}
	else {
		ParameterPTR = &ParameterModificating;
	#if defined(ENABLE_LIBSODIUM)
		DNSCurveParameterPTR = &DNSCurveParameterModificating;
	#endif
	}

//[Base] block
	if (Data.find("Version=") == 0)
	{
		_set_errno(0);
		if (Data.length() > strlen("Version=") && Data.length() < strlen("Version=") + 8U)
		{
			ParameterPTR->Version = strtod(Data.c_str() + strlen("Version="), nullptr);
			if (ParameterPTR->Version == 0 || ParameterPTR->Version == HUGE_VAL)
				goto PrintDataFormatError;
		}
		else {
			goto PrintDataFormatError;
		}
	}

//Parameter version less than 0.4 compatible support
	if (ParameterPTR->Version <= CONFIG_VERSION_POINT_THREE)
	{
	//First read.
		if (IsFirstRead)
			return false;

	//[Base] block
		if (Data.find("Hosts=") == 0 && Data.length() > strlen("Hosts="))
		{
			if (Data.length() < strlen("Hosts=") + UINT16_MAX_STRING_LENGTH)
			{
				_set_errno(0);
				UnsignedResult = strtoul(Data.c_str() + strlen("Hosts="), nullptr, 0);
				if (UnsignedResult >= SHORTEST_FILEREFRESH_TIME && UnsignedResult < ULONG_MAX)
					Parameter.FileRefreshTime = UnsignedResult * SECOND_TO_MILLISECOND;
			}
			else {
				goto PrintDataFormatError;
			}
		}
		else if (Parameter.Target_Server_IPv4.AddressData.Storage.ss_family == 0 && Data.find("IPv4DNSAddress=") == 0 && Data.length() > strlen("IPv4DNSAddress="))
		{
			if (Data.length() > strlen("IPv4DNSAddress=") + 6U && Data.length() < strlen("IPv4DNSAddress=") + 20U)
			{
			//Convert IPv4 address and port.
				uint8_t Target[ADDR_STRING_MAXSIZE] = {0};
				memcpy_s(Target, ADDR_STRING_MAXSIZE, Data.c_str() + strlen("IPv4DNSAddress="), Data.length() - strlen("IPv4DNSAddress="));
				if (!AddressStringToBinary(Target, AF_INET, &Parameter.Target_Server_IPv4.AddressData.IPv4.sin_addr, &SignedResult))
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"IPv4 address format error", SignedResult, FileList_Config.at(FileIndex).FileName.c_str(), Line);
					return false;
				}

				Parameter.Target_Server_IPv4.AddressData.IPv4.sin_port = htons(IPPORT_DNS);
				Parameter.Target_Server_IPv4.AddressData.Storage.ss_family = AF_INET;
			}
			else {
				goto PrintDataFormatError;
			}
		}
		else if (Parameter.Target_Server_Local_IPv4.Storage.ss_family == 0 && Data.find("IPv4LocalDNSAddress=") == 0 && Data.length() > strlen("IPv4LocalDNSAddress="))
		{
			if (Data.length() > strlen("IPv4LocalDNSAddress=") + 6U && Data.length() < strlen("IPv4LocalDNSAddress=") + 20U)
			{
			//Convert IPv4 address and port.
				uint8_t Target[ADDR_STRING_MAXSIZE] = {0};
				memcpy_s(Target, ADDR_STRING_MAXSIZE, Data.c_str() + strlen("IPv4LocalDNSAddress="), Data.length() - strlen("IPv4LocalDNSAddress="));
				if (!AddressStringToBinary(Target, AF_INET, &Parameter.Target_Server_Local_IPv4.IPv4.sin_addr, &SignedResult))
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"IPv4 address format error", SignedResult, FileList_Config.at(FileIndex).FileName.c_str(), Line);
					return false;
				}

				Parameter.Target_Server_Local_IPv4.IPv4.sin_port = htons(IPPORT_DNS);
				Parameter.Target_Server_Local_IPv4.Storage.ss_family = AF_INET;
			}
			else {
				goto PrintDataFormatError;
			}
		}
		else if (Parameter.Target_Server_IPv6.AddressData.Storage.ss_family == 0 && Data.find("IPv6DNSAddress=") == 0 && Data.length() > strlen("IPv6DNSAddress="))
		{
			if (Data.length() > strlen("IPv6DNSAddress=") + 1U && Data.length() < strlen("IPv6DNSAddress=") + 40U)
			{
			//Convert IPv6 address and port.
				uint8_t Target[ADDR_STRING_MAXSIZE] = {0};
				memcpy_s(Target, ADDR_STRING_MAXSIZE, Data.c_str() + strlen("IPv6DNSAddress="), Data.length() - strlen("IPv6DNSAddress="));
				if (!AddressStringToBinary(Target, AF_INET6, &Parameter.Target_Server_IPv6.AddressData.IPv6.sin6_addr, &SignedResult))
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"IPv6 address format error", SignedResult, FileList_Config.at(FileIndex).FileName.c_str(), Line);
					return false;
				}

				Parameter.Target_Server_IPv6.AddressData.IPv6.sin6_port = htons(IPPORT_DNS);
				Parameter.Target_Server_IPv6.AddressData.Storage.ss_family = AF_INET6;
			}
			else {
				goto PrintDataFormatError;
			}
		}
		else if (Parameter.Target_Server_Local_IPv6.Storage.ss_family == 0 && Data.find("IPv6LocalDNSAddress=") == 0 && Data.length() > strlen("IPv6LocalDNSAddress="))
		{
			if (Data.length() > strlen("IPv6LocalDNSAddress=") + 1U && Data.length() < strlen("IPv6LocalDNSAddress=") + 40U)
			{
			//Convert IPv6 address and port.
				uint8_t Target[ADDR_STRING_MAXSIZE] = {0};
				memcpy_s(Target, ADDR_STRING_MAXSIZE, Data.c_str() + strlen("IPv6LocalDNSAddress="), Data.length() - strlen("IPv6LocalDNSAddress="));
				if (!AddressStringToBinary(Target, AF_INET6, &Parameter.Target_Server_Local_IPv6.IPv6.sin6_addr, &SignedResult))
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"IPv6 address format error", SignedResult, FileList_Config.at(FileIndex).FileName.c_str(), Line);
					return false;
				}

				Parameter.Target_Server_Local_IPv6.IPv6.sin6_port = htons(IPPORT_DNS);
				Parameter.Target_Server_Local_IPv6.Storage.ss_family = AF_INET6;
			}
			else {
				goto PrintDataFormatError;
			}
		}
	#if defined(ENABLE_PCAP)
		else if (Data.find("HopLimits/TTLFluctuation=") == 0 && Data.length() > strlen("HopLimits/TTLFluctuation="))
		{
			if (Data.length() < strlen("HopLimits/TTLFluctuation=") + UINT8_MAX_STRING_LENGTH)
			{
				_set_errno(0);
				UnsignedResult = strtoul(Data.c_str() + strlen("HopLimits/TTLFluctuation="), nullptr, 0);
				if (UnsignedResult > 0 && UnsignedResult < UINT8_MAX)
					Parameter.HopLimitFluctuation = (uint8_t)UnsignedResult;
			}
			else {
				goto PrintDataFormatError;
			}
		}
	#endif

	//[Extend Test] block
	#if defined(ENABLE_PCAP)
		else if (Data.find("IPv4OptionsFilter=1") == 0)
		{
			Parameter.HeaderCheck_IPv4 = true;
		}
		else if (Data.find("TCPOptionsFilter=1") == 0)
		{
			Parameter.HeaderCheck_TCP = true;
		}
	#endif
		else if (Data.find("DNSOptionsFilter=1") == 0)
		{
			Parameter.HeaderCheck_DNS = true;
		}

	//[Data] block
	#if defined(ENABLE_PCAP)
		else if (Parameter.DomainTest_Speed == 0 && Data.find("DomainTestSpeed=") == 0 && Data.length() > strlen("DomainTestSpeed="))
		{
			if (Data.length() < strlen("DomainTestSpeed=") + UINT16_MAX_STRING_LENGTH)
			{
				_set_errno(0);
				UnsignedResult = strtoul(Data.c_str() + strlen("DomainTestSpeed="), nullptr, 0);
				if (UnsignedResult > 0 && UnsignedResult < ULONG_MAX)
					Parameter.DomainTest_Speed = UnsignedResult * SECOND_TO_MILLISECOND;
			}
			else {
				goto PrintDataFormatError;
			}
		}
	#endif
	}
	else if (Data.find("FileRefreshTime=") == 0 && Data.length() > strlen("FileRefreshTime="))
	{
		if (Data.length() < strlen("FileRefreshTime=") + UINT16_MAX_STRING_LENGTH)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("FileRefreshTime="), nullptr, 0);
			if (UnsignedResult >= SHORTEST_FILEREFRESH_TIME && UnsignedResult < ULONG_MAX)
				ParameterPTR->FileRefreshTime = UnsignedResult * SECOND_TO_MILLISECOND;
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (IsFirstRead && Data.find("Additional Path = ") == 0 && Data.length() > strlen("Additional Path = "))
	{
	#if defined(PLATFORM_WIN)
		if (!ReadPathAndFileName(Data, strlen("Additional Path = "), true, GlobalRunningStatus.Path_Global, FileIndex, Line))
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		if (!ReadPathAndFileName(Data, strlen("Additional Path = "), true, GlobalRunningStatus.Path_Global, GlobalRunningStatus.sPath_Global, FileIndex, Line))
	#endif
			return false;
	}
	else if (IsFirstRead && Data.find("Hosts File Name = ") == 0 && Data.length() > strlen("Hosts File Name = "))
	{
	#if defined(PLATFORM_WIN)
		if (!ReadPathAndFileName(Data, strlen("Hosts File Name = "), false, GlobalRunningStatus.FileList_Hosts, FileIndex, Line))
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		if (!ReadPathAndFileName(Data, strlen("Hosts File Name = "), false, GlobalRunningStatus.FileList_Hosts, GlobalRunningStatus.sFileList_Hosts, FileIndex, Line))
	#endif
			return false;
	}
	else if (IsFirstRead && Data.find("IPFilter File Name = ") == 0 && Data.length() > strlen("IPFilter File Name = "))
	{
	#if defined(PLATFORM_WIN)
		if (!ReadPathAndFileName(Data, strlen("IPFilter File Name = "), false, GlobalRunningStatus.FileList_IPFilter, FileIndex, Line))
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		if (!ReadPathAndFileName(Data, strlen("IPFilter File Name = "), false, GlobalRunningStatus.FileList_IPFilter, GlobalRunningStatus.sFileList_IPFilter, FileIndex, Line))
	#endif
			return false;
	}

//[Log] block
	if (Data.find("PrintError=0") == 0)
	{
		ParameterPTR->PrintLogLevel = LOG_LEVEL_0;
	}
	else if (Data.find("PrintLogLevel=") == 0)
	{
		if (Data.length() == strlen("PrintLogLevel=") + 1U)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("PrintLogLevel="), nullptr, 0);
			if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > LOG_LEVEL_0 && UnsignedResult <= LOG_LEVEL_MAXNUM))
			{
				ParameterPTR->PrintLogLevel = UnsignedResult;
			}
			else {
				goto PrintDataFormatError;
			}
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (Data.find("LogMaximumSize=") == 0 && Data.length() > strlen("LogMaximumSize="))
	{
		CaseConvert(true, Data);
		if (Data.find("KB") != std::string::npos)
		{
			Data.erase(Data.length() - 2U, 2U);

		//Mark bytes.
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("LogMaximumSize="), nullptr, 0);
			if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult < ULONG_MAX))
				ParameterPTR->LogMaxSize = UnsignedResult * KILOBYTE_TIMES;
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
				ParameterPTR->LogMaxSize = UnsignedResult * MEGABYTE_TIMES;
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
				ParameterPTR->LogMaxSize = UnsignedResult * GIGABYTE_TIMES;
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
				ParameterPTR->LogMaxSize = UnsignedResult;
			else 
				goto PrintDataFormatError;
		}
	}

//[Listen] block
#if defined(ENABLE_PCAP)
	if (IsFirstRead && Data.find("PcapCapture=1") == 0)
	{
		Parameter.PcapCapture = true;
	}
	else if (IsFirstRead && Data.find("PcapDevicesBlacklist=") == 0)
	{
		GetParameterListData(*Parameter.PcapDevicesBlacklist, Data, strlen("PcapDevicesBlacklist="), Data.length());
	}
	else if (IsFirstRead && Data.find("PcapReadingTimeout=") == 0)
	{
		if (Data.length() < strlen("PcapReadingTimeout=") + UINT32_MAX_STRING_LENGTH)
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
	else if (IsFirstRead && Data.find("ListenProtocol=") == 0 && Data.length() > strlen("ListenProtocol="))
	{
		CaseConvert(true, Data);
		if (Data.find("IPV6") != std::string::npos)
		{
			if (Data.find("IPV4") != std::string::npos)
				Parameter.ListenProtocol_Network = LISTEN_PROTOCOL_NETWORK_BOTH;
			else 
				Parameter.ListenProtocol_Network = LISTEN_PROTOCOL_IPV6;
		}
		else {
			Parameter.ListenProtocol_Network = LISTEN_PROTOCOL_IPV4;
		}

		if (Data.find("TCP") != std::string::npos)
		{
			if (Data.find("UDP") != std::string::npos)
				Parameter.ListenProtocol_Transport = LISTEN_PROTOCOL_TRANSPORT_BOTH;
			else 
				Parameter.ListenProtocol_Transport = LISTEN_PROTOCOL_TCP;
		}
		else {
			Parameter.ListenProtocol_Transport = LISTEN_PROTOCOL_UDP;
		}
	}
	else if (IsFirstRead && Data.find("ListenPort=") == 0 && Data.length() > strlen("ListenPort="))
	{
		std::vector<std::string> ListData;
		GetParameterListData(ListData, Data, strlen("ListenPort="), Data.length());
		Parameter.ListenPort->clear();
		for (const auto &StringIter:ListData)
		{
			UnsignedResult = ServiceNameToBinary((const uint8_t *)StringIter.c_str());
			if (UnsignedResult == 0)
			{
				_set_errno(0);
				UnsignedResult = strtoul(StringIter.c_str(), nullptr, 0);
				if (UnsignedResult <= 0 || UnsignedResult > UINT16_MAX)
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"Localhost listening port error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
			}

			Parameter.ListenPort->push_back(htons((uint16_t)UnsignedResult));
		}
	}
	else if (IsFirstRead && Data.find("OperationMode=") == 0 && Data.length() > strlen("OperationMode="))
	{
		CaseConvert(true, Data);
		if (Data.find("PRIVATE") != std::string::npos)
			Parameter.OperationMode = LISTEN_MODE_PRIVATE;
		else if (Data.find("SERVER") != std::string::npos)
			Parameter.OperationMode = LISTEN_MODE_SERVER;
		else if (Data.find("CUSTOM") != std::string::npos)
			Parameter.OperationMode = LISTEN_MODE_CUSTOM;
		else 
			Parameter.OperationMode = LISTEN_MODE_PROXY;
	}
	else if (Data.find("IPFilterType=PERMIT") == 0 || Data.find("IPFilterType=Permit") == 0 || Data.find("IPFilterType=permit") == 0)
	{
		ParameterPTR->IPFilterType = true;
	}
	else if (Data.find("IPFilterLevel<") == 0 && Data.length() > strlen("IPFilterLevel<"))
	{
		if (Data.length() < strlen("IPFilterLevel<") + UINT8_MAX_STRING_LENGTH)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("IPFilterLevel<"), nullptr, 0);
			if (UnsignedResult > 0 && UnsignedResult <= UINT16_MAX)
			{
				ParameterPTR->IPFilterLevel = UnsignedResult;
			}
			else {
				PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"IPFilter Level error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
				return false;
			}
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (Data.find("AcceptType=") == 0 && Data.length() > strlen("AcceptType="))
	{
		if (Data.find(ASCII_COLON) == std::string::npos)
		{
			goto PrintDataFormatError;
		}
		else {
		//Permit or Deny mode check
			if (Data.find("Permit:") != std::string::npos || Data.find("PERMIT:") != std::string::npos || Data.find("permit:") != std::string::npos)
				ParameterPTR->AcceptType = true;
			else 
				ParameterPTR->AcceptType = false;

		//Mark all data in list.
			std::vector<std::string> ListData;
			GetParameterListData(ListData, Data, Data.find(ASCII_COLON) + 1U, Data.length());
			ParameterPTR->AcceptTypeList->clear();
			for (const auto &StringIter:ListData)
			{
				UnsignedResult = DNSTypeNameToBinary((const uint8_t *)StringIter.c_str());
				if (UnsignedResult == 0)
				{
					_set_errno(0);
					UnsignedResult = strtoul(StringIter.c_str(), nullptr, 0);
					if (UnsignedResult <= 0 || UnsignedResult > UINT16_MAX)
					{
						PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"DNS Records type error", errno, FileList_Config.at(FileIndex).FileName.c_str(), Line);
						return false;
					}
				}
				
				ParameterPTR->AcceptTypeList->push_back((uint16_t)UnsignedResult);
			}
		}
	}

//[DNS] block
	if (IsFirstRead && Data.find("Protocol=") == 0 && Data.length() > strlen("Protocol="))
	{
		CaseConvert(true, Data);

	//Network layer
		if (Data.find("IPV6") != std::string::npos)
		{
			if (Data.find("IPV4") != std::string::npos)
				Parameter.RequestMode_Network = REQUEST_MODE_NETWORK_BOTH;
			else 
				Parameter.RequestMode_Network = REQUEST_MODE_IPV6;
		}
		else {
			Parameter.RequestMode_Network = REQUEST_MODE_IPV4;
		}

	//Transport layer
		if (Data.find("TCP") != std::string::npos)
			Parameter.RequestMode_Transport = REQUEST_MODE_TCP;
		else 
			Parameter.RequestMode_Transport = REQUEST_MODE_UDP;
	}
	else if ((Data.find("DirectRequest=") == 0 && Data.length() > strlen("DirectRequest=")) || 
		(Data.find("HostsOnly=") == 0 && Data.length() > strlen("HostsOnly=")))
	{
		if (Data.find("DirectRequest=1") == 0 || Data.find("HostsOnly=1") == 0)
		{
			ParameterPTR->DirectRequest = DIRECT_REQUEST_MODE_BOTH;
		}
		else {
			CaseConvert(true, Data);
			if (Data.find("IPV6") != std::string::npos)
			{
				if (Data.find("IPV4") != std::string::npos)
					ParameterPTR->DirectRequest = DIRECT_REQUEST_MODE_BOTH;
				else 
					ParameterPTR->DirectRequest = DIRECT_REQUEST_MODE_IPV6;
			}
			else if (Data.find("IPV4") != std::string::npos)
			{
				if (Data.find("IPV6") != std::string::npos)
					ParameterPTR->DirectRequest = DIRECT_REQUEST_MODE_BOTH;
				else 
					ParameterPTR->DirectRequest = DIRECT_REQUEST_MODE_IPV4;
			}
		}
	}
	else if (IsFirstRead && Data.find("CacheType=") == 0 && Data.length() > strlen("CacheType="))
	{
		CaseConvert(true, Data);
		if (Data.find("TIMER") != std::string::npos)
			Parameter.CacheType = CACHE_TYPE_TIMER;
		else if (Data.find("QUEUE") != std::string::npos)
			Parameter.CacheType = CACHE_TYPE_QUEUE;
	}
	else if (IsFirstRead && Parameter.CacheType > 0 && Data.find("CacheParameter=") == 0 && Data.length() > strlen("CacheParameter="))
	{
		_set_errno(0);
		UnsignedResult = strtoul(Data.c_str() + strlen("CacheParameter="), nullptr, 0);
		if (UnsignedResult > 0 && UnsignedResult < ULONG_MAX)
		{
			if (Parameter.CacheType == CACHE_TYPE_TIMER)
				Parameter.CacheParameter = UnsignedResult * SECOND_TO_MILLISECOND;
			else if (Parameter.CacheType == CACHE_TYPE_QUEUE)
				Parameter.CacheParameter = UnsignedResult;
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (Data.find("DefaultTTL=") == 0 && Data.length() > strlen("DefaultTTL="))
	{
		if (Data.length() < strlen("DefaultTTL=") + UINT16_MAX_STRING_LENGTH)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("DefaultTTL="), nullptr, 0);
			if (UnsignedResult > 0 && UnsignedResult < ULONG_MAX)
			{
				ParameterPTR->HostsDefaultTTL = (uint32_t)UnsignedResult;
			}
			else {
				PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"Default TTL error", errno, FileList_Config.at(FileIndex).FileName.c_str(), Line);
				return false;
			}
		}
		else {
			goto PrintDataFormatError;
		}
	}

//[Local DNS] block
	if (Data.find("LocalProtocol=") == 0)
	{
		CaseConvert(true, Data);

	//Network layer
		if (Data.find("IPV6") != std::string::npos)
		{
			if (Data.find("IPV4") != std::string::npos)
				ParameterPTR->LocalProtocol_Network = REQUEST_MODE_NETWORK_BOTH;
			else 
				ParameterPTR->LocalProtocol_Network = REQUEST_MODE_IPV6;
		}
		else {
			ParameterPTR->LocalProtocol_Network = REQUEST_MODE_IPV4;
		}

	//Transport layer
		if (Data.find("TCP") != std::string::npos)
			ParameterPTR->LocalProtocol_Transport = REQUEST_MODE_TCP;
		else 
			ParameterPTR->LocalProtocol_Transport = REQUEST_MODE_UDP;
	}
	else if (Data.find("LocalForceRequest=1") == 0)
	{
		ParameterPTR->LocalForce = true;
	}
	else if (IsFirstRead && Data.find("LocalHosts=1") == 0)
	{
		Parameter.LocalHosts = true;
	}
	else if (IsFirstRead && Data.find("LocalMain=1") == 0)
	{
		Parameter.LocalMain = true;
	}
	else if (IsFirstRead && Data.find("LocalRouting=1") == 0)
	{
		Parameter.LocalRouting = true;
	}

//[Addresses] block
	if (IsFirstRead && Data.find("IPv4ListenAddress=") == 0 && Data.length() > strlen("IPv4ListenAddress="))
	{
		Parameter.ListenAddress_IPv4->clear();
		sockaddr_storage SockAddr;
		memset(&SockAddr, 0, sizeof(SockAddr));
		if (!ReadMultipleAddresses(Data, strlen("IPv4ListenAddress="), AF_INET, true, SockAddr, Parameter.ListenAddress_IPv4, FileIndex, Line))
			return false;
	}
	else if (IsFirstRead && Data.find("IPv4EDNSClientSubnetAddress=") == 0 && Data.length() > strlen("IPv4EDNSClientSubnetAddress="))
	{
		if (!ReadAddressPrefixBlock(Data, strlen("IPv4EDNSClientSubnetAddress="), AF_INET, Parameter.LocalhostSubnet_IPv4, FileIndex, Line))
			return false;
	}
	else if (IsFirstRead && Data.find("IPv4DNSAddress=") == 0 && Data.length() > strlen("IPv4DNSAddress="))
	{
		if (!ReadMultipleAddresses(Data, strlen("IPv4DNSAddress="), AF_INET, true, Parameter.Target_Server_IPv4.AddressData.Storage, nullptr, FileIndex, Line))
			return false;
	}
	else if (IsFirstRead && Data.find("IPv4AlternateDNSAddress=") == 0 && Data.length() > strlen("IPv4AlternateDNSAddress="))
	{
		if (!ReadMultipleAddresses(Data, strlen("IPv4AlternateDNSAddress="), AF_INET, true, Parameter.Target_Server_Alternate_IPv4.AddressData.Storage, nullptr, FileIndex, Line))
			return false;
	}
	else if (IsFirstRead && Data.find("IPv4LocalDNSAddress=") == 0 && Data.length() > strlen("IPv4LocalDNSAddress="))
	{
		if (!ReadMultipleAddresses(Data, strlen("IPv4LocalDNSAddress="), AF_INET, false, Parameter.Target_Server_Local_IPv4.Storage, nullptr, FileIndex, Line))
			return false;
	}
	else if (IsFirstRead && Data.find("IPv4LocalAlternateDNSAddress=") == 0 && Data.length() > strlen("IPv4LocalAlternateDNSAddress="))
	{
		if (!ReadMultipleAddresses(Data, strlen("IPv4LocalAlternateDNSAddress="), AF_INET, false, Parameter.Target_Server_Alternate_Local_IPv4.Storage, nullptr, FileIndex, Line))
			return false;
	}
	else if (IsFirstRead && Data.find("IPv6ListenAddress=") == 0 && Data.length() > strlen("IPv6ListenAddress="))
	{
		Parameter.ListenAddress_IPv6->clear();
		sockaddr_storage SockAddr;
		memset(&SockAddr, 0, sizeof(SockAddr));
		if (!ReadMultipleAddresses(Data, strlen("IPv4ListenAddress="), AF_INET6, true, SockAddr, Parameter.ListenAddress_IPv6, FileIndex, Line))
			return false;
	}
	else if (IsFirstRead && Data.find("IPv6EDNSClientSubnetAddress=") == 0 && Data.length() > strlen("IPv6EDNSClientSubnetAddress="))
	{
		if (!ReadAddressPrefixBlock(Data, strlen("IPv6EDNSClientSubnetAddress="), AF_INET6, Parameter.LocalhostSubnet_IPv6, FileIndex, Line))
			return false;
	}
	else if (IsFirstRead && Data.find("IPv6DNSAddress=") == 0 && Data.length() > strlen("IPv6DNSAddress="))
	{
		if (!ReadMultipleAddresses(Data, strlen("IPv6DNSAddress="), AF_INET6, true, Parameter.Target_Server_IPv6.AddressData.Storage, nullptr, FileIndex, Line))
			return false;
	}
	else if (IsFirstRead && Data.find("IPv6AlternateDNSAddress=") == 0 && Data.length() > strlen("IPv6AlternateDNSAddress="))
	{
		if (!ReadMultipleAddresses(Data, strlen("IPv6AlternateDNSAddress="), AF_INET6, true, Parameter.Target_Server_Alternate_IPv6.AddressData.Storage, nullptr, FileIndex, Line))
			return false;
	}
	else if (IsFirstRead && Data.find("IPv6LocalDNSAddress=") == 0 && Data.length() > strlen("IPv6LocalDNSAddress="))
	{
		if (!ReadMultipleAddresses(Data, strlen("IPv6LocalDNSAddress="), AF_INET6, false, Parameter.Target_Server_Local_IPv6.Storage, nullptr, FileIndex, Line))
			return false;
	}
	else if (IsFirstRead && Data.find("IPv6LocalAlternateDNSAddress=") == 0 && Data.length() > strlen("IPv6LocalAlternateDNSAddress="))
	{
		if (!ReadMultipleAddresses(Data, strlen("IPv6LocalAlternateDNSAddress="), AF_INET6, false, Parameter.Target_Server_Alternate_Local_IPv6.Storage, nullptr, FileIndex, Line))
			return false;
	}

//[Values] block
	if (IsFirstRead && Data.find("ThreadPoolBaseNumber=") == 0 && Data.length() > strlen("ThreadPoolBaseNumber="))
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
	else if (IsFirstRead && ((Data.find("BufferQueueLimits=") == 0 && Data.length() > strlen("BufferQueueLimits=")) || 
		(Data.find("ThreadPoolMaximumNumber=") == 0 && Data.length() > strlen("ThreadPoolMaximumNumber="))))
	{
		size_t Offset = 0;
		if (Data.find("BufferQueueLimits=") == 0 && Data.length() > strlen("BufferQueueLimits="))
			Offset = strlen("BufferQueueLimits=");
		else 
			Offset = strlen("ThreadPoolMaximumNumber=");

	//Read data.
		if (Data.length() < Offset + UINT32_MAX_STRING_LENGTH - 1U)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + Offset, nullptr, 0);
			if (UnsignedResult >= THREAD_POOL_MINNUM && UnsignedResult <= THREAD_POOL_MAXNUM)
				Parameter.ThreadPoolMaxNum = UnsignedResult;
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (IsFirstRead && Data.find("ThreadPoolResetTime=") == 0 && Data.length() > strlen("ThreadPoolResetTime="))
	{
		if (Data.length() < strlen("ThreadPoolResetTime=") + UINT16_MAX_STRING_LENGTH)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("ThreadPoolResetTime="), nullptr, 0);
			if (UnsignedResult >= SHORTEST_THREAD_POOL_RESET_TIME && UnsignedResult < ULONG_MAX)
				Parameter.ThreadPoolResetTime = UnsignedResult * SECOND_TO_MILLISECOND;
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (IsFirstRead && Data.find("QueueLimitsResetTime=") == 0 && Data.length() > strlen("QueueLimitsResetTime="))
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
	else if (IsFirstRead && Data.find("EDNSPayloadSize=") == 0 && Data.length() > strlen("EDNSPayloadSize="))
	{
		if (Data.length() < strlen("EDNSPayloadSize=") + UINT16_MAX_STRING_LENGTH)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("EDNSPayloadSize="), nullptr, 0);
			if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult < ULONG_MAX))
				Parameter.EDNSPayloadSize = UnsignedResult;
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (Data.find("IPv4PacketTTL=") == 0 && Data.length() > strlen("IPv4PacketTTL="))
	{
	//Range
		if (Data.find(ASCII_MINUS) != std::string::npos && Data.length() > Data.find(ASCII_MINUS) + 1U)
		{
		//Mark begining value.
			std::string ValueString;
			ValueString.append(Data, strlen("IPv4PacketTTL="), Data.find(ASCII_MINUS) - strlen("IPv4PacketTTL="));
			_set_errno(0);
			UnsignedResult = strtoul(ValueString.c_str(), nullptr, 0);
			if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult <= UINT8_MAX))
				ParameterPTR->PacketHopLimits_IPv4_Begin = (int)UnsignedResult;
			else 
				goto PrintDataFormatError;

		//Mark end value.
			ValueString.clear();
			ValueString.append(Data, Data.find(ASCII_MINUS) + 1U, Data.length() - Data.find(ASCII_MINUS));
			_set_errno(0);
			UnsignedResult = strtoul(ValueString.c_str(), nullptr, 0);
			if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult <= UINT8_MAX))
				ParameterPTR->PacketHopLimits_IPv4_End = (int)UnsignedResult;
			else 
				goto PrintDataFormatError;

		//Range check
			if (ParameterPTR->PacketHopLimits_IPv4_Begin == 0)
				++ParameterPTR->PacketHopLimits_IPv4_Begin;
			if (ParameterPTR->PacketHopLimits_IPv4_Begin >= ParameterPTR->PacketHopLimits_IPv4_End)
			{
				PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"IPv4 packet TTL range error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
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
					ParameterPTR->PacketHopLimits_IPv4_Begin = (int)UnsignedResult;
				else 
					goto PrintDataFormatError;
			}
			else {
				goto PrintDataFormatError;
			}
		}
	}
	else if (Data.find("IPv6PacketHopLimits=") == 0 && Data.length() > strlen("IPv6PacketHopLimits="))
	{
	//Range
		if (Data.find(ASCII_MINUS) != std::string::npos)
		{
		//Mark begining value.
			std::string ValueString;
			ValueString.append(Data, strlen("IPv6PacketHopLimits="), Data.find(ASCII_MINUS) - strlen("IPv6PacketHopLimits="));
			_set_errno(0);
			UnsignedResult = strtoul(ValueString.c_str(), nullptr, 0);
			if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult <= UINT8_MAX))
				ParameterPTR->PacketHopLimits_IPv6_Begin = (int)UnsignedResult;
			else 
				goto PrintDataFormatError;

		//Mark end value.
			ValueString.clear();
			ValueString.append(Data, Data.find(ASCII_MINUS) + 1U, Data.length() - Data.find(ASCII_MINUS));
			_set_errno(0);
			UnsignedResult = strtoul(ValueString.c_str(), nullptr, 0);
			if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult <= UINT8_MAX))
				ParameterPTR->PacketHopLimits_IPv6_End = (int)UnsignedResult;
			else 
				goto PrintDataFormatError;

		//Range check
			if (ParameterPTR->PacketHopLimits_IPv6_Begin == 0)
				++ParameterPTR->PacketHopLimits_IPv6_Begin;
			if (ParameterPTR->PacketHopLimits_IPv6_Begin >= ParameterPTR->PacketHopLimits_IPv6_End)
			{
				PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"IPv6 packet Hop Limits range error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
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
					ParameterPTR->PacketHopLimits_IPv6_Begin = (int)UnsignedResult;
				else 
					goto PrintDataFormatError;
			}
			else {
				goto PrintDataFormatError;
			}
		}
	}
#if defined(ENABLE_PCAP)
	else if (Data.find("IPv4TTL=") == 0 && Data.length() > strlen("IPv4TTL="))
	{
		if (!ReadHopLimitData(Data, strlen("IPv4TTL="), AF_INET, ParameterPTR->Target_Server_IPv4.HopLimitData.TTL, FileIndex, Line))
			return false;
	}
	else if (Data.find("IPv6HopLimits=") == 0 && Data.length() > strlen("IPv6HopLimits="))
	{
		if (!ReadHopLimitData(Data, strlen("IPv6HopLimits="), AF_INET6, ParameterPTR->Target_Server_IPv6.HopLimitData.HopLimit, FileIndex, Line))
			return false;
	}
	else if (Data.find("IPv4AlternateTTL=") == 0 && Data.length() > strlen("IPv4AlternateTTL="))
	{
		if (!ReadHopLimitData(Data, strlen("IPv4AlternateTTL="), AF_INET, ParameterPTR->Target_Server_Alternate_IPv4.HopLimitData.TTL, FileIndex, Line))
			return false;
	}
	else if (Data.find("IPv6AlternateHopLimits=") == 0 && Data.length() > strlen("IPv6AlternateHopLimits="))
	{
		if (!ReadHopLimitData(Data, strlen("IPv6AlternateHopLimits="), AF_INET6, ParameterPTR->Target_Server_Alternate_IPv6.HopLimitData.HopLimit, FileIndex, Line))
			return false;
	}
	else if (Data.find("IPv4DNSTTL=") == 0 && Data.length() > strlen("IPv4DNSTTL="))
	{
		if (!ReadHopLimitData(Data, strlen("IPv4DNSTTL="), AF_INET, ParameterPTR->Target_Server_IPv4.HopLimitData.TTL, FileIndex, Line))
			return false;
	}
	else if (Data.find("IPv6DNSHopLimits=") == 0 && Data.length() > strlen("IPv6DNSHopLimits="))
	{
		if (!ReadHopLimitData(Data, strlen("IPv6DNSHopLimits="), AF_INET6, ParameterPTR->Target_Server_IPv6.HopLimitData.HopLimit, FileIndex, Line))
			return false;
	}
	else if (Data.find("IPv4AlternateDNSTTL=") == 0 && Data.length() > strlen("IPv4AlternateDNSTTL="))
	{
		if (!ReadHopLimitData(Data, strlen("IPv4AlternateDNSTTL="), AF_INET, ParameterPTR->Target_Server_Alternate_IPv4.HopLimitData.TTL, FileIndex, Line))
			return false;
	}
	else if (Data.find("IPv6AlternateDNSHopLimits=") == 0 && Data.length() > strlen("IPv6AlternateDNSHopLimits="))
	{
		if (!ReadHopLimitData(Data, strlen("IPv6AlternateDNSHopLimits="), AF_INET6, ParameterPTR->Target_Server_Alternate_IPv6.HopLimitData.HopLimit, FileIndex, Line))
			return false;
	}
	else if (Data.find("HopLimitsFluctuation=") == 0 && Data.length() > strlen("HopLimitsFluctuation="))
	{
		if (Data.length() < strlen("HopLimitsFluctuation=") + UINT8_MAX_STRING_LENGTH)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("HopLimitsFluctuation="), nullptr, 0);
			if (UnsignedResult > 0 && UnsignedResult < UINT8_MAX)
				ParameterPTR->HopLimitFluctuation = (uint8_t)UnsignedResult;
		}
		else {
			goto PrintDataFormatError;
		}
	}
#endif
	else if (Data.find("ReliableSocketTimeout=") == 0 && Data.length() > strlen("ReliableSocketTimeout="))
	{
		if (Data.length() < strlen("ReliableSocketTimeout=") + UINT32_MAX_STRING_LENGTH)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("ReliableSocketTimeout="), nullptr, 0);
			if (UnsignedResult > SOCKET_MIN_TIMEOUT && UnsignedResult < ULONG_MAX)
			#if defined(PLATFORM_WIN)
				ParameterPTR->SocketTimeout_Reliable = (int)UnsignedResult;
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			{
				ParameterPTR->SocketTimeout_Reliable.tv_sec = UnsignedResult / SECOND_TO_MILLISECOND;
				ParameterPTR->SocketTimeout_Reliable.tv_usec = UnsignedResult % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
			}
			#endif
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (Data.find("UnreliableSocketTimeout=") == 0 && Data.length() > strlen("UnreliableSocketTimeout="))
	{
		if (Data.length() < strlen("UnreliableSocketTimeout=") + UINT32_MAX_STRING_LENGTH)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("UnreliableSocketTimeout="), nullptr, 0);
			if (UnsignedResult > SOCKET_MIN_TIMEOUT && UnsignedResult < ULONG_MAX)
			#if defined(PLATFORM_WIN)
				ParameterPTR->SocketTimeout_Unreliable = (int)UnsignedResult;
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			{
				ParameterPTR->SocketTimeout_Unreliable.tv_sec = UnsignedResult / SECOND_TO_MILLISECOND;
				ParameterPTR->SocketTimeout_Unreliable.tv_usec = UnsignedResult % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
			}
			#endif
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (Data.find("ReceiveWaiting=") == 0 && Data.length() > strlen("ReceiveWaiting="))
	{
		if (Data.length() < strlen("ReceiveWaiting=") + UINT16_MAX_STRING_LENGTH)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("ReceiveWaiting="), nullptr, 0);
			if (UnsignedResult > 0 && UnsignedResult < ULONG_MAX)
				ParameterPTR->ReceiveWaiting = UnsignedResult;
		}
		else {
			goto PrintDataFormatError;
		}
	}
#if defined(ENABLE_PCAP)
	else if (Data.find("ICMPTest=") == 0 && Data.length() > strlen("ICMPTest="))
	{
		if (Data.length() < strlen("ICMPTest=") + UINT16_MAX_STRING_LENGTH)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("ICMPTest="), nullptr, 0);
			if (UnsignedResult >= SHORTEST_ICMP_TEST_TIME && UnsignedResult < ULONG_MAX)
				ParameterPTR->ICMP_Speed = UnsignedResult * SECOND_TO_MILLISECOND;
			else if (UnsignedResult > 0 && UnsignedResult < SHORTEST_ICMP_TEST_TIME)
				ParameterPTR->ICMP_Speed = SHORTEST_ICMP_TEST_TIME * SECOND_TO_MILLISECOND;
			else 
				ParameterPTR->ICMP_Speed = 0; //ICMP Test Disable
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (Data.find("DomainTest=") == 0 && Data.length() > strlen("DomainTest="))
	{
		if (Data.length() < strlen("DomainTest=") + UINT16_MAX_STRING_LENGTH)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("DomainTest="), nullptr, 0);
			if (UnsignedResult > SHORTEST_DOMAIN_TEST_INTERVAL_TIME && UnsignedResult < ULONG_MAX)
				ParameterPTR->DomainTest_Speed = UnsignedResult * SECOND_TO_MILLISECOND;
		}
		else {
			goto PrintDataFormatError;
		}
	}
#endif
	else if (IsFirstRead && Data.find("AlternateTimes=") == 0 && Data.length() > strlen("AlternateTimes="))
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
	else if (IsFirstRead && Data.find("AlternateTimeRange=") == 0 && Data.length() > strlen("AlternateTimeRange="))
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
	else if (IsFirstRead && Data.find("AlternateResetTime=") == 0 && Data.length() > strlen("AlternateResetTime="))
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
	else if (Data.find("MultiRequestTimes=") == 0 && Data.length() > strlen("MultiRequestTimes="))
	{
		if (Data.length() < strlen("MultiRequestTimes=") + UINT16_MAX_STRING_LENGTH)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("MultiRequestTimes="), nullptr, 0);
			if (UnsignedResult > 0 && UnsignedResult < ULONG_MAX)
				ParameterPTR->MultiRequestTimes = UnsignedResult;
		}
		else {
			goto PrintDataFormatError;
		}
	}

//[Switches] block
#if defined(PLATFORM_LINUX)
	if (IsFirstRead && Data.find("TCPFastOpen=1") == 0)
	{
		Parameter.TCP_FastOpen = true;
	}
	else 
#endif
	if (Data.find("DomainCaseConversion=1") == 0)
	{
		ParameterPTR->DomainCaseConversion = true;
	}
	else if (IsFirstRead && Data.find("CompressionPointerMutation=") == 0 && Data.length() > strlen("CompressionPointerMutation="))
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
	else if ((IsFirstRead && Data.find("EDNSLabel=") == 0) || Data.find("EDNS0Label=") == 0)
	{
		if (Data.find("EDNSLabel=1") == 0 || Data.find("EDNS0Label=1") == 0)
		{
			Parameter.EDNS_Label = true;

			Parameter.EDNS_Switch_Local = true;
			Parameter.EDNS_Switch_SOCKS = true;
			Parameter.EDNS_Switch_HTTP = true;
			Parameter.EDNS_Switch_Direct = true;
			Parameter.EDNS_Switch_DNSCurve = true;
			Parameter.EDNS_Switch_TCP = true;
			Parameter.EDNS_Switch_UDP = true;
		}
		else {
			if (Data.find("Local") != std::string::npos)
			{
				Parameter.EDNS_Label = true;
				Parameter.EDNS_Switch_Local = true;
			}
			
			if (Data.find("SOCKS Proxy") != std::string::npos)
			{
				Parameter.EDNS_Label = true;
				Parameter.EDNS_Switch_SOCKS = true;
			}
			
			if (Data.find("HTTP Proxy") != std::string::npos)
			{
				Parameter.EDNS_Label = true;
				Parameter.EDNS_Switch_HTTP = true;
			}
			
			if (Data.find("Direct") != std::string::npos)
			{
				Parameter.EDNS_Label = true;
				Parameter.EDNS_Switch_Direct = true;
			}
			
			if (Data.find("DNSCurve") != std::string::npos || Data.find("DNSCrypt") != std::string::npos)
			{
				Parameter.EDNS_Label = true;
				Parameter.EDNS_Switch_DNSCurve = true;
			}

			if (Data.find("TCP") != std::string::npos)
			{
				Parameter.EDNS_Label = true;
				Parameter.EDNS_Switch_TCP = true;
			}

			if (Data.find("UDP") != std::string::npos)
			{
				Parameter.EDNS_Label = true;
				Parameter.EDNS_Switch_UDP = true;
			}
		}
	}
	else if ((IsFirstRead && Data.find("EDNSClientSubnetRelay=1") == 0) || Data.find("EDNSClientSubnet=1") == 0)
	{
		Parameter.EDNS_ClientSubnet_Relay = true;
	}
	else if (IsFirstRead && Data.find("DNSSECRequest=1") == 0)
	{
		Parameter.DNSSEC_Request = true;
	}
	else if (IsFirstRead && Data.find("DNSSECValidation=1") == 0)
	{
		Parameter.DNSSEC_Validation = true;
	}
	else if (IsFirstRead && Data.find("DNSSECForceValidation=1") == 0)
	{
		Parameter.DNSSEC_ForceValidation = true;
	}
	else if (IsFirstRead && Data.find("AlternateMultiRequest=1") == 0)
	{
		Parameter.AlternateMultiRequest = true;
	}
	else if (Data.find("IPv4DoNotFragment=1") == 0)
	{
		ParameterPTR->DoNotFragment = true;
	}
#if defined(ENABLE_PCAP)
	else if (Data.find("IPv4DataFilter=1") == 0)
	{
		ParameterPTR->HeaderCheck_IPv4 = true;
	}
	else if (Data.find("TCPDataFilter=1") == 0)
	{
		ParameterPTR->HeaderCheck_TCP = true;
	}
#endif
	else if (Data.find("DNSDataFilter=1") == 0)
	{
		ParameterPTR->HeaderCheck_DNS = true;
	}
	else if (IsFirstRead && Data.find("BlacklistFilter=1") == 0)
	{
		Parameter.DataCheck_Blacklist = true;
	}

//[Data] block
#if defined(ENABLE_PCAP)
	if (IsFirstRead && Data.find("ICMPID=") == 0 && Data.length() > strlen("ICMPID="))
	{
		if (Data.length() < strlen("ICMPID=") + 7U)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("ICMPID="), nullptr, 0);
			if (UnsignedResult > 0 && UnsignedResult < ULONG_MAX)
				Parameter.ICMP_ID = htons((uint16_t)UnsignedResult);
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (IsFirstRead && Data.find("ICMPSequence=") == 0 && Data.length() > strlen("ICMPSequence="))
	{
		if (Data.length() < strlen("ICMPSequence=") + 7U)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("ICMPSequence="), nullptr, 0);
			if (UnsignedResult > 0 && UnsignedResult < ULONG_MAX)
				Parameter.ICMP_Sequence = htons((uint16_t)UnsignedResult);
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (IsFirstRead && Data.find("ICMPPaddingData=") == 0 && Data.length() > strlen("ICMPPaddingData="))
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
	else if (IsFirstRead && Data.find("DomainTestID=") == 0 && Data.length() > strlen("DomainTestID="))
	{
		if (Data.length() < strlen("DomainTestID=") + 7U)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("DomainTestID="), nullptr, 0);
			if (UnsignedResult > 0 && UnsignedResult < ULONG_MAX)
				Parameter.DomainTest_ID = htons((uint16_t)UnsignedResult);
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (IsFirstRead && Data.find("DomainTestData=") == 0 && Data.length() > strlen("DomainTestData="))
	{
		if (Data.length() > strlen("DomainTestData=") + DOMAIN_MINSIZE && Data.length() < strlen("DomainTestData=") + DOMAIN_DATA_MAXSIZE)
			memcpy_s(Parameter.DomainTest_Data, DOMAIN_MAXSIZE, Data.c_str() + strlen("DomainTestData="), Data.length() - strlen("DomainTestData="));
		else 
			goto PrintDataFormatError;
	}
#endif
	else if (IsFirstRead && Data.find("LocalhostServerName=") == 0 && Data.length() > strlen("LocalhostServerName="))
	{
		if (Data.length() > strlen("LocalhostServerName=") + DOMAIN_MINSIZE && Data.length() < strlen("LocalhostServerName=") + DOMAIN_DATA_MAXSIZE)
		{
			uint8_t LocalFQDN[DOMAIN_MAXSIZE] = {0};
			Parameter.LocalFQDN_Length = Data.length() - strlen("LocalhostServerName=");
			memcpy_s(LocalFQDN, DOMAIN_MAXSIZE, Data.c_str() + strlen("LocalhostServerName="), Parameter.LocalFQDN_Length);
			*Parameter.LocalFQDN_String = (const char *)LocalFQDN;
			memset(Parameter.LocalFQDN_Response, 0, DOMAIN_MAXSIZE);
			UnsignedResult = CharToDNSQuery(LocalFQDN, Parameter.LocalFQDN_Response);
			if (UnsignedResult > DOMAIN_MINSIZE)
			{
				Parameter.LocalFQDN_Length = UnsignedResult;
			}
			else {
				Parameter.LocalFQDN_Length = 0;
				memset(Parameter.LocalFQDN_Response, 0, DOMAIN_MAXSIZE);
				Parameter.LocalFQDN_String->clear();
			}
		}
		else {
			goto PrintDataFormatError;
		}
	}

//[Proxy] block
	if (IsFirstRead && Data.find("SOCKSProxy=1") == 0)
	{
		Parameter.SOCKS_Proxy = true;
	}
	else if (IsFirstRead && Data.find("SOCKSVersion=") == 0 && Data.length() > strlen("SOCKSVersion="))
	{
		CaseConvert(true, Data);

		if (Data.find("4A") != std::string::npos)
			Parameter.SOCKS_Version = SOCKS_VERSION_CONFIG_4A;
		else if (Data.find("4") != std::string::npos)
			Parameter.SOCKS_Version = SOCKS_VERSION_4;
		else 
			Parameter.SOCKS_Version = SOCKS_VERSION_5;
	}
	else if (IsFirstRead && Data.find("SOCKSProtocol=") == 0)
	{
		CaseConvert(true, Data);

	//Network layer
		if (Data.find("IPV6") != std::string::npos)
		{
			if (Data.find("IPV4") != std::string::npos)
				Parameter.SOCKS_Protocol_Network = REQUEST_MODE_NETWORK_BOTH;
			else 
				Parameter.SOCKS_Protocol_Network = REQUEST_MODE_IPV6;
		}
		else {
			Parameter.SOCKS_Protocol_Network = REQUEST_MODE_IPV4;
		}

	//Transport layer
		if (Data.find("UDP") != std::string::npos)
			Parameter.SOCKS_Protocol_Transport = REQUEST_MODE_UDP;
		else 
			Parameter.SOCKS_Protocol_Transport = REQUEST_MODE_TCP;
	}
	else if (Data.find("SOCKSReliableSocketTimeout=") == 0 && Data.length() > strlen("SOCKSReliableSocketTimeout="))
	{
		if (Data.length() < strlen("SOCKSReliableSocketTimeout=") + UINT32_MAX_STRING_LENGTH)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("SOCKSReliableSocketTimeout="), nullptr, 0);
			if (UnsignedResult > SOCKET_MIN_TIMEOUT && UnsignedResult < ULONG_MAX)
			#if defined(PLATFORM_WIN)
				ParameterPTR->SOCKS_SocketTimeout_Reliable = (int)UnsignedResult;
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			{
				ParameterPTR->SOCKS_SocketTimeout_Reliable.tv_sec = UnsignedResult / SECOND_TO_MILLISECOND;
				ParameterPTR->SOCKS_SocketTimeout_Reliable.tv_usec = UnsignedResult % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
			}
			#endif
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (Data.find("SOCKSUnreliableSocketTimeout=") == 0 && Data.length() > strlen("SOCKSUnreliableSocketTimeout="))
	{
		if (Data.length() < strlen("SOCKSUnreliableSocketTimeout=") + UINT32_MAX_STRING_LENGTH)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("SOCKSUnreliableSocketTimeout="), nullptr, 0);
			if (UnsignedResult > SOCKET_MIN_TIMEOUT && UnsignedResult < ULONG_MAX)
			#if defined(PLATFORM_WIN)
				ParameterPTR->SOCKS_SocketTimeout_Unreliable = (int)UnsignedResult;
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			{
				ParameterPTR->SOCKS_SocketTimeout_Unreliable.tv_sec = UnsignedResult / SECOND_TO_MILLISECOND;
				ParameterPTR->SOCKS_SocketTimeout_Unreliable.tv_usec = UnsignedResult % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
			}
			#endif
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (IsFirstRead && Data.find("SOCKSUDPNoHandshake=1") == 0)
	{
		ParameterPTR->SOCKS_UDP_NoHandshake = true;
	}
	else if (IsFirstRead && Data.find("SOCKSProxyOnly=1") == 0)
	{
		Parameter.SOCKS_Only = true;
	}
	else if (IsFirstRead && Data.find("SOCKSIPv4Address=") == 0 && Data.length() > strlen("SOCKSIPv4Address="))
	{
		if (!ReadMultipleAddresses(Data, strlen("SOCKSIPv4Address="), AF_INET, false, Parameter.SOCKS_Address_IPv4.Storage, nullptr, FileIndex, Line))
			return false;
	}
	else if (IsFirstRead && Data.find("SOCKSIPv6Address=") == 0 && Data.length() > strlen("SOCKSIPv6Address="))
	{
		if (!ReadMultipleAddresses(Data, strlen("SOCKSIPv6Address="), AF_INET6, false, Parameter.SOCKS_Address_IPv6.Storage, nullptr, FileIndex, Line))
			return false;
	}
	else if (Data.find("SOCKSTargetServer=") == 0 && Data.length() > strlen("SOCKSTargetServer="))
	{
		if (!ReadSOCKSAddressAndDomain(Data, strlen("SOCKSTargetServer="), ParameterPTR, FileIndex, Line))
			return false;
	}
	else if (Data.find("SOCKSUsername=") == 0 && Data.length() > strlen("SOCKSUsername="))
	{
		if (Data.length() > strlen("SOCKSUsername=") + SOCKS_USERNAME_PASSWORD_MAXNUM)
		{
			ParameterPTR->SOCKS_Username->clear();
			ParameterPTR->SOCKS_Username->append(Data, strlen("SOCKSUsername="), Data.length() - strlen("SOCKSUsername="));
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (Data.find("SOCKSPassword=") == 0 && Data.length() > strlen("SOCKSPassword="))
	{
		if (Data.length() > strlen("SOCKSPassword=") + SOCKS_USERNAME_PASSWORD_MAXNUM)
		{
			ParameterPTR->SOCKS_Password->clear();
			ParameterPTR->SOCKS_Password->append(Data, strlen("SOCKSPassword="), Data.length() - strlen("SOCKSPassword="));
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (IsFirstRead && Data.find("HTTPProxy=1") == 0)
	{
		Parameter.HTTP_Proxy = true;
	}
	else if (IsFirstRead && Data.find("HTTPProtocol=") == 0)
	{
		CaseConvert(true, Data);
		if (Data.find("IPV6") != std::string::npos)
		{
			if (Data.find("IPV4") != std::string::npos)
				Parameter.HTTP_Protocol = REQUEST_MODE_NETWORK_BOTH;
			else 
				Parameter.HTTP_Protocol = REQUEST_MODE_IPV6;
		}
		else {
			Parameter.HTTP_Protocol = REQUEST_MODE_IPV4;
		}
	}
	else if (Data.find("HTTPSocketTimeout=") == 0 && Data.length() > strlen("HTTPSocketTimeout="))
	{
		if (Data.length() < strlen("HTTPSocketTimeout=") + UINT32_MAX_STRING_LENGTH)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("HTTPSocketTimeout="), nullptr, 0);
			if (UnsignedResult > SOCKET_MIN_TIMEOUT && UnsignedResult < ULONG_MAX)
			#if defined(PLATFORM_WIN)
				ParameterPTR->HTTP_SocketTimeout = (int)UnsignedResult;
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			{
				ParameterPTR->HTTP_SocketTimeout.tv_sec = UnsignedResult / SECOND_TO_MILLISECOND;
				ParameterPTR->HTTP_SocketTimeout.tv_usec = UnsignedResult % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
			}
			#endif
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (IsFirstRead && Data.find("HTTPProxyOnly=1") == 0)
	{
		Parameter.HTTP_Only = true;
	}
	else if (IsFirstRead && Data.find("HTTPIPv4Address=") == 0 && Data.length() > strlen("HTTPIPv4Address="))
	{
		if (!ReadMultipleAddresses(Data, strlen("HTTPIPv4Address="), AF_INET, false, Parameter.HTTP_Address_IPv4.Storage, nullptr, FileIndex, Line))
			return false;
	}
	else if (IsFirstRead && Data.find("HTTPIPv6Address=") == 0 && Data.length() > strlen("HTTPIPv6Address="))
	{
		if (!ReadMultipleAddresses(Data, strlen("HTTPIPv6Address="), AF_INET6, false, Parameter.HTTP_Address_IPv6.Storage, nullptr, FileIndex, Line))
			return false;
	}
	else if (Data.find("HTTPTargetServer=") == 0 && Data.length() > strlen("HTTPTargetServer="))
	{
		ParameterPTR->HTTP_TargetDomain->clear();
		ParameterPTR->HTTP_TargetDomain->append(Data, strlen("HTTPTargetServer="), Data.length() - strlen("HTTPTargetServer="));
	}
	else if (Data.find("HTTPVersion=") == 0 && Data.length() > strlen("HTTPVersion="))
	{
		ParameterPTR->HTTP_Version->clear();
		ParameterPTR->HTTP_Version->append(Data, strlen("HTTPVersion="), Data.length() - strlen("HTTPVersion="));
	}
	else if (Data.find("HTTP Header Field = ") == 0 && Data.length() > strlen("HTTP Header Field = "))
	{
		ParameterPTR->HTTP_HeaderField->append(Data, strlen("HTTP Header Field = "), Data.length() - strlen("HTTP Header Field = "));
		ParameterPTR->HTTP_HeaderField->append("\r\n");
	}
	else if (Data.find("HTTPProxyAuthorization=") == 0 && Data.length() > strlen("HTTPProxyAuthorization="))
	{
		std::shared_ptr<uint8_t> ProxyAuthorization(new uint8_t[BASE64_ENCODE_OUT_SIZE(Data.length() - strlen("HTTPProxyAuthorization=")) + 1U]);
		memset(ProxyAuthorization.get(), 0, BASE64_ENCODE_OUT_SIZE(Data.length() - strlen("HTTPProxyAuthorization=")) + 1U);
		Base64_Encode((uint8_t *)(Data.c_str() + strlen("HTTPProxyAuthorization=")), Data.length() - strlen("HTTPProxyAuthorization="), ProxyAuthorization.get(), BASE64_ENCODE_OUT_SIZE(Data.length() - strlen("HTTPProxyAuthorization=")));
		ParameterPTR->HTTP_ProxyAuthorization->clear();
		ParameterPTR->HTTP_ProxyAuthorization->append("Proxy-Authentication: Basic ");
		ParameterPTR->HTTP_ProxyAuthorization->append((const char *)ProxyAuthorization.get());
		ParameterPTR->HTTP_ProxyAuthorization->append("\r\n");
	}

//[DNSCurve] block
#if defined(ENABLE_LIBSODIUM)
	if (IsFirstRead && Data.find("DNSCurve=1") == 0)
	{
		Parameter.DNSCurve = true;
	}
	else if (IsFirstRead && Data.find("DNSCurveProtocol=") == 0)
	{
		CaseConvert(true, Data);

	//Network layer
		if (Data.find("IPV6") != std::string::npos)
		{
			if (Data.find("IPV4") != std::string::npos)
				DNSCurveParameter.DNSCurveProtocol_Network = REQUEST_MODE_NETWORK_BOTH;
			else 
				DNSCurveParameter.DNSCurveProtocol_Network = REQUEST_MODE_IPV6;
		}
		else {
			DNSCurveParameter.DNSCurveProtocol_Network = REQUEST_MODE_IPV4;
		}

	//Transport layer
		if (Data.find("TCP") != std::string::npos)
			DNSCurveParameter.DNSCurveProtocol_Transport = REQUEST_MODE_TCP;
		else 
			DNSCurveParameter.DNSCurveProtocol_Transport = REQUEST_MODE_UDP;
	}
	else if (IsFirstRead && Data.find("DNSCurvePayloadSize=") == 0 && Data.length() > strlen("DNSCurvePayloadSize="))
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
		else if (Data.find("DNSCurveReliableSocketTimeout=") == 0 && Data.length() > strlen("DNSCurveReliableSocketTimeout="))
	{
		if (Data.length() < strlen("DNSCurveReliableSocketTimeout=") + UINT32_MAX_STRING_LENGTH)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("DNSCurveReliableSocketTimeout="), nullptr, 0);
			if (UnsignedResult > SOCKET_MIN_TIMEOUT && UnsignedResult < ULONG_MAX)
			#if defined(PLATFORM_WIN)
				DNSCurveParameterPTR->DNSCurve_SocketTimeout_Reliable = (int)UnsignedResult;
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			{
				DNSCurveParameterPTR->DNSCurve_SocketTimeout_Reliable.tv_sec = UnsignedResult / SECOND_TO_MILLISECOND;
				DNSCurveParameterPTR->DNSCurve_SocketTimeout_Reliable.tv_usec = UnsignedResult % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
			}
			#endif
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (Data.find("DNSCurveUnreliableSocketTimeout=") == 0 && Data.length() > strlen("DNSCurveUnreliableSocketTimeout="))
	{
		if (Data.length() < strlen("DNSCurveUnreliableSocketTimeout=") + UINT32_MAX_STRING_LENGTH)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("DNSCurveUnreliableSocketTimeout="), nullptr, 0);
			if (UnsignedResult > SOCKET_MIN_TIMEOUT && UnsignedResult < ULONG_MAX)
			#if defined(PLATFORM_WIN)
				DNSCurveParameterPTR->DNSCurve_SocketTimeout_Unreliable = (int)UnsignedResult;
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			{
				DNSCurveParameterPTR->DNSCurve_SocketTimeout_Unreliable.tv_sec = UnsignedResult / SECOND_TO_MILLISECOND;
				DNSCurveParameterPTR->DNSCurve_SocketTimeout_Unreliable.tv_usec = UnsignedResult % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
			}
			#endif
		}
		else {
			goto PrintDataFormatError;
		}
	}
	else if (IsFirstRead && Data.find("Encryption=1") == 0)
	{
		DNSCurveParameter.IsEncryption = true;
	}
	else if (IsFirstRead && Data.find("EncryptionOnly=1") == 0)
	{
		DNSCurveParameter.IsEncryptionOnly = true;
	}
	else if (Data.find("ClientEphemeralKey=1") == 0)
	{
		DNSCurveParameter.ClientEphemeralKey = true;
	}
	else if (Data.find("KeyRecheckTime=") == 0 && Data.length() > strlen("KeyRecheckTime="))
	{
		if (Data.length() < strlen("KeyRecheckTime=") + UINT16_MAX_STRING_LENGTH)
		{
			_set_errno(0);
			UnsignedResult = strtoul(Data.c_str() + strlen("KeyRecheckTime="), nullptr, 0);
			if (UnsignedResult >= SHORTEST_DNSCURVE_RECHECK_TIME && UnsignedResult < ULONG_MAX)
				DNSCurveParameterPTR->KeyRecheckTime = UnsignedResult * SECOND_TO_MILLISECOND;
		}
		else {
			goto PrintDataFormatError;
		}
	}

//[DNSCurve Addresses] block
	if (IsFirstRead && Data.find("DNSCurveIPv4DNSAddress=") == 0 && Data.length() > strlen("DNSCurveIPv4DNSAddress="))
	{
		if (!ReadMultipleAddresses(Data, strlen("DNSCurveIPv4DNSAddress="), AF_INET, false, DNSCurveParameter.DNSCurve_Target_Server_IPv4.AddressData.Storage, nullptr, FileIndex, Line))
			return false;
	}
	else if (IsFirstRead && Data.find("DNSCurveIPv4AlternateDNSAddress=") == 0 && Data.length() > strlen("DNSCurveIPv4AlternateDNSAddress="))
	{
		if (!ReadMultipleAddresses(Data, strlen("DNSCurveIPv4AlternateDNSAddress="), AF_INET, false, DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.AddressData.Storage, nullptr, FileIndex, Line))
			return false;
	}
	else if (IsFirstRead && Data.find("DNSCurveIPv6DNSAddress=") == 0 && Data.length() > strlen("DNSCurveIPv6DNSAddress="))
	{
		if (!ReadMultipleAddresses(Data, strlen("DNSCurveIPv6DNSAddress="), AF_INET6, false, DNSCurveParameter.DNSCurve_Target_Server_IPv6.AddressData.Storage, nullptr, FileIndex, Line))
			return false;
	}
	else if (IsFirstRead && Data.find("DNSCurveIPv6AlternateDNSAddress=") == 0 && Data.length() > strlen("DNSCurveIPv6AlternateDNSAddress="))
	{
		if (!ReadMultipleAddresses(Data, strlen("DNSCurveIPv6AlternateDNSAddress="), AF_INET6, false, DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.AddressData.Storage, nullptr, FileIndex, Line))
			return false;
	}
	else if (IsFirstRead && Data.find("DNSCurveIPv4ProviderName=") == 0 && Data.length() > strlen("DNSCurveIPv4ProviderName="))
	{
		if (!ReadDNSCurveProviderName(Data, strlen("DNSCurveIPv4ProviderName="), DNSCurveParameter.DNSCurve_Target_Server_IPv4.ProviderName, FileIndex, Line))
			return false;
	}
	else if (IsFirstRead && Data.find("DNSCurveIPv4AlternateProviderName=") == 0 && Data.length() > strlen("DNSCurveIPv4AlternateProviderName="))
	{
		if (!ReadDNSCurveProviderName(Data, strlen("DNSCurveIPv4AlternateProviderName="), DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ProviderName, FileIndex, Line))
			return false;
	}
	else if (IsFirstRead && Data.find("DNSCurveIPv6ProviderName=") == 0 && Data.length() > strlen("DNSCurveIPv6ProviderName="))
	{
		if (!ReadDNSCurveProviderName(Data, strlen("DNSCurveIPv6ProviderName="), DNSCurveParameter.DNSCurve_Target_Server_IPv6.ProviderName, FileIndex, Line))
			return false;
	}
	else if (IsFirstRead && Data.find("DNSCurveIPv6AlternateProviderName=") == 0 && Data.length() > strlen("DNSCurveIPv6AlternateProviderName="))
	{
		if (!ReadDNSCurveProviderName(Data, strlen("DNSCurveIPv6AlternateProviderName="), DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ProviderName, FileIndex, Line))
			return false;
	}

//[DNSCurve Keys] block
	if (Data.find("ClientPublicKey=") == 0 && Data.length() > strlen("ClientPublicKey="))
	{
		if (!ReadDNSCurveKey(Data, strlen("ClientPublicKey="), DNSCurveParameterPTR->Client_PublicKey, FileIndex, Line))
			return false;
	}
	else if (Data.find("ClientSecretKey=") == 0 && Data.length() > strlen("ClientSecretKey="))
	{
		if (!ReadDNSCurveKey(Data, strlen("ClientSecretKey="), DNSCurveParameterPTR->Client_SecretKey, FileIndex, Line))
			return false;
	}
	else if (Data.find("IPv4DNSPublicKey=") == 0 && Data.length() > strlen("IPv4DNSPublicKey="))
	{
		if (!ReadDNSCurveKey(Data, strlen("IPv4DNSPublicKey="), DNSCurveParameterPTR->DNSCurve_Target_Server_IPv4.ServerPublicKey, FileIndex, Line))
			return false;
	}
	else if (Data.find("IPv4AlternateDNSPublicKey=") == 0 && Data.length() > strlen("IPv4AlternateDNSPublicKey="))
	{
		if (!ReadDNSCurveKey(Data, strlen("IPv4AlternateDNSPublicKey="), DNSCurveParameterPTR->DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey, FileIndex, Line))
			return false;
	}
	else if (Data.find("IPv6DNSPublicKey=") == 0 && Data.length() > strlen("IPv6DNSPublicKey="))
	{
		if (!ReadDNSCurveKey(Data, strlen("IPv6DNSPublicKey="), DNSCurveParameterPTR->DNSCurve_Target_Server_IPv6.ServerPublicKey, FileIndex, Line))
			return false;
	}
	else if (Data.find("IPv6AlternateDNSPublicKey=") == 0 && Data.length() > strlen("IPv6AlternateDNSPublicKey="))
	{
		if (!ReadDNSCurveKey(Data, strlen("IPv6AlternateDNSPublicKey="), DNSCurveParameterPTR->DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey, FileIndex, Line))
			return false;
	}
	else if (Data.find("IPv4DNSFingerprint=") == 0 && Data.length() > strlen("IPv4DNSFingerprint="))
	{
		if (!ReadDNSCurveKey(Data, strlen("IPv4DNSFingerprint="), DNSCurveParameterPTR->DNSCurve_Target_Server_IPv4.ServerFingerprint, FileIndex, Line))
			return false;
	}
	else if (Data.find("IPv4AlternateDNSFingerprint=") == 0 && Data.length() > strlen("IPv4AlternateDNSFingerprint="))
	{
		if (!ReadDNSCurveKey(Data, strlen("IPv4AlternateDNSFingerprint="), DNSCurveParameterPTR->DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint, FileIndex, Line))
			return false;
	}
	else if (Data.find("IPv6DNSFingerprint=") == 0 && Data.length() > strlen("IPv6DNSFingerprint="))
	{
		if (!ReadDNSCurveKey(Data, strlen("IPv6DNSFingerprint="), DNSCurveParameterPTR->DNSCurve_Target_Server_IPv6.ServerFingerprint, FileIndex, Line))
			return false;
	}
	else if (Data.find("IPv6AlternateDNSFingerprint=") == 0 && Data.length() > strlen("IPv6AlternateDNSFingerprint="))
	{
		if (!ReadDNSCurveKey(Data, strlen("IPv6AlternateDNSFingerprint="), DNSCurveParameterPTR->DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint, FileIndex, Line))
			return false;
	}

//[DNSCurve Magic Number] block
	if (Data.find("IPv4ReceiveMagicNumber=") == 0 && Data.length() > strlen("IPv4ReceiveMagicNumber="))
	{
		if (!ReadDNSCurveMagicNumber(Data, strlen("IPv4ReceiveMagicNumber="), DNSCurveParameterPTR->DNSCurve_Target_Server_IPv4.ReceiveMagicNumber, FileIndex, Line))
			return false;
	}
	else if (Data.find("IPv4AlternateReceiveMagicNumber=") == 0 && Data.length() > strlen("IPv4AlternateReceiveMagicNumber="))
	{
		if (!ReadDNSCurveMagicNumber(Data, strlen("IPv4AlternateReceiveMagicNumber="), DNSCurveParameterPTR->DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber, FileIndex, Line))
			return false;
	}
	else if (Data.find("IPv6ReceiveMagicNumber=") == 0 && Data.length() > strlen("IPv6ReceiveMagicNumber="))
	{
		if (!ReadDNSCurveMagicNumber(Data, strlen("IPv6ReceiveMagicNumber="), DNSCurveParameterPTR->DNSCurve_Target_Server_IPv6.ReceiveMagicNumber, FileIndex, Line))
			return false;
	}
	else if (Data.find("IPv6AlternateReceiveMagicNumber=") == 0 && Data.length() > strlen("IPv6AlternateReceiveMagicNumber="))
	{
		if (!ReadDNSCurveMagicNumber(Data, strlen("IPv6AlternateReceiveMagicNumber="), DNSCurveParameterPTR->DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber, FileIndex, Line))
			return false;
	}
	else if (Data.find("IPv4DNSMagicNumber=") == 0 && Data.length() > strlen("IPv4DNSMagicNumber="))
	{
		if (!ReadDNSCurveMagicNumber(Data, strlen("IPv4DNSMagicNumber="), DNSCurveParameterPTR->DNSCurve_Target_Server_IPv4.SendMagicNumber, FileIndex, Line))
			return false;
	}
	else if (Data.find("IPv4AlternateDNSMagicNumber=") == 0 && Data.length() > strlen("IPv4AlternateDNSMagicNumber="))
	{
		if (!ReadDNSCurveMagicNumber(Data, strlen("IPv4AlternateDNSMagicNumber="), DNSCurveParameterPTR->DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber, FileIndex, Line))
			return false;
	}
	else if (Data.find("IPv6DNSMagicNumber=") == 0 && Data.length() > strlen("IPv6DNSMagicNumber="))
	{
		if (!ReadDNSCurveMagicNumber(Data, strlen("IPv6DNSMagicNumber="), DNSCurveParameterPTR->DNSCurve_Target_Server_IPv6.SendMagicNumber, FileIndex, Line))
			return false;
	}
	else if (Data.find("IPv6AlternateDNSMagicNumber=") == 0 && Data.length() > strlen("IPv6AlternateDNSMagicNumber="))
	{
		if (!ReadDNSCurveMagicNumber(Data, strlen("IPv6AlternateDNSMagicNumber="), DNSCurveParameterPTR->DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber, FileIndex, Line))
			return false;
	}
#endif

	return true;

//Label of printing data format error
PrintDataFormatError:
	PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"Data format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
	return false;
}

//Read file names from data
#if defined(PLATFORM_WIN)
bool ReadPathAndFileName(
	std::string Data, 
	const size_t DataOffset, 
	const bool Path, 
	std::vector<std::wstring> *ListData, 
	const size_t FileIndex, 
	const size_t Line)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
bool ReadPathAndFileName(
	std::string Data, 
	const size_t DataOffset, 
	const bool Path, 
	std::vector<std::wstring> *ListData, 
	std::vector<std::string> *sListData, 
	const size_t FileIndex, const size_t Line)
#endif
{
//Initialization
	std::vector<std::string> InnerListData;
	std::wstring wNameString;
	GetParameterListData(InnerListData, Data, DataOffset, Data.length());

//Read file path.
	if (Path)
	{
	//Mark all data in list.
		for (auto StringIter:InnerListData)
		{
		//Add backslash or slash.
		#if defined(PLATFORM_WIN)
			if (StringIter.back() != ASCII_BACKSLASH)
				StringIter.append("\\");
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			if (StringIter.back() != ASCII_SLASH)
				StringIter.append("/");
		#endif

		//Convert to wide string.
			if (!MBSToWCSString((const uint8_t *)StringIter.c_str(), StringIter.length(), wNameString))
			{
				PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"Read file path error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Double backslash
		#if defined(PLATFORM_WIN)
			for (size_t Index = 0;Index < wNameString.length();++Index)
			{
				if (wNameString.at(Index) == L'\\')
				{
					wNameString.insert(Index, L"\\");
					++Index;
				}
			}
		#endif

		//Add to global list.
			for (auto InnerStringIter = GlobalRunningStatus.Path_Global->begin();InnerStringIter < GlobalRunningStatus.Path_Global->end();++InnerStringIter)
			{
				if (*InnerStringIter == wNameString)
				{
					break;
				}
				else if (InnerStringIter + 1U == GlobalRunningStatus.Path_Global->end())
				{
					GlobalRunningStatus.Path_Global->push_back(wNameString);
					break;
				}
			}

		#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			for (auto InnerStringIter = GlobalRunningStatus.sPath_Global->begin();InnerStringIter < GlobalRunningStatus.sPath_Global->end();++InnerStringIter)
			{
				if (*InnerStringIter == StringIter)
				{
					break;
				}
				else if (InnerStringIter + 1U == GlobalRunningStatus.sPath_Global->end())
				{
					GlobalRunningStatus.sPath_Global->push_back(StringIter);
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
			if (!MBSToWCSString((const uint8_t *)StringIter.c_str(), StringIter.length(), wNameString))
			{
				PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"Read file path error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Add to global list.
			if (ListData->empty())
			{
				ListData->push_back(wNameString);
			}
			else {
				for (auto InnerStringIter = ListData->begin();InnerStringIter != ListData->end();++InnerStringIter)
				{
					if (*InnerStringIter == wNameString)
					{
						break;
					}
					else if (InnerStringIter + 1U == ListData->end())
					{
						ListData->push_back(wNameString);
						break;
					}
				}
			}

		#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			if (sListData->empty())
			{
				sListData->push_back(StringIter);
			}
			else {
				for (auto InnerStringIter = sListData->begin();InnerStringIter != sListData->end();++InnerStringIter)
				{
					if (*InnerStringIter == StringIter)
					{
						break;
					}
					else if (InnerStringIter + 1U == sListData->end())
					{
						sListData->push_back(StringIter);
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
	std::string Data, 
	const size_t DataOffset, 
	const uint16_t Protocol, 
	const bool IsMultiAddresses, 
	sockaddr_storage &SockAddr, 
	std::vector<sockaddr_storage> *SockAddrList, 
	const size_t FileIndex, 
	const size_t Line)
{
//Initialization
	DNS_SERVER_DATA DNSServerDataTemp;
	memset(&DNSServerDataTemp, 0, sizeof(DNSServerDataTemp));
	uint8_t Target[ADDR_STRING_MAXSIZE] = {0};
	std::vector<std::string> ListData;
	ssize_t SignedResult = 0;
	size_t UnsignedResult = 0;
	GetParameterListData(ListData, Data, DataOffset, Data.length());

//IPv6
	if (Protocol == AF_INET6)
	{
	//Mark all data in list.
		for (const auto &StringIter:ListData)
		{
		//IPv6 address and port check.
			if (StringIter.find(ASCII_BRACKETS_LEFT) == std::string::npos || StringIter.find(ASCII_BRACKETS_RIGHT) == std::string::npos || 
				StringIter.find("]:") == std::string::npos || StringIter.find(ASCII_BRACKETS_RIGHT) <= strlen("[") || 
				StringIter.find(ASCII_BRACKETS_RIGHT) < IPV6_SHORTEST_ADDRSTRING || StringIter.length() <= StringIter.find("]:") + strlen("]:"))
			{
				PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"IPv6 address format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Convert IPv6 address.
			memset(Target, 0, ADDR_STRING_MAXSIZE);
			memcpy_s(Target, ADDR_STRING_MAXSIZE, StringIter.c_str() + strlen("["), StringIter.find(ASCII_BRACKETS_RIGHT) - strlen("["));
			if (!AddressStringToBinary(Target, AF_INET6, &DNSServerDataTemp.AddressData.IPv6.sin6_addr, &SignedResult))
			{
				PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"IPv6 address format error", SignedResult, FileList_Config.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Convert IPv6 port.
			memset(Target, 0, ADDR_STRING_MAXSIZE);
			memcpy_s(Target, ADDR_STRING_MAXSIZE, StringIter.c_str() + StringIter.find("]:") + strlen("]:"), StringIter.length() - (StringIter.find("]:") + strlen("]:")));
			UnsignedResult = ServiceNameToBinary(Target);
			if (UnsignedResult == 0)
			{
				_set_errno(0);
				UnsignedResult = strtoul((const char *)Target, nullptr, 0);
				if (UnsignedResult <= 0 || UnsignedResult >= ULONG_MAX)
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"IPv6 address port error", errno, FileList_Config.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
			}
			DNSServerDataTemp.AddressData.IPv6.sin6_port = htons((uint16_t)UnsignedResult);

		//Add to global list.
			DNSServerDataTemp.AddressData.Storage.ss_family = AF_INET6;
			if (SockAddrList != nullptr)
			{
				SockAddrList->push_back(DNSServerDataTemp.AddressData.Storage);
			}
			else if (SockAddr.ss_family > 0)
			{
				if (!IsMultiAddresses)
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"IPv6 address format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
				else {
					Parameter.Target_Server_IPv6_Multi->push_back(DNSServerDataTemp);
				}
			}
			else {
				memcpy_s(&SockAddr, sizeof(SockAddr), &DNSServerDataTemp.AddressData.Storage, sizeof(DNSServerDataTemp.AddressData.Storage));
			}
		}
	}
//IPv4
	else {
	//Mark all data in list.
		for (const auto &StringIter:ListData)
		{
			memset(&DNSServerDataTemp, 0, sizeof(DNSServerDataTemp));

		//IPv4 address and port check.
			if (StringIter.find(ASCII_COLON) == std::string::npos || StringIter.find(ASCII_PERIOD) == std::string::npos || 
				StringIter.find(ASCII_COLON) < IPV4_SHORTEST_ADDRSTRING || StringIter.length() <= StringIter.find(ASCII_COLON) + strlen(":"))
			{
				PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"IPv4 address format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Convert IPv4 address.
			memset(Target, 0, ADDR_STRING_MAXSIZE);
			memcpy_s(Target, ADDR_STRING_MAXSIZE, StringIter.c_str(), StringIter.find(ASCII_COLON));
			if (!AddressStringToBinary(Target, AF_INET, &DNSServerDataTemp.AddressData.IPv4.sin_addr, &SignedResult))
			{
				PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"IPv4 address format error", SignedResult, FileList_Config.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Convert IPv4 port.
			memset(Target, 0, ADDR_STRING_MAXSIZE);
			memcpy_s(Target, ADDR_STRING_MAXSIZE, StringIter.c_str() + StringIter.find(ASCII_COLON) + strlen(":"), StringIter.length() - (StringIter.find(ASCII_COLON) + strlen(":")));
			UnsignedResult = ServiceNameToBinary(Target);
			if (UnsignedResult == 0)
			{
				_set_errno(0);
				UnsignedResult = strtoul((const char *)Target, nullptr, 0);
				if (UnsignedResult <= 0 || UnsignedResult >= ULONG_MAX)
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"IPv4 address port error", errno, FileList_Config.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
			}
			DNSServerDataTemp.AddressData.IPv4.sin_port = htons((uint16_t)UnsignedResult);

		//Add to global list.
			DNSServerDataTemp.AddressData.Storage.ss_family = AF_INET;
			if (SockAddrList != nullptr)
			{
				SockAddrList->push_back(DNSServerDataTemp.AddressData.Storage);
			}
			else if (SockAddr.ss_family > 0)
			{
				if (!IsMultiAddresses)
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"IPv4 address format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
				else {
					Parameter.Target_Server_IPv4_Multi->push_back(DNSServerDataTemp);
				}
			}
			else {
				memcpy_s(&SockAddr, sizeof(SockAddr), &DNSServerDataTemp.AddressData.Storage, sizeof(DNSServerDataTemp.AddressData.Storage));
			}
		}
	}

	return true;
}

//Read address or domain of SOCKS
bool ReadSOCKSAddressAndDomain(
	std::string Data, 
	const size_t DataOffset, 
	CONFIGURATION_TABLE *ParameterPTR, 
	const size_t FileIndex, 
	const size_t Line)
{
//Data check
	if (Data.find(ASCII_COLON) == std::string::npos)
	{
		PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"Data length error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Initialization
	uint8_t Target[ADDR_STRING_MAXSIZE] = {0};
	ssize_t SignedResult = 0;
	size_t UnsignedResult = 0;

//IPv6
	if (Data.find(ASCII_BRACKETS_LEFT) != std::string::npos || Data.find(ASCII_BRACKETS_RIGHT) != std::string::npos)
	{
		if (Data.find("]:") == std::string::npos || Data.find(ASCII_BRACKETS_RIGHT) <= DataOffset + strlen("[") || 
			Data.find(ASCII_BRACKETS_RIGHT) < DataOffset + IPV6_SHORTEST_ADDRSTRING || Data.length() <= Data.find("]:") + strlen("]:"))
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"IPv6 address format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
		else {
		//Convert IPv6 address.
			memcpy_s(Target, ADDR_STRING_MAXSIZE, Data.c_str() + DataOffset + strlen("["), Data.find(ASCII_BRACKETS_RIGHT) - (DataOffset + strlen("[")));
			if (!AddressStringToBinary(Target, AF_INET6, &ParameterPTR->SOCKS_TargetServer.IPv6.sin6_addr, &SignedResult))
			{
				PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"IPv6 address format error", SignedResult, FileList_Config.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Convert IPv6 port.
			memset(Target, 0, ADDR_STRING_MAXSIZE);
			memcpy_s(Target, ADDR_STRING_MAXSIZE, Data.c_str() + Data.find("]:") + strlen("]:"), Data.length() - (Data.find("]:") + strlen("]:")));
			UnsignedResult = ServiceNameToBinary(Target);
			if (UnsignedResult == 0)
			{
				_set_errno(0);
				UnsignedResult = strtoul((const char *)Target, nullptr, 0);
				if (UnsignedResult <= 0 || UnsignedResult >= ULONG_MAX)
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"IPv6 address port error", errno, FileList_Config.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
			}

			ParameterPTR->SOCKS_TargetServer.IPv6.sin6_port = htons((uint16_t)UnsignedResult);
			ParameterPTR->SOCKS_TargetServer.Storage.ss_family = AF_INET6;
		}
	}
	else {
	//Format error
		if (Data.find(ASCII_PERIOD) == std::string::npos)
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"IPv6 address format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
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
			ParameterPTR->SOCKS_TargetDomain->clear();
			ParameterPTR->SOCKS_TargetDomain->append(Data, DataOffset, Data.find(ASCII_COLON) - DataOffset);

		//Convert port.
			memcpy_s(Target, ADDR_STRING_MAXSIZE, Data.c_str() + Data.find(ASCII_COLON) + strlen(":"), Data.length() - (Data.find(ASCII_COLON) + strlen(":")));
			UnsignedResult = ServiceNameToBinary(Target);
			if (UnsignedResult == 0)
			{
				_set_errno(0);
				UnsignedResult = strtoul((const char *)Target, nullptr, 0);
				if (UnsignedResult <= 0 || UnsignedResult >= ULONG_MAX)
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"IPv4 address port error", errno, FileList_Config.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
			}

			ParameterPTR->SOCKS_TargetDomain_Port = htons((uint16_t)UnsignedResult);
		}
	//IPv4
		else {
		//IPv4 address and port check.
			if (Data.find(ASCII_COLON) == std::string::npos || Data.find(ASCII_PERIOD) == std::string::npos || 
				Data.find(ASCII_COLON) < DataOffset + IPV4_SHORTEST_ADDRSTRING || Data.length() <= Data.find(ASCII_COLON) + strlen(":"))
			{
				PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"IPv4 address format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Convert IPv4 address.
			memcpy_s(Target, ADDR_STRING_MAXSIZE, Data.c_str() + DataOffset, Data.find(ASCII_COLON) - DataOffset);
			if (!AddressStringToBinary(Target, AF_INET, &ParameterPTR->SOCKS_TargetServer.IPv4.sin_addr, &SignedResult))
			{
				PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"IPv4 address format error", SignedResult, FileList_Config.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Convert IPv4 port.
			memset(Target, 0, ADDR_STRING_MAXSIZE);
			memcpy_s(Target, ADDR_STRING_MAXSIZE, Data.c_str() + Data.find(ASCII_COLON) + strlen(":"), Data.length() - (Data.find(ASCII_COLON) + strlen(":")));
			UnsignedResult = ServiceNameToBinary(Target);
			if (UnsignedResult == 0)
			{
				_set_errno(0);
				UnsignedResult = strtoul((const char *)Target, nullptr, 0);
				if (UnsignedResult <= 0 || UnsignedResult >= ULONG_MAX)
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"IPv4 address port error", errno, FileList_Config.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
			}

			ParameterPTR->SOCKS_TargetServer.IPv4.sin_port = htons((uint16_t)UnsignedResult);
			ParameterPTR->SOCKS_TargetServer.Storage.ss_family = AF_INET;
		}
	}

	return true;
}

//Read TTL or HopLimit from data
#if defined(ENABLE_PCAP)
bool ReadHopLimitData(
	std::string Data, 
	const size_t DataOffset, 
	const uint16_t Protocol, 
	uint8_t &HopLimit, 
	const size_t FileIndex, 
	const size_t Line)
{
	HopLimit = 0;
	if (Data.length() > DataOffset && Data.length() < DataOffset + ADDR_STRING_MAXSIZE)
	{
		std::vector<std::string> ListData;
		GetParameterListData(ListData, Data, DataOffset, Data.length());
		size_t Index = 0, UnsignedResult = 0;

	//Mark all data in list.
		for (const auto &StringIter:ListData)
		{
			_set_errno(0);
			UnsignedResult = strtoul(StringIter.c_str(), nullptr, 0);
			if (Index == 0)
			{
				if (UnsignedResult > 0 && UnsignedResult < UINT8_MAX)
					HopLimit = (uint8_t)UnsignedResult;
			}
			else {
				if (Protocol == AF_INET6) //IPv6
				{
				//Check queue.
					for (size_t InnerIndex = 0;InnerIndex < Parameter.Target_Server_IPv6_Multi->size();++InnerIndex)
					{
						if (Parameter.Target_Server_IPv6_Multi->at(InnerIndex).HopLimitData.HopLimit == 0)
						{
							Index = InnerIndex;
							break;
						}
					}

				//Convert Hop Limit value.
					if (UnsignedResult > 0 && UnsignedResult < UINT8_MAX && Parameter.Target_Server_IPv6_Multi->size() + 1U > Index)
						Parameter.Target_Server_IPv6_Multi->at(Index - 1U).HopLimitData.HopLimit = (uint8_t)UnsignedResult;
				}
				else { //IPv4
				//Check queue.
					for (size_t InnerIndex = 0;InnerIndex < Parameter.Target_Server_IPv4_Multi->size();++InnerIndex)
					{
						if (Parameter.Target_Server_IPv4_Multi->at(InnerIndex).HopLimitData.TTL == 0)
						{
							Index = InnerIndex;
							break;
						}
					}

				//Convert Hop Limit value.
					if (UnsignedResult > 0 && UnsignedResult < UINT8_MAX && Parameter.Target_Server_IPv4_Multi->size() + 1U > Index)
						Parameter.Target_Server_IPv4_Multi->at(Index - 1U).HopLimitData.TTL = (uint8_t)UnsignedResult;
				}
			}

			++Index;
		}
	}
	else {
		PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"Data length error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

	return true;
}
#endif

//Read Provider Name of DNSCurve server
#if defined(ENABLE_LIBSODIUM)
bool ReadDNSCurveProviderName(
	std::string Data, 
	const size_t DataOffset, 
	uint8_t *ProviderNameData, 
	const size_t FileIndex, 
	const size_t Line)
{
	sodium_memzero(ProviderNameData, DOMAIN_MAXSIZE);
	if (Data.length() > DataOffset + DOMAIN_MINSIZE && Data.length() < DataOffset + DOMAIN_DATA_MAXSIZE)
	{
		for (size_t Index = DataOffset;Index < Data.length() - DataOffset;++Index)
		{
			for (size_t InnerIndex = 0;InnerIndex < strnlen_s((const char *)GlobalRunningStatus.DomainTable, DOMAIN_MAXSIZE);++InnerIndex)
			{
				if (InnerIndex == strnlen_s((const char *)GlobalRunningStatus.DomainTable, DOMAIN_MAXSIZE) - 1U && Data.at(Index) != *(GlobalRunningStatus.DomainTable + InnerIndex))
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"DNSCurve Provider Name error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
					return false;
				}

				if (Data.at(Index) == *(GlobalRunningStatus.DomainTable + InnerIndex))
					break;
			}
		}

		memcpy_s(ProviderNameData, DOMAIN_MAXSIZE, Data.c_str() + DataOffset, Data.length() - DataOffset);
	}
	else {
		PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"Data length error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

	return true;
}

//Read DNSCurve secret keys, public keys and fingerprints
bool ReadDNSCurveKey(
	std::string Data, 
	const size_t DataOffset, 
	uint8_t *KeyData, 
	const size_t FileIndex, 
	const size_t Line)
{
	memset(KeyData, 0, crypto_box_SECRETKEYBYTES);

//Initialization
	uint8_t Target[ADDR_STRING_MAXSIZE] = {0};
	const char *ResultPointer = nullptr;
	size_t ResultLength = 0;

//Convert hex format to binary.
	if (Data.length() > DataOffset + crypto_box_PUBLICKEYBYTES * 2U && Data.length() < DataOffset + crypto_box_PUBLICKEYBYTES * 3U)
	{
		auto Result = sodium_hex2bin(Target, ADDR_STRING_MAXSIZE, Data.c_str() + DataOffset, Data.length() - DataOffset, ": ", &ResultLength, &ResultPointer);
		if (Result == 0 && ResultLength == crypto_box_PUBLICKEYBYTES && ResultPointer != nullptr)
		{
			memcpy_s(KeyData, crypto_box_SECRETKEYBYTES, Target, crypto_box_PUBLICKEYBYTES);
		}
		else {
			PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"DNSCurve Key format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
	}
	else {
		PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"Data length error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

	return true;
}

//Read DNSCurve magic number
bool ReadDNSCurveMagicNumber(
	std::string Data, 
	const size_t DataOffset, 
	uint8_t *MagicNumber, 
	const size_t FileIndex, 
	const size_t Line)
{
	memset(MagicNumber, 0, DNSCURVE_MAGIC_QUERY_LEN);

//Binary format
	if (Data.find("0x") == DataOffset && Data.length() == DataOffset + DNSCURVE_MAGIC_QUERY_HEX_LEN + strlen("0x"))
	{
	//Initialization
		const char *ResultPointer = nullptr;
		size_t ResultLength = 0;

	//Convert hex format to binary.
		auto Result = sodium_hex2bin(MagicNumber, DNSCURVE_MAGIC_QUERY_LEN, Data.c_str() + DataOffset + strlen("0x"), DNSCURVE_MAGIC_QUERY_HEX_LEN, nullptr, &ResultLength, &ResultPointer);
		if (Result != 0 || ResultLength != DNSCURVE_MAGIC_QUERY_LEN || ResultPointer == nullptr)
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"Data length error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
	}
//ASCI format
	else if (Data.length() == DataOffset + DNSCURVE_MAGIC_QUERY_LEN)
	{
		memcpy_s(MagicNumber, DNSCURVE_MAGIC_QUERY_LEN, Data.c_str() + DataOffset, DNSCURVE_MAGIC_QUERY_LEN);
	}
	else {
		PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"Data length error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

	return true;
}
#endif

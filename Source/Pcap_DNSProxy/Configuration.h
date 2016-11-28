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


#ifndef PCAP_DNSPROXY_CONFIGURATION_H
#define PCAP_DNSPROXY_CONFIGURATION_H

#include "Base.h"

//Base definitions
//Label types definitions
#define LABEL_IPFILTER                        1U
#define LABEL_IPFILTER_BLACKLIST              2U
#define LABEL_IPFILTER_LOCAL_ROUTING          3U
#define LABEL_HOSTS_TYPE_WHITE                4U
#define LABEL_HOSTS_TYPE_BANNED               5U
#define LABEL_HOSTS_TYPE_WHITE_EXTENDED       6U
#define LABEL_HOSTS_TYPE_BANNED_EXTENDED      7U
#define LABEL_HOSTS_TYPE_NORMAL               8U
#define LABEL_HOSTS_TYPE_CNAME                9U
#define LABEL_HOSTS_TYPE_LOCAL                10U
#define LABEL_HOSTS_TYPE_ADDRESS              11U
#define LABEL_HOSTS_TYPE_SOURCE               12U

//Length definitions
#define READ_DATA_MINSIZE                     4U
#define READ_TEXT_MINSIZE                     2U
#define READ_PARAMETER_MINSIZE                8U
#define READ_HOSTS_MINSIZE                    3U
#define READ_HOSTS_ADDRESS_MINSIZE            5U
#define READ_IPFILTER_MINSIZE                 5U
#define READ_IPFILTER_BLACKLIST_MINSIZE       3U
#define READ_IPFILTER_LOCAL_ROUTING_MINSIZE   4U

//Global variables
extern CONFIGURATION_TABLE Parameter, ParameterModificating;
extern GLOBAL_STATUS GlobalRunningStatus;
#if defined(ENABLE_LIBSODIUM)
extern DNSCURVE_CONFIGURATION_TABLE DNSCurveParameter, DNSCurveParameterModificating;
#endif
extern std::vector<FILE_DATA> FileList_Config, FileList_IPFilter, FileList_Hosts;
extern std::vector<DIFFERNET_FILE_SET_IPFILTER> *IPFilterFileSetUsing, *IPFilterFileSetModificating;
extern std::vector<DIFFERNET_FILE_SET_HOSTS> *HostsFileSetUsing, *HostsFileSetModificating;
extern std::mutex IPFilterFileLock, HostsFileLock;

//Functions in Configuration.cpp
bool ReadText(
	const FILE * const FileHandle, 
	const size_t InputType, 
	const size_t FileIndex);
void ClearModificatingListData(
	const size_t ClearType, 
	const size_t FileIndex);
void GetParameterListData(
	std::vector<std::string> &ListData, 
	const std::string Data, 
	const size_t DataOffset, 
	const size_t Length, 
	const uint8_t SeparatedSign, 
	const bool IsCaseConvert, 
	const bool KeepEmptyItem);

//Functions in ReadParameter.cpp
bool Parameter_CheckSetting(
	const bool IsFirstRead, 
	const size_t FileIndex);
uint16_t ServiceNameToBinary(
	const uint8_t * const OriginalBuffer);
uint16_t DNSTypeNameToBinary(
	const uint8_t * const OriginalBuffer);
bool ReadParameterData(
	std::string Data, 
	const size_t FileIndex, 
	const bool IsFirstRead, 
	const size_t Line);
#if defined(PLATFORM_WIN)
bool ReadName_PathFile(
	std::string Data, 
	const size_t DataOffset, 
	const bool Path, 
	std::vector<std::wstring> * const ListData, 
	const size_t FileIndex, 
	const size_t Line);
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
bool ReadName_PathFile(
	std::string Data, 
	const size_t DataOffset, 
	const bool Path, 
	std::vector<std::wstring> * const ListData, 
	std::vector<std::string> * const MBS_ListData, 
	const size_t FileIndex, const size_t Line);
#endif
bool ReadMultipleAddresses(
	const uint16_t Protocol, 
	std::string Data, 
	const size_t DataOffset, 
	std::vector<DNS_SERVER_DATA> * const DNSServerDataList, 
	const size_t FileIndex, 
	const size_t Line);
bool Read_SOCKS_AddressDomain(
	std::string Data, 
	const size_t DataOffset, 
	CONFIGURATION_TABLE * const ParameterPTR, 
	const size_t FileIndex, 
	const size_t Line);
#if defined(ENABLE_PCAP)
bool ReadHopLimitData(
	const uint16_t Protocol, 
	std::string Data, 
	const size_t DataOffset, 
	std::vector<DNS_SERVER_DATA> * const DNSServerDataList, 
	const bool IsFirstRead, 
	const size_t FileIndex, 
	const size_t Line);
#endif
#if defined(ENABLE_LIBSODIUM)
bool ReadDNSCurveProviderName(
	std::string Data, 
	const size_t DataOffset, 
	uint8_t * const ProviderNameData, 
	const size_t FileIndex, 
	const size_t Line);
bool ReadDNSCurveKey(
	std::string Data, 
	const size_t DataOffset, 
	uint8_t * const KeyData, 
	const size_t FileIndex, 
	const size_t Line);
#endif
bool ReadDNSCurveMagicNumber(
	std::string Data, 
	const size_t DataOffset, 
	uint8_t * const MagicNumber, 
	const size_t FileIndex, 
	const size_t Line);

//Functions in ReadIPFilter.cpp
bool ReadIPFilterData(
	std::string Data, 
	const size_t FileIndex, 
	const size_t Line, 
	size_t &LabelType, 
	bool &IsStopLabel);
bool ReadBlacklistData(
	std::string Data, 
	const size_t FileIndex, 
	const size_t Line);
bool ReadLocalRoutingData(
	std::string Data, 
	const size_t FileIndex, 
	const size_t Line);
bool ReadAddressPrefixBlock(
	const uint16_t Protocol, 
	std::string OriginalData, 
	const size_t DataOffset, 
	ADDRESS_PREFIX_BLOCK * const AddressPrefix, 
	const size_t FileIndex, 
	const size_t Line);
bool ReadMainIPFilterData(
	std::string Data, 
	const size_t FileIndex, 
	const size_t Line);

//Functions in ReadHosts.cpp
bool ReadHostsData(
	std::string Data, 
	const size_t FileIndex, 
	const size_t Line, 
	size_t &LabelType, 
	bool &IsStopLabel);
bool ReadOtherHostsData(
	std::string Data, 
	const size_t FileIndex, 
	const size_t Line, 
	const size_t LabelType, 
	const size_t ItemType);
bool ReadLocalHostsData(
	std::string Data, 
	const size_t FileIndex, 
	const size_t Line);
bool ReadAddressHostsData(
	std::string Data, 
	const size_t FileIndex, 
	const size_t Line);
bool ReadMainHostsData(
	std::string Data, 
	const size_t HostsType, 
	const size_t FileIndex, 
	const size_t Line);
#endif

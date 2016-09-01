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

//Read hosts data from files
bool ReadHostsData(
	std::string Data, 
	const size_t FileIndex, 
	size_t &LabelType, 
	const size_t Line, 
	bool &IsLabelComments)
{
//Convert horizontal tab/HT to space and delete spaces before or after data.
	for (auto &StringIter:Data)
	{
		if (StringIter == ASCII_HT)
			StringIter = ASCII_SPACE;
	}
	while (!Data.empty() && Data.front() == ASCII_SPACE)
		Data.erase(0, 1U);
	while (!Data.empty() && Data.back() == ASCII_SPACE)
		Data.pop_back();
	while (!Data.empty() && Data.find("  ") != std::string::npos)
		Data.erase(Data.find("  "), 1U);
	if (Data.empty())
		return true;

//Multiple line comments check, delete comments(Number Sign/NS and double slashs) and check minimum length of hosts items.
	if (!ReadMultipleLineComments(Data, IsLabelComments) || Data.find(ASCII_HASHTAG) == 0 || Data.find(ASCII_SLASH) == 0)
		return true;
	if (Data.rfind(" //") != std::string::npos)
		Data.erase(Data.rfind(" //"), Data.length() - Data.rfind(" //"));
	if (Data.rfind(" #") != std::string::npos)
		Data.erase(Data.rfind(" #"), Data.length() - Data.rfind(" #"));
	if (Data.length() < READ_HOSTS_MINSIZE)
		return true;

//[Local Hosts] block(A part)
	if (LabelType == 0 && (Parameter.Target_Server_Local_IPv4.Storage.ss_family > 0 || Parameter.Target_Server_Local_IPv6.Storage.ss_family > 0) && 
		(CompareStringReversed(L"whitelist.txt", FileList_IPFilter.at(FileIndex).FileName.c_str(), true) || 
		CompareStringReversed(L"white_list.txt", FileList_IPFilter.at(FileIndex).FileName.c_str(), true)))
			LabelType = LABEL_HOSTS_TYPE_LOCAL;

//[Address Hosts] block
	if (Data.find("[Source Hosts]") == 0 || Data.find("[Source hosts]") == 0 || Data.find("[source Hosts]") == 0 || Data.find("[source hosts]") == 0)
	{
		LabelType = LABEL_HOSTS_TYPE_SOURCE;
		return true;
	}

//[Hosts] block
	else if (Data.find("[Hosts]") == 0 || Data.find("[hosts]") == 0)
	{
		LabelType = LABEL_HOSTS_TYPE_NORMAL;
		return true;
	}

//[Local Hosts] block(B part)
	else if (Data.find("[Local Hosts]") == 0 || Data.find("[Local hosts]") == 0 || Data.find("[local Hosts]") == 0 || Data.find("[local hosts]") == 0)
	{
		LabelType = LABEL_HOSTS_TYPE_LOCAL;
		return true;
	}

//[CNAME Hosts] block
	else if (Data.find("[CNAME Hosts]") == 0 || Data.find("[CNAME hosts]") == 0 || 
		Data.find("[Cname Hosts]") == 0 || Data.find("[Cname hosts]") == 0 || 
		Data.find("[cname Hosts]") == 0 || Data.find("[cname hosts]") == 0)
	{
		LabelType = LABEL_HOSTS_TYPE_CNAME;
		return true;
	}

//[Address Hosts] block
	else if (Data.find("[Address Hosts]") == 0 || Data.find("[Address hosts]") == 0 || Data.find("[address Hosts]") == 0 || Data.find("[address hosts]") == 0)
	{
		LabelType = LABEL_HOSTS_TYPE_ADDRESS;
		return true;
	}

//Temporary stop read.
	else if (Data.find("[Stop]") == 0 || Data.find("[stop]") == 0)
	{
		LabelType = LABEL_STOP;
		return true;
	}
	else if (LabelType == LABEL_STOP)
	{
		return true;
	}

//Whitelist, Banned and their Extended items
	size_t LabelTypeTemp = 0;
	if (Data.find("NULL ") == 0 || Data.find("NULL,") == 0 || 
		Data.find("Null ") == 0 || Data.find("Null,") == 0 || 
		Data.find("null ") == 0 || Data.find("null,") == 0)
			LabelTypeTemp = LABEL_HOSTS_TYPE_WHITE;
	else if (Data.find("BAN ") == 0 || Data.find("BAN,") == 0 || 
		Data.find("BANNED ") == 0 || Data.find("BANNED,") == 0 || 
		Data.find("Ban ") == 0 || Data.find("Ban,") == 0 || 
		Data.find("Banned ") == 0 || Data.find("Banned,") == 0 || 
		Data.find("ban ") == 0 || Data.find("ban,") == 0 || 
		Data.find("banned ") == 0 || Data.find("banned,") == 0)
			LabelTypeTemp = LABEL_HOSTS_TYPE_BANNED;
	else if (Data.find("NULL") == 0 || Data.find("Null") == 0 || Data.find("null") == 0)
		LabelTypeTemp = LABEL_HOSTS_TYPE_WHITE_EXTENDED;
	else if (Data.find("BAN") == 0 || Data.find("BANNED") == 0 || Data.find("Ban") == 0 || 
		Data.find("Banned") == 0 || Data.find("ban") == 0 || Data.find("banned") == 0)
			LabelTypeTemp = LABEL_HOSTS_TYPE_BANNED_EXTENDED;
	if (LabelTypeTemp > 0)
	{
		if (LabelType == LABEL_HOSTS_TYPE_NORMAL || LabelType == LABEL_HOSTS_TYPE_LOCAL)
		{
			return ReadOtherHostsData(Data, FileIndex, Line, LabelType, LabelTypeTemp);
		}
		else {
			PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
	}

//[Local Hosts] block
	else if (LabelType == LABEL_HOSTS_TYPE_LOCAL)
	{
		if (Parameter.LocalMain)
			return true;
		else if (Parameter.LocalHosts && (Parameter.Target_Server_Local_IPv4.Storage.ss_family > 0 || Parameter.Target_Server_Local_IPv6.Storage.ss_family > 0))
			return ReadLocalHostsData(Data, FileIndex, Line);
	}

//Delete spaces before or after verticals.
	while (Data.find(" |") != std::string::npos || Data.find("| ") != std::string::npos)
	{
		if (Data.find(" |") != std::string::npos)
			Data.erase(Data.find(" |"), strlen(" "));
		if (Data.find("| ") != std::string::npos)
			Data.erase(Data.find("| ") + 1U, strlen("|"));
	}

//[Address Hosts] block
	if (LabelType == LABEL_HOSTS_TYPE_ADDRESS)
	{
		return ReadAddressHostsData(Data, FileIndex, Line);
	}

//Main Hosts block
	else {
	//[CNAME Hosts] block
		if (LabelType == LABEL_HOSTS_TYPE_CNAME)
			return ReadMainHostsData(Data, HOSTS_TYPE_CNAME, FileIndex, Line);
	//[Source Hosts] block
		else if (LabelType == LABEL_HOSTS_TYPE_SOURCE)
			return ReadMainHostsData(Data, HOSTS_TYPE_SOURCE, FileIndex, Line);
	//[Hosts] block
		else 
			return ReadMainHostsData(Data, HOSTS_TYPE_NORMAL, FileIndex, Line);
	}

	return true;
}

//Read other type items in Hosts file from data
bool ReadOtherHostsData(
	std::string Data, 
	const size_t FileIndex, 
	const size_t Line, 
	const size_t LabelType, 
	const size_t ItemType)
{
//Mark separated location and check data format.
	size_t Separated = 0;
	if (Data.find(ASCII_SPACE) != std::string::npos)
	{
		Separated = Data.find(ASCII_SPACE);
	}
	else if (Data.find(ASCII_COMMA) != std::string::npos)
	{
		Separated = Data.find(ASCII_COMMA);
	}
	if (Separated == 0 || 
		((ItemType == LABEL_HOSTS_TYPE_WHITE_EXTENDED || ItemType == LABEL_HOSTS_TYPE_BANNED_EXTENDED) && 
		(Data.find(ASCII_COLON) == std::string::npos || Separated <= Data.find(ASCII_COLON) + 1U)))
	{
		PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Delete all spaces.
	while (Data.find(ASCII_SPACE) != std::string::npos)
		Data.erase(Data.find(ASCII_SPACE), 1U);

//Mark Whitelist Extended and Banned Extended types.
	HOSTS_TABLE HostsTableTemp;
	if (ItemType == LABEL_HOSTS_TYPE_WHITE_EXTENDED || ItemType == LABEL_HOSTS_TYPE_BANNED_EXTENDED)
	{
	//Permit or Deny mode check
		if ((ItemType == LABEL_HOSTS_TYPE_WHITE_EXTENDED && 
			((Data.find("DENY") != std::string::npos && Data.find("DENY") <= Separated) || 
			(Data.find("Deny") != std::string::npos && Data.find("Deny") <= Separated) || 
			(Data.find("deny") != std::string::npos && Data.find("deny") <= Separated))) || 
			(ItemType == LABEL_HOSTS_TYPE_BANNED_EXTENDED && 
			((Data.find("PERMIT") != std::string::npos && Data.find("PERMIT") <= Separated) || 
			(Data.find("Permit") != std::string::npos && Data.find("Permit") <= Separated) || 
			(Data.find("permit") != std::string::npos && Data.find("permit") <= Separated))))
				HostsTableTemp.PermissionOperation = true;

	//Mark types.
		std::vector<std::string> ListData;
		uint16_t RecordType = 0;
		ssize_t Result = 0;

	//Mark all data in list.
		GetParameterListData(ListData, Data, Data.find(ASCII_COLON) + 1U, Separated, ASCII_VERTICAL, false, false);
		for (const auto &StringIter:ListData)
		{
			RecordType = DNSTypeNameToBinary((const uint8_t *)StringIter.c_str());

		//Number types
			if (RecordType <= 0)
			{
				_set_errno(0);
				Result = strtoul(StringIter.c_str(), nullptr, 0);
				if (Result > 0 && Result <= UINT16_MAX)
				{
					HostsTableTemp.RecordTypeList.push_back(htons((uint16_t)Result));
				}
				else {
					PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"DNS Records type error", errno, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
			}
		//Name types
			else {
				HostsTableTemp.RecordTypeList.push_back(RecordType);
			}
		}
	}

//Mark patterns.
	HostsTableTemp.PatternOrDomainString.append(Data, Separated, Data.length() - Separated);
	try {
		std::regex PatternHostsTableTemp(HostsTableTemp.PatternOrDomainString);
		HostsTableTemp.Pattern.swap(PatternHostsTableTemp);
	}
	catch (std::regex_error& Error)
	{
		PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"Regular expression pattern error", Error.code(), FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Mark types.
	if (ItemType == LABEL_HOSTS_TYPE_BANNED || ItemType == LABEL_HOSTS_TYPE_BANNED_EXTENDED)
		HostsTableTemp.PermissionType = HOSTS_TYPE_BANNED;
	else 
		HostsTableTemp.PermissionType = HOSTS_TYPE_WHITE;

//Add to global list.
	for (auto &HostsFileSetIter:*HostsFileSetModificating)
	{
		if (HostsFileSetIter.FileIndex == FileIndex)
		{
			if (LabelType == LABEL_HOSTS_TYPE_LOCAL)
				HostsFileSetIter.HostsList_Local.push_back(HostsTableTemp);
			else //Normal
				HostsFileSetIter.HostsList_Normal.push_back(HostsTableTemp);

			break;
		}
	}

	return true;
}

//Read Local Hosts items in Hosts file from data
bool ReadLocalHostsData(
	std::string Data, 
	const size_t FileIndex, 
	const size_t Line)
{
	HOSTS_TABLE HostsTableTemp;
	std::vector<std::string> HostsListData;
	size_t SeparatedOrResult = 0;
	auto DnsmasqFormat = false;

//Dnsmasq format(http://www.thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html)
	if (Data.find("--") == 0)
	{
		if (Data.find("--Server=/") == std::string::npos && Data.find("--server=/") == std::string::npos)
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
		else {
			DnsmasqFormat = true;
			SeparatedOrResult = Data.find(ASCII_SLASH) + 1U;
		}
	}
	else if (Data.find("Server=/") == 0 || Data.find("Server=/"))
	{
		DnsmasqFormat = true;
		SeparatedOrResult = Data.find(ASCII_SLASH) + 1U;
	}

//Dnsmasq format check
	if (DnsmasqFormat)
	{
	//Delete all spaces and string length check.
		while (Data.find(ASCII_SPACE) != std::string::npos)
			Data.erase(Data.find(ASCII_SPACE), 1U);

	//Get all list data.
		GetParameterListData(HostsListData, Data, SeparatedOrResult, Data.length(), ASCII_SLASH, false, true);
		if (HostsListData.empty() || HostsListData.size() > 2U)
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
		else if (HostsListData.front().empty()) //Dnsmasq unqualified names only
		{
			HostsTableTemp.IsStringMatching = true;
			
		//Default target server
			if (HostsListData.back().empty())
			{
				goto AddToGlobalList;
			}
		//Dnsmasq Whitelist items
			else if (HostsListData.back() == "#") //Dnsmasq use the standard servers
			{
				HostsTableTemp.PermissionType = HOSTS_TYPE_WHITE;
				goto AddToGlobalList;
			}
		//Mark target server.
			else {
			//Target server with port
				std::string DataTemp(HostsListData.back());
				HostsListData.clear();
				GetParameterListData(HostsListData, DataTemp, 0, DataTemp.length(), ASCII_HASHTAG, false, false);
				if (HostsListData.empty() || HostsListData.size() > 2U)
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
			
			//Response initialization
				ADDRESS_UNION_DATA AddressUnionDataTemp;
				memset(&AddressUnionDataTemp, 0, sizeof(AddressUnionDataTemp));
				ssize_t Result = 0;

			//Convert address.
				if (HostsListData.front().find(ASCII_COLON) != std::string::npos) //IPv6
				{
					if (!AddressStringToBinary((const uint8_t *)HostsListData.front().c_str(), AF_INET6, &AddressUnionDataTemp.IPv6.sin6_addr, &Result))
					{
						PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"IPv6 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
						return false;
					}
					else {
						AddressUnionDataTemp.Storage.ss_family = AF_INET6;
					}
				}
				else if (HostsListData.front().find(ASCII_PERIOD) != std::string::npos) //IPv4
				{
					if (!AddressStringToBinary((const uint8_t *)HostsListData.front().c_str(), AF_INET, &AddressUnionDataTemp.IPv4.sin_addr, &Result))
					{
						PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"IPv4 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
						return false;
					}
					else {
						AddressUnionDataTemp.Storage.ss_family = AF_INET;
					}
				}
				else {
					PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}

			//Convert port.
				if (HostsListData.size() == 2U) //Non-standard port
				{
					SeparatedOrResult = ServiceNameToBinary((const uint8_t *)HostsListData.back().c_str());
					if (SeparatedOrResult == 0)
					{
						_set_errno(0);
						SeparatedOrResult = strtoul((const char *)HostsListData.back().c_str(), nullptr, 0);
						if (SeparatedOrResult <= 0 || SeparatedOrResult >= ULONG_MAX)
						{
							PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"IPv6 address port error", errno, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
							return false;
						}
					}
				}
				else { //Standard port
					SeparatedOrResult = IPPORT_DNS;
				}

			//Mark port.
				if (AddressUnionDataTemp.Storage.ss_family == AF_INET6)
				{
					AddressUnionDataTemp.IPv6.sin6_port = htons((uint16_t)SeparatedOrResult);
				}
				else if (AddressUnionDataTemp.Storage.ss_family == AF_INET)
				{
					AddressUnionDataTemp.IPv4.sin_port = htons((uint16_t)SeparatedOrResult);
				}
				else {
					PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}

			//Add to list.
				HostsTableTemp.AddrOrTargetList.push_back(AddressUnionDataTemp);
			}
		}
		else {
		//Domain length check
			if (HostsListData.front().empty())
			{
				PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Mark domain.
			if (HostsListData.front().front() == ASCII_COLON || HostsListData.front().back() == ASCII_COLON) //Dnsmasq regex mode
			{
			//Regex format check
				if (HostsListData.front().front() != ASCII_COLON || HostsListData.front().back() != ASCII_COLON)
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}

			//Mark domain.
				HostsListData.front().erase(0, 1U);
				HostsListData.front().pop_back();
				HostsTableTemp.PatternOrDomainString = HostsListData.front();
			}
			else { //Dnsmasq normal mode
			//Make string reversed.
				MakeStringReversed(HostsListData.front());
				HostsTableTemp.PatternOrDomainString = HostsListData.front();
				HostsTableTemp.IsStringMatching = true;
			}

		//Try to mark target server.
			if (!HostsListData.back().empty())
			{
			//Dnsmasq Whitelist items
				if (HostsListData.back() == "#") //Dnsmasq use the standard servers
				{
					HostsTableTemp.PermissionType = HOSTS_TYPE_WHITE;
				}
			//Mark target server.
				else {
				//Target server with port
					std::string DataTemp(HostsListData.back());
					HostsListData.clear();
					GetParameterListData(HostsListData, DataTemp, 0, DataTemp.length(), ASCII_HASHTAG, false, false);
					if (HostsListData.empty() || HostsListData.size() > 2U)
					{
						PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
						return false;
					}
			
				//Response initialization
					ADDRESS_UNION_DATA AddressUnionDataTemp;
					memset(&AddressUnionDataTemp, 0, sizeof(AddressUnionDataTemp));
					ssize_t Result = 0;

				//Convert address.
					if (HostsListData.front().find(ASCII_COLON) != std::string::npos) //IPv6
					{
						if (!AddressStringToBinary((const uint8_t *)HostsListData.front().c_str(), AF_INET6, &AddressUnionDataTemp.IPv6.sin6_addr, &Result))
						{
							PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"IPv6 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
							return false;
						}
						else {
							AddressUnionDataTemp.Storage.ss_family = AF_INET6;
						}
					}
					else if (HostsListData.front().find(ASCII_PERIOD) != std::string::npos) //IPv4
					{
						if (!AddressStringToBinary((const uint8_t *)HostsListData.front().c_str(), AF_INET, &AddressUnionDataTemp.IPv4.sin_addr, &Result))
						{
							PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"IPv4 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
							return false;
						}
						else {
							AddressUnionDataTemp.Storage.ss_family = AF_INET;
						}
					}
					else {
						PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
						return false;
					}

				//Convert port.
					if (HostsListData.size() == 2U) //Non-standard port
					{
						SeparatedOrResult = ServiceNameToBinary((const uint8_t *)HostsListData.back().c_str());
						if (SeparatedOrResult == 0)
						{
							_set_errno(0);
							SeparatedOrResult = strtoul((const char *)HostsListData.back().c_str(), nullptr, 0);
							if (SeparatedOrResult <= 0 || SeparatedOrResult >= ULONG_MAX)
							{
								PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"IPv6 address port error", errno, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
								return false;
							}
						}
					}
					else { //Standard port
						SeparatedOrResult = IPPORT_DNS;
					}

				//Mark port.
					if (AddressUnionDataTemp.Storage.ss_family == AF_INET6) //IPv6
					{
						AddressUnionDataTemp.IPv6.sin6_port = htons((uint16_t)SeparatedOrResult);
					}
					else if (AddressUnionDataTemp.Storage.ss_family == AF_INET) //IPv4
					{
						AddressUnionDataTemp.IPv4.sin_port = htons((uint16_t)SeparatedOrResult);
					}
					else {
						PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
						return false;
					}

				//Add to list.
					HostsTableTemp.AddrOrTargetList.push_back(AddressUnionDataTemp);
				}
			}
		}
	}

//Mark patterns.
	if (!HostsTableTemp.IsStringMatching)
	{
		if (!DnsmasqFormat)
			HostsTableTemp.PatternOrDomainString = Data;
		try {
			std::regex PatternHostsTableTemp(HostsTableTemp.PatternOrDomainString);
			HostsTableTemp.Pattern.swap(PatternHostsTableTemp);
		}
		catch (std::regex_error& Error)
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"Regular expression pattern error", Error.code(), FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
	}

//Add to global list.
AddToGlobalList:
	for (auto &HostsFileSetIter:*HostsFileSetModificating)
	{
		if (HostsFileSetIter.FileIndex == FileIndex)
		{
			HostsFileSetIter.HostsList_Local.push_back(HostsTableTemp);
			break;
		}
	}

	return true;
}

//Read Address Hosts items in Hosts file from data
bool ReadAddressHostsData(
	std::string Data, 
	const size_t FileIndex, 
	const size_t Line)
{
//Mark separated location.
	size_t Separated = 0;
	if (Data.find(ASCII_COMMA) != std::string::npos)
	{
	//Delete spaces before or after commas.
		while (Data.find(" ,") != std::string::npos)
			Data.erase(Data.find(" ,"), strlen(" "));
		while (Data.find(ASCII_SPACE) != std::string::npos && Data.find(ASCII_SPACE) > Data.find(ASCII_COMMA))
			Data.erase(Data.find(ASCII_SPACE), 1U);

	//Common format
		if (Data.find(ASCII_SPACE) != std::string::npos)
		{
			Separated = Data.find(ASCII_SPACE);
		}
	//Comma-Separated Values/CSV, RFC 4180(https://tools.ietf.org/html/rfc4180), Common Format and MIME Type for Comma-Separated Values (CSV) Files.
		else {
			Separated = Data.find(ASCII_COMMA);
			Data.erase(Separated, 1U);
		}
	}
//Common format
	else if (Data.find(ASCII_SPACE) != std::string::npos)
	{
		Separated = Data.find(ASCII_SPACE);
	}
	else {
		PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Delete all spaces.
	while (Data.find(ASCII_SPACE) != std::string::npos)
		Data.erase(Data.find(ASCII_SPACE), 1U);

//String length check.
	if (Data.length() < READ_HOSTS_ADDRESS_MINSIZE)
	{
		PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Initialization
	ADDRESS_HOSTS_TABLE AddressHostsTableTemp;
	sockaddr_storage SockAddr;
	memset(&SockAddr, 0, sizeof(SockAddr));

//Get target data.
	std::vector<std::string> TargetListData, SourceListData;
	GetParameterListData(TargetListData, Data, 0, Separated, ASCII_VERTICAL, false, false);
	GetParameterListData(SourceListData, Data, Separated, Data.length(), ASCII_VERTICAL, false, false);
	ssize_t Result = 0;

//Mark all data in list.
	for (const auto &StringIter:TargetListData)
	{
	//AAAA records(IPv6)
		if (StringIter.find(ASCII_COLON) != std::string::npos)
		{
		//Convert to binary address.
			memset(&SockAddr, 0, sizeof(SockAddr));
			if (!AddressStringToBinary((const uint8_t *)StringIter.c_str(), AF_INET6, &((PSOCKADDR_IN6)&SockAddr)->sin6_addr, &Result))
			{
				PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"IPv6 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Add to list.
			SockAddr.ss_family = AF_INET6;
			AddressHostsTableTemp.Address_Target.push_back(SockAddr);
		}
	//A records(IPv4)
		else if (StringIter.find(ASCII_PERIOD) != std::string::npos)
		{
		//Convert to binary address.
			memset(&SockAddr, 0, sizeof(SockAddr));
			if (!AddressStringToBinary((const uint8_t *)StringIter.c_str(), AF_INET, &((PSOCKADDR_IN)&SockAddr)->sin_addr, &Result))
			{
				PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"IPv4 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Add to list.
			SockAddr.ss_family = AF_INET;
			AddressHostsTableTemp.Address_Target.push_back(SockAddr);
		}
		else {
			PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
	}

//Get source data.
	ADDRESS_RANGE_TABLE AddressRangeTableTemp;
	uint8_t Addr[ADDR_STRING_MAXSIZE] = {0};
	memset(Addr, 0, ADDR_STRING_MAXSIZE);

//Mark all data in list.
	for (const auto &StringIter:SourceListData)
	{
	//AAAA records(IPv6)
		if (StringIter.find(ASCII_COLON) != std::string::npos)
		{
			memset(&AddressRangeTableTemp, 0, sizeof(AddressRangeTableTemp));

		//Address range format
			if (StringIter.find(ASCII_MINUS) != std::string::npos)
			{
			//Convert address(Begin).
				memset(Addr, 0, ADDR_STRING_MAXSIZE);
				memcpy_s(Addr, ADDR_STRING_MAXSIZE, StringIter.c_str(), StringIter.find(ASCII_MINUS));
				if (!AddressStringToBinary(Addr, AF_INET6, &((PSOCKADDR_IN6)&AddressRangeTableTemp.Begin)->sin6_addr, &Result))
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"IPv6 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
				AddressRangeTableTemp.Begin.ss_family = AF_INET6;

			//Convert address(End).
				memset(Addr, 0, ADDR_STRING_MAXSIZE);
				memcpy_s(Addr, ADDR_STRING_MAXSIZE, StringIter.c_str() + StringIter.find(ASCII_MINUS) + 1U, StringIter.length() - StringIter.find(ASCII_MINUS) - 1U);
				if (!AddressStringToBinary(Addr, AF_INET6, &((PSOCKADDR_IN6)&AddressRangeTableTemp.End)->sin6_addr, &Result))
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"IPv6 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
				AddressRangeTableTemp.End.ss_family = AF_INET6;

			//Check address range.
				if (AddressesComparing(&((PSOCKADDR_IN6)&AddressRangeTableTemp.Begin)->sin6_addr, &((PSOCKADDR_IN6)&AddressRangeTableTemp.End)->sin6_addr, AF_INET6) > ADDRESS_COMPARE_EQUAL)
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"IPv6 address range error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
			}
		//Normal format
			else {
			//Convert to binary address.
				if (!AddressStringToBinary((const uint8_t *)StringIter.c_str(), AF_INET6, &((PSOCKADDR_IN6)&AddressRangeTableTemp.Begin)->sin6_addr, &Result))
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"IPv6 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}

				AddressRangeTableTemp.Begin.ss_family = AF_INET6;
				AddressRangeTableTemp.End = AddressRangeTableTemp.Begin;
			}

		//Add to list.
			AddressHostsTableTemp.Address_Source.push_back(AddressRangeTableTemp);
		}
	//A records(IPv4)
		else if (StringIter.find(ASCII_PERIOD) != std::string::npos)
		{
			memset(&AddressRangeTableTemp, 0, sizeof(AddressRangeTableTemp));

		//Address range format
			if (StringIter.find(ASCII_MINUS) != std::string::npos)
			{
			//Convert address(Begin).
				memset(Addr, 0, ADDR_STRING_MAXSIZE);
				memcpy_s(Addr, ADDR_STRING_MAXSIZE, StringIter.c_str(), StringIter.find(ASCII_MINUS));
				if (!AddressStringToBinary(Addr, AF_INET, &((PSOCKADDR_IN)&AddressRangeTableTemp.Begin)->sin_addr, &Result))
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"IPv4 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
				AddressRangeTableTemp.Begin.ss_family = AF_INET;

			//Convert address(End).
				memset(Addr, 0, ADDR_STRING_MAXSIZE);
				memcpy_s(Addr, ADDR_STRING_MAXSIZE, StringIter.c_str() + StringIter.find(ASCII_MINUS) + 1U, StringIter.length() - StringIter.find(ASCII_MINUS) - 1U);
				if (!AddressStringToBinary(Addr, AF_INET, &((PSOCKADDR_IN)&AddressRangeTableTemp.End)->sin_addr, &Result))
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"IPv4 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
				AddressRangeTableTemp.End.ss_family = AF_INET;

			//Check address range.
				if (AddressesComparing(&((PSOCKADDR_IN)&AddressRangeTableTemp.Begin)->sin_addr, &((PSOCKADDR_IN)&AddressRangeTableTemp.End)->sin_addr, AF_INET) > ADDRESS_COMPARE_EQUAL)
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"IPv4 address range error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
			}
		//Normal format
			else {
			//Convert to binary address.
				if (!AddressStringToBinary((const uint8_t *)StringIter.c_str(), AF_INET, &((PSOCKADDR_IN)&AddressRangeTableTemp.Begin)->sin_addr, &Result))
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"IPv4 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}

				AddressRangeTableTemp.Begin.ss_family = AF_INET;
				AddressRangeTableTemp.End = AddressRangeTableTemp.Begin;
			}

		//Add to list.
			AddressHostsTableTemp.Address_Source.push_back(AddressRangeTableTemp);
		}
		else {
			PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
	}

//Add to global list.
	for (auto &HostsFileSetIter:*HostsFileSetModificating)
	{
		if (HostsFileSetIter.FileIndex == FileIndex)
		{
			HostsFileSetIter.AddressHostsList.push_back(AddressHostsTableTemp);
			break;
		}
	}

	return true;
}

//Read Main Hosts items in Hosts file from data
bool ReadMainHostsData(
	std::string Data, 
	const size_t HostsType, 
	const size_t FileIndex, 
	const size_t Line)
{
	size_t Separated = 0;
	auto DnsmasqFormat = false;

//Mark separated location.
	if (Data.find(ASCII_COMMA) != std::string::npos)
	{
	//Delete spaces before or after commas.
		while (Data.find(" ,") != std::string::npos)
			Data.erase(Data.find(" ,"), strlen(" "));
		while (Data.find(ASCII_SPACE) != std::string::npos && Data.find(ASCII_SPACE) > Data.find(ASCII_COMMA))
			Data.erase(Data.find(ASCII_SPACE), 1U);

	//Common format
		if (Data.find(ASCII_SPACE) != std::string::npos)
		{
			Separated = Data.find(ASCII_SPACE);
		}
	//Comma-Separated Values/CSV, RFC 4180(https://tools.ietf.org/html/rfc4180), Common Format and MIME Type for Comma-Separated Values (CSV) Files.
		else {
			Separated = Data.find(ASCII_COMMA);
			Data.erase(Separated, 1U);
		}
	}
//Common format
	else if (Data.find(ASCII_SPACE) != std::string::npos)
	{
		Separated = Data.find(ASCII_SPACE);
	}
//Dnsmasq format(http://www.thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html)
	else if (HostsType != HOSTS_TYPE_SOURCE && Data.find("--") == 0)
	{
		if ((Data.find("--Address=/") == std::string::npos && Data.find("--address=/") == std::string::npos) || 
			Data.find("--Address=//") == 0 || Data.find("--address=//") == 0)
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
		else {
			DnsmasqFormat = true;
			Separated = Data.find(ASCII_SLASH);
		}
	}
	else if (HostsType != HOSTS_TYPE_SOURCE && (Data.find("Address=/") == 0 || Data.find("address=/") == 0))
	{
		if (Data.find("Address=//") == 0 || Data.find("address=//") == 0)
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
		else {
			DnsmasqFormat = true;
			Separated = Data.find(ASCII_SLASH);
		}
	}
	else {
		PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Source Hosts format check
	if (HostsType == HOSTS_TYPE_SOURCE && (Data.find("->") == std::string::npos || Data.find("->") >= Separated))
	{
		PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Delete all spaces and string length check.
	while (Data.find(ASCII_SPACE) != std::string::npos)
		Data.erase(Data.find(ASCII_SPACE), 1U);
	if (!DnsmasqFormat && Separated < READ_HOSTS_MINSIZE)
		return false;

//Initialization(Part 1)
	HOSTS_TABLE HostsTableTemp;
	std::vector<std::string> HostsListData;

//Mark source address.
	if (HostsType == HOSTS_TYPE_SOURCE)
	{
		std::vector<std::string> SourceListData;
		GetParameterListData(SourceListData, Data, 0, Data.find("->"), ASCII_VERTICAL, false, false);
		if (SourceListData.empty())
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
		else {
		//Protocol settings
			ADDRESS_PREFIX_BLOCK AddressPrefix;
			uint16_t Protocol = 0;
			if (SourceListData.front().find(ASCII_COLON) != std::string::npos)
				Protocol = AF_INET6;
			else 
				Protocol = AF_INET;

		//Mark all data in list.
			for (const auto &StringIter:SourceListData)
			{
				if (!ReadAddressPrefixBlock(StringIter, 0, Protocol, &AddressPrefix, FileIndex, Line))
					return false;
				else 
					HostsTableTemp.SourceList.push_back(AddressPrefix);
			}
		}

		GetParameterListData(HostsListData, Data, Data.find("->") + strlen("->"), Separated, ASCII_VERTICAL, false, false);
	}
	else {
		if (DnsmasqFormat)
			GetParameterListData(HostsListData, Data, Separated, Data.length(), ASCII_SLASH, false, false);
		else 
			GetParameterListData(HostsListData, Data, 0, Separated, ASCII_VERTICAL, false, false);
	}

//Address counts check
	if (HostsListData.empty())
	{
		PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Dnsmasq format check
	std::string *HostsListDataIter = &HostsListData.front();
	if (DnsmasqFormat)
	{
		if (HostsListData.size() > 2U || HostsListData.front().empty())
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
		else if (HostsListData.size() == 2U)
		{
			HostsListDataIter = &HostsListData.back();
		}
	}

//Mark record type.
	if (DnsmasqFormat && HostsListData.size() == 1U) //Dnsmasq Banned items
	{
		HostsTableTemp.PermissionType = HOSTS_TYPE_BANNED;
	}
	else if (HostsListDataIter->find(ASCII_COLON) != std::string::npos) //AAAA records(IPv6)
	{
		if (HostsListData.size() > DNS_RR_MAXCOUNT_AAAA)
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"Too many Hosts IPv6 addresses", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
		else {
			HostsTableTemp.RecordTypeList.push_back(htons(DNS_RECORD_AAAA));
		}
	}
	else if (HostsListDataIter->find(ASCII_PERIOD) != std::string::npos) //A records(IPv4)
	{
		if (HostsListData.size() > DNS_RR_MAXCOUNT_A)
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"Too many Hosts IPv4 addresses", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
		else {
			HostsTableTemp.RecordTypeList.push_back(htons(DNS_RECORD_A));
		}
	}
	else {
		PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Response initialization
	ADDRESS_UNION_DATA AddressUnionDataTemp;
	memset(&AddressUnionDataTemp, 0, sizeof(AddressUnionDataTemp));
	ssize_t Result = 0;

//Mark all data in list.
	if (DnsmasqFormat)
	{
		if (HostsListData.size() != 1U)
		{
			memset(&AddressUnionDataTemp, 0, sizeof(AddressUnionDataTemp));

		//AAAA records(IPv6)
			if (HostsTableTemp.RecordTypeList.front() == htons(DNS_RECORD_AAAA))
			{
				if (!AddressStringToBinary((const uint8_t *)HostsListData.back().c_str(), AF_INET6, &AddressUnionDataTemp.IPv6.sin6_addr, &Result))
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"IPv6 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
			}
		//A records(IPv4)
			else if (HostsTableTemp.RecordTypeList.front() == htons(DNS_RECORD_A))
			{
				if (!AddressStringToBinary((const uint8_t *)HostsListData.back().c_str(), AF_INET, &AddressUnionDataTemp.IPv4.sin_addr, &Result))
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"IPv4 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
			}
			else {
				PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Add to global list.
			HostsTableTemp.AddrOrTargetList.push_back(AddressUnionDataTemp);
		}
	}
	else {
		for (const auto &StringIter:HostsListData)
		{
			memset(&AddressUnionDataTemp, 0, sizeof(AddressUnionDataTemp));

		//AAAA records(IPv6)
			if (HostsTableTemp.RecordTypeList.front() == htons(DNS_RECORD_AAAA))
			{
				if (!AddressStringToBinary((const uint8_t *)StringIter.c_str(), AF_INET6, &AddressUnionDataTemp.IPv6.sin6_addr, &Result))
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"IPv6 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
			}
		//A records(IPv4)
			else if (HostsTableTemp.RecordTypeList.front() == htons(DNS_RECORD_A))
			{
				if (!AddressStringToBinary((const uint8_t *)StringIter.c_str(), AF_INET, &AddressUnionDataTemp.IPv4.sin_addr, &Result))
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"IPv4 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
			}
			else {
				PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Add to global list.
			HostsTableTemp.AddrOrTargetList.push_back(AddressUnionDataTemp);
		}
	}

//Address list check
	if (HostsTableTemp.PermissionType != HOSTS_TYPE_BANNED && HostsTableTemp.AddrOrTargetList.empty())
	{
		PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Dnsmasq format(Normal mode)
	if (DnsmasqFormat && (HostsListData.front().front() != ASCII_COLON || HostsListData.front().back() != ASCII_COLON))
	{
	//Make string reversed and mark it to list.
		MakeStringReversed(HostsListData.front());
		HostsTableTemp.PatternOrDomainString.append(HostsListData.front());
		HostsTableTemp.IsStringMatching = true;
	}
//Mark patterns.
	else {
		if (DnsmasqFormat) //Dnsmasq format(Regex mode)
		{
		//Regex format check
			if (HostsListData.front().front() != ASCII_COLON || HostsListData.front().back() != ASCII_COLON)
			{
				PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Mark domain.
			HostsListData.front().erase(0, 1U);
			HostsListData.front().pop_back();
			HostsTableTemp.PatternOrDomainString.append(HostsListData.front());
		}
		else {
			HostsTableTemp.PatternOrDomainString.append(Data, Separated, Data.length() - Separated);
		}
		
	//Try to mark patterns.
		try {
			std::regex PatternHostsTableTemp(HostsTableTemp.PatternOrDomainString);
			HostsTableTemp.Pattern.swap(PatternHostsTableTemp);
		}
		catch (std::regex_error& Error)
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_HOSTS, L"Regular expression pattern error", Error.code(), FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
	}

//Add to global list.
	for (auto &HostsFileSetIter:*HostsFileSetModificating)
	{
		if (HostsFileSetIter.FileIndex == FileIndex)
		{
			if (HostsType == HOSTS_TYPE_CNAME)
				HostsFileSetIter.HostsList_CNAME.push_back(HostsTableTemp);
			else //Normal
				HostsFileSetIter.HostsList_Normal.push_back(HostsTableTemp);

			break;
		}
	}

	return true;
}

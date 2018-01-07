// This code is part of Pcap_DNSProxy
// Pcap_DNSProxy, a local DNS server based on WinPcap and LibPcap
// Copyright (C) 2012-2018 Chengr28
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
	const size_t Line, 
	LABEL_HOSTS_TYPE &LabelType, 
	bool &IsStopLabel)
{
//Convert horizontal tab/HT to space and remove spaces before or after data.
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

//Delete comments(Number Sign/NS and double slashs) and check minimum length of hosts items.
	if (Data.compare(0, strlen("#"), ("#")) == 0 || Data.compare(0, strlen("/"), ("/")) == 0)
		return true;
	if (Data.rfind(" //") != std::string::npos)
		Data.erase(Data.rfind(" //"), Data.length() - Data.rfind(" //"));
	if (Data.rfind(" #") != std::string::npos)
		Data.erase(Data.rfind(" #"), Data.length() - Data.rfind(" #"));
	if (Data.length() < READ_HOSTS_MINSIZE)
		return true;

//Case insensitive
	std::string InsensitiveString(Data);
	CaseConvert(InsensitiveString, true);

//[Local Hosts] block(A part)
	if (LabelType == LABEL_HOSTS_TYPE::NONE && 
		(Parameter.Target_Server_Local_Main_IPv4.Storage.ss_family != 0 || Parameter.Target_Server_Local_Main_IPv6.Storage.ss_family != 0))
	{
		std::wstring WCS_InsensitiveString(FileList_Hosts.at(FileIndex).FileName);
		CaseConvert(WCS_InsensitiveString, true);
		if (CompareStringReversed(L"WHITELIST.TXT", WCS_InsensitiveString.c_str()) || CompareStringReversed(L"WHITE_LIST.TXT", WCS_InsensitiveString.c_str()))
		{
			LabelType = LABEL_HOSTS_TYPE::LOCAL;
			IsStopLabel = false;
		}
	}

//[Address Hosts] block
	if (InsensitiveString.compare(0, strlen("[SOURCE HOSTS]"), ("[SOURCE HOSTS]")) == 0)
	{
		LabelType = LABEL_HOSTS_TYPE::SOURCE;
		IsStopLabel = false;

		return true;
	}

//[Hosts] block
	else if (InsensitiveString.compare(0, strlen("[HOSTS]"), ("[HOSTS]")) == 0)
	{
		LabelType = LABEL_HOSTS_TYPE::NORMAL;
		IsStopLabel = false;

		return true;
	}

//[Local Hosts] block(B part)
	else if (InsensitiveString.compare(0, strlen("[LOCAL HOSTS]"), ("[LOCAL HOSTS]")) == 0)
	{
		LabelType = LABEL_HOSTS_TYPE::LOCAL;
		IsStopLabel = false;

		return true;
	}

//[CNAME Hosts] block
	else if (InsensitiveString.compare(0, strlen("[CNAME HOSTS]"), ("[CNAME HOSTS]")) == 0)
	{
		LabelType = LABEL_HOSTS_TYPE::CNAME;
		IsStopLabel = false;

		return true;
	}

//[Address Hosts] block
	else if (InsensitiveString.compare(0, strlen("[ADDRESS HOSTS]"), ("[ADDRESS HOSTS]")) == 0)
	{
		LabelType = LABEL_HOSTS_TYPE::ADDRESS;
		IsStopLabel = false;

		return true;
	}

//Temporary stop read.
	else if (InsensitiveString.compare(0, strlen("[STOP"), ("[STOP")) == 0)
	{
		if (InsensitiveString.compare(0, strlen("[STOP]"), ("[STOP]")) == 0)
		{
			IsStopLabel = true;
			return true;
		}
		else if (InsensitiveString.find("END") != std::string::npos)
		{
			IsStopLabel = false;
			return true;
		}
	}
	else if (IsStopLabel)
	{
		return true;
	}

//Whitelist, Banned and their Extended items
	auto LabelTypeTemp = LABEL_HOSTS_TYPE::NONE;
	if (InsensitiveString.compare(0, strlen("NULL "), ("NULL ")) == 0 || InsensitiveString.compare(0, strlen("NULL,"), ("NULL,")) == 0)
		LabelTypeTemp = LABEL_HOSTS_TYPE::WHITE;
	else if (InsensitiveString.compare(0, strlen("BAN "), ("BAN ")) == 0 || InsensitiveString.compare(0, strlen("BAN,"), ("BAN,")) == 0 || 
		InsensitiveString.compare(0, strlen("BANNED "), ("BANNED ")) == 0 || InsensitiveString.compare(0, strlen("BANNED,"), ("BANNED,")) == 0)
			LabelTypeTemp = LABEL_HOSTS_TYPE::BANNED;
	else if (InsensitiveString.compare(0, strlen("NULL"), ("NULL")) == 0)
		LabelTypeTemp = LABEL_HOSTS_TYPE::WHITE_EXTENDED;
	else if (InsensitiveString.compare(0, strlen("BAN"), ("BAN")) == 0 || InsensitiveString.compare(0, strlen("BANNED"), ("BANNED")) == 0)
		LabelTypeTemp = LABEL_HOSTS_TYPE::BANNED_EXTENDED;
	if (LabelTypeTemp != LABEL_HOSTS_TYPE::NONE)
	{
		if (LabelType == LABEL_HOSTS_TYPE::LOCAL && 
			(!Parameter.IsLocalHosts || //Do not read [Local Hosts] block when Local Hosts is disabled.
			(Parameter.Target_Server_Local_Main_IPv6.Storage.ss_family == 0 && Parameter.Target_Server_Local_Main_IPv4.Storage.ss_family == 0)))
		{
			return true;
		}
		else if (LabelType == LABEL_HOSTS_TYPE::NORMAL || LabelType == LABEL_HOSTS_TYPE::LOCAL)
		{
			return ReadOtherHostsData(Data, FileIndex, Line, LabelType, LabelTypeTemp);
		}
		else {
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
	}

//[Local Hosts] block
	else if (LabelType == LABEL_HOSTS_TYPE::LOCAL)
	{
		if (!Parameter.IsLocalHosts || //Do not read [Local Hosts] block when Local Hosts is disabled.
			(!Parameter.IsLocalForce && Parameter.IsLocalRouting) || //Do not read local hosts items in [Local Hosts] block when Local Routing is enabled and Local Force Request is disabled.
			(Parameter.Target_Server_Local_Main_IPv6.Storage.ss_family == 0 && Parameter.Target_Server_Local_Main_IPv4.Storage.ss_family == 0))
				return true;
		else 
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

//Main Hosts block
	if (LabelType == LABEL_HOSTS_TYPE::ADDRESS) //[Address Hosts] block
		return ReadAddressHostsData(Data, FileIndex, Line);
	else if (LabelType == LABEL_HOSTS_TYPE::CNAME) //[CNAME Hosts] block
		return ReadMainHostsData(Data, HOSTS_TYPE::CNAME, FileIndex, Line);
	else if (LabelType == LABEL_HOSTS_TYPE::SOURCE) //[Source Hosts] block
		return ReadMainHostsData(Data, HOSTS_TYPE::SOURCE, FileIndex, Line);
	else //[Hosts] block
		return ReadMainHostsData(Data, HOSTS_TYPE::NORMAL, FileIndex, Line);

	return true;
}

//Read other type items in Hosts file from data
bool ReadOtherHostsData(
	std::string Data, 
	const size_t FileIndex, 
	const size_t Line, 
	const LABEL_HOSTS_TYPE LabelType, 
	const LABEL_HOSTS_TYPE ItemType)
{
//Mark separated location and check data format.
	size_t Separated = 0;
	if (Data.find(ASCII_SPACE) != std::string::npos)
		Separated = Data.find(ASCII_SPACE);
	else if (Data.find(ASCII_COMMA) != std::string::npos)
		Separated = Data.find(ASCII_COMMA);
	if (Separated == 0 || 
		((ItemType == LABEL_HOSTS_TYPE::WHITE_EXTENDED || ItemType == LABEL_HOSTS_TYPE::BANNED_EXTENDED) && 
		(Data.find(ASCII_COLON) == std::string::npos || Separated <= Data.find(ASCII_COLON) + 1U)))
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Delete all spaces.
	while (Data.find(ASCII_SPACE) != std::string::npos)
		Data.erase(Data.find(ASCII_SPACE), 1U);

//Mark Whitelist Extended and Banned Extended types.
	HOSTS_TABLE HostsTableTemp;
	if (ItemType == LABEL_HOSTS_TYPE::WHITE_EXTENDED || ItemType == LABEL_HOSTS_TYPE::BANNED_EXTENDED)
	{
	//Case insensitive
		std::string InsensitiveString(Data);
		CaseConvert(InsensitiveString, true);

	//Permit or Deny mode check
		if ((ItemType == LABEL_HOSTS_TYPE::WHITE_EXTENDED && InsensitiveString.find("DENY") != std::string::npos && InsensitiveString.find("DENY") <= Separated) || 
			(ItemType == LABEL_HOSTS_TYPE::BANNED_EXTENDED && InsensitiveString.find("PERMIT") != std::string::npos && InsensitiveString.find("PERMIT") <= Separated))
				HostsTableTemp.PermissionOperation = true;

	//Mark types.
		std::vector<std::string> ListData;
		ssize_t Result = 0;

	//Mark all data in list.
		GetParameterListData(ListData, Data, Data.find(ASCII_COLON) + 1U, Separated, ASCII_VERTICAL, false, false);
		for (const auto &StringIter:ListData)
		{
			const auto RecordType = DNSTypeNameToBinary(reinterpret_cast<const uint8_t *>(StringIter.c_str()));

		//Number types
			if (RecordType == 0)
			{
				_set_errno(0);
				Result = strtoul(StringIter.c_str(), nullptr, 0);
				if (Result > 0 && Result <= UINT16_MAX)
				{
					HostsTableTemp.RecordTypeList.push_back(htons(static_cast<uint16_t>(Result)));
				}
				else {
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"DNS record type error", errno, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
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
		std::regex PatternRegexTemp(HostsTableTemp.PatternOrDomainString);
		std::swap(HostsTableTemp.PatternRegex, PatternRegexTemp);
		HostsTableTemp.PatternOrDomainString.clear();
		HostsTableTemp.PatternOrDomainString.shrink_to_fit();
	}
	catch (std::regex_error &Error)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"Regular expression pattern error", Error.code(), FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Mark types.
	if (ItemType == LABEL_HOSTS_TYPE::BANNED || ItemType == LABEL_HOSTS_TYPE::BANNED_EXTENDED)
		HostsTableTemp.PermissionType = HOSTS_TYPE::BANNED;
	else 
		HostsTableTemp.PermissionType = HOSTS_TYPE::WHITE;

//Mark to global list.
	for (auto &HostsFileSetIter:*HostsFileSetModificating)
	{
		if (HostsFileSetIter.FileIndex == FileIndex)
		{
			if (LabelType == LABEL_HOSTS_TYPE::LOCAL)
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
//Initialization
	HOSTS_TABLE HostsTableTemp;
	std::vector<std::string> HostsListData;
	size_t SeparatedOrResult = 0;
	auto IsDnsmasqFormat = false;

//Case insensitive
	std::string InsensitiveString(Data);
	CaseConvert(InsensitiveString, true);

//Dnsmasq format, please visit http://www.thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html.
	if (Data.compare(0, strlen("--"), ("--")) == 0)
	{
		if (InsensitiveString.find("--SERVER=/") == std::string::npos)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
		else {
			IsDnsmasqFormat = true;
			SeparatedOrResult = Data.find(ASCII_SLASH) + 1U;
		}
	}
	else if (InsensitiveString.compare(0, strlen("SERVER=/"), ("SERVER=/")) == 0)
	{
		IsDnsmasqFormat = true;
		SeparatedOrResult = Data.find(ASCII_SLASH) + 1U;
	}

//Dnsmasq format check
	if (IsDnsmasqFormat)
	{
	//Delete all spaces and string length check.
		while (Data.find(ASCII_SPACE) != std::string::npos)
			Data.erase(Data.find(ASCII_SPACE), 1U);

	//Get all list data.
		GetParameterListData(HostsListData, Data, SeparatedOrResult, Data.length(), ASCII_SLASH, false, true);
		if (HostsListData.empty() || HostsListData.size() > 2U)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
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
			else if (HostsListData.back() == ("#")) //Dnsmasq use the standard servers
			{
				HostsTableTemp.PermissionType = HOSTS_TYPE::WHITE;
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
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}

			//Response initialization
				ADDRESS_UNION_DATA AddressUnionDataTemp;
				memset(&AddressUnionDataTemp, 0, sizeof(AddressUnionDataTemp));
				ssize_t Result = 0;

			//Convert address.
				if (HostsListData.front().find(ASCII_COLON) != std::string::npos && HostsListData.front().find(ASCII_PERIOD) == std::string::npos) //IPv6
				{
					if (!AddressStringToBinary(AF_INET6, reinterpret_cast<const uint8_t *>(HostsListData.front().c_str()), &AddressUnionDataTemp.IPv6.sin6_addr, &Result))
					{
						PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv6 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
						return false;
					}
					else {
						AddressUnionDataTemp.Storage.ss_family = AF_INET6;
					}
				}
				else if (HostsListData.front().find(ASCII_PERIOD) != std::string::npos && HostsListData.front().find(ASCII_COLON) == std::string::npos) //IPv4
				{
					if (!AddressStringToBinary(AF_INET, reinterpret_cast<const uint8_t *>(HostsListData.front().c_str()), &AddressUnionDataTemp.IPv4.sin_addr, &Result))
					{
						PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv4 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
						return false;
					}
					else {
						AddressUnionDataTemp.Storage.ss_family = AF_INET;
					}
				}
				else {
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}

			//Convert port.
				if (HostsListData.size() == 2U) //Non-standard port
				{
					SeparatedOrResult = ServiceNameToBinary(reinterpret_cast<const uint8_t *>(HostsListData.back().c_str()));
					if (SeparatedOrResult == 0)
					{
						_set_errno(0);
						SeparatedOrResult = strtoul(reinterpret_cast<const char *>(HostsListData.back().c_str()), nullptr, 0);
						if (SeparatedOrResult == 0 || SeparatedOrResult >= ULONG_MAX)
						{
							PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv6 address port error", errno, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
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
					AddressUnionDataTemp.IPv6.sin6_port = htons(static_cast<uint16_t>(SeparatedOrResult));
				}
				else if (AddressUnionDataTemp.Storage.ss_family == AF_INET)
				{
					AddressUnionDataTemp.IPv4.sin_port = htons(static_cast<uint16_t>(SeparatedOrResult));
				}
				else {
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}

			//Add to list.
				HostsTableTemp.AddrOrTargetList.push_back(AddressUnionDataTemp);
			}
		}
		else {
		//Mark domain.
			if (HostsListData.front().front() == ASCII_COLON || HostsListData.front().back() == ASCII_COLON) //Dnsmasq regex mode
			{
			//Regex format check
				if (HostsListData.front().front() != ASCII_COLON || HostsListData.front().back() != ASCII_COLON)
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
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
				if (HostsTableTemp.PatternOrDomainString.back() != ASCII_PERIOD)
					HostsTableTemp.PatternOrDomainString.append(".");
				HostsTableTemp.IsStringMatching = true;
			}

		//Mark target server.
			if (!HostsListData.back().empty())
			{
			//Dnsmasq Whitelist items
				if (HostsListData.back() == ("#")) //Dnsmasq use the standard servers
				{
					HostsTableTemp.PermissionType = HOSTS_TYPE::WHITE;
				}
			//Mark target server.
				else {
				//Target server with port
					std::string DataTemp(HostsListData.back());
					HostsListData.clear();
					GetParameterListData(HostsListData, DataTemp, 0, DataTemp.length(), ASCII_HASHTAG, false, false);
					if (HostsListData.empty() || HostsListData.size() > 2U)
					{
						PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
						return false;
					}

				//Response initialization
					ADDRESS_UNION_DATA AddressUnionDataTemp;
					memset(&AddressUnionDataTemp, 0, sizeof(AddressUnionDataTemp));
					ssize_t Result = 0;

				//Convert address.
					if (HostsListData.front().find(ASCII_COLON) != std::string::npos && HostsListData.front().find(ASCII_PERIOD) == std::string::npos) //IPv6
					{
						if (!AddressStringToBinary(AF_INET6, reinterpret_cast<const uint8_t *>(HostsListData.front().c_str()), &AddressUnionDataTemp.IPv6.sin6_addr, &Result))
						{
							PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv6 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
							return false;
						}
						else {
							AddressUnionDataTemp.Storage.ss_family = AF_INET6;
						}
					}
					else if (HostsListData.front().find(ASCII_PERIOD) != std::string::npos && HostsListData.front().find(ASCII_COLON) == std::string::npos) //IPv4
					{
						if (!AddressStringToBinary(AF_INET, reinterpret_cast<const uint8_t *>(HostsListData.front().c_str()), &AddressUnionDataTemp.IPv4.sin_addr, &Result))
						{
							PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv4 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
							return false;
						}
						else {
							AddressUnionDataTemp.Storage.ss_family = AF_INET;
						}
					}
					else {
						PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
						return false;
					}

				//Convert port.
					if (HostsListData.size() == 2U) //Non-standard port
					{
						SeparatedOrResult = ServiceNameToBinary(reinterpret_cast<const uint8_t *>(HostsListData.back().c_str()));
						if (SeparatedOrResult == 0)
						{
							_set_errno(0);
							SeparatedOrResult = strtoul(reinterpret_cast<const char *>(HostsListData.back().c_str()), nullptr, 0);
							if (SeparatedOrResult == 0 || SeparatedOrResult >= ULONG_MAX)
							{
								PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv6 address port error", errno, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
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
						AddressUnionDataTemp.IPv6.sin6_port = htons(static_cast<uint16_t>(SeparatedOrResult));
					}
					else if (AddressUnionDataTemp.Storage.ss_family == AF_INET) //IPv4
					{
						AddressUnionDataTemp.IPv4.sin_port = htons(static_cast<uint16_t>(SeparatedOrResult));
					}
					else {
						PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
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
		if (!IsDnsmasqFormat)
			HostsTableTemp.PatternOrDomainString = Data;
		try {
			std::regex PatternRegexTemp(HostsTableTemp.PatternOrDomainString);
			std::swap(HostsTableTemp.PatternRegex, PatternRegexTemp);
			HostsTableTemp.PatternOrDomainString.clear();
			HostsTableTemp.PatternOrDomainString.shrink_to_fit();
		}
		catch (std::regex_error &Error)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"Regular expression pattern error", Error.code(), FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
	}

//Jump here to mark to global list.
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
		PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Delete all spaces.
	while (Data.find(ASCII_SPACE) != std::string::npos)
		Data.erase(Data.find(ASCII_SPACE), 1U);

//String length check.
	if (Data.length() < READ_HOSTS_ADDRESS_MINSIZE)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Initialization
	ADDRESS_HOSTS_TABLE AddressHostsTableTemp;
	ADDRESS_PREFIX_BLOCK AddressTargetPrefix;
	size_t Prefix = 0;

//Get target data.
	std::vector<std::string> TargetListData, SourceListData;
	GetParameterListData(TargetListData, Data, 0, Separated, ASCII_VERTICAL, false, false);
	GetParameterListData(SourceListData, Data, Separated, Data.length(), ASCII_VERTICAL, false, false);
	ssize_t Result = 0;
	uint16_t PreviousType = 0;

//Mark all data in list.
	for (auto &StringIter:TargetListData)
	{
		AddressTargetPrefix.second = 0;

	//AAAA record(IPv6)
		if (StringIter.find(ASCII_COLON) != std::string::npos)
		{
		//Before type check
			if (PreviousType == 0)
			{
				PreviousType = AF_INET6;
			}
			else if (PreviousType != AF_INET6)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Reset parameters.
			memset(&AddressTargetPrefix.first, 0, sizeof(AddressTargetPrefix.first));

		//Address prefix format
			if (StringIter.find(ASCII_SLASH) != std::string::npos)
			{
				if (!ReadAddressPrefixBlock(AF_INET6, StringIter, 0, &AddressTargetPrefix, FileList_Hosts, FileIndex, Line))
					return false;

			//Address prefix check
				if (Prefix == 0)
				{
					Prefix = AddressTargetPrefix.second;
				}
				else if (Prefix > 0 && Prefix != AddressTargetPrefix.second)
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
			}
		//Normal format
			else {
				if (!AddressStringToBinary(AF_INET6, reinterpret_cast<const uint8_t *>(StringIter.c_str()), &reinterpret_cast<sockaddr_in6 *>(&AddressTargetPrefix.first)->sin6_addr, &Result))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"IPv6 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
				else {
					AddressTargetPrefix.first.ss_family = AF_INET6;
				}
			}
		}
	//A record(IPv4)
		else if (StringIter.find(ASCII_PERIOD) != std::string::npos)
		{
		//Before type check
			if (PreviousType == 0)
			{
				PreviousType = AF_INET;
			}
			else if (PreviousType != AF_INET)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Reset parameters.
			memset(&AddressTargetPrefix.first, 0, sizeof(AddressTargetPrefix.first));

		//Address prefix format
			if (StringIter.find(ASCII_SLASH) != std::string::npos)
			{
				if (!ReadAddressPrefixBlock(AF_INET, StringIter, 0, &AddressTargetPrefix, FileList_Hosts, FileIndex, Line))
					return false;

			//Address prefix check
				if (Prefix == 0)
				{
					Prefix = AddressTargetPrefix.second;
				}
				else if (Prefix > 0 && Prefix != AddressTargetPrefix.second)
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
			}
		//Normal format
			else {
				if (!AddressStringToBinary(AF_INET, reinterpret_cast<const uint8_t *>(StringIter.c_str()), &reinterpret_cast<sockaddr_in *>(&AddressTargetPrefix.first)->sin_addr, &Result))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"IPv4 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
				else {
					AddressTargetPrefix.first.ss_family = AF_INET;
				}
			}
		}
		else {
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
			return false;
		}

	//Add to list.
		AddressHostsTableTemp.Address_Target.push_back(AddressTargetPrefix);
	}

//Get source data.
	ADDRESS_RANGE_TABLE AddressRangeTableTemp;
	uint8_t AddrBuffer[ADDRESS_STRING_MAXSIZE]{0};

//Mark all data in list.
	for (auto &StringIter:SourceListData)
	{
	//AAAA record(IPv6)
		if (StringIter.find(ASCII_COLON) != std::string::npos && PreviousType == AF_INET6)
		{
			memset(&AddressRangeTableTemp, 0, sizeof(AddressRangeTableTemp));

		//Address range format
			if (StringIter.find(ASCII_MINUS) != std::string::npos)
			{
			//Convert address(Begin).
				memset(AddrBuffer, 0, ADDRESS_STRING_MAXSIZE);
				memcpy_s(AddrBuffer, ADDRESS_STRING_MAXSIZE, StringIter.c_str(), StringIter.find(ASCII_MINUS));
				if (!AddressStringToBinary(AF_INET6, AddrBuffer, &reinterpret_cast<sockaddr_in6 *>(&AddressRangeTableTemp.Begin)->sin6_addr, &Result))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"IPv6 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
				else {
					AddressRangeTableTemp.Begin.ss_family = AF_INET6;
				}

			//Convert address(End).
				memset(AddrBuffer, 0, ADDRESS_STRING_MAXSIZE);
				memcpy_s(AddrBuffer, ADDRESS_STRING_MAXSIZE, StringIter.c_str() + StringIter.find(ASCII_MINUS) + 1U, StringIter.length() - StringIter.find(ASCII_MINUS) - 1U);
				if (!AddressStringToBinary(AF_INET6, AddrBuffer, &reinterpret_cast<sockaddr_in6 *>(&AddressRangeTableTemp.End)->sin6_addr, &Result))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"IPv6 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
				else {
					AddressRangeTableTemp.End.ss_family = AF_INET6;
				}

			//Check address range.
				if (AddressesComparing(AF_INET6, &reinterpret_cast<sockaddr_in6 *>(&AddressRangeTableTemp.Begin)->sin6_addr, &reinterpret_cast<sockaddr_in6 *>(&AddressRangeTableTemp.End)->sin6_addr) == ADDRESS_COMPARE_TYPE::GREATER)
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"IPv6 address range error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
			}
		//Normal format
			else {
			//Convert to binary address.
				if (!AddressStringToBinary(AF_INET6, reinterpret_cast<const uint8_t *>(StringIter.c_str()), &reinterpret_cast<sockaddr_in6 *>(&AddressRangeTableTemp.Begin)->sin6_addr, &Result))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"IPv6 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}

			//Mark address.
				AddressRangeTableTemp.Begin.ss_family = AF_INET6;
				AddressRangeTableTemp.End = AddressRangeTableTemp.Begin;
			}

		//Add to list.
			AddressHostsTableTemp.Address_Source.push_back(AddressRangeTableTemp);
		}
	//A record(IPv4)
		else if (StringIter.find(ASCII_PERIOD) != std::string::npos && PreviousType == AF_INET)
		{
			memset(&AddressRangeTableTemp, 0, sizeof(AddressRangeTableTemp));

		//Address range format
			if (StringIter.find(ASCII_MINUS) != std::string::npos)
			{
			//Convert address(Begin).
				memset(AddrBuffer, 0, ADDRESS_STRING_MAXSIZE);
				memcpy_s(AddrBuffer, ADDRESS_STRING_MAXSIZE, StringIter.c_str(), StringIter.find(ASCII_MINUS));
				if (!AddressStringToBinary(AF_INET, AddrBuffer, &reinterpret_cast<sockaddr_in *>(&AddressRangeTableTemp.Begin)->sin_addr, &Result))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"IPv4 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
				else {
					AddressRangeTableTemp.Begin.ss_family = AF_INET;
				}

			//Convert address(End).
				memset(AddrBuffer, 0, ADDRESS_STRING_MAXSIZE);
				memcpy_s(AddrBuffer, ADDRESS_STRING_MAXSIZE, StringIter.c_str() + StringIter.find(ASCII_MINUS) + 1U, StringIter.length() - StringIter.find(ASCII_MINUS) - 1U);
				if (!AddressStringToBinary(AF_INET, AddrBuffer, &reinterpret_cast<sockaddr_in *>(&AddressRangeTableTemp.End)->sin_addr, &Result))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"IPv4 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
				else {
					AddressRangeTableTemp.End.ss_family = AF_INET;
				}

			//Check address range.
				if (AddressesComparing(AF_INET, &reinterpret_cast<sockaddr_in *>(&AddressRangeTableTemp.Begin)->sin_addr, &reinterpret_cast<sockaddr_in *>(&AddressRangeTableTemp.End)->sin_addr) == ADDRESS_COMPARE_TYPE::GREATER)
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"IPv4 address range error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
			}
		//Normal format
			else {
			//Convert to binary address.
				if (!AddressStringToBinary(AF_INET, reinterpret_cast<const uint8_t *>(StringIter.c_str()), &reinterpret_cast<sockaddr_in *>(&AddressRangeTableTemp.Begin)->sin_addr, &Result))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"IPv4 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}

			//Mark address.
				AddressRangeTableTemp.Begin.ss_family = AF_INET;
				AddressRangeTableTemp.End = AddressRangeTableTemp.Begin;
			}

		//Add to list.
			AddressHostsTableTemp.Address_Source.push_back(AddressRangeTableTemp);
		}
		else {
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
	}

//Mark to global list.
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
	const HOSTS_TYPE HostsType, 
	const size_t FileIndex, 
	const size_t Line)
{
//Initialization
	size_t Separated = 0;
	auto IsDnsmasqFormat = false;

//Case insensitive
	std::string InsensitiveString(Data);
	CaseConvert(InsensitiveString, true);

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
//Dnsmasq format, please visit http://www.thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html.
	else if (HostsType != HOSTS_TYPE::SOURCE && Data.compare(0, strlen("--"), ("--")) == 0)
	{
		if (InsensitiveString.find("--ADDRESS=/") == std::string::npos || InsensitiveString.compare(0, strlen("--ADDRESS=//"), ("--ADDRESS=//")) == 0)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
		else {
			IsDnsmasqFormat = true;
			Separated = Data.find(ASCII_SLASH);
		}
	}
	else if (HostsType != HOSTS_TYPE::SOURCE && InsensitiveString.compare(0, strlen("ADDRESS=/"), ("ADDRESS=/")) == 0)
	{
		if (InsensitiveString.compare(0, strlen("ADDRESS=//"), ("ADDRESS=//")) == 0)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
		else {
			IsDnsmasqFormat = true;
			Separated = Data.find(ASCII_SLASH);
		}
	}
	else {
		PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Source Hosts format check
	if (HostsType == HOSTS_TYPE::SOURCE && (Data.find("->") == std::string::npos || Data.find("->") >= Separated))
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Delete all spaces and string length check.
	while (Data.find(ASCII_SPACE) != std::string::npos)
		Data.erase(Data.find(ASCII_SPACE), 1U);
	if (!IsDnsmasqFormat && Separated < READ_HOSTS_MINSIZE)
		return false;

//Initialization(Part 1)
	HOSTS_TABLE HostsTableTemp;
	std::vector<std::string> HostsListData;

//Mark source address.
	if (HostsType == HOSTS_TYPE::SOURCE)
	{
		std::vector<std::string> SourceListData;
		GetParameterListData(SourceListData, Data, 0, Data.find("->"), ASCII_VERTICAL, false, false);
		if (SourceListData.empty())
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
		else {
		//Protocol settings
			ADDRESS_PREFIX_BLOCK AddressPrefix;
			uint16_t Protocol = 0;
			if (SourceListData.front().find(ASCII_COLON) != std::string::npos) //IPv6
				Protocol = AF_INET6;
			else //IPv4
				Protocol = AF_INET;

		//Mark all data in list.
			for (const auto &StringIter:SourceListData)
			{
				if (!ReadAddressPrefixBlock(Protocol, StringIter, 0, &AddressPrefix, FileList_Hosts, FileIndex, Line))
					return false;
				else 
					HostsTableTemp.SourceList.push_back(AddressPrefix);
			}
		}

		GetParameterListData(HostsListData, Data, Data.find("->") + strlen("->"), Separated, ASCII_VERTICAL, false, false);
	}
	else {
		if (IsDnsmasqFormat)
			GetParameterListData(HostsListData, Data, Separated, Data.length(), ASCII_SLASH, false, false);
		else 
			GetParameterListData(HostsListData, Data, 0, Separated, ASCII_VERTICAL, false, false);
	}

//Address counts check
	if (HostsListData.empty())
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Dnsmasq format check
	std::string *HostsListDataIter = &HostsListData.front();
	if (IsDnsmasqFormat)
	{
		if (HostsListData.size() > 2U || HostsListData.front().empty())
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
		else if (HostsListData.size() == 2U)
		{
			HostsListDataIter = &HostsListData.back();
		}
	}

//Mark record type.
	if (IsDnsmasqFormat && HostsListData.size() == 1U) //Dnsmasq Banned items
	{
		HostsTableTemp.PermissionType = HOSTS_TYPE::BANNED;
	}
	else if (HostsListDataIter->find(ASCII_COLON) != std::string::npos) //AAAA record(IPv6)
	{
		if (HostsListData.size() > DNS_RR_MAX_AAAA_COUNT)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"Too many Hosts IPv6 addresses", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
		else {
			HostsTableTemp.RecordTypeList.push_back(htons(DNS_TYPE_AAAA));
		}
	}
	else if (HostsListDataIter->find(ASCII_PERIOD) != std::string::npos) //A record(IPv4)
	{
		if (HostsListData.size() > DNS_RR_MAX_A_COUNT)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"Too many Hosts IPv4 addresses", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
		else {
			HostsTableTemp.RecordTypeList.push_back(htons(DNS_TYPE_A));
		}
	}
	else {
		PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Response initialization
	ADDRESS_UNION_DATA AddressUnionDataTemp;
	memset(&AddressUnionDataTemp, 0, sizeof(AddressUnionDataTemp));
	ssize_t Result = 0;

//Mark all data in list.
	if (IsDnsmasqFormat)
	{
		if (HostsListData.size() != 1U)
		{
			memset(&AddressUnionDataTemp, 0, sizeof(AddressUnionDataTemp));

		//AAAA record(IPv6)
			if (HostsTableTemp.RecordTypeList.front() == htons(DNS_TYPE_AAAA))
			{
				if (!AddressStringToBinary(AF_INET6, reinterpret_cast<const uint8_t *>(HostsListData.back().c_str()), &AddressUnionDataTemp.IPv6.sin6_addr, &Result))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"IPv6 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
			}
		//A record(IPv4)
			else if (HostsTableTemp.RecordTypeList.front() == htons(DNS_TYPE_A))
			{
				if (!AddressStringToBinary(AF_INET, reinterpret_cast<const uint8_t *>(HostsListData.back().c_str()), &AddressUnionDataTemp.IPv4.sin_addr, &Result))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"IPv4 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
			}
			else {
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Mark to global list.
			HostsTableTemp.AddrOrTargetList.push_back(AddressUnionDataTemp);
		}
	}
	else {
		for (const auto &StringIter:HostsListData)
		{
			memset(&AddressUnionDataTemp, 0, sizeof(AddressUnionDataTemp));

		//AAAA record(IPv6)
			if (HostsTableTemp.RecordTypeList.front() == htons(DNS_TYPE_AAAA))
			{
				if (!AddressStringToBinary(AF_INET6, reinterpret_cast<const uint8_t *>(StringIter.c_str()), &AddressUnionDataTemp.IPv6.sin6_addr, &Result))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"IPv6 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
			}
		//A record(IPv4)
			else if (HostsTableTemp.RecordTypeList.front() == htons(DNS_TYPE_A))
			{
				if (!AddressStringToBinary(AF_INET, reinterpret_cast<const uint8_t *>(StringIter.c_str()), &AddressUnionDataTemp.IPv4.sin_addr, &Result))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"IPv4 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
			}
			else {
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Mark to global list.
			HostsTableTemp.AddrOrTargetList.push_back(AddressUnionDataTemp);
		}
	}

//Address list check
	if (HostsTableTemp.PermissionType != HOSTS_TYPE::BANNED && HostsTableTemp.AddrOrTargetList.empty())
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Dnsmasq format(Normal mode)
	if (IsDnsmasqFormat && (HostsListData.front().front() != ASCII_COLON || HostsListData.front().back() != ASCII_COLON))
	{
	//Make string reversed and mark it to list.
		MakeStringReversed(HostsListData.front());
		HostsTableTemp.PatternOrDomainString.append(HostsListData.front());
		HostsTableTemp.PatternOrDomainString.append(".");
		HostsTableTemp.IsStringMatching = true;
	}
//Mark patterns.
	else {
		if (IsDnsmasqFormat) //Dnsmasq format(Regex mode)
		{
		//Regex format check
			if (HostsListData.front().front() != ASCII_COLON || HostsListData.front().back() != ASCII_COLON)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
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

	//Mark patterns.
		try {
			std::regex PatternRegexTemp(HostsTableTemp.PatternOrDomainString);
			std::swap(HostsTableTemp.PatternRegex, PatternRegexTemp);
			HostsTableTemp.PatternOrDomainString.clear();
			HostsTableTemp.PatternOrDomainString.shrink_to_fit();
		}
		catch (std::regex_error &Error)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HOSTS, L"Regular expression pattern error", Error.code(), FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
	}

//Mark to global list.
	for (auto &HostsFileSetIter:*HostsFileSetModificating)
	{
		if (HostsFileSetIter.FileIndex == FileIndex)
		{
			if (HostsType == HOSTS_TYPE::CNAME)
				HostsFileSetIter.HostsList_CNAME.push_back(HostsTableTemp);
			else //Normal
				HostsFileSetIter.HostsList_Normal.push_back(HostsTableTemp);

			break;
		}
	}

	return true;
}

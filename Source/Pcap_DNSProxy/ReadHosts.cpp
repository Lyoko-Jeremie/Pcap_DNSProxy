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
bool __fastcall ReadHostsData(
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
	while (!Data.empty() && Data.at(0) == ASCII_SPACE)
		Data.erase(0, 1U);
	while (!Data.empty() && Data.back() == ASCII_SPACE)
		Data.pop_back();
	while (!Data.empty() && Data.find("  ") != std::string::npos)
		Data.erase(Data.find("  "), 1U);

//Multi-line comments check, delete comments(Number Sign/NS and double slashs) and check minimum length of hosts items.
	if (!ReadMultiLineComments(Data, IsLabelComments) || Data.find(ASCII_HASHTAG) == 0 || Data.find(ASCII_SLASH) == 0)
		return true;
	if (Data.rfind(" //") != std::string::npos)
		Data.erase(Data.rfind(" //"), Data.length() - Data.rfind(" //"));
	if (Data.rfind(" #") != std::string::npos)
		Data.erase(Data.rfind(" #"), Data.length() - Data.rfind(" #"));
	if (Data.length() < READ_HOSTS_MINSIZE)
		return true;

//[Base] block
	if (Data.find("[Base]") == 0 || Data.find("[base]") == 0 || 
		Data.find("Version = ") == 0 || Data.find("version = ") == 0 || 
		Data.find("Default TTL = ") == 0 || Data.find("default ttl = ") == 0)
			return true;

//[Local Hosts] block(A part)
	if (LabelType == 0 && (Parameter.DNSTarget.Local_IPv4.Storage.ss_family > 0 || Parameter.DNSTarget.Local_IPv6.Storage.ss_family > 0) && 
	#if defined(PLATFORM_WIN) //Case-insensitive in Windows
		(FileList_Hosts.at(FileIndex).FileName.rfind(L"whitelist.txt") != std::wstring::npos && FileList_Hosts.at(FileIndex).FileName.length() > wcslen(L"whitelist.txt") && 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"whitelist.txt") + wcslen(L"whitelist.txt") == FileList_Hosts.at(FileIndex).FileName.length() || 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"white_list.txt") != std::wstring::npos && FileList_Hosts.at(FileIndex).FileName.length() > wcslen(L"white_list.txt") && 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"white_list.txt") + wcslen(L"white_list.txt") == FileList_Hosts.at(FileIndex).FileName.length()))
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		(FileList_Hosts.at(FileIndex).FileName.rfind(L"WhiteList.txt") != std::wstring::npos && FileList_Hosts.at(FileIndex).FileName.length() > wcslen(L"WhiteList.txt") && 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"WhiteList.txt") + wcslen(L"WhiteList.txt") == FileList_Hosts.at(FileIndex).FileName.length() || 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"Whitelist.txt") != std::wstring::npos && FileList_Hosts.at(FileIndex).FileName.length() > wcslen(L"Whitelist.txt") && 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"Whitelist.txt") + wcslen(L"Whitelist.txt") == FileList_Hosts.at(FileIndex).FileName.length() || 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"whitelist.txt") != std::wstring::npos && FileList_Hosts.at(FileIndex).FileName.length() > wcslen(L"whitelist.txt") && 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"whitelist.txt") + wcslen(L"whitelist.txt") == FileList_Hosts.at(FileIndex).FileName.length() || 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"White_List.txt") != std::wstring::npos && FileList_Hosts.at(FileIndex).FileName.length() > wcslen(L"White_List.txt") && 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"White_List.txt") + wcslen(L"White_List.txt") == FileList_Hosts.at(FileIndex).FileName.length() || 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"White_list.txt") != std::wstring::npos && FileList_Hosts.at(FileIndex).FileName.length() > wcslen(L"White_list.txt") && 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"White_list.txt") + wcslen(L"White_list.txt") == FileList_Hosts.at(FileIndex).FileName.length() || 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"white_list.txt") != std::wstring::npos && FileList_Hosts.at(FileIndex).FileName.length() > wcslen(L"white_list.txt") && 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"white_list.txt") + wcslen(L"white_list.txt") == FileList_Hosts.at(FileIndex).FileName.length()))
	#endif
			LabelType = LABEL_HOSTS_TYPE_LOCAL;

//[Hosts] block
	if (Data.find("[Hosts]") == 0 || Data.find("[hosts]") == 0)
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

//[Address Hosts] block
	else if (Data.find("[Address Hosts]") == 0 || Data.find("[Address hosts]") == 0 || Data.find("[address Hosts]") == 0 || Data.find("[address hosts]") == 0)
	{
		LabelType = LABEL_HOSTS_TYPE_ADDRESS;
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

//Temporary stop read.
	else if (Data.find("[Stop]") == 0 || Data.find("[stop]") == 0)
	{
		LabelType = LABEL_STOP;
		return true;
	}
	if (LabelType == LABEL_STOP)
		return true;

//Whitelist items
	if (Data.find("NULL ") == 0 || Data.find("NULL,") == 0 || 
		Data.find("Null ") == 0 || Data.find("Null,") == 0 || 
		Data.find("null ") == 0 || Data.find("null,") == 0)
	{
		return ReadOtherHostsData(Data, FileIndex, Line, LabelType, LABEL_HOSTS_TYPE_WHITE);
	}

//Banned items
	else if (Data.find("BAN ") == 0 || Data.find("BAN,") == 0 || 
		Data.find("BANNED ") == 0 || Data.find("BANNED,") == 0 || 
		Data.find("Ban ") == 0 || Data.find("Ban,") == 0 || 
		Data.find("Banned ") == 0 || Data.find("Banned,") == 0 || 
		Data.find("ban ") == 0 || Data.find("ban,") == 0 || 
		Data.find("banned ") == 0 || Data.find("banned,") == 0)
	{
		return ReadOtherHostsData(Data, FileIndex, Line, LabelType, LABEL_HOSTS_TYPE_BANNED);
	}

//Whitelist Extended items
	else if (Data.find("NULL") == 0 || Data.find("Null") == 0 || Data.find("null") == 0)
	{
		return ReadOtherHostsData(Data, FileIndex, Line, LabelType, LABEL_HOSTS_TYPE_WHITE_EXTENDED);
	}

//Banned Extended items
	else if (Data.find("BAN") == 0 || Data.find("BANNED") == 0 || Data.find("Ban") == 0 || 
		Data.find("Banned") == 0 || Data.find("ban") == 0 || Data.find("banned") == 0)
	{
		return ReadOtherHostsData(Data, FileIndex, Line, LabelType, LABEL_HOSTS_TYPE_BANNED_EXTENDED);
	}

//[Local Hosts] block
	else if (LabelType == LABEL_HOSTS_TYPE_LOCAL)
	{
		if (Parameter.LocalMain)
			return true;
		else if (Parameter.LocalHosts && (Parameter.DNSTarget.Local_IPv4.Storage.ss_family > 0 || Parameter.DNSTarget.Local_IPv6.Storage.ss_family > 0))
			return ReadLocalHostsData(Data, FileIndex, Line);
	}

//[Address Hosts] block
	else if (LabelType == LABEL_HOSTS_TYPE_ADDRESS)
	{
	//Delete spaces before or after verticals.
		while (Data.find(" |") != std::string::npos || Data.find("| ") != std::string::npos)
		{
			if (Data.find(" |") != std::string::npos)
				Data.erase(Data.find(" |"), strlen(" "));
			if (Data.find("| ") != std::string::npos)
				Data.erase(Data.find("| ") + 1U, strlen("|"));
		}

		return ReadAddressHostsData(Data, FileIndex, Line);
	}

//Main Hosts block
	else {
	//Delete spaces before or after verticals.
		while (Data.find(" |") != std::string::npos || Data.find("| ") != std::string::npos)
		{
			if (Data.find(" |") != std::string::npos)
				Data.erase(Data.find(" |"), strlen(" "));
			if (Data.find("| ") != std::string::npos)
				Data.erase(Data.find("| ") + 1U, strlen("|"));
		}

	//[CNAME Hosts] block
		if (LabelType == LABEL_HOSTS_TYPE_CNAME)
			return ReadMainHostsData(Data, HOSTS_TYPE_CNAME, FileIndex, Line);
	//[Hosts] block
		else 
			return ReadMainHostsData(Data, HOSTS_TYPE_NORMAL, FileIndex, Line);
	}

	return true;
}

//Read other type items in Hosts file from data
bool __fastcall ReadOtherHostsData(
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
	if (Separated == 0 || ((ItemType == LABEL_HOSTS_TYPE_WHITE_EXTENDED || ItemType == LABEL_HOSTS_TYPE_BANNED_EXTENDED) && 
		(Data.find(ASCII_COLON) == std::string::npos || Separated <= Data.find(ASCII_COLON) + 1U)))
	{
		PrintError(LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Delete all spaces.
	while (Data.find(ASCII_SPACE) != std::string::npos)
		Data.erase(Data.find(ASCII_SPACE), 1U);

//Mark Whitelist Extended and Banned Extended types.
	HOSTS_TABLE HostsTableTemp;
	if (ItemType == LABEL_HOSTS_TYPE_WHITE_EXTENDED || ItemType == LABEL_HOSTS_TYPE_BANNED_EXTENDED)
	{
	//Permit or Deny
		if (ItemType == LABEL_HOSTS_TYPE_WHITE_EXTENDED && 
			(Data.find("DENY") != std::string::npos && Data.find("DENY") <= Separated || 
			Data.find("Deny") != std::string::npos && Data.find("Deny") <= Separated || 
			Data.find("deny") != std::string::npos && Data.find("deny") <= Separated) || 
			ItemType == LABEL_HOSTS_TYPE_BANNED_EXTENDED && 
			(Data.find("PERMIT") != std::string::npos && Data.find("PERMIT") <= Separated || 
			Data.find("Permit") != std::string::npos && Data.find("Permit") <= Separated || 
			Data.find("permit") != std::string::npos && Data.find("permit") <= Separated))
				HostsTableTemp.PermissionOperation = true;

	//Mark types.
		std::vector<std::string> ListData;
		uint16_t RecordType = 0;
		SSIZE_T Result = 0;

	//Mark all data in list.
		GetParameterListData(ListData, Data, Data.find(ASCII_COLON) + 1U, Separated);
		for (auto StringIter:ListData)
		{
			RecordType = DNSTypeNameToHex(StringIter.c_str());

		//Number types
			if (RecordType <= 0)
			{
				Result = strtoul(StringIter.c_str(), nullptr, 0);
				if (errno != ERANGE && Result > 0 && Result <= UINT16_MAX)
				{
					HostsTableTemp.RecordTypeList.push_back(htons((uint16_t)Result));
				}
				else {
					PrintError(LOG_ERROR_PARAMETER, L"DNS Records type error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
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
	HostsTableTemp.PatternString.append(Data, Separated, Data.length() - Separated);
	try {
		std::regex PatternHostsTableTemp(HostsTableTemp.PatternString);
		HostsTableTemp.Pattern.swap(PatternHostsTableTemp);
	}
	catch (std::regex_error& Error)
	{
		PrintError(LOG_ERROR_HOSTS, L"Regular expression pattern error", Error.code(), FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Mark types.
	if (ItemType == LABEL_HOSTS_TYPE_BANNED || ItemType == LABEL_HOSTS_TYPE_BANNED_EXTENDED)
		HostsTableTemp.PermissionType = HOSTS_TYPE_BANNED;
	else 
		HostsTableTemp.PermissionType = HOSTS_TYPE_WHITE;

//Add to global HostsList.
	for (auto &HostsFileSetIter:*HostsFileSetModificating)
	{
		if (HostsFileSetIter.FileIndex == FileIndex)
		{
			if (LabelType == LABEL_HOSTS_TYPE_NORMAL)
				HostsFileSetIter.HostsList_Normal.push_back(HostsTableTemp);
			else if (LabelType == LABEL_HOSTS_TYPE_LOCAL)
				HostsFileSetIter.HostsList_Local.push_back(HostsTableTemp);

			break;
		}
	}

	return true;
}

//Read Local Hosts items in Hosts file from data
bool __fastcall ReadLocalHostsData(
	std::string Data, 
	const size_t FileIndex, 
	const size_t Line)
{
	HOSTS_TABLE HostsTableTemp;

//Mark patterns.
	HostsTableTemp.PatternString = Data;
	try {
		std::regex PatternHostsTableTemp(HostsTableTemp.PatternString);
		HostsTableTemp.Pattern.swap(PatternHostsTableTemp);
	}
	catch (std::regex_error& Error)
	{
		PrintError(LOG_ERROR_HOSTS, L"Regular expression pattern error", Error.code(), FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Add to global HostsTable.
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
bool __fastcall ReadAddressHostsData(
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
		PrintError(LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Delete all spaces.
	while (Data.find(ASCII_SPACE) != std::string::npos)
		Data.erase(Data.find(ASCII_SPACE), 1U);

//String length check.
	if (Data.length() < READ_HOSTS_ADDRESS_MINSIZE)
	{
		PrintError(LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Initialization
	ADDRESS_HOSTS_TABLE AddressHostsTableTemp;
	auto SockAddr = std::make_shared<sockaddr_storage>();
	std::shared_ptr<char> Addr(new char[ADDR_STRING_MAXSIZE]());
	memset(SockAddr.get(), 0, sizeof(sockaddr_storage));
	memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);

//Get target data.
	std::vector<std::string> TargetListData, SourceListData;
	GetParameterListData(TargetListData, Data, 0, Separated);
	GetParameterListData(SourceListData, Data, Separated, Data.length());
	SSIZE_T Result = 0;

//Mark all data in list.
	for (auto StringIter:TargetListData)
	{
	//AAAA records(IPv6)
		if (StringIter.find(ASCII_COLON) != std::string::npos)
		{
		//Convert to binary address.
			memset(SockAddr.get(), 0, sizeof(sockaddr_storage));
			if (!AddressStringToBinary(StringIter.c_str(), AF_INET6, &((PSOCKADDR_IN6)SockAddr.get())->sin6_addr, &Result))
			{
				PrintError(LOG_ERROR_HOSTS, L"IPv6 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Add to list.
			SockAddr->ss_family = AF_INET6;
			AddressHostsTableTemp.Address_Target.push_back(*SockAddr);
		}
	//A records(IPv4)
		else {
		//Convert to binary address.
			memset(SockAddr.get(), 0, sizeof(sockaddr_storage));
			if (!AddressStringToBinary(StringIter.c_str(), AF_INET, &((PSOCKADDR_IN)SockAddr.get())->sin_addr, &Result))
			{
				PrintError(LOG_ERROR_HOSTS, L"IPv4 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Add to list.
			SockAddr->ss_family = AF_INET;
			AddressHostsTableTemp.Address_Target.push_back(*SockAddr);
		}
	}

	SockAddr.reset();

//Get source data.
	ADDRESS_RANGE_TABLE AddressRangeTableTemp;
	memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);

//Mark all data in list.
	for (auto StringIter:SourceListData)
	{
	//AAAA records(IPv6)
		if (StringIter.find(ASCII_COLON) != std::string::npos)
		{
			memset(&AddressRangeTableTemp, 0, sizeof(ADDRESS_RANGE_TABLE));

		//Address range format
			if (StringIter.find(ASCII_MINUS) != std::string::npos)
			{
			//Convert address(Begin).
				memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
				memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, StringIter.c_str(), StringIter.find(ASCII_MINUS));
				if (!AddressStringToBinary(Addr.get(), AF_INET6, &((PSOCKADDR_IN6)&AddressRangeTableTemp.Begin)->sin6_addr, &Result))
				{
					PrintError(LOG_ERROR_HOSTS, L"IPv6 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
				AddressRangeTableTemp.Begin.ss_family = AF_INET6;

			//Convert address(End).
				memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
				memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, StringIter.c_str() + StringIter.find(ASCII_MINUS) + 1U, StringIter.length() - StringIter.find(ASCII_MINUS) - 1U);
				if (!AddressStringToBinary(Addr.get(), AF_INET6, &((PSOCKADDR_IN6)&AddressRangeTableTemp.End)->sin6_addr, &Result))
				{
					PrintError(LOG_ERROR_HOSTS, L"IPv6 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
				AddressRangeTableTemp.End.ss_family = AF_INET6;

			//Check address range.
				if (AddressesComparing(&((PSOCKADDR_IN6)&AddressRangeTableTemp.Begin)->sin6_addr, &((PSOCKADDR_IN6)&AddressRangeTableTemp.End)->sin6_addr, AF_INET6) > ADDRESS_COMPARE_EQUAL)
				{
					PrintError(LOG_ERROR_HOSTS, L"IPv6 address range error", WSAGetLastError(), FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
			}
		//Normal format
			else {
			//Convert to binary address.
				if (!AddressStringToBinary(StringIter.c_str(), AF_INET6, &((PSOCKADDR_IN6)&AddressRangeTableTemp.Begin)->sin6_addr, &Result))
				{
					PrintError(LOG_ERROR_HOSTS, L"IPv6 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}

				AddressRangeTableTemp.Begin.ss_family = AF_INET6;
				AddressRangeTableTemp.End = AddressRangeTableTemp.Begin;
			}

		//Add to list.
			AddressHostsTableTemp.Address_Source.push_back(AddressRangeTableTemp);
		}
	//A records(IPv4)
		else {
			memset(&AddressRangeTableTemp, 0, sizeof(ADDRESS_RANGE_TABLE));

		//Address range format
			if (StringIter.find(ASCII_MINUS) != std::string::npos)
			{
			//Convert address(Begin).
				memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
				memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, StringIter.c_str(), StringIter.find(ASCII_MINUS));
				if (!AddressStringToBinary(Addr.get(), AF_INET, &((PSOCKADDR_IN)&AddressRangeTableTemp.Begin)->sin_addr, &Result))
				{
					PrintError(LOG_ERROR_HOSTS, L"IPv4 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
				AddressRangeTableTemp.Begin.ss_family = AF_INET;

			//Convert address(End).
				memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
				memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, StringIter.c_str() + StringIter.find(ASCII_MINUS) + 1U, StringIter.length() - StringIter.find(ASCII_MINUS) - 1U);
				if (!AddressStringToBinary(Addr.get(), AF_INET, &((PSOCKADDR_IN)&AddressRangeTableTemp.End)->sin_addr, &Result))
				{
					PrintError(LOG_ERROR_HOSTS, L"IPv4 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
				AddressRangeTableTemp.End.ss_family = AF_INET;

			//Check address range.
				if (AddressesComparing(&((PSOCKADDR_IN)&AddressRangeTableTemp.Begin)->sin_addr, &((PSOCKADDR_IN)&AddressRangeTableTemp.End)->sin_addr, AF_INET) > ADDRESS_COMPARE_EQUAL)
				{
					PrintError(LOG_ERROR_HOSTS, L"IPv4 address range error", WSAGetLastError(), FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
			}
		//Normal format
			else {
			//Convert to binary address.
				if (!AddressStringToBinary(StringIter.c_str(), AF_INET, &((PSOCKADDR_IN)&AddressRangeTableTemp.Begin)->sin_addr, &Result))
				{
					PrintError(LOG_ERROR_HOSTS, L"IPv4 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}

				AddressRangeTableTemp.Begin.ss_family = AF_INET;
				AddressRangeTableTemp.End = AddressRangeTableTemp.Begin;
			}

		//Add to list.
			AddressHostsTableTemp.Address_Source.push_back(AddressRangeTableTemp);
		}
	}

	Addr.reset();

//Add to global AddressHostsTable.
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
bool __fastcall ReadMainHostsData(
	std::string Data, 
	const size_t HostsType, 
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
		PrintError(LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Delete all spaces and string length check.
	while (Data.find(ASCII_SPACE) != std::string::npos)
		Data.erase(Data.find(ASCII_SPACE), 1U);
	if (Separated < READ_HOSTS_MINSIZE)
		return false;

//Initialization
	HOSTS_TABLE HostsTableTemp;
	std::vector<std::string> ListData;
	GetParameterListData(ListData, Data, 0, Separated);

//Address counts check
	if (ListData.empty())
	{
		PrintError(LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
		return false;
	}
	else if (ListData.front().find(ASCII_COLON) != std::string::npos) //AAAA records(IPv6)
	{
		if (ListData.size() > DNS_RR_MAXCOUNT_AAAA)
		{
			PrintError(LOG_ERROR_HOSTS, L"Too many Hosts IPv6 addresses", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
		else {
			HostsTableTemp.RecordTypeList.push_back(htons(DNS_RECORD_AAAA));
		}
	}
	else { //A records(IPv4)
		if (ListData.size() > DNS_RR_MAXCOUNT_A)
		{
			PrintError(LOG_ERROR_HOSTS, L"Too many Hosts IPv4 addresses", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
		else {
			HostsTableTemp.RecordTypeList.push_back(htons(DNS_RECORD_A));
		}
	}

//Response initialization
	auto AddressUnionDataTemp = std::make_shared<ADDRESS_UNION_DATA>();
	std::shared_ptr<char> Addr(new char[ADDR_STRING_MAXSIZE]());
	SSIZE_T Result = 0;

//Mark all data in list.
	for (auto StringIter:ListData)
	{
		memset(AddressUnionDataTemp.get(), 0, sizeof(ADDRESS_UNION_DATA));
		memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
		memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, StringIter.c_str(), StringIter.length());

	//AAAA records(IPv6)
		if (HostsTableTemp.RecordTypeList.front() == htons(DNS_RECORD_AAAA))
		{
			if (!AddressStringToBinary(Addr.get(), AF_INET6, &AddressUnionDataTemp->IPv6.sin6_addr, &Result))
			{
				PrintError(LOG_ERROR_HOSTS, L"IPv6 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
				return false;
			}
		}
	//A records(IPv4)
		else {
			if (!AddressStringToBinary(Addr.get(), AF_INET, &AddressUnionDataTemp->IPv4.sin_addr, &Result))
			{
				PrintError(LOG_ERROR_HOSTS, L"IPv4 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
				return false;
			}
		}

	//Add to global list.
		HostsTableTemp.AddrList.push_back(*AddressUnionDataTemp);
	}

//Address list check
	if (HostsTableTemp.AddrList.empty())
	{
		PrintError(LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
		return false;
	}
	else {
		Addr.reset();
	}

//Mark patterns.
	HostsTableTemp.PatternString.append(Data, Separated, Data.length() - Separated);
	try {
		std::regex PatternHostsTableTemp(HostsTableTemp.PatternString);
		HostsTableTemp.Pattern.swap(PatternHostsTableTemp);
	}
	catch (std::regex_error& Error)
	{
		PrintError(LOG_ERROR_HOSTS, L"Regular expression pattern error", Error.code(), FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Add to global HostsTable.
	for (auto &HostsFileSetIter:*HostsFileSetModificating)
	{
		if (HostsFileSetIter.FileIndex == FileIndex)
		{
			if (HostsType == HOSTS_TYPE_NORMAL)
				HostsFileSetIter.HostsList_Normal.push_back(HostsTableTemp);
			else if (HostsType == HOSTS_TYPE_CNAME)
				HostsFileSetIter.HostsList_CNAME.push_back(HostsTableTemp);

			break;
		}
	}

	return true;
}

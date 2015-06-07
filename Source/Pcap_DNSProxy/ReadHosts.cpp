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


#include "Configuration.h"

//Read hosts data from files
bool __fastcall ReadHostsData(const char *Buffer, const size_t FileIndex, const size_t Line, size_t &LabelType, bool &IsLabelComments)
{
	std::string Data(Buffer);

//Multi-line comments check, delete comments(Number Sign/NS and double slashs) and check minimum length of hosts items.
	if (!ReadMultiLineComments(Buffer, Data, IsLabelComments) || Data.find(ASCII_HASHTAG) == 0 || Data.find(ASCII_SLASH) == 0)
		return true;
	else if (Data.rfind(" //") != std::string::npos)
		Data.erase(Data.rfind(" //"), Data.length() - Data.rfind(" //"));
	else if (Data.rfind("	//") != std::string::npos)
		Data.erase(Data.rfind("	//"), Data.length() - Data.rfind("	//"));
	else if (Data.rfind(" #") != std::string::npos)
		Data.erase(Data.rfind(" #"), Data.length() - Data.rfind(" #"));
	else if (Data.rfind("	#") != std::string::npos)
		Data.erase(Data.rfind("	#"), Data.length() - Data.rfind("	#"));
	if (Data.length() < READ_HOSTS_MINSIZE)
		return true;

//[Base] block
	if (Data.find("[Base]") == 0 || Data.find("[base]") == 0 || 
		Data.find("Version = ") == 0 || Data.find("version = ") == 0 || 
		Data.find("Default TTL = ") == 0 || Data.find("default ttl = ") == 0)
			return true;

//[Local Hosts] block(A part)
	if (LabelType == 0 && (Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family > 0 || Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family > 0) && 
	#if defined(PLATFORM_WIN) //Case-insensitive on Windows
		(FileList_Hosts.at(FileIndex).FileName.rfind(L"whitelist.txt") != std::wstring::npos && FileList_Hosts.at(FileIndex).FileName.length() > wcslen(L"whitelist.txt") && 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"whitelist.txt") == FileList_Hosts.at(FileIndex).FileName.length() - wcslen(L"whitelist.txt") || 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"white_list.txt") != std::wstring::npos && FileList_Hosts.at(FileIndex).FileName.length() > wcslen(L"white_list.txt") && 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"white_list.txt") == FileList_Hosts.at(FileIndex).FileName.length() - wcslen(L"white_list.txt")))
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		(FileList_Hosts.at(FileIndex).FileName.rfind(L"WhiteList.txt") != std::wstring::npos && FileList_Hosts.at(FileIndex).FileName.length() > wcslen(L"WhiteList.txt") && 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"WhiteList.txt") == FileList_Hosts.at(FileIndex).FileName.length() - wcslen(L"WhiteList.txt") || 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"Whitelist.txt") != std::wstring::npos && FileList_Hosts.at(FileIndex).FileName.length() > wcslen(L"Whitelist.txt") && 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"Whitelist.txt") == FileList_Hosts.at(FileIndex).FileName.length() - wcslen(L"Whitelist.txt") || 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"whitelist.txt") != std::wstring::npos && FileList_Hosts.at(FileIndex).FileName.length() > wcslen(L"whitelist.txt") && 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"whitelist.txt") == FileList_Hosts.at(FileIndex).FileName.length() - wcslen(L"whitelist.txt") || 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"White_List.txt") != std::wstring::npos && FileList_Hosts.at(FileIndex).FileName.length() > wcslen(L"White_List.txt") && 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"White_List.txt") == FileList_Hosts.at(FileIndex).FileName.length() - wcslen(L"White_List.txt") || 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"White_list.txt") != std::wstring::npos && FileList_Hosts.at(FileIndex).FileName.length() > wcslen(L"White_list.txt") && 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"White_list.txt") == FileList_Hosts.at(FileIndex).FileName.length() - wcslen(L"White_list.txt") || 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"white_list.txt") != std::wstring::npos && FileList_Hosts.at(FileIndex).FileName.length() > wcslen(L"white_list.txt") && 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"white_list.txt") == FileList_Hosts.at(FileIndex).FileName.length() - wcslen(L"white_list.txt")))
	#endif
			LabelType = LABEL_HOSTS_TYPE_LOCAL;

//[Hosts] block
	if (Data.find("[Hosts]") == 0 || Data.find("[hosts]") == 0)
	{
		LabelType = LABEL_HOSTS;
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
		LabelType = LABEL_HOSTS_ADDRESS;
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
		Data.erase(Data.find("  "), strlen("  "));

//Whitelist items
	if (Data.find("NULL ") == 0 || Data.find("NULL	") == 0 || Data.find("NULL,") == 0 || 
		Data.find("Null ") == 0 || Data.find("Null	") == 0 || Data.find("Null,") == 0 || 
		Data.find("null ") == 0 || Data.find("null	") == 0 || Data.find("null,") == 0)
	{
		return ReadWhitelistAndBannedData(Data, FileIndex, Line, LABEL_HOSTS_TYPE_WHITELIST);
	}

//Banned items
	else if (Data.find("BAN ") == 0 || Data.find("BAN,") == 0 || 
		Data.find("BANNED ") == 0 || Data.find("BANNED,") == 0 || 
		Data.find("Ban ") == 0 || Data.find("Ban,") == 0 || 
		Data.find("Banned ") == 0 || Data.find("Banned,") == 0 || 
		Data.find("ban ") == 0 || Data.find("ban,") == 0 || 
		Data.find("banned ") == 0 || Data.find("banned,") == 0)
	{
		return ReadWhitelistAndBannedData(Data, FileIndex, Line, LABEL_HOSTS_TYPE_BANNED);
	}

//Type Banned items
	else if (Data.find("BAN") == 0 || Data.find("BANNED") == 0 || Data.find("Ban") == 0 || 
		Data.find("Banned") == 0 || Data.find("ban") == 0 || Data.find("banned") == 0)
	{
		return ReadWhitelistAndBannedData(Data, FileIndex, Line, LABEL_HOSTS_TYPE_BANNED_TYPE);
	}

//[Local Hosts] block
	else if (LabelType == LABEL_HOSTS_TYPE_LOCAL)
	{
		if ((Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family > 0 || Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family > 0) && Parameter.LocalHosts && !(Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family == 0 && Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family == 0 && Parameter.LocalMain))
			return ReadLocalHostsData(Data, FileIndex, Line);
	}

//[Address Hosts] block
	else if (LabelType == LABEL_HOSTS_ADDRESS)
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

//[Hosts] block
	else {
	//Delete spaces before or after verticals.
		while (Data.find(" |") != std::string::npos || Data.find("| ") != std::string::npos)
		{
			if (Data.find(" |") != std::string::npos)
				Data.erase(Data.find(" |"), strlen(" "));
			if (Data.find("| ") != std::string::npos)
				Data.erase(Data.find("| ") + 1U, strlen("|"));
		}

		return ReadMainHostsData(Data, FileIndex, Line);
	}

	return true;
}

//Read Whitelist and Banned items in Hosts file from data
bool __fastcall ReadWhitelistAndBannedData(std::string Data, const size_t FileIndex, const size_t Line, const size_t LabelType)
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
	if (Separated == 0 || (LabelType == LABEL_HOSTS_TYPE_BANNED_TYPE && (Data.find(ASCII_COLON) == std::string::npos || Separated <= Data.find(ASCII_COLON) + 1U)))
	{
		PrintError(LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Delete all spaces.
	while (Data.find(ASCII_SPACE) != std::string::npos)
		Data.erase(Data.find(ASCII_SPACE), 1U);

	HOSTS_TABLE HostsTableTemp;
//Mark banned types.
	if (LabelType == LABEL_HOSTS_TYPE_BANNED_TYPE)
	{
	//Permit or Deny
		if (Data.find("PERMIT") != std::string::npos && Data.find("PERMIT") <= Separated || 
			Data.find("Permit") != std::string::npos && Data.find("Permit") <= Separated || 
			Data.find("permit") != std::string::npos && Data.find("permit") <= Separated)
				HostsTableTemp.Type_Operation = true;

	//Mark types.
		std::string TypeString;
		uint16_t RecordType = 0;
		for (size_t Index = Data.find(ASCII_COLON) + 1U;Index <= Separated;++Index)
		{
			if (Data.at(Index) == ASCII_VERTICAL || Index == Separated)
			{
				RecordType = DNSTypeNameToHex(TypeString.c_str());
				if (RecordType <= 0)
				{
				//Number types
					SSIZE_T Result = strtoul(TypeString.c_str(), nullptr, 0);
					if (errno != ERANGE && Result > 0 && Result <= UINT16_MAX)
					{
						HostsTableTemp.Type_Record.push_back(htons((uint16_t)Result));
					}
					else {
						PrintError(LOG_ERROR_PARAMETER, L"DNS Records type error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
						return false;
					}
				}
				else { //Name types
					HostsTableTemp.Type_Record.push_back(RecordType);
				}

				TypeString.clear();
			}
			else {
				TypeString.append(Data, Index, 1U);
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
	if (LabelType == LABEL_HOSTS_TYPE_BANNED || LabelType == LABEL_HOSTS_TYPE_BANNED_TYPE)
		HostsTableTemp.Type_Hosts = HOSTS_TYPE_BANNED;
	else 
		HostsTableTemp.Type_Hosts = HOSTS_TYPE_WHITE;

//Add to global HostsList.
	for (auto &HostsFileSetIter:*HostsFileSetModificating)
	{
		if (HostsFileSetIter.FileIndex == FileIndex)
		{
			HostsFileSetIter.HostsList.push_back(HostsTableTemp);
			break;
		}
	}

	return true;
}

//Read Local Hosts items in Hosts file from data
bool __fastcall ReadLocalHostsData(std::string Data, const size_t FileIndex, const size_t Line)
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
	HostsTableTemp.Type_Hosts = HOSTS_TYPE_LOCAL;
	for (auto &HostsFileSetIter:*HostsFileSetModificating)
	{
		if (HostsFileSetIter.FileIndex == FileIndex)
		{
			HostsFileSetIter.HostsList.push_back(HostsTableTemp);
			break;
		}
	}

	return true;
}

//Read Address Hosts items in Hosts file from data
bool __fastcall ReadAddressHostsData(std::string Data, const size_t FileIndex, const size_t Line)
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
	std::string TargetString, SourceString;
	std::shared_ptr<sockaddr_storage> SockAddr(new sockaddr_storage());
	std::shared_ptr<char> Addr(new char[ADDR_STRING_MAXSIZE]());
	memset(SockAddr.get(), 0, sizeof(sockaddr_storage));
	memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
	SSIZE_T Result = 0;

//Separate target and source.
	TargetString.append(Data, 0, Separated);
	SourceString.append(Data, Separated, Data.length() - Separated);

//Get target data.
//Single address
	if (TargetString.find(ASCII_VERTICAL) == std::string::npos)
	{
	//AAAA record(IPv6)
		if (TargetString.find(ASCII_COLON) != std::string::npos)
		{
		//Convert to binary address.
			if (!AddressStringToBinary(TargetString.c_str(), &((PSOCKADDR_IN6)SockAddr.get())->sin6_addr, AF_INET6, Result))
			{
				PrintError(LOG_ERROR_HOSTS, L"IPv6 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Add to list.
			SockAddr->ss_family = AF_INET6;
			AddressHostsTableTemp.Address_Target.push_back(*SockAddr);
		}
	//A record(IPv4)
		else {
		//Convert to binary address.
			if (!AddressStringToBinary(TargetString.c_str(), &((PSOCKADDR_IN)SockAddr.get())->sin_addr, AF_INET, Result))
			{
				PrintError(LOG_ERROR_HOSTS, L"IPv4 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Add to list.
			SockAddr->ss_family = AF_INET;
			AddressHostsTableTemp.Address_Target.push_back(*SockAddr);
		}
	}
//Multiple addresses
	else {
		size_t VerticalIndex = 0, Index = 0;

	//AAAA records(IPv6)
		if (TargetString.find(ASCII_COLON) != std::string::npos)
		{
			for (Index = 0;Index <= TargetString.length();++Index)
			{
				if (TargetString.at(Index) == ASCII_VERTICAL || Index == TargetString.length())
				{
				//Convert addresses.
					memset(SockAddr.get(), 0, sizeof(sockaddr_storage));
					memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
					memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, TargetString.c_str() + VerticalIndex, Index - VerticalIndex);
					if (!AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN6)SockAddr.get())->sin6_addr, AF_INET6, Result))
					{
						PrintError(LOG_ERROR_HOSTS, L"IPv6 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
						return false;
					}

				//Add to list.
					SockAddr->ss_family = AF_INET6;
					AddressHostsTableTemp.Address_Target.push_back(*SockAddr);
					VerticalIndex = Index + 1U;
				}
			}
		}
	//A records(IPv4)
		else {
			for (Index = 0;Index <= TargetString.length();++Index)
			{
				if (TargetString.at(Index) == ASCII_VERTICAL || Index == TargetString.length())
				{
				//Convert addresses.
					memset(SockAddr.get(), 0, sizeof(sockaddr_storage));
					memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
					memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, TargetString.c_str() + VerticalIndex, Index - VerticalIndex);
					if (!AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN)SockAddr.get())->sin_addr, AF_INET, Result))
					{
						PrintError(LOG_ERROR_HOSTS, L"IPv4 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
						return false;
					}

				//Add to list.
					SockAddr->ss_family = AF_INET;
					AddressHostsTableTemp.Address_Target.push_back(*SockAddr);
					VerticalIndex = Index + 1U;
				}
			}
		}
	}
	SockAddr.reset();

//Get source data.
	ADDRESS_RANGE_TABLE AddressRangeTableTemp;
	memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);

//Single address
	if (SourceString.find(ASCII_VERTICAL) == std::string::npos)
	{
	//AAAA record(IPv6)
		if (SourceString.find(ASCII_COLON) != std::string::npos)
		{
		//Address range format
			if (SourceString.find(ASCII_MINUS) != std::string::npos)
			{
			//Convert address(Begin).
				memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, SourceString.c_str(), SourceString.find(ASCII_MINUS));
				if (!AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN6)&AddressRangeTableTemp.Begin)->sin6_addr, AF_INET6, Result))
				{
					PrintError(LOG_ERROR_HOSTS, L"IPv6 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
				AddressRangeTableTemp.Begin.ss_family = AF_INET6;

			//Convert address(End).
				memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
				memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, SourceString.c_str() + SourceString.find(ASCII_MINUS) + 1U, SourceString.length() - SourceString.find(ASCII_MINUS) - 1U);
				if (!AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN6)&AddressRangeTableTemp.End)->sin6_addr, AF_INET6, Result))
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
				if (!AddressStringToBinary(SourceString.c_str(), &((PSOCKADDR_IN6)&AddressRangeTableTemp.Begin)->sin6_addr, AF_INET6, Result))
				{
					PrintError(LOG_ERROR_HOSTS, L"IPv6 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}

				AddressRangeTableTemp.Begin.ss_family = AF_INET6;
				AddressRangeTableTemp.End = AddressRangeTableTemp.Begin;
			}
		}
	//A record(IPv4)
		else {
		//Address range format
			if (SourceString.find(ASCII_MINUS) != std::string::npos)
			{
			//Convert address(Begin).
				memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, SourceString.c_str(), SourceString.find(ASCII_MINUS));
				if (!AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN)&AddressRangeTableTemp.Begin)->sin_addr, AF_INET, Result))
				{
					PrintError(LOG_ERROR_HOSTS, L"IPv4 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
				AddressRangeTableTemp.Begin.ss_family = AF_INET;

			//Convert address(End).
				memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
				memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, SourceString.c_str() + SourceString.find(ASCII_MINUS) + 1U, SourceString.length() - SourceString.find(ASCII_MINUS) - 1U);
				if (!AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN)&AddressRangeTableTemp.End)->sin_addr, AF_INET, Result))
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
				if (!AddressStringToBinary(SourceString.c_str(), &((PSOCKADDR_IN)&AddressRangeTableTemp.Begin)->sin_addr, AF_INET, Result))
				{
					PrintError(LOG_ERROR_HOSTS, L"IPv4 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}

				AddressRangeTableTemp.Begin.ss_family = AF_INET;
				AddressRangeTableTemp.End = AddressRangeTableTemp.Begin;
			}
		}

		AddressHostsTableTemp.Address_Source.push_back(AddressRangeTableTemp);
	}
//Multiple addresses
	else {
		std::string ItemString;
		size_t VerticalIndex = 0, Index = 0;

	//AAAA records(IPv6)
		if (SourceString.find(ASCII_COLON) != std::string::npos)
		{
			for (Index = 0;Index <= SourceString.length();++Index)
			{
				if (SourceString.at(Index) == ASCII_VERTICAL || Index == SourceString.length())
				{
					memset(&AddressRangeTableTemp, 0, sizeof(ADDRESS_RANGE_TABLE));
					memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
					ItemString.clear();
					ItemString.append(SourceString, VerticalIndex, Index - VerticalIndex);

				//Address range format
					if (ItemString.find(ASCII_MINUS) != std::string::npos)
					{
					//Convert address(Begin).
						memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, ItemString.c_str(), ItemString.find(ASCII_MINUS));
						if (!AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN6)&AddressRangeTableTemp.Begin)->sin6_addr, AF_INET6, Result))
						{
							PrintError(LOG_ERROR_HOSTS, L"IPv6 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
							return false;
						}
						AddressRangeTableTemp.Begin.ss_family = AF_INET6;

					//Convert address(End).
						memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
						memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, ItemString.c_str() + ItemString.find(ASCII_MINUS) + 1U, ItemString.length() - ItemString.find(ASCII_MINUS) - 1U);
						if (!AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN6)&AddressRangeTableTemp.End)->sin6_addr, AF_INET6, Result))
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
						if (!AddressStringToBinary(ItemString.c_str(), &((PSOCKADDR_IN6)&AddressRangeTableTemp.Begin)->sin6_addr, AF_INET6, Result))
						{
							PrintError(LOG_ERROR_HOSTS, L"IPv6 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
							return false;
						}

						AddressRangeTableTemp.Begin.ss_family = AF_INET6;
						AddressRangeTableTemp.End = AddressRangeTableTemp.Begin;
					}

				//Add to list.
					AddressHostsTableTemp.Address_Source.push_back(AddressRangeTableTemp);
					VerticalIndex = Index + 1U;
				}
			}
		}
	//A records(IPv4)
		else {
			for (Index = 0;Index <= SourceString.length();++Index)
			{
				if (SourceString.at(Index) == ASCII_VERTICAL || Index == SourceString.length())
				{
					memset(&AddressRangeTableTemp, 0, sizeof(ADDRESS_RANGE_TABLE));
					memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
					ItemString.clear();
					ItemString.append(SourceString, VerticalIndex, Index - VerticalIndex);

				//Address range format
					if (ItemString.find(ASCII_MINUS) != std::string::npos)
					{
					//Convert address(Begin).
						memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, ItemString.c_str(), ItemString.find(ASCII_MINUS));
						if (!AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN)&AddressRangeTableTemp.Begin)->sin_addr, AF_INET, Result))
						{
							PrintError(LOG_ERROR_HOSTS, L"IPv4 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
							return false;
						}
						AddressRangeTableTemp.Begin.ss_family = AF_INET;

					//Convert address(End).
						memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
						memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, ItemString.c_str() + ItemString.find(ASCII_MINUS) + 1U, ItemString.length() - ItemString.find(ASCII_MINUS) - 1U);
						if (!AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN)&AddressRangeTableTemp.End)->sin_addr, AF_INET, Result))
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
						if (!AddressStringToBinary(ItemString.c_str(), &((PSOCKADDR_IN)&AddressRangeTableTemp.Begin)->sin_addr, AF_INET, Result))
						{
							PrintError(LOG_ERROR_HOSTS, L"IPv4 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
							return false;
						}

						AddressRangeTableTemp.Begin.ss_family = AF_INET;
						AddressRangeTableTemp.End = AddressRangeTableTemp.Begin;
					}

				//Add to list.
					AddressHostsTableTemp.Address_Source.push_back(AddressRangeTableTemp);
					VerticalIndex = Index + 1U;
				}
			}
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
bool __fastcall ReadMainHostsData(std::string Data, const size_t FileIndex, const size_t Line)
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
	std::shared_ptr<char> Addr(new char[ADDR_STRING_MAXSIZE]());
	memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
	HOSTS_TABLE HostsTableTemp;

//Response initialization
	std::shared_ptr<char> BufferHostsTableTemp(new char[PACKET_MAXSIZE]());
	memset(BufferHostsTableTemp.get(), 0, PACKET_MAXSIZE);
	HostsTableTemp.Response.swap(BufferHostsTableTemp);
	BufferHostsTableTemp.reset();
	pdns_record_aaaa DNS_Record_AAAA = nullptr;
	pdns_record_a DNS_Record_A = nullptr;
	SSIZE_T Result = 0;

//Single address
	if (Data.find(ASCII_VERTICAL) == std::string::npos)
	{
	//AAAA records(IPv6)
		if (Data.find(ASCII_COLON) < Separated)
		{
		//IPv6 addresses check
			if (Separated > ADDR_STRING_MAXSIZE)
			{
				PrintError(LOG_ERROR_HOSTS, L"IPv6 address format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
				return false;
			}
			else if (Data.at(0) < ASCII_ZERO || Data.at(0) > ASCII_COLON && Data.at(0) < ASCII_UPPERCASE_A || Data.at(0) > ASCII_UPPERCASE_F && Data.at(0) < ASCII_LOWERCASE_A || Data.at(0) > ASCII_LOWERCASE_F)
			{
				return false;
			}

		//Make responses.
			DNS_Record_AAAA = (pdns_record_aaaa)HostsTableTemp.Response.get();
			DNS_Record_AAAA->Name = htons(DNS_POINTER_QUERY);
			DNS_Record_AAAA->Classes = htons(DNS_CLASS_IN);
			DNS_Record_AAAA->TTL = htonl(Parameter.HostsDefaultTTL);
			DNS_Record_AAAA->Type = htons(DNS_RECORD_AAAA);
			DNS_Record_AAAA->Length = htons(sizeof(in6_addr));

		//Convert addresses.
			memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, Data.c_str(), Separated);
			if (!AddressStringToBinary(Addr.get(), &DNS_Record_AAAA->Addr, AF_INET6, Result))
			{
				PrintError(LOG_ERROR_HOSTS, L"IPv6 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

			HostsTableTemp.Type_Record.push_back(htons(DNS_RECORD_AAAA));
			HostsTableTemp.Length = sizeof(dns_record_aaaa);
		}
	//A records(IPv4)
		else {
		//IPv4 addresses check
			if (Separated > ADDR_STRING_MAXSIZE)
			{
				PrintError(LOG_ERROR_HOSTS, L"IPv4 address format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
				return false;
			}
			else if (Data.at(0) < ASCII_ZERO || Data.at(0) > ASCII_NINE)
			{
				return false;
			}

		//Make responses.
			DNS_Record_A = (pdns_record_a)HostsTableTemp.Response.get();
			DNS_Record_A->Name = htons(DNS_POINTER_QUERY);
			DNS_Record_A->Classes = htons(DNS_CLASS_IN);
			DNS_Record_A->TTL = htonl(Parameter.HostsDefaultTTL);
			DNS_Record_A->Type = htons(DNS_RECORD_A);
			DNS_Record_A->Length = htons(sizeof(in_addr));

		//Convert addresses.
			memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, Data.c_str(), Separated);
			if (!AddressStringToBinary(Addr.get(), &DNS_Record_A->Addr, AF_INET, Result))
			{
				PrintError(LOG_ERROR_HOSTS, L"IPv4 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

			HostsTableTemp.Type_Record.push_back(htons(DNS_RECORD_A));
			HostsTableTemp.Length = sizeof(dns_record_a);
		}
	}
//Multiple addresses
	else {
		size_t Index = 0, VerticalIndex = 0, ResultCount = 0;

	//AAAA records(IPv6)
		if (Data.find(ASCII_COLON) < Separated)
		{
		//IPv6 addresses check
			if (Data.at(0) < ASCII_ZERO || Data.at(0) > ASCII_COLON && Data.at(0) < ASCII_UPPERCASE_A || Data.at(0) > ASCII_UPPERCASE_F && Data.at(0) < ASCII_LOWERCASE_A || Data.at(0) > ASCII_LOWERCASE_F)
				return false;

			HostsTableTemp.Type_Record.push_back(htons(DNS_RECORD_AAAA));
			for (Index = 0, ResultCount = 0;Index <= Separated;++Index)
			{
			//Read data.
				if (Data.at(Index) == ASCII_VERTICAL || Index == Separated)
				{
					++ResultCount;

				//Length check
					if (ResultCount > DNS_RR_MAXCOUNT_AAAA)
					{
						PrintError(LOG_ERROR_HOSTS, L"Too many Hosts IP addresses", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
						return false;
					}
					else if (Index - VerticalIndex > ADDR_STRING_MAXSIZE)
					{
						PrintError(LOG_ERROR_HOSTS, L"IPv6 address format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
						return false;
					}

				//Make responses
					DNS_Record_AAAA = (pdns_record_aaaa)(HostsTableTemp.Response.get() + HostsTableTemp.Length);
					DNS_Record_AAAA->Name = htons(DNS_POINTER_QUERY);
					DNS_Record_AAAA->Classes = htons(DNS_CLASS_IN);
					DNS_Record_AAAA->TTL = htonl(Parameter.HostsDefaultTTL);
					DNS_Record_AAAA->Type = htons(DNS_RECORD_AAAA);
					DNS_Record_AAAA->Length = htons(sizeof(in6_addr));

				//Convert addresses.
					memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
					memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, Data.c_str() + VerticalIndex, Index - VerticalIndex);
					if (!AddressStringToBinary(Addr.get(), &DNS_Record_AAAA->Addr, AF_INET6, Result))
					{
						PrintError(LOG_ERROR_HOSTS, L"IPv6 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
						return false;
					}

					HostsTableTemp.Length += sizeof(dns_record_aaaa);
					VerticalIndex = Index + 1U;
				}
			}
		}
	//A records(IPv4)
		else {
		//IPv4 addresses check
			if (Data.at(0) < ASCII_ZERO || Data.at(0) > ASCII_NINE)
				return false;

			HostsTableTemp.Type_Record.push_back(htons(DNS_RECORD_A));
			for (Index = 0, ResultCount = 0;Index <= Separated;++Index)
			{
			//Read data.
				if (Data.at(Index) == ASCII_VERTICAL || Index == Separated)
				{
					++ResultCount;

				//Length check
					if (ResultCount > DNS_RR_MAXCOUNT_A)
					{
						PrintError(LOG_ERROR_HOSTS, L"Too many Hosts IP addresses", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
						return false;
					}
					else if (Index - VerticalIndex > ADDR_STRING_MAXSIZE)
					{
						PrintError(LOG_ERROR_HOSTS, L"IPv4 address format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
						return false;
					}

				//Make responses.
					DNS_Record_A = (pdns_record_a)(HostsTableTemp.Response.get() + HostsTableTemp.Length);
					DNS_Record_A->Name = htons(DNS_POINTER_QUERY);
					DNS_Record_A->Classes = htons(DNS_CLASS_IN);
					DNS_Record_A->TTL = htonl(Parameter.HostsDefaultTTL);
					DNS_Record_A->Type = htons(DNS_RECORD_A);
					DNS_Record_A->Length = htons(sizeof(in_addr));

				//Convert addresses.
					memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
					memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, Data.c_str() + VerticalIndex, Index - VerticalIndex);
					if (!AddressStringToBinary(Addr.get(), &DNS_Record_A->Addr, AF_INET, Result))
					{
						PrintError(LOG_ERROR_HOSTS, L"IPv4 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
						return false;
					}

					HostsTableTemp.Length += sizeof(dns_record_a);
					VerticalIndex = Index + 1U;
				}
			}
		}
	}

	Addr.reset();
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
	if (HostsTableTemp.Length >= sizeof(dns_qry) + sizeof(in_addr)) //Shortest reply is a A Records with Question part.
	{
		HostsTableTemp.Type_Hosts = HOSTS_TYPE_NORMAL;
		for (auto &HostsFileSetIter:*HostsFileSetModificating)
		{
			if (HostsFileSetIter.FileIndex == FileIndex)
			{
				HostsFileSetIter.HostsList.push_back(HostsTableTemp);
				break;
			}
		}
	}

	return true;
}

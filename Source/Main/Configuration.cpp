// This code is part of Pcap_DNSProxy
// Copyright (C) 2012-2014 Chengr28
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


#include "Pcap_DNSProxy.h"

#define UTF_8             65001       //Codepage of UTF-8 with BOM

std::vector<HostsTable> HostsList[2], *Using = &HostsList[0], *Modificating = &HostsList[1];

extern std::wstring Path;
extern Configuration Parameter;

//Read codepages of file
SSIZE_T Configuration::ReadEncoding(const char *Buffer, const size_t Length)
{
	if (Length > 4) //Length is longer than BOM of UTF-8
	{
	//UTF-16 and UTF-32
		if (Buffer[0] == 0 && Buffer[1] == 0 && Buffer[2] == 0xFFFFFFFE && Buffer[3] == 0xFFFFFFFF || //UTF-32 BE/Big Endian
			Buffer[0] == 0xFFFFFFFF && Buffer[1] == 0xFFFFFFFE || //UTF-32 LE/Little Endian or UTF-16 LE/Little Endian
			Buffer[0] == 0xFFFFFFFE && Buffer[1] == 0xFFFFFFFF) //UTF-16 BE/Big Endian
		{
			::PrintError("Parameter Error: Encoding error", false, NULL);
			return RETURN_ERROR;
		}

	//UTF-8 with BOM
		if (Buffer[0] == 0xFFFFFFEF && Buffer[1] == 0xFFFFFFBB && Buffer[2] == 0xFFFFFFBF)
			return UTF_8;

	//Non-ASCII
		size_t Index = 0;
		for (Index = 0;Index < Length;Index++)
		{
			if (Buffer[Index] < 0 || Buffer[Index] > 255)
			{
				::PrintError("Parameter Error: Encoding error", false, NULL);
				return RETURN_ERROR;
			}
		}

		return Length;
	}

	return 0;
}

//Read parameter from configuration file
SSIZE_T Configuration::ReadParameter()
{
//Initialization
	FILE *Input = nullptr;
	char *Buffer = nullptr, *Target = nullptr, *LocalhostServer = nullptr;
	try {
		Buffer = new char[UDP_MAXSIZE]();
		Target = new char[UDP_MAXSIZE/32]();
		LocalhostServer = new char[UDP_MAXSIZE/8]();
	}
	catch (std::bad_alloc)
	{
		delete[] Buffer;
		delete[] Target;
		delete[] LocalhostServer;
		::PrintError("Parameter Error: Memory allocation failed", false, NULL);
		return RETURN_ERROR;
	}
	memset(Buffer, 0, UDP_MAXSIZE);
	memset(Target, 0, UDP_MAXSIZE/32);
	memset(LocalhostServer, 0, UDP_MAXSIZE/8);

//Open file
	std::wstring ConfigPath(Path);
	ConfigPath.append(_T("Config.ini"));
	_wfopen_s(&Input, ConfigPath.c_str(), _T("r"));

	if (Input == nullptr)
	{
		delete[] Buffer;
		delete[] Target;
		delete[] LocalhostServer;
		::PrintError("Parameter Error: Cannot open configuration file", false, NULL);
		return RETURN_ERROR;
	}

	std::string sBuffer;
	static const char PaddingData[] = ("abcdefghijklmnopqrstuvwabcdefghi"); //Microsoft Windows Ping padding data
	static const char LocalDNSName[] = ("pcap_dnsproxy.localhost.server"); //Localhost DNS server name
	while(!feof(Input))
	{
		fgets(Buffer, UDP_MAXSIZE, Input);
		if (Buffer[(int)strlen(Buffer) - 1] == 0x0A || Buffer[(int)strlen(Buffer) - 1] == 0x0D) //CR/Carriage Return or LF/Line Feed
			Buffer[(int)strlen(Buffer) - 1] = 0;
		
		sBuffer = Buffer;
	//Check encoding
		SSIZE_T Encoding = ReadEncoding(Buffer, sBuffer.length());
		if (Encoding < 9) //The shortest option in configuration file is "Hosts = "
		{
			continue;
		}
		else if (Encoding == UTF_8)
		{
			char *Temp = nullptr;
			try {
				Temp = new char[UDP_MAXSIZE]();
			}
			catch (std::bad_alloc)
			{
				delete[] Buffer;
				delete[] Target;
				delete[] LocalhostServer;
				::PrintError("Parameter Error: Memory allocation failed", false, NULL);
				return RETURN_ERROR;
			}
			memset(Temp, 0, UDP_MAXSIZE);

			memcpy(Temp, Buffer + 3, UDP_MAXSIZE - 3);
			memset(Buffer, 0, UDP_MAXSIZE);
			memcpy(Buffer, Temp, UDP_MAXSIZE - 3);
			sBuffer = Buffer;
			delete[] Temp;
		}

	//Base block
		if (sBuffer.find("Print Error = ") == 0 && sBuffer.length() < 17)
		{
			SSIZE_T PrintError = atoi(Buffer + 14);
			if (PrintError == 0)
				this->PrintError = false;
		}
		else if (sBuffer.find("Hosts = ") == 0 && sBuffer.length() < 25)
		{
			SSIZE_T Hosts = atoi(Buffer + 8);
			if (Hosts >= 5)
				this->Hosts = Hosts * 1000;
			else if (Hosts > 0 && Hosts < 5)
				this->Hosts = 5000; //5s is least time between auto-refreshing
			else 
				this->Hosts = 0; //Read Hosts OFF
		}
		else if (sBuffer.find("IPv4 DNS Address = ") == 0 && sBuffer.length() > 25 && sBuffer.length() < 35)
		{
			if (sBuffer.find('.') == std::string::npos) //IPv4 Address
			{
				delete[] Buffer;
				delete[] Target;
				delete[] LocalhostServer;
				::PrintError("Parameter Error: DNS server IPv4 Address format error", false, NULL);
				return RETURN_ERROR;
			}

		//IPv4 Address check
			memcpy(Target, Buffer + 19, sBuffer.length() - 19);
			if (inet_pton(AF_INET, Target, &(this->DNSTarget.IPv4Target)) <= 0)
			{
				delete[] Buffer;
				delete[] Target;
				delete[] LocalhostServer;
				::PrintError("Parameter Error: DNS server IPv4 Address convert error", false, NULL);
				return RETURN_ERROR;
			}

			this->DNSTarget.IPv4 = true;
		}
		else if (sBuffer.find("IPv6 DNS Address = ") == 0 && sBuffer.length() > 21 && sBuffer.length() < 59)
		{
			if (sBuffer.find(':') == std::string::npos) //IPv6 Address
			{
				delete[] Buffer;
				delete[] Target;
				delete[] LocalhostServer;
				::PrintError("Parameter Error: DNS server IPv6 Address format error", false, NULL);
				return RETURN_ERROR;
			}

		//IPv6 Address check
			memcpy(Target, Buffer + 19, sBuffer.length() - 19);
			if (inet_pton(AF_INET6, Target, &(this->DNSTarget.IPv6Target)) <= 0)
			{
				delete[] Buffer;
				delete[] Target;
				delete[] LocalhostServer;
				::PrintError("Parameter Error: DNS server IPv6 Address convert error", false, NULL);
				return RETURN_ERROR;
			}

			this->DNSTarget.IPv6 = true;
		}
		else if (sBuffer.find("Operation Mode = ") == 0 && sBuffer.length() < 24)
		{
			if (sBuffer.find("Server") == 17)
				this->ServerMode = true;
		}
		else if (sBuffer.find("Protocol = ") == 0 && sBuffer.length() < 15)
		{
			if (sBuffer.find("TCP") == 11)
				this->TCPMode = true;
		}
	//Extend Test
		else if (sBuffer.find("IPv4 TTL = ") == 0 && sBuffer.length() > 11 && sBuffer.length() < 15)
		{
			SSIZE_T TTL = atoi(Buffer + 11);
			if (TTL > 0 && TTL < 256)
				this->HopLimitOptions.IPv4TTL = TTL;
		}
		else if (sBuffer.find("IPv6 Hop Limits = ") == 0 && sBuffer.length() > 18 && sBuffer.length() < 22)
		{
			SSIZE_T HopLimit = atoi(Buffer + 18);
			if (HopLimit > 0 && HopLimit < 256)
				this->HopLimitOptions.IPv6HopLimit = HopLimit;
		}
		else if (sBuffer.find("Hop Limits/TTL Fluctuation = ") == 0 && sBuffer.length() > 29 && sBuffer.length() < 34)
		{
			SSIZE_T HopLimitFluctuation = atoi(Buffer + 29);
			if (HopLimitFluctuation >= 0 && HopLimitFluctuation < 255)
				this->HopLimitOptions.HopLimitFluctuation = HopLimitFluctuation;
		}
		else if (sBuffer.find("IPv4 Options Filter = ") == 0 && sBuffer.length() < 24)
		{
			SSIZE_T IPv4Options = atoi(Buffer + 22);
			if (IPv4Options == 1)
				this->IPv4Options = true;
		}
		else if (sBuffer.find("ICMP Test = ") == 0 && sBuffer.length() < 23)
		{
			SSIZE_T ICMPSpeed = atoi(Buffer + 12);
			if (ICMPSpeed >= 5)
				this->ICMPOptions.ICMPSpeed = ICMPSpeed * 1000;
			else if (ICMPSpeed > 0 && ICMPSpeed < 5)
				this->ICMPOptions.ICMPSpeed = 10000; //5s is least time between ICMP Tests
			else 
				this->ICMPOptions.ICMPSpeed = 0; //ICMP Test OFF
		}
		else if (sBuffer.find("ICMP ID = ") == 0 && sBuffer.length() < 17)
		{
			SSIZE_T ICMPID = strtol(Buffer + 10, NULL, 16);
			if (ICMPID > 0)
				this->ICMPOptions.ICMPID = htons((USHORT)ICMPID);
		}
		else if (sBuffer.find("ICMP Sequence = ") == 0 && sBuffer.length() < 23)
		{
			SSIZE_T ICMPSequence = strtol(Buffer + 16, NULL, 16);
			if (ICMPSequence > 0)
				this->ICMPOptions.ICMPSequence = htons((USHORT)ICMPSequence);
		}
		else if (sBuffer.find("TCP Options Filter = ") == 0 && sBuffer.length() < 23)
		{
			SSIZE_T TCPOptions = atoi(Buffer + 21);
			if (TCPOptions == 1)
				this->TCPOptions = true;
		}
		else if (sBuffer.find("DNS Options Filter = ") == 0 && sBuffer.length() < 23)
		{
			SSIZE_T DNSOptions = atoi(Buffer + 21);
			if (DNSOptions == 1)
				this->DNSOptions = true;
		}
		else if (sBuffer.find("Blacklist Filter = ") == 0 && sBuffer.length() < 22)
		{
			SSIZE_T Blacklist = atoi(Buffer + 19);
			if (Blacklist == 1)
				this->Blacklist = true;
		}
	//Data block
		else if (sBuffer.find("Domain Test = ") == 0)
		{
			if (sBuffer.length() > 17 && sBuffer.length() < 270) //Maximum length of domain is 253 bytes.
			{
				memcpy(this->DomainTestOptions.DomainTest, Buffer + 14, sBuffer.length() - 14);
				this->DomainTestOptions.DomainTestCheck = true;
			}
			else {
				continue;
			}
		}
		else if (sBuffer.find("Domain Test ID = ") == 0 && sBuffer.length() < 24)
		{
			SSIZE_T DomainTestID = strtol(Buffer + 17, NULL, 16);
			if (DomainTestID > 0)
				this->DomainTestOptions.DomainTestID = htons((USHORT)DomainTestID);
		}
		else if (sBuffer.find("Domain Test Speed = ") == 0 && sBuffer.length() < 30 /* && Parameter.DomainTest[0] != 0 */ )
		{
			SSIZE_T DomainTestSpeed = atoi(Buffer + 20);
			if (DomainTestSpeed > 0)
				this->DomainTestOptions.DomainTestSpeed = DomainTestSpeed * 1000;
		}
		else if (sBuffer.find("ICMP PaddingData = ") == 0)
		{
			if (sBuffer.length() > 36 && sBuffer.length() < 84) //The length of ICMP padding data must between 18 bits and 64 bits.
			{
				this->PaddingDataOptions.PaddingDataLength = sBuffer.length() - 18;
				memcpy(this->PaddingDataOptions.PaddingData, Buffer + 19, sBuffer.length() - 19);
			}
			else if (sBuffer.length() >= 84)
			{
				::PrintError("Parameter Error: The ICMP PaddingData is too long", false, NULL);
				continue;
			}
			else {
				continue;
			}
		}
		else if (sBuffer.find("Localhost Server Name = ") == 0 && sBuffer.length() > 26 && sBuffer.length() < 280) //Maximum length of domain is 253 bytes.
		{
			int *Point = nullptr;
			try {
				Point = new int[UDP_MAXSIZE/8]();
			}
			catch (std::bad_alloc)
			{
				delete[] Buffer;
				delete[] Target;
				delete[] LocalhostServer;
				::PrintError("Parameter Error: Memory allocation failed", false, NULL);
				return RETURN_ERROR;
			}
			memset(Point, 0, sizeof(int)*(UDP_MAXSIZE/8));

			size_t PointSign = 0, Index = 0;
			this->LocalhostServerOptions.LocalhostServerLength = sBuffer.length() - 24;

		//Convert from char to DNS query
			LocalhostServer[0] = 46;
			memcpy(LocalhostServer + sizeof(char), Buffer + 24, this->LocalhostServerOptions.LocalhostServerLength);
			for (Index = 0;Index < sBuffer.length() - 25;Index++)
			{
				if (LocalhostServer[Index] == 45 || LocalhostServer[Index] == 46 || LocalhostServer[Index] == 95 || 
					LocalhostServer[Index] > 47 && LocalhostServer[Index] < 58 || LocalhostServer[Index] > 96 && LocalhostServer[Index] < 123)
				{
					if (LocalhostServer[Index] == 46)
					{
						Point[PointSign] = (int)Index;
						PointSign++;
					}
					continue;
				}
				else {
					::PrintError("Parameter Error: Localhost server name format error", false, NULL);
					this->LocalhostServerOptions.LocalhostServerLength = 0;
					break;
				}
			}

			if (this->LocalhostServerOptions.LocalhostServerLength > 2)
			{
				char *LocalhostServerName = nullptr;
				try {
					LocalhostServerName = new char[UDP_MAXSIZE/8]();
				}
				catch (std::bad_alloc)
				{
					delete[] Buffer;
					delete[] Target;
					delete[] LocalhostServer;
					delete[] Point;
					::PrintError("Parameter Error: Memory allocation failed", false, NULL);
					return RETURN_ERROR;
				}
				memset(LocalhostServerName, 0, UDP_MAXSIZE/8);

				for (Index = 0;Index < PointSign;Index++)
				{
					if (Index == PointSign - 1)
					{
						LocalhostServerName[Point[Index]] = (int)(this->LocalhostServerOptions.LocalhostServerLength - Point[Index]);
						memcpy(LocalhostServerName + Point[Index] + 1, LocalhostServer + Point[Index] + 1, this->LocalhostServerOptions.LocalhostServerLength - Point[Index]);
					}
					else {
						LocalhostServerName[Point[Index]] = Point[Index + 1] - Point[Index] - 1;
						memcpy(LocalhostServerName + Point[Index] + 1, LocalhostServer + Point[Index] + 1, Point[Index + 1] - Point[Index]);
					}
				}

				memcpy(this->LocalhostServerOptions.LocalhostServer, LocalhostServerName, this->LocalhostServerOptions.LocalhostServerLength + 1);
				delete[] Point;
				delete[] LocalhostServerName;
			}
		}
		else {
			continue;
		}
	}
	fclose(Input);
	delete[] Buffer;
	delete[] Target;
	delete[] LocalhostServer;

//Set default
	if (this->HopLimitOptions.HopLimitFluctuation < 0 && this->HopLimitOptions.HopLimitFluctuation >= 255)
		this->HopLimitOptions.HopLimitFluctuation = 2; //Default HopLimitFluctuation is 2
	if (ntohs(this->ICMPOptions.ICMPID) <= 0)
		this->ICMPOptions.ICMPID = htons((USHORT)GetCurrentProcessId()); //Default DNS ID is current process ID
	if (ntohs(this->ICMPOptions.ICMPSequence) <= 0)
		this->ICMPOptions.ICMPSequence = htons(0x0001); //Default DNS Sequence is 0x0001
	if (ntohs(this->DomainTestOptions.DomainTestID) <= 0)
		this->DomainTestOptions.DomainTestID = htons(0x0001); //Default Domain Test DNS ID is 0x0001
	if (this->DomainTestOptions.DomainTestSpeed <= 3000)
		this->DomainTestOptions.DomainTestSpeed = 900000; //Default Domain Test request every 15 minutes.
	if (this->PaddingDataOptions.PaddingDataLength <= 0)
	{
		this->PaddingDataOptions.PaddingDataLength = sizeof(PaddingData);
		memcpy(this->PaddingDataOptions.PaddingData, PaddingData, sizeof(PaddingData) - 1); //Load default padding data from Microsoft Windows Ping
	}
	if (this->LocalhostServerOptions.LocalhostServerLength <= 0)
		this->LocalhostServerOptions.LocalhostServerLength = CharToDNSQuery(LocalDNSName, this->LocalhostServerOptions.LocalhostServer); //Default Localhost DNS server name

//Check parameters
	if (!this->DNSTarget.IPv4 && !this->DNSTarget.IPv6 || !this->TCPMode && this->TCPOptions)
	{
		::PrintError("Parameter Error: Rule(s) error", false, NULL);
		return RETURN_ERROR;
	}

	return 0;
}

//Read Hosts file
SSIZE_T Configuration::ReadHosts()
{
//Read Hosts: ON/OFF
	if (Parameter.Hosts == 0)
		return 0;

//Initialization
	FILE *Input = nullptr;
	char *Buffer = nullptr, *EndcodingTemp = nullptr, *AddrTemp = nullptr;
	try {
		Buffer = new char[UDP_MAXSIZE]();
		EndcodingTemp = new char[UDP_MAXSIZE]();
		AddrTemp = new char[UDP_MAXSIZE/16]();
	}
	catch (std::bad_alloc)
	{
		delete[] Buffer;
		delete[] EndcodingTemp;
		delete[] AddrTemp;
		::PrintError("Hosts Error: Memory allocation failed", false, NULL);
		return RETURN_ERROR;
	}
	memset(Buffer, 0, UDP_MAXSIZE);
	memset(EndcodingTemp, 0, UDP_MAXSIZE);
	memset(AddrTemp, 0, UDP_MAXSIZE/16);
	std::wstring HostsFilePath(Path);
	std::string sBuffer, Domain;
	HostsFilePath.append(_T("Hosts.ini"));

	while (true)
	{
		_wfopen_s(&Input, HostsFilePath.c_str(), _T("r"));
		if (Input == nullptr)
		{
			delete[] Buffer;
			delete[] EndcodingTemp;
			delete[] AddrTemp;
			CleanHostsTable();

			::PrintError("Hosts Error: Cannot open configuration file", false, NULL);
			return RETURN_ERROR;
		}
		
		while(!feof(Input))
		{
			memset(Buffer, 0, UDP_MAXSIZE);
			fgets(Buffer, UDP_MAXSIZE, Input);
			if (Buffer[(int)strlen(Buffer) - 1] == 0x0A || Buffer[(int)strlen(Buffer) - 1] == 0x0D) //CR/Carriage Return or LF/Line Feed
				Buffer[(int)strlen(Buffer) - 1] = 0;

			sBuffer = Buffer;
		//Check encoding
			SSIZE_T Encoding = ReadEncoding(Buffer, sBuffer.length());
			if (Encoding < 6) //The shortest regex in hosts file is "::? ?"
			{
				continue;
			}
			else if (Encoding == UTF_8)
			{
				memcpy(EndcodingTemp, Buffer + 3, UDP_MAXSIZE - 3);
				memset(Buffer, 0, UDP_MAXSIZE);
				memcpy(Buffer, EndcodingTemp, UDP_MAXSIZE - 3);
				sBuffer = Buffer;
				memset(EndcodingTemp, 0, UDP_MAXSIZE);
			}

		//Check spacing
			size_t Index = 0, Front = 0, Rear = 0;
			if (sBuffer.find(32) != std::string::npos) //Space
			{
				Index = sBuffer.find(32);
				Front = Index;
				if (sBuffer.rfind(32) > Index)
					Rear = sBuffer.rfind(32);
				else 
					Rear = Front;
			}
			if (sBuffer.find(9) != std::string::npos) //HT
			{
				if (Index == 0)
					Index = sBuffer.find(9);
				if (Index > sBuffer.find(9))
					Front = sBuffer.find(9);
				else 
					Front = Index;
				if (sBuffer.rfind(9) > Index)
					Rear = sBuffer.rfind(9);
				else 
					Rear = Front;
			}

		//End

			Domain.clear();
			if (Front > 5)
			{
				HostsTable Temp;
				memset(AddrTemp, 0, UDP_MAXSIZE/16);

				bool IPv4 = false, IPv6 = false;
				size_t Vertical[THREAD_MAXNUM/8] = {0}, VerticalIndex = 0;
			//Multiple Addresses
				for (Index = 0;Index < Front;Index++)
				{
					if (Buffer[Index] == 124)
					{
						if (VerticalIndex > THREAD_MAXNUM/8)
						{
							delete[] Buffer;
							delete[] EndcodingTemp;
							delete[] AddrTemp;
							CleanHostsTable();

							::PrintError("Hosts Error: Too many IP addresses", false, NULL);
							return RETURN_ERROR;
						}
						else {
							VerticalIndex++;
							Vertical[VerticalIndex] = Index + 1;
						}
					}
				}
				VerticalIndex++;
				Vertical[VerticalIndex] = Front + 1;
				Temp.ResponseNum = VerticalIndex;

			//IPv4 Address
				for (Index = 0;Index < Front;Index++)
				{
					if (Buffer[Index] < 46 || Buffer[Index] == 47 || Buffer[Index] > 57 && Buffer[Index] < 124 || Buffer[Index] > 124)
						break;

					if (Index == Front - 1 && Front)
						IPv4 = true;
				}
			//IPv6 Address
				for (Index = 0;Index < Front;Index++)
				{
					if (Buffer[Index] < 48 || Buffer[Index] > 58 && Buffer[Index] < 65 || Buffer[Index] > 70 && Buffer[Index] < 97 && Buffer[Index] > 102 && Buffer[Index] < 124 || Buffer[Index] > 124)
						break;

					if (Index == Front - 1)
						IPv6 = true;
				}

			//End

				Index = 0;
				if (VerticalIndex > 0)
				{
				//Response initialization
					try {
						Temp.Response = new char[UDP_MAXSIZE]();
					}
					catch (std::bad_alloc)
					{
						delete[] Buffer;
						delete[] EndcodingTemp;
						delete[] AddrTemp;
						CleanHostsTable();

						::PrintError("Hosts Error: Memory allocation failed", false, NULL);
						return RETURN_ERROR;
					}
					memset(Temp.Response, 0, UDP_MAXSIZE);

				//AAAA Records
					if (IPv6 && !IPv4)
					{
						Temp.Protocol = AF_INET6;
						while (Index < VerticalIndex)
						{
						//Make a response
							dns_aaaa_record rsp = {0};
							rsp.Name = htons(0xC00C); //Pointer of same requesting
							rsp.Classes = htons(Class_IN); //Class IN
							rsp.TTL = htonl(600); //10 minutes
							rsp.Type = htons(AAAA_Records);
							rsp.Length = htons(sizeof(in6_addr));

						//Convert addresses
							memcpy(AddrTemp, Buffer + Vertical[Index], Vertical[Index + 1] - Vertical[Index] - 1);
							if (inet_pton(AF_INET6, AddrTemp, &rsp.Addr) <= 0)
							{
								delete[] Buffer;
								delete[] EndcodingTemp;
								delete[] AddrTemp;
								delete[] Temp.Response;
								CleanHostsTable();

								::PrintError("Hosts Error: Hosts IPv6 address format error", false, NULL);
								return RETURN_ERROR;
							}
							memcpy(Temp.Response + Temp.ResponseLength, &rsp, sizeof(dns_aaaa_record));
							Temp.ResponseLength += sizeof(dns_aaaa_record);

							memset(AddrTemp, 0, UDP_MAXSIZE/16);
							Index++;
						}
					}
				//A Records
					else if (IPv4 && !IPv6)
					{
						Temp.Protocol = AF_INET;
						while (Index < VerticalIndex)
						{
						//Make a response
							dns_a_record rsp = {0};
							rsp.Name = htons(0xC00C); //Pointer of same requesting
							rsp.Classes = htons(Class_IN); //Class IN
							rsp.TTL = htonl(600); //10 minutes
							rsp.Type = htons(A_Records);
							rsp.Length = htons(sizeof(in_addr));

						//Convert addresses
							memcpy(AddrTemp, Buffer + Vertical[Index], Vertical[Index + 1] - Vertical[Index] - 1);
							if (inet_pton(AF_INET, AddrTemp, &rsp.Addr) <= 0)
							{
								delete[] Buffer;
								delete[] EndcodingTemp;
								delete[] AddrTemp;
								delete[] Temp.Response;
								CleanHostsTable();

								::PrintError("Hosts Error: Hosts IPv4 address format error", false, NULL);
								return RETURN_ERROR;
							}
							memcpy(Temp.Response + Temp.ResponseLength, &rsp, sizeof(dns_a_record));
							Temp.ResponseLength += sizeof(dns_a_record);

							memset(AddrTemp, 0, UDP_MAXSIZE/16);
							Index++;
						}
					}
					else {
						delete[] Temp.Response;
						continue;
					}
				}

			//Sign patterns
				Domain.append(sBuffer, Rear + 1, sBuffer.length() - Rear);
				try {
					std::regex TempPattern(Domain, std::regex_constants::extended);
					Temp.Pattern = TempPattern;
				}
				catch(std::regex_error)
				{
					delete[] Buffer;
					delete[] AddrTemp;
					delete[] EndcodingTemp;
					delete[] Temp.Response;
					CleanHostsTable();

					::PrintError("Hosts Error: Regular expression pattern(s) error", false, NULL);
					return RETURN_ERROR;
				}

			//Add to global HostsTable
				if (Temp.ResponseLength > 0)
					Modificating->push_back(Temp);
			}
		}
		fclose(Input);

	//Update Hosts list
		if (!Modificating->empty())
		{
			Using->swap(*Modificating);
			for (std::vector<HostsTable>::iterator iter = Modificating->begin();iter != Modificating->end();iter++)
				delete[] iter->Response;
			Modificating->clear();
			Modificating->resize(0);
		}
		else { //Hosts Table is empty
			CleanHostsTable();
		}
		
	//Auto-refresh
		Sleep((DWORD)this->Hosts);
	}

	delete[] Buffer;
	delete[] EndcodingTemp;
	delete[] AddrTemp;
	return 0;
}

//Clean Hosts Table
inline void __stdcall CleanHostsTable()
{
	for (std::vector<HostsTable>::iterator iter = Modificating->begin();iter != Modificating->end();iter++)
		delete[] iter->Response;
	for (std::vector<HostsTable>::iterator iter = Using->begin();iter != Using->end();iter++)
		delete[] iter->Response;
	Modificating->clear();
	Modificating->resize(0);
	Using->clear();
	Using->resize(0);
	return;
}
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

//Version define(Linux)
#define INI_VERSION       0.1         //Version of configuration file
#define HOSTS_VERSION     0.1         //Version of hosts file

//Codepage define
#define ANSI              1 * 100     //ANSI Codepage(Own)
#define UTF_8             65001       //Microsoft Windows Codepage of UTF-8
#define UTF_16_LE         1200 * 100  //Microsoft Windows Codepage of UTF-16 Little Endian/LE(Make it longer than the PACKET_MAXSIZE)
#define UTF_16_BE         1201 * 100  //Microsoft Windows Codepage of UTF-16 Big Endian/BE(Make it longer than the PACKET_MAXSIZE)
#define UTF_32_LE         12000       //Microsoft Windows Codepage of UTF-32 Little Endian/LE
#define UTF_32_BE         12001       //Microsoft Windows Codepage of UTF-32 Big Endian/BE

//Next line type define
//CR/Carriage Return is 0x0D and LF/Line Feed is 0x0A
#define CR_LF             1
#define LF                2
#define CR                3

std::vector<HostsTable> HostsList[2], *Using = &HostsList[0], *Modificating = &HostsList[1];

extern std::string ParameterPath, HostsPath;
extern Configuration Parameter;

//Read parameter from configuration file
size_t Configuration::ReadParameter()
{
//Initialization
	FILE *Input = nullptr;
	char *Buffer = nullptr, *Addition = nullptr;
	try {
		Buffer = new char[PACKET_MAXSIZE]();
		Addition = new char[PACKET_MAXSIZE]();
	}
	catch (std::bad_alloc)
	{
		::PrintError(System_Error, L"Memory allocation failed", 0, 0);

		delete[] Buffer;
		delete[] Addition;
		return EXIT_FAILURE;
	}
	memset(Buffer, 0, PACKET_MAXSIZE);
	memset(Addition, 0, PACKET_MAXSIZE);

//Open file
	Input = fopen(ParameterPath.c_str(), "rb");
	if (Input == nullptr)
	{
		::PrintError(Parameter_Error, L"Cannot open configuration file(Config.conf)", 0, 0);

		delete[] Buffer;
		delete[] Addition;
		return EXIT_FAILURE;
	}

	size_t Encoding = 0, NextLineType = 0, ReadLength = 0, AdditionLength = 0, Line = 1, Index = 0, Start = 0;
//Read data
	while(!feof(Input))
	{
		memset(Buffer, 0, PACKET_MAXSIZE);
		ReadLength = fread(Buffer, sizeof(char), PACKET_MAXSIZE, Input);
		if (Encoding == 0)
		{
			ReadEncoding(Buffer, ReadLength, Encoding, NextLineType); //Read encoding
			ReadEncoding(Buffer, ReadLength, Encoding, NextLineType); //Read next line type
			if (Encoding == UTF_8)
			{
				memcpy(Addition, Buffer + 3, PACKET_MAXSIZE - 3);
				memset(Buffer, 0, PACKET_MAXSIZE);
				memcpy(Buffer, Addition, PACKET_MAXSIZE - 3);
				memset(Addition, 0, PACKET_MAXSIZE);
				ReadLength -= 3;
			}
			else if (Encoding == UTF_16_LE || Encoding == UTF_16_BE)
			{
				memcpy(Addition, Buffer + 2, PACKET_MAXSIZE - 2);
				memset(Buffer, 0, PACKET_MAXSIZE);
				memcpy(Buffer, Addition, PACKET_MAXSIZE - 2);
				memset(Addition, 0, PACKET_MAXSIZE);
				ReadLength -= 2;
			}
			else if (Encoding == UTF_32_LE || Encoding == UTF_32_BE)
			{
				memcpy(Addition, Buffer + 4, PACKET_MAXSIZE - 4);
				memset(Buffer, 0, PACKET_MAXSIZE);
				memcpy(Buffer, Addition, PACKET_MAXSIZE - 4);
				memset(Addition, 0, PACKET_MAXSIZE);
				ReadLength -= 4; 
			}
		}

		for (Index = 0, Start = 0;Index < ReadLength + 1;Index++)
		{
		//CR/Carriage Return and LF/Line Feed
			if ((Encoding == UTF_8 || Encoding == ANSI || 
				((Encoding == UTF_16_LE || Encoding == UTF_32_LE) && Buffer[Index + 1] == 0) || 
				((Encoding == UTF_16_BE || Encoding == UTF_32_BE) && Buffer[Index - 1] == 0)) && 
				(Buffer[Index] == 0x0D || Buffer[Index] == 0x0A))
			{
				if (Index - Start > 8) //Minimum length of rules
				{
					if (Parameter.ReadParameterData(Addition, Line) == EXIT_FAILURE)
					{
						delete[] Buffer;
						delete[] Addition;
						return EXIT_FAILURE;
					}
				}

				memset(Addition, 0, PACKET_MAXSIZE);
				AdditionLength = 0;
				Start = Index;
			//Mark lines
				if (NextLineType == CR_LF || NextLineType == CR)
				{
					if (Buffer[Index] == 0x0D)
						Line++;
				}
				else {
					if (Buffer[Index] == 0x0A)
						Line++;
				}

				continue;
			}
		//ASCII data
			else if (Buffer[Index] != 0)
			{
				if (AdditionLength < PACKET_MAXSIZE)
				{
					Addition[AdditionLength] = Buffer[Index];
					AdditionLength++;
				}
				else {
					::PrintError(Parameter_Error, L"Parameter data of a line is too long", 0, Line);

					delete[] Buffer;
					delete[] Addition;
					return EXIT_FAILURE;
				}
			}
		//Last line
			else if (Buffer[Index] == 0 && Index == ReadLength && ReadLength != PACKET_MAXSIZE)
			{
				Line++;
				if (Parameter.ReadParameterData(Addition, Line) == EXIT_FAILURE)
				{
					delete[] Buffer;
					delete[] Addition;
					return EXIT_FAILURE;
				}
			}
		}
	}
	fclose(Input);
	delete[] Buffer;
	delete[] Addition;

//Set default
	static const char *PaddingData = ("\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x20 !\"#$%&\'()*+,-./01234567"); //Default Ping padding data(Linux)
	static const char *LocalDNSName = ("pcap_dnsproxy.localhost.server"); //Localhost DNS server name
	if (this->HopLimitOptions.HopLimitFluctuation < 0 && this->HopLimitOptions.HopLimitFluctuation >= 255)
		this->HopLimitOptions.HopLimitFluctuation = 2; //Default HopLimitFluctuation is 2
	if (ntohs(this->ICMPOptions.ICMPID) <= 0)
		this->ICMPOptions.ICMPID = htons((uint16_t)getpid()); //Default DNS ID is current process ID
	if (ntohs(this->ICMPOptions.ICMPSequence) <= 0)
		this->ICMPOptions.ICMPSequence = htons(0x0001); //Default DNS Sequence is 0x0001
	if (ntohs(this->DomainTestOptions.DomainTestID) <= 0)
		this->DomainTestOptions.DomainTestID = htons(0x0001); //Default Domain Test DNS ID is 0x0001
	if (this->DomainTestOptions.DomainTestSpeed <= 5) //5s is least time between Domain Tests
		this->DomainTestOptions.DomainTestSpeed = 900; //Default Domain Test request every 15 minutes.
	if (this->PaddingDataOptions.PaddingDataLength <= 0)
	{
		this->PaddingDataOptions.PaddingDataLength = 36;
		memcpy(this->PaddingDataOptions.PaddingData, PaddingData, this->PaddingDataOptions.PaddingDataLength - 1); //Load default padding data from Linux Ping
	}
	if (this->LocalhostServerOptions.LocalhostServerLength <= 0)
		this->LocalhostServerOptions.LocalhostServerLength = CharToDNSQuery((char *)LocalDNSName, this->LocalhostServerOptions.LocalhostServer); //Default Localhost DNS server name

//Check parameters
	if ((!this->DNSTarget.IPv4 && !this->DNSTarget.IPv6) || (!this->TCPMode && this->TCPOptions))
	{
		::PrintError(Parameter_Error, L"Base rule(s) error", 0, 0);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

//Read parameter data from configuration file
size_t Configuration::ReadParameterData(const char *Buffer, const size_t Line)
{
//Initialization
	char *Target = nullptr, *LocalhostServer = nullptr;
	try {
		Target = new char[PACKET_MAXSIZE/8]();
		LocalhostServer = new char[PACKET_MAXSIZE/8]();
	}
	catch (std::bad_alloc)
	{
		::PrintError(System_Error, L"Memory allocation failed", 0, 0);

		delete[] Target;
		delete[] LocalhostServer;
		return EXIT_FAILURE;
	}
	memset(Target, 0, PACKET_MAXSIZE/8);
	memset(LocalhostServer, 0, PACKET_MAXSIZE/8);
	std::string Data = Buffer;
	ssize_t Result = 0;

//Base block
	if (Data.find("Version = ") == 0 && Data.length() < 18)
	{
		double ReadVersion = atof(Buffer + 10);
		if (ReadVersion != INI_VERSION)
		{
			::PrintError(Parameter_Error, L"Configuration file version error", 0, 0);

			delete[] Target;
			delete[] LocalhostServer;
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("Print Error = ") == 0 && Data.length() < 16)
	{
		Result = atoi(Buffer + 14);
		if (Result == 0)
			this->PrintError = false;
	}
	else if (Data.find("Hosts = ") == 0 && Data.length() < 14)
	{
		Result = atoi(Buffer + 8);
		if (Result >= 5)
			this->Hosts = Result;
		else if (Result > 0 && Result < 5)
			this->Hosts = 5; //5s is least time between auto-refreshing
		else 
			this->Hosts = 0; //Read Hosts OFF
	}
	else if (Data.find("IPv4 DNS Address = ") == 0 && Data.length() > 25 && Data.length() < 35)
	{
		if (Data.find('.') == std::string::npos) //IPv4 Address
		{
			::PrintError(Parameter_Error, L"DNS server IPv4 Address format error", 0, Line);

			delete[] Target;
			delete[] LocalhostServer;
			return EXIT_FAILURE;
		}

	//IPv4 Address check
		memset(Target, 0, PACKET_MAXSIZE/8);
		memcpy(Target, Buffer + 19, Data.length() - 19);
		Result = inet_pton(AF_INET, Target, &(this->DNSTarget.IPv4Target));
		if (Result == FALSE)
		{
			::PrintError(Parameter_Error, L"DNS server IPv4 Address format error", errno, Line);

			delete[] Target;
			delete[] LocalhostServer;
			return EXIT_FAILURE;
		}
		else if (Result == RETURN_ERROR)
		{
			::PrintError(Parameter_Error, L"DNS server IPv4 Address convert failed", errno, Line);

			delete[] Target;
			delete[] LocalhostServer;
			return EXIT_FAILURE;
		}
		this->DNSTarget.IPv4 = true;
	}
	else if (Data.find("IPv4 Local DNS Address = ") == 0 && Data.length() > 31 && Data.length() < 41)
	{
		if (Data.find('.') == std::string::npos) //IPv4 Address
		{
			::PrintError(Parameter_Error, L"DNS server IPv4 Address format error", 0, Line);

			delete[] Target;
			delete[] LocalhostServer;
			return EXIT_FAILURE;
		}

	//IPv4 Address check
		memset(Target, 0, PACKET_MAXSIZE/8);
		memcpy(Target, Buffer + 25, Data.length() - 25);
		Result = inet_pton(AF_INET, Target, &(this->DNSTarget.Local_IPv4Target));
		if (Result == FALSE)
		{
			::PrintError(Parameter_Error, L"DNS server IPv4 Address format error", errno, Line);

			delete[] Target;
			delete[] LocalhostServer;
			return EXIT_FAILURE;
		}
		else if (Result == RETURN_ERROR)
		{
			::PrintError(Parameter_Error, L"DNS server IPv4 Address convert failed", errno, Line);

			delete[] Target;
			delete[] LocalhostServer;
			return EXIT_FAILURE;
		}
		this->DNSTarget.Local_IPv4 = true;
	}
	else if (Data.find("IPv6 DNS Address = ") == 0 && Data.length() > 21 && Data.length() < 59)
	{
		if (Data.find(':') == std::string::npos) //IPv6 Address
		{
			::PrintError(Parameter_Error, L"DNS server IPv6 Address format error", 0, Line);

			delete[] Target;
			delete[] LocalhostServer;
			return EXIT_FAILURE;
		}

	//IPv6 Address check
		memset(Target, 0, PACKET_MAXSIZE/8);
		memcpy(Target, Buffer + 19, Data.length() - 19);
		Result = inet_pton(AF_INET6, Target, &(this->DNSTarget.IPv6Target));
		if (Result == FALSE)
		{
			::PrintError(Parameter_Error, L"DNS server IPv6 Address format error", 0, Line);

			delete[] Target;
			delete[] LocalhostServer;
			return EXIT_FAILURE;
		}
		else if (Result == RETURN_ERROR)
		{
			::PrintError(Parameter_Error, L"DNS server IPv6 Address convert failed", errno, Line);

			delete[] Target;
			delete[] LocalhostServer;
			return EXIT_FAILURE;
		}
		this->DNSTarget.IPv6 = true;
	}
	else if (Data.find("IPv6 Local DNS Address = ") == 0 && Data.length() > 27 && Data.length() < 65)
	{
		if (Data.find(':') == std::string::npos) //IPv6 Address
		{
			::PrintError(Parameter_Error, L"DNS server IPv6 Address format error", 0, Line);

			delete[] Target;
			delete[] LocalhostServer;
			return EXIT_FAILURE;
		}

	//IPv6 Address check
		memset(Target, 0, PACKET_MAXSIZE/8);
		memcpy(Target, Buffer + 25, Data.length() - 25);
		Result = inet_pton(AF_INET6, Target, &(this->DNSTarget.Local_IPv6Target));
		if (Result == FALSE)
		{
			::PrintError(Parameter_Error, L"DNS server IPv6 Address format error", 0, Line);

			delete[] Target;
			delete[] LocalhostServer;
			return EXIT_FAILURE;
		}
		else if (Result == RETURN_ERROR)
		{
			::PrintError(Parameter_Error, L"DNS server IPv6 Address convert failed", errno, Line);

			delete[] Target;
			delete[] LocalhostServer;
			return EXIT_FAILURE;
		}
		this->DNSTarget.Local_IPv6 = true;
	}
	else if (Data.find("Operation Mode = ") == 0)
	{
		if (Data.find("Server") == 17)
			this->ServerMode = true;
	}
	else if (Data.find("Protocol = ") == 0)
	{
		if (Data.find("TCP") == 11)
			this->TCPMode = true;
	}

//Extend Test
	else if (Data.find("IPv4 TTL = ") == 0 && Data.length() > 11 && Data.length() < 15)
	{
		Result = atoi(Buffer + 11);
		if (Result > 0 && Result < 256)
			this->HopLimitOptions.IPv4TTL = Result;
	}
	else if (Data.find("IPv6 Hop Limits = ") == 0 && Data.length() > 18 && Data.length() < 22)
	{
		Result = atoi(Buffer + 18);
		if (Result > 0 && Result < 256)
			this->HopLimitOptions.IPv6HopLimit = Result;
	}
	else if (Data.find("Hop Limits/TTL Fluctuation = ") == 0 && Data.length() > 29 && Data.length() < 33)
	{
		Result = atoi(Buffer + 29);
		if (Result >= 0 && Result < 256)
			this->HopLimitOptions.HopLimitFluctuation = Result;
	}
	else if (Data.find("IPv4 Options Filter = ") == 0 && Data.length() < 24)
	{
		Result = atoi(Buffer + 22);
		if (Result == 1)
			this->IPv4Options = true;
	}
	else if (Data.find("ICMP Test = ") == 0 && Data.length() > 12 && Data.length() < 18)
	{
		Result = atoi(Buffer + 12);
		if (Result >= 5)
			this->ICMPOptions.ICMPSpeed = Result;
		else if (Result > 0 && Result < 5)
			this->ICMPOptions.ICMPSpeed = 5; //5s is least time between ICMP Tests
		else 
			this->ICMPOptions.ICMPSpeed = 0; //ICMP Test OFF
	}
	else if (Data.find("ICMP ID = ") == 0 && Data.length() < 17)
	{
		Result = strtol(Buffer + 10, NULL, 16);
		if (Result > 0)
			this->ICMPOptions.ICMPID = htons((uint16_t)Result);
	}
	else if (Data.find("ICMP Sequence = ") == 0 && Data.length() < 23)
	{
		Result = strtol(Buffer + 16, NULL, 16);
		if (Result > 0)
			this->ICMPOptions.ICMPSequence = htons((uint16_t)Result);
	}
	else if (Data.find("TCP Options Filter = ") == 0 && Data.length() < 23)
	{
		Result = atoi(Buffer + 21);
		if (Result == 1)
			this->TCPOptions = true;
	}
	else if (Data.find("DNS Options Filter = ") == 0 && Data.length() < 23)
	{
		Result = atoi(Buffer + 21);
		if (Result == 1)
			this->DNSOptions = true;
	}
	else if (Data.find("Blacklist Filter = ") == 0 && Data.length() < 22)
	{
		Result = atoi(Buffer + 19);
		if (Result == 1)
			this->Blacklist = true;
	}

//Data block
	else if (Data.find("Domain Test = ") == 0 && Data.length() > 17 && Data.length() < 270) //Maximum length of whole level domain is 253 bytes(Section 2.3.1 in RFC 1035).
	{
		memcpy(this->DomainTestOptions.DomainTest, Buffer + 14, Data.length() - 14);
		this->DomainTestOptions.DomainTestCheck = true;
	}
	else if (Data.find("Domain Test ID = ") == 0 && Data.length() < 24)
	{
		Result = strtol(Buffer + 17, NULL, 16);
		if (Result > 0)
			this->DomainTestOptions.DomainTestID = htons((uint16_t)Result);
	}
	else if (Data.find("Domain Test Speed = ") == 0 && Data.length() > 20 && Data.length() < 26)
	{
		Result = atoi(Buffer + 20);
		if (Result >= 5)
			this->DomainTestOptions.DomainTestSpeed = (useconds_t)Result;
		else 
			this->DomainTestOptions.DomainTestSpeed = 5; //5s is least time between Domain Tests
	}
	else if (Data.find("ICMP PaddingData = ") == 0)
	{
		if (Data.length() > 36 && Data.length() < 84) //The length of ICMP padding data must between 18 bytes and 64 bytes.
		{
			this->PaddingDataOptions.PaddingDataLength = Data.length() - 18;
			memcpy(this->PaddingDataOptions.PaddingData, Buffer + 19, Data.length() - 19);
		}
		else if (Data.length() >= 84)
		{
			::PrintError(Parameter_Error, L"The ICMP padding data is too long", 0, Line);
		}
	}
	else if (Data.find("Localhost Server Name = ") == 0 && Data.length() > 26 && Data.length() < 280) //Maximum length of whole level domain is 253 bytes(Section 2.3.1 in RFC 1035).
	{
		int *Point = nullptr;
		try {
			Point = new int[PACKET_MAXSIZE/8]();
		}
		catch (std::bad_alloc)
		{
			::PrintError(System_Error, L"Memory allocation failed", 0, 0);

			delete[] Target;
			delete[] LocalhostServer;
			return EXIT_FAILURE;
		}
		memset(Point, 0, sizeof(int)*(PACKET_MAXSIZE/8));

		size_t Index = 0;
		this->LocalhostServerOptions.LocalhostServerLength = Data.length() - 24;

	//Convert from char to DNS query
		LocalhostServer[0] = 46;
		memcpy(LocalhostServer + sizeof(char), Buffer + 24, this->LocalhostServerOptions.LocalhostServerLength);
		for (Index = 0;Index < Data.length() - 25;Index++)
		{
		//Preferred name syntax(Section 2.3.1 in RFC 1035)
			if (LocalhostServer[Index] == 45 || LocalhostServer[Index] == 46 || LocalhostServer[Index] == 95 || 
				(LocalhostServer[Index] > 47 && LocalhostServer[Index] < 58) || (LocalhostServer[Index] > 96 && LocalhostServer[Index] < 123))
			{
				if (LocalhostServer[Index] == 46)
				{
					Point[Result] = (int)Index;
					Result++;
				}
				continue;
			}
			else {
				::PrintError(Parameter_Error, L"Localhost server name format error", 0, Line);
				this->LocalhostServerOptions.LocalhostServerLength = 0;
				break;
			}
		}

		if (this->LocalhostServerOptions.LocalhostServerLength > 2)
		{
			char *LocalhostServerName = nullptr;
			try {
				LocalhostServerName = new char[PACKET_MAXSIZE/8]();
			}
			catch (std::bad_alloc)
			{
				::PrintError(System_Error, L"Memory allocation failed", 0, 0);

				delete[] Target;
				delete[] LocalhostServer;
				delete[] Point;
				return EXIT_FAILURE;
			}
			memset(LocalhostServerName, 0, PACKET_MAXSIZE/8);

			for (Index = 0;Index < (size_t)Result;Index++)
			{
				if (Index == (size_t)Result - 1)
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

	delete[] Target;
	delete[] LocalhostServer;
	return EXIT_SUCCESS;
}

//Read hosts from hosts file
size_t Configuration::ReadHosts()
{
//Read Hosts: ON/OFF
	if (Parameter.Hosts == 0)
		return FALSE;

//Initialization
	FILE *Input = nullptr;
	char *Buffer = nullptr, *Addition = nullptr;
	try {
		Buffer = new char[PACKET_MAXSIZE]();
		Addition = new char[PACKET_MAXSIZE]();
	}
	catch (std::bad_alloc)
	{
		::PrintError(System_Error, L"Memory allocation failed", 0, 0);

		delete[] Buffer;
		delete[] Addition;
		return EXIT_FAILURE;
	}
	memset(Buffer, 0, PACKET_MAXSIZE);
	memset(Addition, 0, PACKET_MAXSIZE);

//Open file
	size_t Encoding = 0, NextLineType = 0, ReadLength = 0, AdditionLength = 0, Line = 1, Index = 0, Start = 0;
	bool Local = false;
	while (true)
	{
		Input = fopen(HostsPath.c_str(), "rb");
		if (Input == nullptr)
		{
			::PrintError(Hosts_Error, L"Cannot open hosts file(Hosts.conf)", 0, 0);

			CleanupHostsTable();
			sleep(this->Hosts);
			continue;
		}
		
		Encoding = 0, Line = 1, AdditionLength = 0;
//Read data
		while(!feof(Input))
		{
			Local = false;
			memset(Buffer, 0, PACKET_MAXSIZE);
			ReadLength = fread(Buffer, sizeof(char), PACKET_MAXSIZE, Input);
			if (Encoding == 0)
			{
				ReadEncoding(Buffer, ReadLength, Encoding, NextLineType); //Read encoding
				ReadEncoding(Buffer, ReadLength, Encoding, NextLineType); //Read next line type
				if (Encoding == UTF_8)
				{
					memcpy(Addition, Buffer + 3, PACKET_MAXSIZE - 3);
					memset(Buffer, 0, PACKET_MAXSIZE);
					memcpy(Buffer, Addition, PACKET_MAXSIZE - 3);
					memset(Addition, 0, PACKET_MAXSIZE);
					ReadLength -= 3;
				}
				else if (Encoding == UTF_16_LE || Encoding == UTF_16_BE)
				{
					memcpy(Addition, Buffer + 2, PACKET_MAXSIZE - 2);
					memset(Buffer, 0, PACKET_MAXSIZE);
					memcpy(Buffer, Addition, PACKET_MAXSIZE - 2);
					memset(Addition, 0, PACKET_MAXSIZE);
					ReadLength -= 2;
				}
				else if (Encoding == UTF_32_LE || Encoding == UTF_32_BE)
				{
					memcpy(Addition, Buffer + 4, PACKET_MAXSIZE - 4);
					memset(Buffer, 0, PACKET_MAXSIZE);
					memcpy(Buffer, Addition, PACKET_MAXSIZE - 4);
					memset(Addition, 0, PACKET_MAXSIZE);
					ReadLength -= 4;
				}
			}

			for (Index = 0, Start = 0;Index < ReadLength + 1;Index++)
			{
			//CR/Carriage Return and LF/Line Feed
				if ((Encoding == UTF_8 || Encoding == ANSI || 
					((Encoding == UTF_16_LE || Encoding == UTF_32_LE) && Buffer[Index + 1] == 0) || 
					((Encoding == UTF_16_BE || Encoding == UTF_32_BE) && Buffer[Index - 1] == 0)) && 
					(Buffer[Index] == 0x0D || Buffer[Index] == 0x0A))
				{
					if (Index - Start > 6) //Minimum length of IPv6 addresses and regular expression
					{
						if (Parameter.ReadHostsData(Addition, Line, Local) == EXIT_FAILURE)
						{
							memset(Addition, 0, PACKET_MAXSIZE);
							continue;
						}
					}

					memset(Addition, 0, PACKET_MAXSIZE);
					AdditionLength = 0;
					Start = Index;
				//Mark lines
					if (NextLineType == CR_LF || NextLineType == CR)
					{
						if (Buffer[Index] == 0x0D)
							Line++;
					}
					else {
						if (Buffer[Index] == 0x0A)
							Line++;
					}

					continue;
				}
			//ASCII data
				else if (Buffer[Index] != 0)
				{
					if (AdditionLength < PACKET_MAXSIZE)
					{
						Addition[AdditionLength] = Buffer[Index];
						AdditionLength++;
					}
					else {
						::PrintError(Parameter_Error, L"Hosts data of a line is too long", 0, Line);

						memset(Addition, 0, PACKET_MAXSIZE);
						AdditionLength = 0;
						continue;
					}
				}
			//Last line
				else if (Buffer[Index] == 0 && Index == ReadLength && ReadLength != PACKET_MAXSIZE)
				{
					if (Parameter.ReadHostsData(Addition, Line, Local) == EXIT_FAILURE)
					{
						memset(Addition, 0, PACKET_MAXSIZE);
						AdditionLength = 0;
						break;
					}
				}
			}
		}
		fclose(Input);

	//Update Hosts list
		if (!Modificating->empty())
		{
			Using->swap(*Modificating);
			for (std::vector<HostsTable>::iterator iter = Modificating->begin();iter != Modificating->end();iter++)
			{
				delete[] iter->Response;
				regfree(&iter->Pattern); 
			}
			Modificating->clear();
			Modificating->resize(0);
		}
		else { //Hosts Table is empty
			CleanupHostsTable();
		}
		
	//Auto-refresh
		sleep(this->Hosts);
	}

	delete[] Buffer;
	delete[] Addition;
	return EXIT_SUCCESS;
}

//Read hosts data from hosts file
size_t Configuration::ReadHostsData(const char *Buffer, const size_t Line, bool &Local)
{
	std::string Data = Buffer;
	if (Data.length() < 3) //Minimum length of whole level domain is 3 bytes(Section 2.3.1 in RFC 1035).
		return EXIT_SUCCESS;

	bool Whitelist = false;
//Base block
	if (Data.find("Version = ") == 0 && Data.length() < 18)
	{
		double ReadVersion = atof(Buffer + 10);
		if (ReadVersion != HOSTS_VERSION)
		{
			::PrintError(Hosts_Error, L"Hosts file version error", 0, 0);

			return EXIT_FAILURE;
		}
		else {
			return EXIT_SUCCESS;
		}
	}
//Main hosts list
	else if (Data.find("[Hosts]") == 0)
	{
		Local = false;
		return EXIT_SUCCESS;
	}
//Local hosts list
	else if (Data.find("[Local Hosts]") == 0)
	{
		if (this->DNSTarget.Local_IPv4 || this->DNSTarget.Local_IPv6)
		{
			Local = true;
			return EXIT_SUCCESS;
		}
		else {
			return EXIT_SUCCESS;
		}
	}
//Whitelist
	else if (Data.find("NULL ") == 0 || Data.find("NULL	") == 0)
	{
		Whitelist = true;
	}
//Comments
	else if (Data.find(35) == 0) //Number Sign/NS
	{
		return EXIT_SUCCESS;
	}

//Initialization
	char *Addr = nullptr;
	try {
		Addr = new char[PACKET_MAXSIZE/8]();
	}
	catch (std::bad_alloc)
	{
		::PrintError(System_Error, L"Memory allocation failed", 0, 0);

		CleanupHostsTable();
		return EXIT_FAILURE;
	}
	memset(Addr, 0, PACKET_MAXSIZE/8);
	size_t Index = 0, Front = 0, Rear = 0;
	ssize_t Result = 0;

//Mark space and horizontal tab/HT
	if (Data.find(32) != std::string::npos) //Space
	{
		Index = Data.find(32);
		Front = Index;
		if (Data.rfind(32) > Index)
			Rear = Data.rfind(32);
		else 
			Rear = Front;
	}
	if (Data.find(9) != std::string::npos) //Horizontal Tab/HT
	{
		if (Index == 0)
			Index = Data.find(9);
		if (Index > Data.find(9))
			Front = Data.find(9);
		else 
			Front = Index;
		if (Data.rfind(9) > Index)
			Rear = Data.rfind(9);
		else 
			Rear = Front;
	}

//Whitelist block
	if (Whitelist)
	{
		HostsTable Temp;

	//Mark patterns
		if (regcomp(&(Temp.Pattern), Buffer + Rear + 1, REG_EXTENDED|REG_ICASE|REG_NOSUB) != 0)
		{
			::PrintError(Hosts_Error, L"Regular expression pattern error", 0, Line);

			delete[] Addr;
			CleanupHostsTable();
			return EXIT_FAILURE;
		}
		Temp.White = true;
		Modificating->push_back(Temp);
	}
//Main hosts block
	else if (!Local)
	{
	//Read data
		if (Front > 2) //Minimum length of IPv6 addresses
		{
			HostsTable Temp;
			Temp.Local = false;
			size_t Vertical[THREAD_MAXNUM/4] = {0}, VerticalIndex = 0;

		//Multiple Addresses
			for (Index = 0;Index < Front;Index++)
			{
				if (Buffer[Index] == 124)
				{
					if (VerticalIndex > THREAD_MAXNUM/4)
					{
						::PrintError(Hosts_Error, L"Too many Hosts IP addresses", 0, Line);

						delete[] Addr;
						CleanupHostsTable();
						return EXIT_FAILURE;
					}
					else if (Index - Vertical[VerticalIndex] < 2) //Minimum length of IPv6 address
					{
						::PrintError(Hosts_Error, L"Multiple addresses format error", 0, Line);

						delete[] Addr;
						CleanupHostsTable();
						return EXIT_FAILURE;
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

			Index = 0;
			if (VerticalIndex > 0)
			{
				memset(Addr, 0, PACKET_MAXSIZE/8);

			//Response initialization
				try {
					Temp.Response = new char[PACKET_MAXSIZE]();
				}
				catch (std::bad_alloc)
				{
					::PrintError(System_Error, L"Memory allocation failed", 0, 0);

					delete[] Addr;
					CleanupHostsTable();
					return EXIT_FAILURE;
				}
				memset(Temp.Response, 0, PACKET_MAXSIZE);

			//AAAA Records(IPv6)
				if (Data.find(58) != std::string::npos)
				{
					Temp.Protocol = AF_INET6;
					while (Index < VerticalIndex)
					{
					//Make a response
						dns_aaaa_record rsp = {0};
						rsp.Name = htons(0xC00C); //Pointer of same request
						rsp.Classes = htons(Class_IN); //Class IN
						rsp.TTL = htonl(600); //10 minutes
						rsp.Type = htons(AAAA_Records);
						rsp.Length = htons(sizeof(in6_addr));

					//Convert addresses
						memcpy(Addr, Buffer + Vertical[Index], Vertical[Index + 1] - Vertical[Index] - 1);
						Result = inet_pton(AF_INET6, Addr, &rsp.Addr);
						if (Result == FALSE)
						{
							::PrintError(Hosts_Error, L"Hosts IPv6 address format error", 0, Line);
							delete[] Temp.Response;

							Index++;
							continue;
						}
						else if (Result == RETURN_ERROR)
						{
							::PrintError(Hosts_Error, L"Hosts IPv6 address convert failed", errno, Line);
							delete[] Temp.Response;

							Index++;
							continue;
						}
						memcpy(Temp.Response + Temp.ResponseLength, &rsp, sizeof(dns_aaaa_record));
						
					//Check length
						Temp.ResponseLength += sizeof(dns_aaaa_record);
						if (Temp.ResponseLength >= PACKET_MAXSIZE / 8 * 7 - sizeof(dns_hdr) - sizeof(dns_qry)) //Maximun length of domain levels(256 bytes), DNS Header and DNS Query
						{
							::PrintError(Hosts_Error, L"Too many Hosts IP addresses", 0, Line);
							delete[] Temp.Response;

							Index++;
							continue;
						}

						memset(Addr, 0, PACKET_MAXSIZE/8);
						Index++;
					}
				}
			//A Records(IPv4)
				else {
					Temp.Protocol = AF_INET;
					while (Index < VerticalIndex)
					{
					//Make a response
						dns_a_record rsp = {0};
						rsp.Name = htons(0xC00C); //Pointer of same request
						rsp.Classes = htons(Class_IN); //Class IN
						rsp.TTL = htonl(600); //10 minutes
						rsp.Type = htons(A_Records);
						rsp.Length = htons(sizeof(in_addr));

					//Convert addresses
						memcpy(Addr, Buffer + Vertical[Index], Vertical[Index + 1] - Vertical[Index] - 1);
						Result = inet_pton(AF_INET, Addr, &rsp.Addr);
						if (Result == FALSE)
						{
							::PrintError(Hosts_Error, L"Hosts IPv4 address format error", 0, Line);
								
							delete[] Temp.Response;
							Index++;
							continue;
						}
						else if (Result == RETURN_ERROR)
						{
							::PrintError(Hosts_Error, L"Hosts IPv4 address convert failed", errno, Line);

							delete[] Temp.Response;
							Index++;
							continue;
						}
						memcpy(Temp.Response + Temp.ResponseLength, &rsp, sizeof(dns_a_record));

					//Check length
						Temp.ResponseLength += sizeof(dns_a_record);
						if (Temp.ResponseLength >= PACKET_MAXSIZE / 8 * 7 - sizeof(dns_hdr) - sizeof(dns_qry)) //Maximun length of domain levels(256 bytes), DNS Header and DNS Query
						{
							::PrintError(Hosts_Error, L"Too many Hosts IP addresses", 0, Line);

							delete[] Temp.Response;
							Index++;
							continue;
						}

						memset(Addr, 0, PACKET_MAXSIZE/8);
						Index++;
					}
				}

			//Mark patterns(Linux)
				if (regcomp(&(Temp.Pattern), Buffer + Rear + 1, REG_EXTENDED|REG_ICASE|REG_NOSUB) != 0)
				{
					::PrintError(Hosts_Error, L"Regular expression pattern error", 0, Line);

					delete[] Addr;
					CleanupHostsTable();
					return EXIT_FAILURE;
				}

			//Add to global HostsTable
				if (Temp.ResponseLength >= sizeof(dns_qry) + sizeof(in_addr)) //The shortest reply is a A Records with Question part
					Modificating->push_back(Temp);
			}
		}
	}
//Local hosts block
	else if (Local && (Parameter.DNSTarget.Local_IPv4 || Parameter.DNSTarget.Local_IPv6))
	{
		HostsTable Temp;

	//Mark patterns(Linux)
		if (regcomp(&(Temp.Pattern), Buffer + Rear + 1, REG_EXTENDED|REG_ICASE|REG_NOSUB) != 0)
		{
			::PrintError(Hosts_Error, L"Regular expression pattern error", 0, Line);

			delete[] Addr;
			CleanupHostsTable();
			return EXIT_FAILURE;
		}
		Temp.Local = true;
		Modificating->push_back(Temp);
	}

	delete[] Addr;
	return EXIT_SUCCESS;
}

//Read encoding of file
inline void ReadEncoding(const char *Buffer, const size_t Length, size_t &Encoding, size_t &NextLineType)
{
//Read next line type
	size_t Index = 0;
	for (Index = 4;Index < Length - 3;Index++)
	{
		if (Buffer[Index] == 0x0A && 
			(((Encoding == ANSI || Encoding == UTF_8) && Buffer[Index - 1] == 0x0D) || 
			((Encoding == UTF_16_LE || Encoding == UTF_16_BE) && Buffer[Index - 2] == 0x0D) || 
			((Encoding == UTF_32_LE || Encoding == UTF_32_BE) && Buffer[Index - 4] == 0x0D)))
		{
			NextLineType = CR_LF;
			return;
		}
		else if (Buffer[Index] == 0x0A && 
			(((Encoding == ANSI || Encoding == UTF_8) && Buffer[Index - 1] != 0x0D) || 
			((Encoding == UTF_16_LE || Encoding == UTF_16_BE) && Buffer[Index - 2] != 0x0D) || 
			((Encoding == UTF_32_LE || Encoding == UTF_32_BE) && Buffer[Index - 4] != 0x0D)))
		{
			NextLineType = LF;
			return;
		}
		else if (Buffer[Index] == 0x0D && 
			(((Encoding == ANSI || Encoding == UTF_8) && Buffer[Index + 1] != 0x0A) || 
			((Encoding == UTF_16_LE || Encoding == UTF_16_BE) && Buffer[Index + 2] != 0x0A) || 
			((Encoding == UTF_32_LE || Encoding == UTF_32_BE) && Buffer[Index + 4] != 0x0A)))
		{
			NextLineType = CR;
			return;
		}
	}

//8-bit Unicode Transformation Format/UTF-8 with BOM
	if ((u_char)Buffer[0] == 0xEF && (u_char)Buffer[1] == 0xBB && (u_char)Buffer[2] == 0xBF)
		Encoding = UTF_8;
//32-bit Unicode Transformation Format/UTF-32 Little Endian/LE
	else if ((u_char)Buffer[0] == 0xFF && (u_char)Buffer[1] == 0xFE && Buffer[2] == 0 && Buffer[3] == 0)
		Encoding = UTF_32_LE;
//32-bit Unicode Transformation Format/UTF-32 Big Endian/BE
	else if (Buffer[0] == 0 && Buffer[1] == 0 && (u_char)Buffer[2] == 0xFE && (u_char)Buffer[3] == 0xFF)
		Encoding = UTF_32_BE;
//16-bit Unicode Transformation Format/UTF-16 Little Endian/LE
	else if ((u_char)Buffer[0] == 0xFF && (u_char)Buffer[1] == 0xFE)
		Encoding = UTF_16_LE;
//16-bit Unicode Transformation Format/UTF-16 Big Endian/BE
	else if ((u_char)Buffer[0] == 0xFE && (u_char)Buffer[1] == 0xFF)
		Encoding = UTF_16_BE;
//8-bit Unicode Transformation Format/UTF-8 without BOM/Microsoft Windows ANSI Codepages
	else 
		Encoding = ANSI;

	return;
}

//Cleanup Hosts Table
inline void CleanupHostsTable()
{
//Delete all heap data(Linux)
	for (std::vector<HostsTable>::iterator iter = Modificating->begin();iter != Modificating->end();iter++)
	{
		delete[] iter->Response;
		regfree(&iter->Pattern); 
	}
	for (std::vector<HostsTable>::iterator iter = Using->begin();iter != Using->end();iter++)
	{
		delete[] iter->Response;
		regfree(&iter->Pattern); 
	}

//Cleanup vector list
	Modificating->clear();
	Modificating->resize(0);
	Using->clear();
	Using->resize(0);
	return;
}

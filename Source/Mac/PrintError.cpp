// This code is part of Pcap_DNSProxy(Mac)
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

extern std::string ErrorLogPath, ParameterPath, HostPath;
extern Configuration Parameter;

//Print errors to log file(Linux/Mac)
size_t PrintError(const size_t Type, const wchar_t *Message, const ssize_t Code, const size_t Line)
{
//Print Error(s): ON/OFF
	if (!Parameter.PrintError)
		return FALSE;

//Get current date&time
	time_t TimeSecond = 0;
	tm TimeStructure = {0};
	TimeSecond = time(NULL);
	localtime_r(&TimeSecond, &TimeStructure);

//PrintError to file
	FILE *Output = fopen(ErrorLogPath.c_str(), "a");
	if (Output != nullptr)
	{
	// Error Type
	// 01: System Error
	// 02: Parameter Error
	// 03: Hosts Error
	// 04: Socket Error
	// 05: LibPcap Error
		switch (Type)
		{
		//System Error
			case System_Error:
			{
				fwprintf(Output, L"%d-%02d-%02d %02d:%02d:%02d -> System Error: %ls.\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec, Message);
			}break;
		//Parameter Error
			case Parameter_Error:
			{
				fwprintf(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Parameter Error: %ls", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec, Message);
				if (Line != 0)
					fwprintf(Output, L" in Line %d", (int)Line);
				if (Code != 0)
					fwprintf(Output, L", Error Code is %d", (int)Code);
				
				fprintf(Output,".\n");
			}break;
		//Hosts Error
			case Hosts_Error:
			{
				fwprintf(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Hosts Error: %ls", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec, Message);
				if (Line != 0)
					fwprintf(Output, L" in Line %d", (int)Line);
				if (Code != 0)
					fwprintf(Output, L", Error Code is %d", (int)Code);
				
				fwprintf(Output, L".\n");
			}break;
		//Socket Error
			case Socket_Error:
			{
				if (Code == 0)
					fwprintf(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Socket Error: %ls.\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec, Message);
				else
					fwprintf(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Socket Error: %ls, Error code is %d\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec, Message, (int)Code);
			}break;
		//LibPcap Error
			case LibPcap_Error:
			{
				fwprintf(Output, L"%d-%02d-%02d %02d:%02d:%02d -> LibPcap Error: %ls.\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec, Message);
			}break;
			default:
			{
				fclose(Output);
				return EXIT_FAILURE;
			}
		}

		fclose(Output);
		return EXIT_SUCCESS;
	}

	return EXIT_FAILURE;
}

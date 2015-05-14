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

//Read texts
bool __fastcall ReadText(const FILE *Input, const size_t InputType, const size_t FileIndex)
{
//Initialization
	std::shared_ptr<char> FileBuffer(new char[FILE_BUFFER_SIZE]()), TextBuffer(new char[FILE_BUFFER_SIZE]()), TextData(new char[FILE_BUFFER_SIZE]());
	memset(FileBuffer.get(), 0, FILE_BUFFER_SIZE);
	memset(TextBuffer.get(), 0, FILE_BUFFER_SIZE);
	memset(TextData.get(), 0, FILE_BUFFER_SIZE);
	size_t ReadLength = 0, Index = 0, TextLength = 0, TextBufferLength = 0, Line = 0, LabelType = 0;
	auto CRLF_Length = false, IsEraseBOM = true, IsLabelComments = false;

//Read data.
	while (!feof((FILE *)Input))
	{
	//Read file and Mark last read.
		ReadLength = fread_s(FileBuffer.get(), FILE_BUFFER_SIZE, sizeof(char), FILE_BUFFER_SIZE, (FILE *)Input);

	//Erase BOM of Unicode Transformation Format/UTF at first.
		if (IsEraseBOM)
		{
			if (ReadLength <= READ_DATA_MINSIZE)
			{
				if (InputType == READTEXT_HOSTS) //ReadHosts
					PrintError(LOG_ERROR_HOSTS, L"Data of a line is too short", 0, HostsFileList[FileIndex].FileName.c_str(), Line);
				else if (InputType == READTEXT_IPFILTER) //ReadIPFilter
					PrintError(LOG_ERROR_IPFILTER, L"Data of a line is too short", 0, IPFilterFileList[FileIndex].FileName.c_str(), Line);
				else //ReadParameter
					PrintError(LOG_ERROR_PARAMETER, L"Data of a line is too short", 0, ConfigFileList[FileIndex].c_str(), Line);

				return false;
			}
			else {
				IsEraseBOM = false;
			}

		//8-bit Unicode Transformation Format/UTF-8 with BOM
			if ((UCHAR)FileBuffer.get()[0] == 0xEF && (UCHAR)FileBuffer.get()[1U] == 0xBB && (UCHAR)FileBuffer.get()[2U] == 0xBF) //0xEF, 0xBB, 0xBF
			{
				memmove_s(FileBuffer.get(), FILE_BUFFER_SIZE, FileBuffer.get() + BOM_UTF_8_LENGTH, FILE_BUFFER_SIZE - BOM_UTF_8_LENGTH);
				memset(FileBuffer.get() + FILE_BUFFER_SIZE - BOM_UTF_8_LENGTH, 0, BOM_UTF_8_LENGTH);
				ReadLength -= BOM_UTF_8_LENGTH;
			}
		//32-bit Unicode Transformation Format/UTF-32 Little Endian/LE
			else if ((UCHAR)FileBuffer.get()[0] == 0xFF && (UCHAR)FileBuffer.get()[1U] == 0xFE && FileBuffer.get()[2U] == 0 && FileBuffer.get()[3U] == 0) //0xFF, 0xFE, 0x00, 0x00
			{
				memmove_s(FileBuffer.get(), FILE_BUFFER_SIZE, FileBuffer.get() + BOM_UTF_32_LENGTH, FILE_BUFFER_SIZE - BOM_UTF_32_LENGTH);
				memset(FileBuffer.get() + FILE_BUFFER_SIZE - BOM_UTF_32_LENGTH, 0, BOM_UTF_32_LENGTH);
				ReadLength -= BOM_UTF_32_LENGTH;
			}
		//32-bit Unicode Transformation Format/UTF-32 Big Endian/BE
			else if (FileBuffer.get()[0] == 0 && FileBuffer.get()[1U] == 0 && (UCHAR)FileBuffer.get()[2U] == 0xFE && (UCHAR)FileBuffer.get()[3U] == 0xFF) //0x00, 0x00, 0xFE, 0xFF
			{
				memmove_s(FileBuffer.get(), FILE_BUFFER_SIZE, FileBuffer.get() + BOM_UTF_32_LENGTH, FILE_BUFFER_SIZE - BOM_UTF_32_LENGTH);
				memset(FileBuffer.get() + FILE_BUFFER_SIZE - BOM_UTF_32_LENGTH, 0, BOM_UTF_32_LENGTH);
				ReadLength -= BOM_UTF_32_LENGTH;
			}
		//16-bit Unicode Transformation Format/UTF-16 Little Endian/LE
			else if ((UCHAR)FileBuffer.get()[0] == 0xFF && (UCHAR)FileBuffer.get()[1U] == 0xFE) //0xFF, 0xFE
			{
				memmove_s(FileBuffer.get(), FILE_BUFFER_SIZE, FileBuffer.get() + BOM_UTF_16_LENGTH, FILE_BUFFER_SIZE - BOM_UTF_16_LENGTH);
				memset(FileBuffer.get() + FILE_BUFFER_SIZE - BOM_UTF_16_LENGTH, 0, BOM_UTF_16_LENGTH);
				ReadLength -= BOM_UTF_16_LENGTH;
			}
		//16-bit Unicode Transformation Format/UTF-16 Big Endian/BE
			else if ((UCHAR)FileBuffer.get()[0] == 0xFE && (UCHAR)FileBuffer.get()[1U] == 0xFF) //0xFE, 0xFF
			{
				memmove_s(FileBuffer.get(), FILE_BUFFER_SIZE, FileBuffer.get() + BOM_UTF_16_LENGTH, FILE_BUFFER_SIZE - BOM_UTF_16_LENGTH);
				memset(FileBuffer.get() + FILE_BUFFER_SIZE - BOM_UTF_16_LENGTH, 0, BOM_UTF_16_LENGTH);
				ReadLength -= BOM_UTF_16_LENGTH;
			}
/*		  8-bit Unicode Transformation Format/UTF-8 without BOM/Microsoft Windows ANSI Codepages
			else {
				;
			}
*/		}

	//Mark words.
		for (Index = 0;Index < ReadLength;++Index)
		{
			if (FileBuffer.get()[Index] != 0)
			{
				if (!CRLF_Length && (FileBuffer.get()[Index] == ASCII_CR || FileBuffer.get()[Index] == ASCII_LF))
					CRLF_Length = true;

				TextBuffer.get()[TextBufferLength] = FileBuffer.get()[Index];
				++TextBufferLength;
			}
		}

	//Lines length check
		if (!CRLF_Length && ReadLength == FILE_BUFFER_SIZE)
		{
			if (InputType == READTEXT_HOSTS) //ReadHosts
				PrintError(LOG_ERROR_HOSTS, L"Data of a line is too long", 0, HostsFileList[FileIndex].FileName.c_str(), Line);
			else if (InputType == READTEXT_IPFILTER) //ReadIPFilter
				PrintError(LOG_ERROR_IPFILTER, L"Data of a line is too long", 0, IPFilterFileList[FileIndex].FileName.c_str(), Line);
			else //ReadParameter
				PrintError(LOG_ERROR_PARAMETER, L"Data of a line is too long", 0, ConfigFileList[FileIndex].c_str(), Line);

			return false;
		}
		else {
			CRLF_Length = false;
		}

		memset(FileBuffer.get(), 0, FILE_BUFFER_SIZE);
		memcpy_s(FileBuffer.get(), FILE_BUFFER_SIZE, TextBuffer.get(), TextBufferLength);
		ReadLength = TextBufferLength;
		memset(TextBuffer.get(), 0, FILE_BUFFER_SIZE);
		TextBufferLength = 0;

	//Read data.
		for (Index = 0;Index < ReadLength;++Index)
		{
			if (FileBuffer.get()[Index] == ASCII_CR) //Macintosh format.
			{
				++Line;

			//Read texts.
				if (TextLength > READ_TEXT_MINSIZE)
				{
				//ReadHosts
					if (InputType == READTEXT_HOSTS)
					{
						ReadHostsData(TextData.get(), FileIndex, Line, LabelType, IsLabelComments);
					}
				//ReadIPFilter
					else if (InputType == READTEXT_IPFILTER)
					{
						ReadIPFilterData(TextData.get(), FileIndex, Line, LabelType, IsLabelComments);
					}
				//ReadParameter
					else {
						if (ReadParameterData(TextData.get(), FileIndex, Line, IsLabelComments) == EXIT_FAILURE)
							return false;
					}
				}

				memset(TextData.get(), 0, FILE_BUFFER_SIZE);
				TextLength = 0;
			}
			else if (FileBuffer.get()[Index] == ASCII_LF) //Unix format.
			{
				++Line;
				if (Index > 0 && FileBuffer.get()[Index - 1U] == ASCII_CR) //Windows format.
					--Line;

			//Read texts.
				if (TextLength > READ_TEXT_MINSIZE)
				{
				//ReadHosts
					if (InputType == READTEXT_HOSTS)
					{
						ReadHostsData(TextData.get(), FileIndex, Line, LabelType, IsLabelComments);
					}
				//ReadIPFilter
					else if (InputType == READTEXT_IPFILTER)
					{
						ReadIPFilterData(TextData.get(), FileIndex, Line, LabelType, IsLabelComments);
					}
				//ReadParameter
					else {
						if (ReadParameterData(TextData.get(), FileIndex, Line, IsLabelComments) == EXIT_FAILURE)
							return false;
					}
				}

				memset(TextData.get(), 0, FILE_BUFFER_SIZE);
				TextLength = 0;
			}
			else if (Index == ReadLength - 1U && feof((FILE *)Input)) //Last line
			{
				++Line;
				TextData.get()[TextLength] = FileBuffer.get()[Index];

			//Read texts.
				if (TextLength > READ_TEXT_MINSIZE)
				{
				//ReadHosts
					if (InputType == READTEXT_HOSTS)
					{
						if (ReadHostsData(TextData.get(), FileIndex, Line, LabelType, IsLabelComments) == EXIT_FAILURE)
							return false;
					}
				//ReadIPFilter
					else if (InputType == READTEXT_IPFILTER)
					{
						if (ReadIPFilterData(TextData.get(), FileIndex, Line, LabelType, IsLabelComments) == EXIT_FAILURE)
							return false;
					}
				//ReadParameter
					else {
						if (ReadParameterData(TextData.get(), FileIndex, Line, IsLabelComments) == EXIT_FAILURE)
							return false;
					}
				}

				return true;
			}
			else {
				TextData.get()[TextLength] = FileBuffer.get()[Index];
				++TextLength;
			}
		}

		memset(FileBuffer.get(), 0, FILE_BUFFER_SIZE);
	}

	return true;
}

//Check Multi-line comments
size_t __fastcall ReadMultiLineComments(const char *Buffer, std::string &Data, bool &IsLabelComments)
{
	if (IsLabelComments)
	{
		if (Data.find("*/") != std::string::npos)
		{
			Data = Buffer + Data.find("*/") + 2U;
			IsLabelComments = false;
		}
		else {
			return EXIT_FAILURE;
		}
	}
	while (Data.find("/*") != std::string::npos)
	{
		if (Data.find("*/") == std::string::npos)
		{
			Data.erase(Data.find("/*"), Data.length() - Data.find("/*"));
			IsLabelComments = true;
			break;
		}
		else {
			Data.erase(Data.find("/*"), Data.find("*/") - Data.find("/*") + 2U);
		}
	}

	return EXIT_SUCCESS;
}

//Read parameter from file
size_t __fastcall ReadParameter(void)
{
//Initialization
	FILE *Input = nullptr;
	size_t Index = 0;

//Open file.
	std::wstring ConfigFileName(Parameter.Path->front());
	ConfigFileName.append(L"Config.ini");
	ConfigFileList.push_back(ConfigFileName);
	ConfigFileName = Parameter.Path->front();
	ConfigFileName.append(L"Config.conf");
	ConfigFileList.push_back(ConfigFileName);
	ConfigFileName = Parameter.Path->front();
	ConfigFileName.append(L"Config");
	ConfigFileList.push_back(ConfigFileName);
	ConfigFileName.clear();
	ConfigFileName.shrink_to_fit();
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	std::string sConfigFileName(Parameter.sPath->front());
	sConfigFileName.append("Config.ini");
	sConfigFileList.push_back(sConfigFileName);
	sConfigFileName = Parameter.sPath->front();
	sConfigFileName.append("Config.conf");
	sConfigFileList.push_back(sConfigFileName);
	sConfigFileName = Parameter.sPath->front();
	sConfigFileName.append("Config");
	sConfigFileList.push_back(sConfigFileName);
	sConfigFileName.clear();
	sConfigFileName.shrink_to_fit();
#endif
	for (Index = 0; Index < ConfigFileList.size(); ++Index)
	{
	#if defined(PLATFORM_WIN)
		if (_wfopen_s(&Input, ConfigFileList[Index].c_str(), L"rb") != 0 || Input == nullptr)
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		Input = fopen(sConfigFileList[Index].c_str(), "rb");
		if (Input == nullptr)
	#endif
		{
		//Check all configuration files.
			if (Index == ConfigFileList.size() - 1U)
			{
				PrintError(LOG_ERROR_PARAMETER, L"Cannot open any configuration files", 0, nullptr, 0);
				return EXIT_FAILURE;
			}

			continue;
		}
		else {
			break;
		}
	}

//Check whole file size.
#if defined(PLATFORM_WIN)
	std::shared_ptr<WIN32_FILE_ATTRIBUTE_DATA> File_WIN32_FILE_ATTRIBUTE_DATA(new WIN32_FILE_ATTRIBUTE_DATA());
	memset(File_WIN32_FILE_ATTRIBUTE_DATA.get(), 0, sizeof(WIN32_FILE_ATTRIBUTE_DATA));
	if (GetFileAttributesExW(ConfigFileList[Index].c_str(), GetFileExInfoStandard, File_WIN32_FILE_ATTRIBUTE_DATA.get()) != FALSE)
	{
		std::shared_ptr<LARGE_INTEGER> ConfigFileSize(new LARGE_INTEGER());
		memset(ConfigFileSize.get(), 0, sizeof(LARGE_INTEGER));
		ConfigFileSize->HighPart = File_WIN32_FILE_ATTRIBUTE_DATA->nFileSizeHigh;
		ConfigFileSize->LowPart = File_WIN32_FILE_ATTRIBUTE_DATA->nFileSizeLow;
		if (ConfigFileSize->QuadPart >= DEFAULT_FILE_MAXSIZE)
		{
			PrintError(LOG_ERROR_PARAMETER, L"Configuration file is too large", 0, ConfigFileList[Index].c_str(), 0);
			return EXIT_FAILURE;
		}
	}

	File_WIN32_FILE_ATTRIBUTE_DATA.reset();
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	std::shared_ptr<struct stat> FileStat(new struct stat());
	memset(FileStat.get(), 0, sizeof(struct stat));
	if (stat(sConfigFileList[Index].c_str(), FileStat.get()) == 0 && FileStat->st_size >= (off_t)DEFAULT_FILE_MAXSIZE)
	{
		PrintError(LOG_ERROR_PARAMETER, L"Configuration file is too large", 0, ConfigFileList[Index].c_str(), 0);
		return EXIT_FAILURE;
	}

	FileStat.reset();
#endif

//Read data.
	if (Input != nullptr)
	{
		if (!ReadText(Input, READTEXT_PARAMETER, Index))
			return EXIT_FAILURE;
		fclose(Input);
	}
	else {
		PrintError(LOG_ERROR_PARAMETER, L"Cannot open any configuration files", 0, nullptr, 0);
		return EXIT_FAILURE;
	}

//Check parameters.
	if (Parameter.Version > PRODUCT_VERSION) //Version check
	{
		PrintError(LOG_ERROR_PARAMETER, L"Configuration file version error", 0, ConfigFileList[Index].c_str(), 0);
		return EXIT_FAILURE;
	}
	else if (Parameter.Version < PRODUCT_VERSION)
	{
		PrintError(LOG_ERROR_PARAMETER, L"Configuration file is not the latest version", 0, ConfigFileList[Index].c_str(), 0);
	}

//Clear when Print Running Log is disable.
//Print Running Log disable
	Parameter.PrintRunningLog = false;
	if (!Parameter.PrintRunningLog)
	{
		delete Parameter.RunningLogPath;
		Parameter.RunningLogPath = nullptr;
	}

//Log max size check
	if (Parameter.LogMaxSize < DEFAULT_LOG_MINSIZE || Parameter.LogMaxSize > DEFAULT_FILE_MAXSIZE)
	{
		PrintError(LOG_ERROR_PARAMETER, L"Log file size error", 0, ConfigFileList[Index].c_str(), 0);
		return EXIT_FAILURE;
	}

//DNS and Alternate Targets check
	if (Parameter.ListenAddress_IPv4->empty())
	{
		delete Parameter.ListenAddress_IPv4;
		Parameter.ListenAddress_IPv4 = nullptr;
	}
	if (Parameter.ListenAddress_IPv6->empty())
	{
		delete Parameter.ListenAddress_IPv6;
		Parameter.ListenAddress_IPv6 = nullptr;
	}
	if (!Parameter.DNSTarget.IPv6_Multi->empty())
	{
		Parameter.AlternateMultiRequest = true;

	//Copy DNS Server Data when Main or Alternate data are empty.
		if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family == 0)
		{
			uint8_t HopLimitTemp = 0;
			if (Parameter.DNSTarget.IPv6.HopLimitData.HopLimit > 0)
				HopLimitTemp = Parameter.DNSTarget.IPv6.HopLimitData.HopLimit;
			Parameter.DNSTarget.IPv6 = Parameter.DNSTarget.IPv6_Multi->front();
			Parameter.DNSTarget.IPv6.HopLimitData.HopLimit = HopLimitTemp;
			Parameter.DNSTarget.IPv6_Multi->erase(Parameter.DNSTarget.IPv6_Multi->begin());
		}

		if (Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family == 0 && !Parameter.DNSTarget.IPv6_Multi->empty())
		{
			uint8_t HopLimitTemp = 0;
			if (Parameter.DNSTarget.Alternate_IPv6.HopLimitData.HopLimit > 0)
				HopLimitTemp = Parameter.DNSTarget.Alternate_IPv6.HopLimitData.HopLimit;
			Parameter.DNSTarget.Alternate_IPv6 = Parameter.DNSTarget.IPv6_Multi->front();
			Parameter.DNSTarget.Alternate_IPv6.HopLimitData.HopLimit = HopLimitTemp;
			Parameter.DNSTarget.IPv6_Multi->erase(Parameter.DNSTarget.IPv6_Multi->begin());
		}

	//Multi select mode check
		if (Parameter.DNSTarget.IPv6_Multi->size() + 2U > FD_SETSIZE || //UDP requesting
			Parameter.RequestMode == REQUEST_TCPMODE && (Parameter.DNSTarget.IPv6_Multi->size() + 2U) * Parameter.MultiRequestTimes > FD_SETSIZE) //TCP requesting
		{
			PrintError(LOG_ERROR_PARAMETER, L"Too many multi addresses", 0, ConfigFileList[Index].c_str(), 0);
			return EXIT_FAILURE;
		}

	//Multi DNS Server check
		if (Parameter.DNSTarget.IPv6_Multi->empty())
		{
			delete Parameter.DNSTarget.IPv6_Multi;
			Parameter.DNSTarget.IPv6_Multi = nullptr;
		}
	}
	else {
		delete Parameter.DNSTarget.IPv6_Multi;
		Parameter.DNSTarget.IPv6_Multi = nullptr;
	}
	if (!Parameter.DNSTarget.IPv4_Multi->empty())
	{
		Parameter.AlternateMultiRequest = true;

	//Copy DNS Server Data when Main or Alternate data are empty.
		if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family == 0)
		{
			uint8_t TTLTemp = 0;
			if (Parameter.DNSTarget.IPv4.HopLimitData.TTL > 0)
				TTLTemp = Parameter.DNSTarget.IPv4.HopLimitData.TTL;
			Parameter.DNSTarget.IPv4 = Parameter.DNSTarget.IPv4_Multi->front();
			Parameter.DNSTarget.IPv4.HopLimitData.TTL = TTLTemp;
			Parameter.DNSTarget.IPv4_Multi->erase(Parameter.DNSTarget.IPv4_Multi->begin());
		}

		if (Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family == 0 && !Parameter.DNSTarget.IPv4_Multi->empty())
		{
			uint8_t TTLTemp = 0;
			if (Parameter.DNSTarget.Alternate_IPv4.HopLimitData.TTL > 0)
				TTLTemp = Parameter.DNSTarget.Alternate_IPv4.HopLimitData.TTL;
			Parameter.DNSTarget.Alternate_IPv4 = Parameter.DNSTarget.IPv4_Multi->front();
			Parameter.DNSTarget.Alternate_IPv4.HopLimitData.TTL = TTLTemp;
			Parameter.DNSTarget.IPv4_Multi->erase(Parameter.DNSTarget.IPv4_Multi->begin());
		}

	//Multi select mode check
		if (Parameter.DNSTarget.IPv4_Multi->size() + 2U > FD_SETSIZE || //UDP requesting
			Parameter.RequestMode == REQUEST_TCPMODE && (Parameter.DNSTarget.IPv4_Multi->size() + 2U) * Parameter.MultiRequestTimes > FD_SETSIZE) //TCP requesting
		{
			PrintError(LOG_ERROR_PARAMETER, L"Too many multi addresses", 0, ConfigFileList[Index].c_str(), 0);
			return EXIT_FAILURE;
		}

	//Multi DNS Server check
		if (Parameter.DNSTarget.IPv4_Multi->empty())
		{
			delete Parameter.DNSTarget.IPv4_Multi;
			Parameter.DNSTarget.IPv4_Multi = nullptr;
		}
	}
	else {
		delete Parameter.DNSTarget.IPv4_Multi;
		Parameter.DNSTarget.IPv4_Multi = nullptr;
	}
	if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family == 0 && Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0)
	{
		Parameter.DNSTarget.IPv6 = Parameter.DNSTarget.Alternate_IPv6;
		memset(&Parameter.DNSTarget.Alternate_IPv6, 0, sizeof(DNS_SERVER_DATA));
	}
	if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family == 0 && Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0)
	{
		Parameter.DNSTarget.IPv4 = Parameter.DNSTarget.Alternate_IPv4;
		memset(&Parameter.DNSTarget.Alternate_IPv4, 0, sizeof(DNS_SERVER_DATA));
	}
	if (Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family == 0 && Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family > 0)
	{
		Parameter.DNSTarget.Local_IPv6 = Parameter.DNSTarget.Alternate_Local_IPv6;
		memset(&Parameter.DNSTarget.Alternate_Local_IPv6, 0, sizeof(DNS_SERVER_DATA));
	}
	if (Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family == 0 && Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage.ss_family > 0)
	{
		Parameter.DNSTarget.Local_IPv4 = Parameter.DNSTarget.Alternate_Local_IPv4;
		memset(&Parameter.DNSTarget.Alternate_Local_IPv4, 0, sizeof(DNS_SERVER_DATA));
	}
	if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family == 0 && Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family == 0 || 
	//Check repeating items.
		Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0 && Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && 
		Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr.s_addr == Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr.s_addr && Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_port == Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_port || 
		Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family > 0 && Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage.ss_family > 0 && 
		Parameter.DNSTarget.Local_IPv4.AddressData.IPv4.sin_addr.s_addr == Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.IPv4.sin_addr.s_addr && Parameter.DNSTarget.Local_IPv4.AddressData.IPv4.sin_port == Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.IPv4.sin_port || 
		Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0 && Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && 
		memcmp(&Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr, &Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr, sizeof(in6_addr)) == 0 && Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_port == Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_port || 
		Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family > 0 && Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family > 0 && 
		memcmp(&Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_addr, &Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6.sin6_addr, sizeof(in6_addr)) == 0 && Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_port == Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6.sin6_port)
	{
		PrintError(LOG_ERROR_PARAMETER, L"DNS Targets error", 0, ConfigFileList[Index].c_str(), 0);
		return EXIT_FAILURE;
	}

//Hop Limit or TTL Fluctuations check
	if (Parameter.HopLimitFluctuation > 0)
	{
		//IPv6
		if (Parameter.DNSTarget.IPv6.HopLimitData.HopLimit > 0 && 
			((size_t)Parameter.DNSTarget.IPv6.HopLimitData.HopLimit + (size_t)Parameter.HopLimitFluctuation > UINT8_MAX || 
			(SSIZE_T)Parameter.DNSTarget.IPv6.HopLimitData.HopLimit < (SSIZE_T)Parameter.HopLimitFluctuation + 1) || 
			Parameter.DNSTarget.Alternate_IPv6.HopLimitData.HopLimit > 0 && 
			((size_t)Parameter.DNSTarget.Alternate_IPv6.HopLimitData.HopLimit + (size_t)Parameter.HopLimitFluctuation > UINT8_MAX || 
			(SSIZE_T)Parameter.DNSTarget.Alternate_IPv6.HopLimitData.HopLimit < (SSIZE_T)Parameter.HopLimitFluctuation + 1) || 
		//IPv4
			Parameter.DNSTarget.IPv4.HopLimitData.TTL > 0 && 
			((size_t)Parameter.DNSTarget.IPv4.HopLimitData.TTL + (size_t)Parameter.HopLimitFluctuation > UINT8_MAX || 
			(SSIZE_T)Parameter.DNSTarget.IPv4.HopLimitData.TTL < (SSIZE_T)Parameter.HopLimitFluctuation + 1) || 
			Parameter.DNSTarget.Alternate_IPv4.HopLimitData.TTL > 0 && 
			((size_t)Parameter.DNSTarget.Alternate_IPv4.HopLimitData.TTL + (size_t)Parameter.HopLimitFluctuation > UINT8_MAX || 
			(SSIZE_T)Parameter.DNSTarget.Alternate_IPv4.HopLimitData.TTL < (SSIZE_T)Parameter.HopLimitFluctuation + 1))
		{
			PrintError(LOG_ERROR_PARAMETER, L"Hop Limit or TTL Fluctuations error", 0, ConfigFileList[Index].c_str(), 0); //Hop Limit and TTL must between 1 and 255.
			return EXIT_FAILURE;
		}
	}

//Other error which need to print to log.
#if defined(ENABLE_LIBSODIUM)
	if (!Parameter.PcapCapture && !Parameter.HostsOnly && !Parameter.DNSCurve && Parameter.RequestMode != REQUEST_TCPMODE)
#else
	if (!Parameter.PcapCapture && !Parameter.HostsOnly && Parameter.RequestMode != REQUEST_TCPMODE)
#endif
	{
		PrintError(LOG_ERROR_PARAMETER, L"Pcap Capture error", 0, ConfigFileList[Index].c_str(), 0);
		return EXIT_FAILURE;
	}
	if (Parameter.LocalMain && Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family == 0 && Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family || 
		Parameter.LocalMain && Parameter.LocalHosts)
	{
		PrintError(LOG_ERROR_PARAMETER, L"Local Main and Local Hosts error", 0, ConfigFileList[Index].c_str(), 0);
		return EXIT_FAILURE;
	}
	else if (Parameter.LocalHosts && (Parameter.LocalMain || Parameter.LocalRouting) || Parameter.LocalRouting && !Parameter.LocalMain)
	{
		PrintError(LOG_ERROR_PARAMETER, L"Local Main / Local Hosts / Local Routing error", 0, ConfigFileList[Index].c_str(), 0);
		return EXIT_FAILURE;
	}
	if (Parameter.CacheType > 0 && Parameter.CacheParameter == 0)
	{
		PrintError(LOG_ERROR_PARAMETER, L"DNS Cache error", 0, ConfigFileList[Index].c_str(), 0);
		return EXIT_FAILURE;
	}
	if (Parameter.EDNS0PayloadSize < OLD_DNS_MAXSIZE)
	{
		if (Parameter.EDNS0PayloadSize > 0)
			PrintError(LOG_ERROR_PARAMETER, L"EDNS0 Payload Size must longer than 512 bytes(Old DNS packets minimum supported size)", 0, ConfigFileList[Index].c_str(), 0);
		Parameter.EDNS0PayloadSize = EDNS0_MINSIZE; //Default UDP maximum payload size.
	}
	else if (Parameter.EDNS0PayloadSize >= PACKET_MAXSIZE - sizeof(ipv6_hdr) - sizeof(udp_hdr))
	{
		PrintError(LOG_ERROR_PARAMETER, L"EDNS0 Payload Size may be too long", 0, ConfigFileList[Index].c_str(), 0);
		Parameter.EDNS0PayloadSize = EDNS0_MINSIZE;
	}
	if (Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family == 0 && Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family == 0 && 
		Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage.ss_family == 0 && Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family == 0
	#if defined(ENABLE_LIBSODIUM)
		&& Parameter.DNSCurve && DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family == 0 && DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family == 0
	#endif
		)
	{
		PrintError(LOG_ERROR_PARAMETER, L"Alternate Multi requesting error", 0, ConfigFileList[Index].c_str(), 0);
		return EXIT_FAILURE;
	}
	if (Parameter.MultiRequestTimes > MULTI_REQUEST_TIMES_MAXNUM) //Multi Request Times check
	{
		PrintError(LOG_ERROR_PARAMETER, L"Multi requesting times error", 0, ConfigFileList[Index].c_str(), 0);
		return EXIT_FAILURE;
	}
	else if (Parameter.MultiRequestTimes < 1U)
	{
		Parameter.MultiRequestTimes = 1U;
	}

//Set before checking.
	if (Parameter.RequestMode != REQUEST_TCPMODE) //TCP Mode options check
		Parameter.TCPDataCheck = false;
	if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family == 0)
		Parameter.IPv4DataCheck = false;

	//DNSCurve options check
#if defined(ENABLE_LIBSODIUM)
	if (Parameter.DNSCurve)
	{
	//Libsodium initialization
		if (sodium_init() != EXIT_SUCCESS)
		{
			PrintError(LOG_ERROR_DNSCURVE, L"Libsodium initialization error", 0, ConfigFileList[Index].c_str(), 0);
			return EXIT_FAILURE;
		}

	//Client keys check
		if (!CheckEmptyBuffer(DNSCurveParameter.Client_PublicKey, crypto_box_PUBLICKEYBYTES) && !CheckEmptyBuffer(DNSCurveParameter.Client_SecretKey, crypto_box_SECRETKEYBYTES) && 
			!VerifyKeypair(DNSCurveParameter.Client_PublicKey, DNSCurveParameter.Client_SecretKey))
		{
			PrintError(LOG_ERROR_DNSCURVE, L"Client keypair(public key and secret key) error", 0, ConfigFileList[Index].c_str(), 0);
			return EXIT_FAILURE;
		}
		else if (DNSCurveParameter.IsEncryption)
		{
			memset(DNSCurveParameter.Client_PublicKey, 0, crypto_box_PUBLICKEYBYTES);
			memset(DNSCurveParameter.Client_SecretKey, 0, crypto_box_SECRETKEYBYTES);
			crypto_box_curve25519xsalsa20poly1305_keypair(DNSCurveParameter.Client_PublicKey, DNSCurveParameter.Client_SecretKey);
		}
		else {
			delete[] DNSCurveParameter.Client_PublicKey;
			delete[] DNSCurveParameter.Client_SecretKey;
			DNSCurveParameter.Client_PublicKey = nullptr;
			DNSCurveParameter.Client_SecretKey = nullptr;
		}

	//DNSCurve targets check
		if (DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family == 0 && DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0)
		{
			DNSCurveParameter.DNSCurveTarget.IPv6 = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6;
			memset(&DNSCurveParameter.DNSCurveTarget.Alternate_IPv6, 0, sizeof(DNSCURVE_SERVER_DATA));
		}
		if (DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family == 0 && DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0)
		{
			DNSCurveParameter.DNSCurveTarget.IPv4 = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4;
			memset(&DNSCurveParameter.DNSCurveTarget.Alternate_IPv4, 0, sizeof(DNSCURVE_SERVER_DATA));
		}

		if (DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family == 0 && DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family == 0 || 
		//Check repeating items.
			DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family > 0 && DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_addr.s_addr == DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_addr.s_addr || 
			DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family > 0 && DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && memcmp(&DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_addr, &DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr, sizeof(in6_addr)) == 0)
		{
			PrintError(LOG_ERROR_PARAMETER, L"DNSCurve Targets error", 0, ConfigFileList[Index].c_str(), 0);
			return EXIT_FAILURE;
		}

	//Eencryption options check
		if (DNSCurveParameter.IsEncryptionOnly && !DNSCurveParameter.IsEncryption)
		{
			DNSCurveParameter.IsEncryption = true;
			PrintError(LOG_ERROR_PARAMETER, L"DNSCurve encryption options error", 0, ConfigFileList[Index].c_str(), 0);
		}

	//Main(IPv6)
		if (DNSCurveParameter.IsEncryption && DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family > 0)
		{
		//Empty Server Fingerprint
			if (CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES))
			{
			//Encryption Only mode check
				if (DNSCurveParameter.IsEncryptionOnly && 
					CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNSCurve Encryption Only mode error", 0, ConfigFileList[Index].c_str(), 0);
					return EXIT_FAILURE;
				}

			//Empty Provider Name
				if (CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.ProviderName, DOMAIN_MAXSIZE))
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNSCurve empty Provider Name error", 0, ConfigFileList[Index].c_str(), 0);
					return EXIT_FAILURE;
				}

			//Empty Public Key
				if (CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES))
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNSCurve empty Public Key error", 0, ConfigFileList[Index].c_str(), 0);
					return EXIT_FAILURE;
				}
			}
			else {
				crypto_box_curve25519xsalsa20poly1305_beforenm(
					DNSCurveParameter.DNSCurveTarget.IPv6.PrecomputationKey,
					DNSCurveParameter.DNSCurveTarget.IPv6.ServerFingerprint,
					DNSCurveParameter.Client_SecretKey);
			}
		}
		else {
			delete[] DNSCurveParameter.DNSCurveTarget.IPv6.ProviderName;
			delete[] DNSCurveParameter.DNSCurveTarget.IPv6.PrecomputationKey;
			delete[] DNSCurveParameter.DNSCurveTarget.IPv6.ServerPublicKey;
			delete[] DNSCurveParameter.DNSCurveTarget.IPv6.ReceiveMagicNumber;
			delete[] DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber;

			DNSCurveParameter.DNSCurveTarget.IPv6.ProviderName = nullptr;
			DNSCurveParameter.DNSCurveTarget.IPv6.PrecomputationKey = nullptr;
			DNSCurveParameter.DNSCurveTarget.IPv6.ServerPublicKey = nullptr;
			DNSCurveParameter.DNSCurveTarget.IPv6.ReceiveMagicNumber = nullptr;
			DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber = nullptr;
		}

	//Main(IPv4)
		if (DNSCurveParameter.IsEncryption && DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family > 0)
		{
		//Empty Server Fingerprint
			if (CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES))
			{
			//Encryption Only mode check
				if (DNSCurveParameter.IsEncryptionOnly && 
					CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNSCurve Encryption Only mode error", 0, ConfigFileList[Index].c_str(), 0);
					return EXIT_FAILURE;
				}

			//Empty Provider Name
				if (CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.ProviderName, DOMAIN_MAXSIZE))
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNSCurve empty Provider Name error", 0, ConfigFileList[Index].c_str(), 0);
					return EXIT_FAILURE;
				}

			//Empty Public Key
				if (CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES))
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNSCurve empty Public Key error", 0, ConfigFileList[Index].c_str(), 0);
					return EXIT_FAILURE;
				}
			}
			else {
				crypto_box_curve25519xsalsa20poly1305_beforenm(
					DNSCurveParameter.DNSCurveTarget.IPv4.PrecomputationKey,
					DNSCurveParameter.DNSCurveTarget.IPv4.ServerFingerprint,
					DNSCurveParameter.Client_SecretKey);
			}
		}
		else {
			delete[] DNSCurveParameter.DNSCurveTarget.IPv4.ProviderName;
			delete[] DNSCurveParameter.DNSCurveTarget.IPv4.PrecomputationKey;
			delete[] DNSCurveParameter.DNSCurveTarget.IPv4.ServerPublicKey;
			delete[] DNSCurveParameter.DNSCurveTarget.IPv4.ReceiveMagicNumber;
			delete[] DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber;

			DNSCurveParameter.DNSCurveTarget.IPv4.ProviderName = nullptr;
			DNSCurveParameter.DNSCurveTarget.IPv4.PrecomputationKey = nullptr;
			DNSCurveParameter.DNSCurveTarget.IPv4.ServerPublicKey = nullptr;
			DNSCurveParameter.DNSCurveTarget.IPv4.ReceiveMagicNumber = nullptr;
			DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber = nullptr;
		}

	//Alternate(IPv6)
		if (DNSCurveParameter.IsEncryption && DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0)
		{
		//Empty Server Fingerprint
			if (CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES))
			{
			//Encryption Only mode check
				if (DNSCurveParameter.IsEncryptionOnly && 
					CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNSCurve Encryption Only mode error", 0, ConfigFileList[Index].c_str(), 0);
					return EXIT_FAILURE;
				}

			//Empty Provider Name
				if (CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ProviderName, DOMAIN_MAXSIZE))
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNSCurve empty Provider Name error", 0, ConfigFileList[Index].c_str(), 0);
					return EXIT_FAILURE;
				}

			//Empty Public Key
				if (CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES))
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNSCurve empty Public Key error", 0, ConfigFileList[Index].c_str(), 0);
					return EXIT_FAILURE;
				}
			}
			else {
				crypto_box_curve25519xsalsa20poly1305_beforenm(
					DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey,
					DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ServerFingerprint,
					DNSCurveParameter.Client_SecretKey);
			}
		}
		else {
			delete[] DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ProviderName;
			delete[] DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey;
			delete[] DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ServerPublicKey;
			delete[] DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ReceiveMagicNumber;
			delete[] DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber;

			DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ProviderName = nullptr;
			DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey = nullptr;
			DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ServerPublicKey = nullptr;
			DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ReceiveMagicNumber = nullptr;
			DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber = nullptr;
		}

	//Alternate(IPv4)
		if (DNSCurveParameter.IsEncryption && DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0)
		{
		//Empty Server Fingerprint
			if (CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES))
			{
			//Encryption Only mode check
				if (DNSCurveParameter.IsEncryptionOnly && 
					CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNSCurve Encryption Only mode error", 0, ConfigFileList[Index].c_str(), 0);
					return EXIT_FAILURE;
				}

			//Empty Provider Name
				if (CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ProviderName, DOMAIN_MAXSIZE))
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNSCurve empty Provider Name error", 0, ConfigFileList[Index].c_str(), 0);
					return EXIT_FAILURE;
				}

			//Empty Public Key
				if (CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES))
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNSCurve empty Public Key error", 0, ConfigFileList[Index].c_str(), 0);
					return EXIT_FAILURE;
				}
			}
			else {
				crypto_box_curve25519xsalsa20poly1305_beforenm(
					DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.PrecomputationKey,
					DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ServerFingerprint,
					DNSCurveParameter.Client_SecretKey);
			}
		}
		else {
			delete[] DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ProviderName;
			delete[] DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.PrecomputationKey;
			delete[] DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ServerPublicKey;
			delete[] DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ReceiveMagicNumber;
			delete[] DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.SendMagicNumber;

			DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ProviderName = nullptr;
			DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.PrecomputationKey = nullptr;
			DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ServerPublicKey = nullptr;
			DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ReceiveMagicNumber = nullptr;
			DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.SendMagicNumber = nullptr;
		}
	}
	else {
		delete[] DNSCurveParameter.DNSCurveTarget.IPv4.ProviderName;
		delete[] DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ProviderName;
		delete[] DNSCurveParameter.DNSCurveTarget.IPv6.ProviderName;
		delete[] DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ProviderName;
	//DNSCurve Keys
		delete[] DNSCurveParameter.Client_PublicKey;
		delete[] DNSCurveParameter.Client_SecretKey;
		delete[] DNSCurveParameter.DNSCurveTarget.IPv4.PrecomputationKey;
		delete[] DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.PrecomputationKey;
		delete[] DNSCurveParameter.DNSCurveTarget.IPv6.PrecomputationKey;
		delete[] DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey;
		delete[] DNSCurveParameter.DNSCurveTarget.IPv4.ServerPublicKey;
		delete[] DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ServerPublicKey;
		delete[] DNSCurveParameter.DNSCurveTarget.IPv6.ServerPublicKey;
		delete[] DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ServerPublicKey;
		delete[] DNSCurveParameter.DNSCurveTarget.IPv4.ServerFingerprint;
		delete[] DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ServerFingerprint;
		delete[] DNSCurveParameter.DNSCurveTarget.IPv6.ServerFingerprint;
		delete[] DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ServerFingerprint;
	//DNSCurve Magic Numbers
		delete[] DNSCurveParameter.DNSCurveTarget.IPv4.ReceiveMagicNumber;
		delete[] DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ReceiveMagicNumber;
		delete[] DNSCurveParameter.DNSCurveTarget.IPv6.ReceiveMagicNumber;
		delete[] DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ReceiveMagicNumber;
		delete[] DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber;
		delete[] DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.SendMagicNumber;
		delete[] DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber;
		delete[] DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber;

		DNSCurveParameter.DNSCurveTarget.IPv4.ProviderName = nullptr, DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ProviderName = nullptr, DNSCurveParameter.DNSCurveTarget.IPv6.ProviderName = nullptr, DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ProviderName = nullptr;
		DNSCurveParameter.Client_PublicKey = nullptr, DNSCurveParameter.Client_SecretKey = nullptr;
		DNSCurveParameter.DNSCurveTarget.IPv4.PrecomputationKey = nullptr, DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.PrecomputationKey = nullptr, DNSCurveParameter.DNSCurveTarget.IPv6.PrecomputationKey = nullptr, DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.PrecomputationKey = nullptr;
		DNSCurveParameter.DNSCurveTarget.IPv4.ServerPublicKey = nullptr, DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ServerPublicKey = nullptr, DNSCurveParameter.DNSCurveTarget.IPv6.ServerPublicKey = nullptr, DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ServerPublicKey = nullptr;
		DNSCurveParameter.DNSCurveTarget.IPv4.ServerFingerprint = nullptr, DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ServerFingerprint = nullptr, DNSCurveParameter.DNSCurveTarget.IPv6.ServerFingerprint = nullptr, DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ServerFingerprint = nullptr;
		DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber = nullptr, DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.SendMagicNumber = nullptr, DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber = nullptr, DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber = nullptr;
		DNSCurveParameter.DNSCurveTarget.IPv4.ReceiveMagicNumber = nullptr, DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ReceiveMagicNumber = nullptr, DNSCurveParameter.DNSCurveTarget.IPv6.ReceiveMagicNumber = nullptr, DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ReceiveMagicNumber = nullptr;
	}
#endif

//Default settings
	if (Parameter.ListenPort != nullptr && Parameter.ListenPort->empty())
		Parameter.ListenPort->push_back(htons(IPPORT_DNS));

	if (!Parameter.EDNS0Label)
	{
		if (Parameter.DNSSECRequest)
		{
			PrintError(LOG_ERROR_PARAMETER, L"EDNS0 Label must turn ON when request DNSSEC", 0, ConfigFileList[Index].c_str(), 0);
			Parameter.EDNS0Label = true;
		}
	}
	if (Parameter.CompressionPointerMutation && Parameter.EDNS0Label)
	{
		PrintError(LOG_ERROR_PARAMETER, L"Compression Pointer Mutation must turn OFF when request EDNS0 Label", 0, ConfigFileList[Index].c_str(), 0);
		Parameter.CompressionPointerMutation = false;
	}

	if (CheckEmptyBuffer(Parameter.DomainTestData, DOMAIN_MAXSIZE))
	{
		delete[] Parameter.DomainTestData;
		Parameter.DomainTestData = nullptr;
	}

	//Default Local DNS server name
	if (Parameter.LocalFQDNLength <= 0)
	{
		Parameter.LocalFQDNLength = CharToDNSQuery(DEFAULT_LOCAL_SERVERNAME, Parameter.LocalFQDN);
		*Parameter.LocalFQDNString = DEFAULT_LOCAL_SERVERNAME;
	}

	//Set Local DNS server PTR response.
	if (Parameter.LocalServerResponseLength <= 0)
	{
		auto DNS_Record_PTR = (pdns_record_ptr)Parameter.LocalServerResponse;
		DNS_Record_PTR->PTR = htons(DNS_QUERY_PTR);
		DNS_Record_PTR->Classes = htons(DNS_CLASS_IN);
		DNS_Record_PTR->TTL = htonl(Parameter.HostsDefaultTTL);
		DNS_Record_PTR->Type = htons(DNS_RECORD_PTR);
		DNS_Record_PTR->Length = htons((uint16_t)Parameter.LocalFQDNLength);
		Parameter.LocalServerResponseLength += sizeof(dns_record_ptr);

		memcpy_s(Parameter.LocalServerResponse + Parameter.LocalServerResponseLength, DOMAIN_MAXSIZE + sizeof(dns_record_ptr) + sizeof(dns_record_opt) - Parameter.LocalServerResponseLength, Parameter.LocalFQDN, Parameter.LocalFQDNLength);
		Parameter.LocalServerResponseLength += Parameter.LocalFQDNLength;

	//EDNS0 Label
		if (Parameter.EDNS0Label)
		{
			auto DNS_Record_OPT = (pdns_record_opt)(Parameter.LocalServerResponse + Parameter.LocalServerResponseLength);
			DNS_Record_OPT->Type = htons(DNS_RECORD_OPT);
			DNS_Record_OPT->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
			Parameter.LocalServerResponseLength += sizeof(dns_record_opt);
		}
	}

//DNSCurve default settings
#if defined(ENABLE_LIBSODIUM)
	if (Parameter.DNSCurve && DNSCurveParameter.IsEncryption)
	{
	//DNSCurve PayloadSize check
		if (DNSCurveParameter.DNSCurvePayloadSize < OLD_DNS_MAXSIZE)
		{
			if (DNSCurveParameter.DNSCurvePayloadSize > 0)
				PrintError(LOG_ERROR_PARAMETER, L"DNSCurve Payload Size must longer than 512 bytes(Old DNS packets minimum supported size)", 0, ConfigFileList[Index].c_str(), 0);
			DNSCurveParameter.DNSCurvePayloadSize = OLD_DNS_MAXSIZE; //Default DNSCurve UDP maximum payload size.
		}
		else if (DNSCurveParameter.DNSCurvePayloadSize >= PACKET_MAXSIZE - sizeof(ipv6_hdr) - sizeof(udp_hdr))
		{
			PrintError(LOG_ERROR_PARAMETER, L"DNSCurve Payload Size may be too long", 0, ConfigFileList[Index].c_str(), 0);
			DNSCurveParameter.DNSCurvePayloadSize = EDNS0_MINSIZE;
		}

	//Main(IPv6)
		if (DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family > 0 && CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
			memcpy_s(DNSCurveParameter.DNSCurveTarget.IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCRYPT_RECEIVE_MAGIC, DNSCURVE_MAGIC_QUERY_LEN);

	//Main(IPv4)
		if (DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family > 0 && CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
			memcpy_s(DNSCurveParameter.DNSCurveTarget.IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCRYPT_RECEIVE_MAGIC, DNSCURVE_MAGIC_QUERY_LEN);

	//Alternate(IPv6)
		if (DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
			memcpy_s(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCRYPT_RECEIVE_MAGIC, DNSCURVE_MAGIC_QUERY_LEN);

	//Alternate(IPv4)
		if (DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
			memcpy_s(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCRYPT_RECEIVE_MAGIC, DNSCURVE_MAGIC_QUERY_LEN);

	//DNSCurve keys recheck time
		if (DNSCurveParameter.KeyRecheckTime == 0)
			DNSCurveParameter.KeyRecheckTime = DEFAULT_DNSCURVE_RECHECK_TIME * SECOND_TO_MILLISECOND;
	}
#endif

//Sort AcceptTypeList.
	std::sort(Parameter.AcceptTypeList->begin(), Parameter.AcceptTypeList->end());

//Print global parameter list and run Running Log writing Monitor.
	if (Parameter.PrintRunningLog)
	{
		PrintParameterList();
		if (Parameter.RunningLogRefreshTime > 0)
		{
			std::thread RunningLogWriteMonitorThread(RunningLogWriteMonitor);
			RunningLogWriteMonitorThread.detach();
		}
		else {
			delete Parameter.RunningLogWriteQueue;
			Parameter.RunningLogWriteQueue = nullptr;
		}
	}
	else {
		delete Parameter.RunningLogWriteQueue;
		Parameter.RunningLogWriteQueue = nullptr;
	}

	return EXIT_SUCCESS;
}

//Read parameter data from files
size_t __fastcall ReadParameterData(const char *Buffer, const size_t FileIndex, const size_t Line, bool &IsLabelComments)
{
	std::string Data(Buffer);

//Multi-line comments check
	if (ReadMultiLineComments(Buffer, Data, IsLabelComments) == EXIT_FAILURE)
		return EXIT_SUCCESS;

	SSIZE_T Result = 0;
//Parameter version less than 0.4 compatible support.
	if (Data.find("Hop Limits/TTL Fluctuation = ") == 0 && Data.length() > strlen("Hop Limits/TTL Fluctuation = "))
	{
		if (Data.length() < strlen("Hop Limits/TTL Fluctuation = ") + 4U)
		{
			Result = strtoul(Data.c_str() + strlen("Hop Limits/TTL Fluctuation = "), nullptr, 0);
			if (errno != ERANGE && Result > 0 && Result < UINT8_MAX)
				Parameter.HopLimitFluctuation = (uint8_t)Result;
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
			return EXIT_FAILURE;
		}
	}

//Delete delete spaces, horizontal tab/HT, check comments(Number Sign/NS and double slashs) and check minimum length of ipfilter items.
//Delete comments(Number Sign/NS and double slashs) and check minimum length of configuration items.
	if (Data.find(ASCII_HASHTAG) == 0 || Data.find(ASCII_SLASH) == 0)
		return EXIT_SUCCESS;
	while (Data.find(ASCII_HT) != std::string::npos)
		Data.erase(Data.find(ASCII_HT), 1U);
	while (Data.find(ASCII_SPACE) != std::string::npos)
		Data.erase(Data.find(ASCII_SPACE), 1U);
	if (Data.find(ASCII_HASHTAG) != std::string::npos)
		Data.erase(Data.find(ASCII_HASHTAG));
	else if (Data.find(ASCII_SLASH) != std::string::npos)
		Data.erase(Data.find(ASCII_SLASH));
	if (Data.length() < READ_PARAMETER_MINSIZE)
		return FALSE;

//[Base] block
	if (Data.find("Version=") == 0)
	{
		if (Data.length() > strlen("Version=") && Data.length() < strlen("Version=") + 8U)
		{
			Parameter.Version = strtod(Data.c_str() + strlen("Version="), nullptr);
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
			return EXIT_FAILURE;
		}
	}

//Parameter version less than 0.4 compatible support.
	if (Parameter.Version < PRODUCT_VERSION)
	{
	//[Base] block
		if (Data.find("Hosts=") == 0 && Data.length() > strlen("Hosts="))
		{
			if (Data.length() < strlen("Hosts=") + 6U)
			{
				Result = strtoul(Data.c_str() + strlen("Hosts="), nullptr, 0);
				if (errno != ERANGE && Result >= SHORTEST_FILEREFRESH_TIME)
					Parameter.FileRefreshTime = Result * SECOND_TO_MILLISECOND;
				else 
					Parameter.FileRefreshTime = DEFAULT_FILEREFRESH_TIME * SECOND_TO_MILLISECOND;
			}
			else {
				PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
				return EXIT_FAILURE;
			}
		}
		else if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family == 0 && Data.find("IPv4DNSAddress=") == 0 && Data.length() > strlen("IPv4DNSAddress="))
		{
			if (Data.length() > strlen("IPv4DNSAddress=") + 6U && Data.length() < strlen("IPv4DNSAddress=") + 20U)
			{
			//Convert IPv4 address and port.
				std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());
				memset(Target.get(), 0, ADDR_STRING_MAXSIZE);
				memcpy_s(Target.get(), ADDR_STRING_MAXSIZE, Data.c_str() + strlen("IPv4DNSAddress="), Data.length() - strlen("IPv4DNSAddress="));
				if (AddressStringToBinary(Target.get(), &Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr, AF_INET, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 address format error", Result, ConfigFileList[FileIndex].c_str(), Line);
					return EXIT_FAILURE;
				}

				Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_port = htons(IPPORT_DNS);
				Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family = AF_INET;
			}
			else {
				PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
				return EXIT_FAILURE;
			}
		}
		else if (Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family == 0 && Data.find("IPv4LocalDNSAddress=") == 0 && Data.length() > strlen("IPv4LocalDNSAddress="))
		{
			if (Data.length() > strlen("IPv4LocalDNSAddress=") + 6U && Data.length() < strlen("IPv4LocalDNSAddress=") + 20U)
			{
			//Convert IPv4 address and port.
				std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());
				memset(Target.get(), 0, ADDR_STRING_MAXSIZE);
				memcpy_s(Target.get(), ADDR_STRING_MAXSIZE, Data.c_str() + strlen("IPv4LocalDNSAddress="), Data.length() - strlen("IPv4LocalDNSAddress="));
				if (AddressStringToBinary(Target.get(), &Parameter.DNSTarget.Local_IPv4.AddressData.IPv4.sin_addr, AF_INET, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 address format error", Result, ConfigFileList[FileIndex].c_str(), Line);
					return EXIT_FAILURE;
				}

				Parameter.DNSTarget.Local_IPv4.AddressData.IPv4.sin_port = htons(IPPORT_DNS);
				Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family = AF_INET;
			}
			else {
				PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
				return EXIT_FAILURE;
			}
		}
		else if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family == 0 && Data.find("IPv6DNSAddress=") == 0 && Data.length() > strlen("IPv6DNSAddress="))
		{
			if (Data.length() > strlen("IPv6DNSAddress=") + 1U && Data.length() < strlen("IPv6DNSAddress=") + 40U)
			{
			//Convert IPv6 address and port.
				std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());
				memset(Target.get(), 0, ADDR_STRING_MAXSIZE);
				memcpy_s(Target.get(), ADDR_STRING_MAXSIZE, Data.c_str() + strlen("IPv6DNSAddress="), Data.length() - strlen("IPv6DNSAddress="));
				if (AddressStringToBinary(Target.get(), &Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 address format error", Result, ConfigFileList[FileIndex].c_str(), Line);
					return EXIT_FAILURE;
				}

				Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_port = htons(IPPORT_DNS);
				Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family = AF_INET6;
			}
			else {
				PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
				return EXIT_FAILURE;
			}
		}
		else if (Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family == 0 && Data.find("IPv6LocalDNSAddress=") == 0 && Data.length() > strlen("IPv6LocalDNSAddress="))
		{
			if (Data.length() > strlen("IPv6LocalDNSAddress=") + 1U && Data.length() < strlen("IPv6LocalDNSAddress=") + 40U)
			{
			//Convert IPv6 address and port.
				std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());
				memset(Target.get(), 0, ADDR_STRING_MAXSIZE);
				memcpy_s(Target.get(), ADDR_STRING_MAXSIZE, Data.c_str() + strlen("IPv6LocalDNSAddress="), Data.length() - strlen("IPv6LocalDNSAddress="));
				if (AddressStringToBinary(Target.get(), &Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 address format error", Result, ConfigFileList[FileIndex].c_str(), Line);
					return EXIT_FAILURE;
				}

				Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_port = htons(IPPORT_DNS);
				Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family = AF_INET6;
			}
			else {
				PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
				return EXIT_FAILURE;
			}
		}

	//[Extend Test] block
		else if (Data.find("IPv4OptionsFilter=1") == 0)
		{
			Parameter.IPv4DataCheck = true;
		}
		else if (Data.find("TCPOptionsFilter=1") == 0)
		{
			Parameter.TCPDataCheck = true;
		}
		else if (Data.find("DNSOptionsFilter=1") == 0)
		{
			Parameter.DNSDataCheck = true;
		}

	//[Data] block
		else if (Parameter.DomainTestSpeed == 0 && Data.find("DomainTestSpeed=") == 0 && Data.length() > strlen("DomainTestSpeed="))
		{
			if (Data.length() < strlen("DomainTestSpeed=") + 6U)
			{
				Result = strtoul(Data.c_str() + strlen("DomainTestSpeed="), nullptr, 0);
				if (errno != ERANGE && Result > 0)
					Parameter.DomainTestSpeed = Result * SECOND_TO_MILLISECOND;
			}
			else {
				PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
				return EXIT_FAILURE;
			}
		}
	}
	else if (Data.find("FileRefreshTime=") == 0 && Data.length() > strlen("FileRefreshTime="))
	{
		if (Data.length() < strlen("FileRefreshTime=") + 6U)
		{
			Result = strtoul(Data.c_str() + strlen("FileRefreshTime="), nullptr, 0);
			if (errno != ERANGE && Result >= SHORTEST_FILEREFRESH_TIME)
				Parameter.FileRefreshTime = Result * SECOND_TO_MILLISECOND;
			else 
				Parameter.FileRefreshTime = DEFAULT_FILEREFRESH_TIME * SECOND_TO_MILLISECOND;
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("AdditionalPath=") == 0 && Data.length() > strlen("AdditionalPath="))
	{
		std::string NameStringTemp;
		std::wstring wNameStringTemp;
		for (Result = strlen("AdditionalPath=");Result < (SSIZE_T)Data.length();++Result)
		{
			if (Result == (SSIZE_T)(Data.length() - 1U))
			{
				NameStringTemp.append(Data, Result, 1U);

			//Case Convert.
			#if defined(PLATFORM_WIN) //Case-insensitive on Windows
				for (auto &StringIter:NameStringTemp)
				{
					if (StringIter > ASCII_AT && StringIter < ASCII_BRACKETS_LEAD)
						StringIter += ASCII_UPPER_TO_LOWER;
				}
			#endif

			//Add backslash.
				if (NameStringTemp.back() != ASCII_BACKSLASH)
					NameStringTemp.append("\\");

			//Convert to wide string.
				MBSToWCSString(wNameStringTemp, NameStringTemp.c_str());
				for (auto wStringIter = Parameter.Path->begin();wStringIter < Parameter.Path->end();++wStringIter)
				{
					if (*wStringIter == wNameStringTemp)
						break;

					if (wStringIter + 1U == Parameter.Path->end())
					{
						Parameter.Path->push_back(wNameStringTemp);
						for (size_t Index = 0;Index < Parameter.Path->back().length();++Index)
						{
							if ((Parameter.Path->back())[Index] == L'\\')
							{
								Parameter.Path->back().insert(Index, L"\\");
								++Index;
							}
						}

						break;
					}
				}
			}
			else if (Data[Result] == ASCII_VERTICAL)
			{
			//Case Convert.
			#if defined(PLATFORM_WIN) //Case-insensitive on Windows
				for (auto &StringIter:NameStringTemp)
				{
					if (StringIter > ASCII_AT && StringIter < ASCII_BRACKETS_LEAD)
						StringIter += ASCII_UPPER_TO_LOWER;
				}
			#endif

			//Add backslash.
				if (NameStringTemp.back() != ASCII_BACKSLASH)
					NameStringTemp.append("\\");

			//Convert to wide string.
				MBSToWCSString(wNameStringTemp, NameStringTemp.c_str());
				for (auto wStringIter = Parameter.Path->begin();wStringIter < Parameter.Path->end();++wStringIter)
				{
					if (*wStringIter == wNameStringTemp)
						break;

					if (wStringIter + 1U == Parameter.Path->end())
					{
						Parameter.Path->push_back(wNameStringTemp);
						for (size_t Index = 0;Index < Parameter.Path->back().length();++Index)
						{
							if ((Parameter.Path->back())[Index] == L'\\')
							{
								Parameter.Path->back().insert(Index, L"\\");
								++Index;
							}

							break;
						}
					}
				}

				NameStringTemp.clear();
				wNameStringTemp.clear();
			}
			else {
				NameStringTemp.append(Data, Result, 1U);
			}
		}
	}
	else if (Data.find("HostsFileName=") == 0 && Data.length() > strlen("HostsFileName="))
	{
	#if defined(PLATFORM_WIN)
		if (ReadFileName(Data, strlen("HostsFileName="), Parameter.HostsFileList) == EXIT_FAILURE)
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		if (ReadFileName(Data, strlen("HostsFileName="), Parameter.HostsFileList, Parameter.sHostsFileList) == EXIT_FAILURE)
	#endif
			return EXIT_FAILURE;
	}
	else if (Data.find("IPFilterFileName=") == 0 && Data.length() > strlen("IPFilterFileName="))
	{
	#if defined(PLATFORM_WIN)
		if (ReadFileName(Data, strlen("IPFilterFileName="), Parameter.IPFilterFileList) == EXIT_FAILURE)
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		if (ReadFileName(Data, strlen("IPFilterFileName="), Parameter.IPFilterFileList, Parameter.sIPFilterFileList) == EXIT_FAILURE)
	#endif
			return EXIT_FAILURE;
	}

//[Log] block
	else if (Data.find("PrintError=0") == 0)
	{
		Parameter.PrintError = false;
		delete Parameter.ErrorLogPath;
		Parameter.ErrorLogPath = nullptr;
	}
	else if (Data.find("PrintRunningLog=1") == 0)
	{
		Parameter.PrintRunningLog = true;
	}
	else if (Data.find("RunningLogRefreshTime=") == 0 && Data.length() > strlen("RunningLogRefreshTime="))
	{
		if (Data.length() < strlen("RunningLogRefreshTime=") + 6U)
		{
			Result = strtoul(Data.c_str() + strlen("RunningLogRefreshTime="), nullptr, 0);
			if (errno != ERANGE && Result >= SHORTEST_FILEREFRESH_TIME)
				Parameter.RunningLogRefreshTime = Result * SECOND_TO_MILLISECOND;
			else if (Result > 0 && Result < SHORTEST_FILEREFRESH_TIME)
				Parameter.RunningLogRefreshTime = DEFAULT_FILEREFRESH_TIME * SECOND_TO_MILLISECOND;
			else
				Parameter.RunningLogRefreshTime = 0; //Refresh immediately.
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("LogMaximumSize=") == 0 && Data.length() > strlen("LogMaximumSize="))
	{
		if (Data.find("KB") != std::string::npos || Data.find("Kb") != std::string::npos || Data.find("kB") != std::string::npos || Data.find("kb") != std::string::npos)
		{
			Data.erase(Data.length() - 2U, 2U);

		//Mark bytes.
			Result = strtoul(Data.c_str() + strlen("LogMaximumSize="), nullptr, 0);
			if (errno != ERANGE && Result >= 0)
			{
				Parameter.LogMaxSize = Result * KILOBYTE_TIMES;
			}
			else {
				PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
				return EXIT_FAILURE;
			}
		}
		else if (Data.find("MB") != std::string::npos || Data.find("Mb") != std::string::npos || Data.find("mB") != std::string::npos || Data.find("mb") != std::string::npos)
		{
			Data.erase(Data.length() - 2U, 2U);

		//Mark bytes.
			Result = strtoul(Data.c_str() + strlen("LogMaximumSize="), nullptr, 0);
			if (errno != ERANGE && Result >= 0)
			{
				Parameter.LogMaxSize = Result * MEGABYTE_TIMES;
			}
			else {
				PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
				return EXIT_FAILURE;
			}
		}
		else if (Data.find("GB") != std::string::npos || Data.find("Gb") != std::string::npos || Data.find("gB") != std::string::npos || Data.find("gb") != std::string::npos)
		{
			Data.erase(Data.length() - 2U, 2U);

		//Mark bytes.
			Result = strtoul(Data.c_str() + strlen("LogMaximumSize="), nullptr, 0);
			if (errno != ERANGE && Result >= 0)
			{
				Parameter.LogMaxSize = Result * GIGABYTE_TIMES;
			}
			else {
				PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
				return EXIT_FAILURE;
			}
		}
		else {
		//Check number.
			for (auto StringIter = Data.begin() + strlen("LogMaximumSize=");StringIter != Data.end();++StringIter)
			{
				if (*StringIter < ASCII_ZERO || *StringIter > ASCII_NINE)
				{
					PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
					return EXIT_FAILURE;
				}
			}

		//Mark bytes.
			Result = strtoul(Data.c_str() + strlen("LogMaximumSize="), nullptr, 0);
			if (errno != ERANGE && Result >= 0)
			{
				Parameter.LogMaxSize = Result;
			}
			else {
				PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
				return EXIT_FAILURE;
			}
		}
	}

//[DNS] block
	else if (Data.find("Protocol=TCP") == 0 || Data.find("Protocol=Tcp") == 0 || Data.find("Protocol=tcp") == 0)
	{
		Parameter.RequestMode = REQUEST_TCPMODE;
	}
	else if (Data.find("HostsOnly=1") == 0)
	{
		Parameter.HostsOnly = true;
	}
	else if (Data.find("LocalMain=1") == 0)
	{
		Parameter.LocalMain = true;
	}
	else if (Data.find("LocalHosts=1") == 0)
	{
		Parameter.LocalHosts = true;
	}
	else if (Data.find("LocalRouting=1") == 0)
	{
		Parameter.LocalRouting = true;
	}
	else if (Data.find("CacheType=") == 0 && Data.length() > strlen("CacheType="))
	{
		if (Data.find("Timer") != std::string::npos || Data.find("timer") != std::string::npos)
			Parameter.CacheType = CACHE_TIMER;
		else if (Data.find("Queue") != std::string::npos || Data.find("queue") != std::string::npos)
			Parameter.CacheType = CACHE_QUEUE;
	}
	else if (Parameter.CacheType > 0 && Data.find("CacheParameter=") == 0 && Data.length() > strlen("CacheParameter="))
	{
		Result = strtoul(Data.c_str() + strlen("CacheParameter="), nullptr, 0);
		if (errno != ERANGE && Result > 0)
		{
			if (Parameter.CacheType == CACHE_TIMER)
				Parameter.CacheParameter = Result * SECOND_TO_MILLISECOND;
			else //CACHE_QUEUE
				Parameter.CacheParameter = Result;
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("DefaultTTL=") == 0 && Data.length() > strlen("DefaultTTL="))
	{
		if (Data.length() < strlen("DefaultTTL=") + 6U)
		{
			Result = strtoul(Data.c_str() + strlen("DefaultTTL="), nullptr, 0);
			if (errno != ERANGE && Result > 0 && Result <= UINT16_MAX)
			{
				Parameter.HostsDefaultTTL = (uint32_t)Result;
			}
			else {
				PrintError(LOG_ERROR_PARAMETER, L"Default TTL error", 0, ConfigFileList[FileIndex].c_str(), Line);
				return EXIT_FAILURE;
			}
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
			return EXIT_FAILURE;
		}
	}

//[Listen] block
	else if (Data.find("PcapCapture=1") == 0)
	{
		Parameter.PcapCapture = true;
	}
	else if (Data.find("OperationMode=") == 0)
	{
		if (Data.find("Private") != std::string::npos || Data.find("private") != std::string::npos)
			Parameter.OperationMode = LISTEN_PRIVATEMODE;
		else if (Data.find("Server") != std::string::npos || Data.find("server") != std::string::npos)
			Parameter.OperationMode = LISTEN_SERVERMODE;
		else if (Data.find("Custom") != std::string::npos || Data.find("custom") != std::string::npos)
			Parameter.OperationMode = LISTEN_CUSTOMMODE;
		else 
			Parameter.OperationMode = LISTEN_PROXYMODE;
	}
	else if (Data.find("ListenProtocol=") == 0)
	{
		if (Data.find("IPv6") != std::string::npos || Data.find("IPV6") != std::string::npos || Data.find("ipv6") != std::string::npos)
		{
			if (Data.find("IPv4") != std::string::npos || Data.find("IPV4") != std::string::npos || Data.find("ipv4") != std::string::npos)
				Parameter.ListenProtocol_NetworkLayer = LISTEN_IPV6_IPV4;
			else 
				Parameter.ListenProtocol_NetworkLayer = LISTEN_IPV6;
		}
		else {
			Parameter.ListenProtocol_NetworkLayer = LISTEN_IPV4;
		}

		if (Data.find("TCP") != std::string::npos || Data.find("tcp") != std::string::npos)
		{
			if (Data.find("UDP") != std::string::npos || Data.find("udp") != std::string::npos)
				Parameter.ListenProtocol_TransportLayer = LISTEN_TCP_UDP;
			else 
				Parameter.ListenProtocol_TransportLayer = LISTEN_TCP;
		}
		else {
			Parameter.ListenProtocol_TransportLayer = LISTEN_UDP;
		}
	}
	else if (Data.find("ListenPort=") == 0 && Data.length() > strlen("ListenPort="))
	{
	//Multiple Ports
		if (Data.find(ASCII_VERTICAL) != std::string::npos)
		{
			std::string PortString;
			for (size_t Index = strlen("ListenPort=");Index < Data.length();++Index)
			{
				if (Index == Data.length() - 1U)
				{
					PortString.append(Data, Index, 1U);
					Result = ServiceNameToHex(PortString.c_str());
					if (Result == 0)
					{
						Result = strtoul(PortString.c_str(), nullptr, 0);
						if (errno != ERANGE && Result > 0 && Result <= UINT16_MAX)
						{
							Parameter.ListenPort->push_back(htons((uint16_t)Result));
						}
						else {
							PrintError(LOG_ERROR_PARAMETER, L"Localhost server listening port error", 0, ConfigFileList[FileIndex].c_str(), Line);
							return EXIT_FAILURE;
						}
					}

					break;
				}
				else if (Data[Index] == ASCII_VERTICAL)
				{
					Result = ServiceNameToHex(PortString.c_str());
					if (Result == 0)
					{
						Result = strtoul(PortString.c_str(), nullptr, 0);
						if (errno != ERANGE && Result > 0 && Result <= UINT16_MAX)
						{
							Parameter.ListenPort->push_back(htons((uint16_t)Result));
						}
						else {
							PrintError(LOG_ERROR_PARAMETER, L"Localhost server listening port error", 0, ConfigFileList[FileIndex].c_str(), Line);
							return EXIT_FAILURE;
						}
					}

					PortString.clear();
				}
				else {
					PortString.append(Data, Index, 1U);
				}
			}
		}
	//Single Ports
		else {
			Result = ServiceNameToHex(Data.c_str() + strlen("ListenPort="));
			if (Result == 0)
			{
				Result = strtoul(Data.c_str() + strlen("ListenPort="), nullptr, 0);
				if (errno != ERANGE && Result > 0 && Result <= UINT16_MAX)
				{
					Parameter.ListenPort->push_back(htons((uint16_t)Result));
				}
				else {
					PrintError(LOG_ERROR_PARAMETER, L"Localhost server listening port error", 0, ConfigFileList[FileIndex].c_str(), Line);
					return EXIT_FAILURE;
				}
			}
		}
	}
	else if (Data.find("IPFilterType=PERMIT") == 0 || Data.find("IPFilterType=Permit") == 0 || Data.find("IPFilterType=permit") == 0)
	{
		Parameter.IPFilterType = true;
	}
	else if (Data.find("IPFilterLevel<") == 0 && Data.length() > strlen("IPFilterLevel<"))
	{
		if (Data.length() < strlen("IPFilterLevel<") + 4U)
		{
			Result = strtoul(Data.c_str() + strlen("IPFilterLevel<"), nullptr, 0);
			if (errno != ERANGE && Result > 0 && Result <= UINT16_MAX)
			{
				Parameter.IPFilterLevel = (size_t)Result;
			}
			else {
				PrintError(LOG_ERROR_PARAMETER, L"IPFilter Level error", 0, ConfigFileList[FileIndex].c_str(), Line);
				return EXIT_FAILURE;
			}
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("AcceptType=") == 0 && Data.length() > strlen("AcceptType="))
	{
		if (Data.find(ASCII_COLON) == std::string::npos)
		{
			PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
			return EXIT_FAILURE;
		}
		else {
		//Permit or Deny
			if (Data.find("PERMIT:") != std::string::npos || Data.find("Permit:") != std::string::npos || Data.find("permit:") != std::string::npos)
				Parameter.AcceptType = true;
			else 
				Parameter.AcceptType = false;

			std::string TypeString(Data, Data.find(ASCII_COLON) + 1U);
		//Add to global list.
			if (TypeString.empty())
			{
				PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
				return EXIT_FAILURE;
			}
			else if (TypeString.find(ASCII_COMMA) == std::string::npos && TypeString.find(ASCII_VERTICAL) == std::string::npos)
			{
				Result = DNSTypeNameToHex(TypeString.c_str());
				if (Result == 0)
				{
				//Number types
					Result = strtoul(TypeString.c_str(), nullptr, 0);
					if (errno != ERANGE && Result > 0 && Result <= UINT16_MAX)
					{
						Parameter.AcceptTypeList->push_back(htons((uint16_t)Result));
					}
					else {
						PrintError(LOG_ERROR_PARAMETER, L"DNS Records type error", 0, ConfigFileList[FileIndex].c_str(), Line);
						return EXIT_FAILURE;
					}
				}
				else {
					Parameter.AcceptTypeList->push_back((uint16_t)Result);
				}
			}
			else {
				std::string TypeStringTemp;
				Result = 0;
				for (size_t Index = 0;Index < TypeString.length();++Index)
				{
				//Last value
					if (Index == TypeString.length() - 1U)
					{
						TypeStringTemp.append(TypeString, Result, (SSIZE_T)Index - Result + 1U);
						Result = DNSTypeNameToHex(TypeString.c_str());
						if (Result == 0) 
						{
						//Number types
							Result = strtoul(TypeString.c_str(), nullptr, 0);
							if (errno != ERANGE && Result > 0 && Result <= UINT16_MAX)
							{
								Parameter.AcceptTypeList->push_back(htons((uint16_t)Result));
							}
							else {
								PrintError(LOG_ERROR_PARAMETER, L"DNS Records type error", 0, ConfigFileList[FileIndex].c_str(), Line);
								return EXIT_FAILURE;
							}
						}
						else {
							Parameter.AcceptTypeList->push_back((uint16_t)Result);
						}
					}
					else if (TypeString[Index] == ASCII_COMMA || TypeString[Index] == ASCII_VERTICAL)
					{
						TypeStringTemp.append(TypeString, Result, (SSIZE_T)Index - Result);
						Result = DNSTypeNameToHex(TypeString.c_str());
						if (Result == 0)
						{
						//Number types
							Result = strtoul(TypeString.c_str(), nullptr, 0);
							if (errno != ERANGE && Result > 0 && Result <= UINT16_MAX)
							{
								Parameter.AcceptTypeList->push_back(htons((uint16_t)Result));
							}
							else {
								PrintError(LOG_ERROR_PARAMETER, L"DNS Records type error", 0, ConfigFileList[FileIndex].c_str(), Line);
								return EXIT_FAILURE;
							}
						}
						else {
							Parameter.AcceptTypeList->push_back((uint16_t)Result);
						}

						TypeStringTemp.clear();
						Result = Index + 1U;
					}
				}
			}
		}
	}

//[Addresses] block
	else if (Data.find("IPv4ListenAddress=") == 0 && Data.length() > strlen("IPv4ListenAddress="))
	{
		if (ReadListenAddress(Data, strlen("IPv4ListenAddress="), AF_INET, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}
	else if (Data.find("IPv4DNSAddress=") == 0 && Data.length() > strlen("IPv4DNSAddress="))
	{
		if (ReadMultipleAddresses(Data, strlen("IPv4DNSAddress="), Parameter.DNSTarget.IPv4.AddressData.Storage, AF_INET, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}
	else if (Data.find("IPv4AlternateDNSAddress=") == 0 && Data.length() > strlen("IPv4AlternateDNSAddress="))
	{
		if (ReadMultipleAddresses(Data, strlen("IPv4AlternateDNSAddress="), Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage, AF_INET, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}
	else if (Data.find("IPv4LocalDNSAddress=") == 0 && Data.length() > strlen("IPv4LocalDNSAddress="))
	{
		if (ReadSingleAddress(Data, strlen("IPv4LocalDNSAddress="), Parameter.DNSTarget.Local_IPv4.AddressData.Storage, AF_INET, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}
	else if (Data.find("IPv4LocalAlternateDNSAddress=") == 0 && Data.length() > strlen("IPv4LocalAlternateDNSAddress="))
	{
		if (ReadSingleAddress(Data, strlen("IPv4LocalAlternateDNSAddress="), Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage, AF_INET, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}
	else if (Data.find("IPv6ListenAddress=") == 0 && Data.length() > strlen("IPv6ListenAddress="))
	{
		if (ReadListenAddress(Data, strlen("IPv6ListenAddress="), AF_INET6, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}
	else if (Data.find("IPv6DNSAddress=") == 0 && Data.length() > strlen("IPv6DNSAddress="))
	{
		if (ReadMultipleAddresses(Data, strlen("IPv6DNSAddress="), Parameter.DNSTarget.IPv6.AddressData.Storage, AF_INET6, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}
	else if (Data.find("IPv6AlternateDNSAddress=") == 0 && Data.length() > strlen("IPv6AlternateDNSAddress="))
	{
		if (ReadMultipleAddresses(Data, strlen("IPv6AlternateDNSAddress="), Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage, AF_INET6, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}
	else if (Data.find("IPv6LocalDNSAddress=") == 0 && Data.length() > strlen("IPv6LocalDNSAddress="))
	{
		if (ReadSingleAddress(Data, strlen("IPv6LocalDNSAddress="), Parameter.DNSTarget.Local_IPv6.AddressData.Storage, AF_INET6, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}
	else if (Data.find("IPv6LocalAlternateDNSAddress=") == 0 && Data.length() > strlen("IPv6LocalAlternateDNSAddress="))
	{
		if (ReadSingleAddress(Data, strlen("IPv6LocalAlternateDNSAddress="), Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage, AF_INET6, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}

//[Values] block
	else if (Data.find("EDNS0PayloadSize=") == 0 && Data.length() > strlen("EDNS0PayloadSize="))
	{
		if (Data.length() < strlen("EDNS0PayloadSize=") + 6U)
		{
			Result = strtoul(Data.c_str() + strlen("EDNS0PayloadSize="), nullptr, 0);
			if (errno != ERANGE && Result >= 0)
				Parameter.EDNS0PayloadSize = Result;
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("IPv4TTL=") == 0 && Data.length() > strlen("IPv4TTL="))
	{
		if (ReadHopLimitData(Data, strlen("IPv4TTL="), Parameter.DNSTarget.IPv4.HopLimitData.TTL, AF_INET, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}
	else if (Data.find("IPv6HopLimits=") == 0 && Data.length() > strlen("IPv6HopLimits="))
	{
		if (ReadHopLimitData(Data, strlen("IPv6HopLimits="), Parameter.DNSTarget.IPv6.HopLimitData.HopLimit, AF_INET6, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}
	else if (Data.find("IPv4AlternateTTL=") == 0 && Data.length() > strlen("IPv4AlternateTTL="))
	{
		if (ReadHopLimitData(Data, strlen("IPv4AlternateTTL="), Parameter.DNSTarget.Alternate_IPv4.HopLimitData.TTL, AF_INET, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}
	else if (Data.find("IPv6AlternateHopLimits=") == 0 && Data.length() > strlen("IPv6AlternateHopLimits="))
	{
		if (ReadHopLimitData(Data, strlen("IPv6AlternateHopLimits="), Parameter.DNSTarget.Alternate_IPv6.HopLimitData.HopLimit, AF_INET6, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}
	else if (Data.find("HopLimitsFluctuation=") == 0 && Data.length() > strlen("HopLimitsFluctuation="))
	{
		if (Data.length() < strlen("HopLimitsFluctuation=") + 4U)
		{
			Result = strtoul(Data.c_str() + strlen("HopLimitsFluctuation="), nullptr, 0);
			if (errno != ERANGE && Result > 0 && Result < UINT8_MAX)
				Parameter.HopLimitFluctuation = (uint8_t)Result;
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("ReliableSocketTimeout=") == 0 && Data.length() > strlen("ReliableSocketTimeout="))
	{
		if (Data.length() < strlen("ReliableSocketTimeout=") + 9U)
		{
			Result = strtoul(Data.c_str() + strlen("ReliableSocketTimeout="), nullptr, 0);
			if (errno != ERANGE && Result > SOCKET_MIN_TIMEOUT)
			#if defined(PLATFORM_WIN)
				Parameter.ReliableSocketTimeout = (int)Result;
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			{
				Parameter.ReliableSocketTimeout.tv_sec = Result / SECOND_TO_MILLISECOND;
				Parameter.ReliableSocketTimeout.tv_usec = Result % SECOND_TO_MILLISECOND * SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
			}
			#endif
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("UnreliableSocketTimeout=") == 0 && Data.length() > strlen("UnreliableSocketTimeout="))
	{
		if (Data.length() < strlen("UnreliableSocketTimeout=") + 9U)
		{
			Result = strtoul(Data.c_str() + strlen("UnreliableSocketTimeout="), nullptr, 0);
			if (errno != ERANGE && Result > SOCKET_MIN_TIMEOUT)
			#if defined(PLATFORM_WIN)
				Parameter.UnreliableSocketTimeout = (int)Result;
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			{
				Parameter.UnreliableSocketTimeout.tv_sec = Result / SECOND_TO_MILLISECOND;
				Parameter.UnreliableSocketTimeout.tv_usec = Result % SECOND_TO_MILLISECOND * SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
			}
			#endif
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("ICMPTest=") == 0 && Data.length() > strlen("ICMPTest="))
	{
		if (Data.length() < strlen("ICMPTest=") + 6U)
		{
			Result = strtoul(Data.c_str() + strlen("ICMPTest="), nullptr, 0);
			if (errno != ERANGE && Result >= 5)
				Parameter.ICMPSpeed = Result * SECOND_TO_MILLISECOND;
			else if (Result > 0 && Result < DEFAULT_ICMPTEST_TIME)
				Parameter.ICMPSpeed = DEFAULT_ICMPTEST_TIME * SECOND_TO_MILLISECOND;
			else 
				Parameter.ICMPSpeed = 0; //ICMP Test Disable.
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("DomainTest=") == 0 && Data.length() > strlen("DomainTest="))
	{
		if (Data.length() < strlen("DomainTest=") + 6U)
		{
			Result = strtoul(Data.c_str() + strlen("DomainTest="), nullptr, 0);
			if (errno != ERANGE && Result > 0)
				Parameter.DomainTestSpeed = Result * SECOND_TO_MILLISECOND;
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);

			return EXIT_FAILURE;
		}
	}
	else if (Data.find("AlternateTimes=") == 0 && Data.length() > strlen("AlternateTimes="))
	{
		if (Data.length() < strlen("AlternateTimes=") + 6U)
		{
			Result = strtoul(Data.c_str() + strlen("AlternateTimes="), nullptr, 0);
			if (errno != ERANGE && Result > 0)
				Parameter.AlternateTimes = Result;
			else 
				Parameter.AlternateTimes = DEFAULT_ALTERNATE_TIMES;
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("AlternateTimeRange=") == 0 && Data.length() > strlen("AlternateTimeRange="))
	{
		if (Data.length() < strlen("AlternateTimeRange=") + 6U)
		{
			Result = strtoul(Data.c_str() + strlen("AlternateTimeRange="), nullptr, 0);
			if (errno != ERANGE && Result >= DEFAULT_ALTERNATE_RANGE)
				Parameter.AlternateTimeRange = Result * SECOND_TO_MILLISECOND;
			else 
				Parameter.AlternateTimeRange = DEFAULT_ALTERNATE_RANGE * SECOND_TO_MILLISECOND;
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("AlternateResetTime=") == 0 && Data.length() > strlen("AlternateResetTime="))
	{
		if (Data.length() < strlen("AlternateResetTime=") + 6U)
		{
			Result = strtoul(Data.c_str() + strlen("AlternateResetTime="), nullptr, 0);
			if (errno != ERANGE && Result >= DEFAULT_ALTERNATERESET_TIME)
				Parameter.AlternateResetTime = Result * SECOND_TO_MILLISECOND;
			else 
				Parameter.AlternateResetTime = DEFAULT_ALTERNATERESET_TIME * SECOND_TO_MILLISECOND;
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("MultiRequestTimes=") == 0 && Data.length() > strlen("MultiRequestTimes="))
	{
		if (Data.length() < strlen("MultiRequestTimes=") + 6U)
		{
			Result = strtoul(Data.c_str() + strlen("MultiRequestTimes="), nullptr, 0);
			if (errno != ERANGE && Result > 0)
				Parameter.MultiRequestTimes = Result + 1U;
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
			return EXIT_FAILURE;
		}
	}

//[Switches] block
	else if (Data.find("DomainCaseConversion=1") == 0)
	{
		Parameter.DomainCaseConversion = true;
	}
	else if (Data.find("CompressionPointerMutation=") == 0 && Data.length() > strlen("CompressionPointerMutation="))
	{
		if (Data.find(ASCII_ONE) != std::string::npos)
			Parameter.CPMPointerToHeader = true;
		if (Data.find(ASCII_TWO) != std::string::npos)
			Parameter.CPMPointerToRR = true;
		if (Data.find(ASCII_THREE) != std::string::npos)
			Parameter.CPMPointerToAdditional = true;
		if (Parameter.CPMPointerToHeader || Parameter.CPMPointerToRR || Parameter.CPMPointerToAdditional)
			Parameter.CompressionPointerMutation = true;
	}
	else if (Data.find("EDNS0Label=1") == 0)
	{
		Parameter.EDNS0Label = true;
	}
	else if (Data.find("DNSSECRequest=1") == 0)
	{
		Parameter.DNSSECRequest = true;
	}
	else if (Data.find("AlternateMultiRequest=1") == 0)
	{
		Parameter.AlternateMultiRequest = true;
	}
	else if (Data.find("IPv4DataFilter=1") == 0)
	{
		Parameter.IPv4DataCheck = true;
	}
	else if (Data.find("TCPDataFilter=1") == 0)
	{
		Parameter.TCPDataCheck = true;
	}
	else if (Data.find("DNSDataFilter=1") == 0)
	{
		Parameter.DNSDataCheck = true;
	}
	else if (Data.find("BlacklistFilter=1") == 0)
	{
		Parameter.Blacklist = true;
	}

//[Data] block
	else if (Data.find("ICMPID=") == 0 && Data.length() > strlen("ICMPID="))
	{
		if (Data.length() < strlen("ICMPID=") + 7U)
		{
			Result = strtoul(Data.c_str() + strlen("ICMPID="), nullptr, 0);
			if (errno != ERANGE && Result > 0)
				Parameter.ICMPID = htons((uint16_t)Result);
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("ICMPSequence=") == 0 && Data.length() > strlen("ICMPSequence="))
	{
		if (Data.length() < strlen("ICMPSequence=") + 7U)
		{
			Result = strtoul(Data.c_str() + strlen("ICMPSequence="), nullptr, 0);
			if (errno != ERANGE && Result > 0)
				Parameter.ICMPSequence = htons((uint16_t)Result);
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("ICMPPaddingData=") == 0 && Data.length() > strlen("ICMPPaddingData="))
	{
		if (Data.length() > strlen("ICMPPaddingData=") + 17U && Data.length() < strlen("ICMPPaddingData=") + ICMP_PADDING_MAXSIZE - 1U)
		{
			Parameter.ICMPPaddingDataLength = Data.length() - strlen("ICMPPaddingData=") - 1U;
			memcpy_s(Parameter.ICMPPaddingData, ICMP_PADDING_MAXSIZE, Data.c_str() + strlen("ICMPPaddingData="), Data.length() - strlen("ICMPPaddingData="));
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("DomainTestID=") == 0 && Data.length() > strlen("DomainTestID="))
	{
		if (Data.length() < strlen("DomainTestID=") + 7U)
		{
			Result = strtoul(Data.c_str() + strlen("DomainTestID="), nullptr, 0);
			if (errno != ERANGE && Result > 0)
				Parameter.DomainTestID = htons((uint16_t)Result);
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("DomainTestData=") == 0 && Data.length() > strlen("DomainTestData="))
	{
		if (Data.length() > strlen("DomainTestData=") + DOMAIN_MINSIZE && Data.length() < strlen("DomainTestData=") + DOMAIN_DATA_MAXSIZE)
		{
			memcpy_s(Parameter.DomainTestData, DOMAIN_MAXSIZE, Data.c_str() + strlen("DomainTestData="), Data.length() - strlen("DomainTestData="));
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("LocalhostServerName=") == 0 && Data.length() > strlen("LocalhostServerName="))
	{
		if (Data.length() > strlen("LocalhostServerName=") + DOMAIN_MINSIZE && Data.length() < strlen("LocalhostServerName=") + DOMAIN_DATA_MAXSIZE)
		{
			std::shared_ptr<char> LocalFQDN(new char[DOMAIN_MAXSIZE]());
			memset(LocalFQDN.get(), 0, DOMAIN_MAXSIZE);
			Parameter.LocalFQDNLength = Data.length() - strlen("LocalhostServerName=");
			memcpy_s(LocalFQDN.get(), DOMAIN_MAXSIZE, Data.c_str() + strlen("LocalhostServerName="), Parameter.LocalFQDNLength);
			*Parameter.LocalFQDNString = LocalFQDN.get();
			Result = CharToDNSQuery(LocalFQDN.get(), Parameter.LocalFQDN);
			if (Result > DOMAIN_MINSIZE)
			{
				Parameter.LocalFQDNLength = Result;
			}
			else {
				Parameter.LocalFQDNLength = 0;
				memset(Parameter.LocalFQDN, 0, DOMAIN_MAXSIZE);
				Parameter.LocalFQDNString->clear();
			}
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
			return EXIT_FAILURE;
		}
	}

//[DNSCurve] block
#if defined(ENABLE_LIBSODIUM)
	else if (Data.find("DNSCurve=1") == 0)
	{
		Parameter.DNSCurve = true;
	}
	else if (Data.find("DNSCurveProtocol=TCP") == 0 || Data.find("DNSCurveProtocol=Tcp") == 0 || Data.find("DNSCurveProtocol=tcp") == 0)
	{
		DNSCurveParameter.DNSCurveMode = DNSCURVE_REQUEST_TCPMODE;
	}
	else if (Data.find("DNSCurvePayloadSize=") == 0 && Data.length() > strlen("DNSCurvePayloadSize="))
	{
		if (Data.length() > strlen("DNSCurvePayloadSize=") + 2U)
		{
			Result = strtoul(Data.c_str() + strlen("DNSCurvePayloadSize="), nullptr, 0);
			if (errno != ERANGE && Result > (SSIZE_T)(sizeof(eth_hdr) + sizeof(ipv4_hdr) + sizeof(udp_hdr) + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES))
				DNSCurveParameter.DNSCurvePayloadSize = Result;
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("Encryption=1") == 0)
	{
		DNSCurveParameter.IsEncryption = true;
	}
	else if (Data.find("EncryptionOnly=1") == 0)
	{
		DNSCurveParameter.IsEncryptionOnly = true;
	}
	else if (Data.find("KeyRecheckTime=") == 0 && Data.length() > strlen("KeyRecheckTime="))
	{
		if (Data.length() < strlen("KeyRecheckTime=") + 6U)
		{
			Result = strtoul(Data.c_str() + strlen("KeyRecheckTime="), nullptr, 0);
			if (Result >= SHORTEST_DNSCURVE_RECHECK_TIME && Result < DEFAULT_DNSCURVE_RECHECK_TIME)
				DNSCurveParameter.KeyRecheckTime = Result * SECOND_TO_MILLISECOND;
			else 
				DNSCurveParameter.KeyRecheckTime = DEFAULT_DNSCURVE_RECHECK_TIME * SECOND_TO_MILLISECOND;
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
			return EXIT_FAILURE;
		}
	}

//[DNSCurve Addresses] block
	else if (Data.find("DNSCurveIPv4DNSAddress=") == 0 && Data.length() > strlen("DNSCurveIPv4DNSAddress="))
	{
		if (ReadSingleAddress(Data, strlen("DNSCurveIPv4DNSAddress="), DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage, AF_INET, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}
	else if (Data.find("DNSCurveIPv4AlternateDNSAddress=") == 0 && Data.length() > strlen("DNSCurveIPv4AlternateDNSAddress="))
	{
		if (ReadSingleAddress(Data, strlen("DNSCurveIPv4AlternateDNSAddress="), DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage, AF_INET, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}
	else if (Data.find("DNSCurveIPv6DNSAddress=") == 0 && Data.length() > strlen("DNSCurveIPv6DNSAddress="))
	{
		if (ReadSingleAddress(Data, strlen("DNSCurveIPv6DNSAddress="), DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage, AF_INET6, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}
	else if (Data.find("DNSCurveIPv6AlternateDNSAddress=") == 0 && Data.length() > strlen("DNSCurveIPv6AlternateDNSAddress="))
	{
		if (ReadSingleAddress(Data, strlen("DNSCurveIPv6AlternateDNSAddress="), DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage, AF_INET6, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}

	else if (Data.find("DNSCurveIPv4ProviderName=") == 0 && Data.length() > strlen("DNSCurveIPv4ProviderName="))
	{
		if (ReadDNSCurveProviderName(Data, strlen("DNSCurveIPv4ProviderName="), DNSCurveParameter.DNSCurveTarget.IPv4.ProviderName, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}
	else if (Data.find("DNSCurveIPv4AlternateProviderName=") == 0 && Data.length() > strlen("DNSCurveIPv4AlternateProviderName="))
	{
		if (ReadDNSCurveProviderName(Data, strlen("DNSCurveIPv4AlternateProviderName="), DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ProviderName, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}
	else if (Data.find("DNSCurveIPv6ProviderName=") == 0 && Data.length() > strlen("DNSCurveIPv6ProviderName="))
	{
		if (ReadDNSCurveProviderName(Data, strlen("DNSCurveIPv6ProviderName="), DNSCurveParameter.DNSCurveTarget.IPv6.ProviderName, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}
	else if (Data.find("DNSCurveIPv6AlternateProviderName=") == 0 && Data.length() > strlen("DNSCurveIPv6AlternateProviderName="))
	{
		if (ReadDNSCurveProviderName(Data, strlen("DNSCurveIPv6AlternateProviderName="), DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ProviderName, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}

//[DNSCurve Keys] block
	else if (Data.find("ClientPublicKey=") == 0 && Data.length() > strlen("ClientPublicKey="))
	{
		if (ReadDNSCurveKey(Data, strlen("ClientPublicKey="), DNSCurveParameter.Client_PublicKey, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}
	else if (Data.find("ClientSecretKey=") == 0 && Data.length() > strlen("ClientSecretKey="))
	{
		if (ReadDNSCurveKey(Data, strlen("ClientSecretKey="), DNSCurveParameter.Client_SecretKey, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}
	else if (Data.find("IPv4DNSPublicKey=") == 0 && Data.length() > strlen("IPv4DNSPublicKey="))
	{
		if (ReadDNSCurveKey(Data, strlen("IPv4DNSPublicKey="), DNSCurveParameter.DNSCurveTarget.IPv4.ServerPublicKey, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}
	else if (Data.find("IPv4AlternateDNSPublicKey=") == 0 && Data.length() > strlen("IPv4AlternateDNSPublicKey="))
	{
		if (ReadDNSCurveKey(Data, strlen("IPv4AlternateDNSPublicKey="), DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ServerPublicKey, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}
	else if (Data.find("IPv6DNSPublicKey=") == 0 && Data.length() > strlen("IPv6DNSPublicKey="))
	{
		if (ReadDNSCurveKey(Data, strlen("IPv6DNSPublicKey="), DNSCurveParameter.DNSCurveTarget.IPv6.ServerPublicKey, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}
	else if (Data.find("IPv6AlternateDNSPublicKey=") == 0 && Data.length() > strlen("IPv6AlternateDNSPublicKey="))
	{
		if (ReadDNSCurveKey(Data, strlen("IPv6AlternateDNSPublicKey="), DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ServerPublicKey, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}
	else if (Data.find("IPv4DNSFingerprint=") == 0 && Data.length() > strlen("IPv4DNSFingerprint="))
	{
		if (ReadDNSCurveKey(Data, strlen("IPv4DNSFingerprint="), DNSCurveParameter.DNSCurveTarget.IPv4.ServerFingerprint, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}
	else if (Data.find("IPv4AlternateDNSFingerprint=") == 0 && Data.length() > strlen("IPv4AlternateDNSFingerprint="))
	{
		if (ReadDNSCurveKey(Data, strlen("IPv4AlternateDNSFingerprint="), DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ServerFingerprint, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}
	else if (Data.find("IPv6DNSFingerprint=") == 0 && Data.length() > strlen("IPv6DNSFingerprint="))
	{
		if (ReadDNSCurveKey(Data, strlen("IPv6DNSFingerprint="), DNSCurveParameter.DNSCurveTarget.IPv6.ServerFingerprint, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}
	else if (Data.find("IPv6AlternateDNSFingerprint=") == 0 && Data.length() > strlen("IPv6AlternateDNSFingerprint="))
	{
		if (ReadDNSCurveKey(Data, strlen("IPv6AlternateDNSFingerprint="), DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ServerFingerprint, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}

//[DNSCurve Magic Number] block
	else if (Data.find("IPv4ReceiveMagicNumber=") == 0 && Data.length() > strlen("IPv4ReceiveMagicNumber="))
	{
		if (ReadMagicNumber(Data, strlen("IPv4ReceiveMagicNumber="), DNSCurveParameter.DNSCurveTarget.IPv4.ReceiveMagicNumber, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}
	else if (Data.find("IPv4AlternateReceiveMagicNumber=") == 0 && Data.length() > strlen("IPv4AlternateReceiveMagicNumber="))
	{
		if (ReadMagicNumber(Data, strlen("IPv4AlternateReceiveMagicNumber="), DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ReceiveMagicNumber, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}
	else if (Data.find("IPv6ReceiveMagicNumber=") == 0 && Data.length() > strlen("IPv6ReceiveMagicNumber="))
	{
		if (ReadMagicNumber(Data, strlen("IPv6ReceiveMagicNumber="), DNSCurveParameter.DNSCurveTarget.IPv6.ReceiveMagicNumber, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}
	else if (Data.find("IPv6AlternateReceiveMagicNumber=") == 0 && Data.length() > strlen("IPv6AlternateReceiveMagicNumber="))
	{
		if (ReadMagicNumber(Data, strlen("IPv6AlternateReceiveMagicNumber="), DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ReceiveMagicNumber, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}
	else if (Data.find("IPv4DNSMagicNumber=") == 0 && Data.length() > strlen("IPv4DNSMagicNumber="))
	{
		if (ReadMagicNumber(Data, strlen("IPv4DNSMagicNumber="), DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}
	else if (Data.find("IPv4AlternateDNSMagicNumber=") == 0 && Data.length() > strlen("IPv4AlternateDNSMagicNumber="))
	{
		if (ReadMagicNumber(Data, strlen("IPv4AlternateDNSMagicNumber="), DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.SendMagicNumber, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}
	else if (Data.find("IPv6DNSMagicNumber=") == 0 && Data.length() > strlen("IPv6DNSMagicNumber="))
	{
		if (ReadMagicNumber(Data, strlen("IPv6DNSMagicNumber="), DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}
	else if (Data.find("IPv6AlternateDNSMagicNumber=") == 0 && Data.length() > strlen("IPv6AlternateDNSMagicNumber="))
	{
		if (ReadMagicNumber(Data, strlen("IPv6AlternateDNSMagicNumber="), DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, FileIndex, Line) == EXIT_FAILURE)
			return EXIT_FAILURE;
	}
#endif

	return EXIT_SUCCESS;
}

//Read ipfilter from file
size_t __fastcall ReadIPFilter(void)
{
//Create file list.
	for (size_t Index = 0;Index < Parameter.Path->size();++Index)
	{
		for (size_t InnerIndex = 0;InnerIndex < Parameter.IPFilterFileList->size();++InnerIndex)
		{
			FILE_DATA FileDataTemp;
			FileDataTemp.FileName.clear();
		#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			FileDataTemp.sFileName.clear();
		#endif
			FileDataTemp.ModificationTime = 0;

		//Add to global list.
			FileDataTemp.FileName.append(Parameter.Path->at(Index));
			FileDataTemp.FileName.append(Parameter.IPFilterFileList->at(InnerIndex));
		#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			FileDataTemp.sFileName.append(Parameter.sPath->at(Index));
			FileDataTemp.sFileName.append(Parameter.sIPFilterFileList->at(InnerIndex));
		#endif
			IPFilterFileList.push_back(FileDataTemp);
		}
	}

//Files Monitor
	FILE *Input = nullptr;
	size_t FileIndex = 0;
	auto IsFileModified = false;
#if defined(PLATFORM_WIN)
	std::shared_ptr<LARGE_INTEGER> File_LARGE_INTEGER(new LARGE_INTEGER());
	std::shared_ptr<WIN32_FILE_ATTRIBUTE_DATA> File_WIN32_FILE_ATTRIBUTE_DATA(new WIN32_FILE_ATTRIBUTE_DATA());
	memset(File_LARGE_INTEGER.get(), 0, sizeof(LARGE_INTEGER));
	memset(File_WIN32_FILE_ATTRIBUTE_DATA.get(), 0, sizeof(WIN32_FILE_ATTRIBUTE_DATA));
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	std::shared_ptr<struct stat> FileStat(new struct stat());
	memset(FileStat.get(), 0, sizeof(struct stat));
#endif
	std::unique_lock<std::mutex> ResultBlacklistMutex(ResultBlacklistLock);
	std::unique_lock<std::mutex> AddressRangeMutex(AddressRangeLock);
	std::unique_lock<std::mutex> LocalRoutingListMutex(LocalRoutingListLock);
	ResultBlacklistMutex.unlock();
	AddressRangeMutex.unlock();
	LocalRoutingListMutex.unlock();

	for (;;)
	{
		IsFileModified = false;

	//Check File lists.
		for (FileIndex = 0;FileIndex < IPFilterFileList.size();++FileIndex)
		{
		//Get attributes of file.
		#if defined(PLATFORM_WIN)
			if (GetFileAttributesExW(IPFilterFileList[FileIndex].FileName.c_str(), GetFileExInfoStandard, File_WIN32_FILE_ATTRIBUTE_DATA.get()) == FALSE)
			{
				memset(File_WIN32_FILE_ATTRIBUTE_DATA.get(), 0, sizeof(WIN32_FILE_ATTRIBUTE_DATA));
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			if (stat(IPFilterFileList[FileIndex].sFileName.c_str(), FileStat.get()) != 0)
			{
				memset(FileStat.get(), 0, sizeof(struct stat));
		#endif
				if (IPFilterFileList[FileIndex].ModificationTime > 0)
					IsFileModified = true;
				IPFilterFileList[FileIndex].ModificationTime = 0;

				ClearListData(READTEXT_IPFILTER, FileIndex);
			}
			else {
			//Check whole file size.
			#if defined(PLATFORM_WIN)
				File_LARGE_INTEGER->HighPart = File_WIN32_FILE_ATTRIBUTE_DATA->nFileSizeHigh;
				File_LARGE_INTEGER->LowPart = File_WIN32_FILE_ATTRIBUTE_DATA->nFileSizeLow;
				if (File_LARGE_INTEGER->QuadPart >= DEFAULT_FILE_MAXSIZE)
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				if (FileStat->st_size >= (off_t)DEFAULT_FILE_MAXSIZE)
			#endif
				{
					PrintError(LOG_ERROR_PARAMETER, L"IPFilter file size is too large", 0, IPFilterFileList[FileIndex].FileName.c_str(), 0);

				#if defined(PLATFORM_WIN)
					memset(File_WIN32_FILE_ATTRIBUTE_DATA.get(), 0, sizeof(WIN32_FILE_ATTRIBUTE_DATA));
					memset(File_LARGE_INTEGER.get(), 0, sizeof(LARGE_INTEGER));
				#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
					memset(FileStat.get(), 0, sizeof(struct stat));
				#endif
					if (IPFilterFileList[FileIndex].ModificationTime > 0)
						IsFileModified = true;
					IPFilterFileList[FileIndex].ModificationTime = 0;

					ClearListData(READTEXT_IPFILTER, FileIndex);
					continue;
				}

			//Check modification time of file.
			#if defined(PLATFORM_WIN)
				memset(File_LARGE_INTEGER.get(), 0, sizeof(LARGE_INTEGER));
				File_LARGE_INTEGER->HighPart = File_WIN32_FILE_ATTRIBUTE_DATA->ftLastWriteTime.dwHighDateTime;
				File_LARGE_INTEGER->LowPart = File_WIN32_FILE_ATTRIBUTE_DATA->ftLastWriteTime.dwLowDateTime;
				if (IPFilterFileList[FileIndex].ModificationTime == 0 || File_LARGE_INTEGER->QuadPart != IPFilterFileList[FileIndex].ModificationTime)
				{
					IPFilterFileList[FileIndex].ModificationTime = File_LARGE_INTEGER->QuadPart;
					memset(File_WIN32_FILE_ATTRIBUTE_DATA.get(), 0, sizeof(WIN32_FILE_ATTRIBUTE_DATA));
					memset(File_LARGE_INTEGER.get(), 0, sizeof(LARGE_INTEGER));
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				if (IPFilterFileList[FileIndex].ModificationTime == 0 || FileStat->st_mtime != IPFilterFileList[FileIndex].ModificationTime)
				{
					IPFilterFileList[FileIndex].ModificationTime = FileStat->st_mtime;
					memset(FileStat.get(), 0, sizeof(struct stat));
			#endif
					ClearListData(READTEXT_IPFILTER, FileIndex);
					IsFileModified = true;

				//Read file.
				#if defined(PLATFORM_WIN)
					if (_wfopen_s(&Input, IPFilterFileList[FileIndex].FileName.c_str(), L"rb") == 0)
					{
				#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
					Input = fopen(IPFilterFileList[FileIndex].sFileName.c_str(), "rb");
				#endif
						if (Input == nullptr)
						{
							continue;
						}
						else {
						//Scan global list.
							for (auto IPFilterFileSetIter = IPFilterFileSetModificating->begin();IPFilterFileSetIter != IPFilterFileSetModificating->end();++IPFilterFileSetIter)
							{
								if (IPFilterFileSetIter->FileIndex == FileIndex)
								{
									break;
								}
								else if (IPFilterFileSetIter + 1U == IPFilterFileSetModificating->end())
								{
									DIFFERNET_IPFILTER_FILE_SET IPFilterFileSetTemp;
									IPFilterFileSetTemp.FileIndex = FileIndex;
									IPFilterFileSetModificating->push_back(IPFilterFileSetTemp);
									break;
								}
							}
							if (IPFilterFileSetModificating->empty())
							{
								DIFFERNET_IPFILTER_FILE_SET IPFilterFileSetTemp;
								IPFilterFileSetTemp.FileIndex = FileIndex;
								IPFilterFileSetModificating->push_back(IPFilterFileSetTemp);
							}

						//Read data.
							ReadText(Input, READTEXT_IPFILTER, FileIndex);
							fclose(Input);
							Input = nullptr;
						}
				#if defined(PLATFORM_WIN)
					}
				#endif
				}
				else {
				#if defined(PLATFORM_WIN)
					memset(File_WIN32_FILE_ATTRIBUTE_DATA.get(), 0, sizeof(WIN32_FILE_ATTRIBUTE_DATA));
					memset(File_LARGE_INTEGER.get(), 0, sizeof(LARGE_INTEGER));
				#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
					memset(FileStat.get(), 0, sizeof(struct stat));
				#endif
				}
			}
		}

	//Update global lists.
		if (!IsFileModified)
		{
			Sleep(Parameter.FileRefreshTime);
			continue;
		}

	//Copy to using list.
		ResultBlacklistMutex.lock();
		AddressRangeMutex.lock();
		LocalRoutingListMutex.lock();
		*IPFilterFileSetUsing = *IPFilterFileSetModificating;
		IPFilterFileSetUsing->shrink_to_fit();
		ResultBlacklistMutex.unlock();
		AddressRangeMutex.unlock();
		LocalRoutingListMutex.unlock();
		IPFilterFileSetModificating->shrink_to_fit();

	//Flush DNS cache and Auto-refresh
		FlushSystemDNSCache();
		Sleep(Parameter.FileRefreshTime);
	}

	PrintError(LOG_ERROR_SYSTEM, L"Read IPFilter module Monitor terminated", 0, nullptr, 0);
	return EXIT_SUCCESS;
}

//Read ipfilter data from files
size_t __fastcall ReadIPFilterData(const char *Buffer, const size_t FileIndex, const size_t Line, size_t &LabelType, bool &IsLabelComments)
{
	std::string Data(Buffer);

//Multi-line comments check, delete spaces, horizontal tab/HT, check comments(Number Sign/NS and double slashs) and check minimum length of ipfilter items.
	if (ReadMultiLineComments(Buffer, Data, IsLabelComments) == EXIT_FAILURE || Data.find(ASCII_HASHTAG) == 0 || Data.find(ASCII_SLASH) == 0)
		return EXIT_SUCCESS;

//[Base] block
	if (Data.find("[Base]") == 0 || Data.find("[base]") == 0 || 
		Data.find("Version = ") == 0 || Data.find("version = ") == 0 || 
		Data.find("Default TTL = ") == 0 || Data.find("default ttl = ") == 0)
			return EXIT_SUCCESS;

//[Local Routing] block(A part)
	if (LabelType == 0 && (Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family > 0 || Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family > 0) && 
	#if defined(PLATFORM_WIN) //Case-insensitive on Windows
		(IPFilterFileList[FileIndex].FileName.rfind(L"chnrouting.txt") != std::wstring::npos && IPFilterFileList[FileIndex].FileName.length() > wcslen(L"chnrouting.txt") && 
		IPFilterFileList[FileIndex].FileName.rfind(L"chnrouting.txt") == IPFilterFileList[FileIndex].FileName.length() - wcslen(L"chnrouting.txt") || 
		IPFilterFileList[FileIndex].FileName.rfind(L"chnroute.txt") != std::wstring::npos && IPFilterFileList[FileIndex].FileName.length() > wcslen(L"chnroute.txt") && 
		IPFilterFileList[FileIndex].FileName.rfind(L"chnroute.txt") == IPFilterFileList[FileIndex].FileName.length() - wcslen(L"chnroute.txt")))
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		(IPFilterFileList[FileIndex].FileName.rfind(L"chnrouting.txt") != std::wstring::npos && IPFilterFileList[FileIndex].FileName.length() > wcslen(L"chnrouting.txt") && 
		IPFilterFileList[FileIndex].FileName.rfind(L"chnrouting.txt") == IPFilterFileList[FileIndex].FileName.length() - wcslen(L"chnrouting.txt") || 
		IPFilterFileList[FileIndex].FileName.rfind(L"chnroute.txt") != std::wstring::npos && IPFilterFileList[FileIndex].FileName.length() > wcslen(L"chnroute.txt") && 
		IPFilterFileList[FileIndex].FileName.rfind(L"chnroute.txt") == IPFilterFileList[FileIndex].FileName.length() - wcslen(L"chnroute.txt")))
	#endif
			LabelType = LABEL_IPFILTER_LOCAL_ROUTING;

//[IPFilter] block
	if (Data.find("[IPFilter]") == 0 || Data.find("[IPfilter]") == 0 || Data.find("[ipfilter]") == 0)
	{
		LabelType = LABEL_IPFILTER;
		return EXIT_SUCCESS;
	}

//[Blacklist] block(A part)
	else if (Data.find("[BlackList]") == 0 || Data.find("[Blacklist]") == 0 || Data.find("[blacklist]") == 0)
	{
		LabelType = LABEL_IPFILTER_BLACKLIST;
		return EXIT_SUCCESS;
	}

//[Local Routing] block(B part)
	else if (Data.find("[Local Routing]") == 0 || Data.find("[Local routing]") == 0 || Data.find("[local routing]") == 0)
	{
		LabelType = LABEL_IPFILTER_LOCAL_ROUTING;
		return EXIT_SUCCESS;
	}

//Temporary stop read.
	else if (Data.find("[Stop]") == 0 || Data.find("[stop]") == 0)
	{
		LabelType = LABEL_STOP;
		return EXIT_SUCCESS;
	}
	if (LabelType == LABEL_STOP)
		return EXIT_SUCCESS;

//[Blacklist] block(B part)
	if (LabelType == LABEL_IPFILTER && Data.find(ASCII_MINUS) == std::string::npos)
	{
		PrintError(LOG_ERROR_IPFILTER, L"Data format error", 0, IPFilterFileList[FileIndex].FileName.c_str(), Line);
		return EXIT_FAILURE;
	}

//Multi-line comments check, delete comments(Number Sign/NS and double slashs) and check minimum length.
	else if (Data.rfind(" //") != std::string::npos)
	{
		Data.erase(Data.rfind(" //"), Data.length() - Data.rfind(" //"));
	}
	else if (Data.rfind("	//") != std::string::npos)
	{
		Data.erase(Data.rfind("	//"), Data.length() - Data.rfind("	//"));
	}
	else if (Data.rfind(" #") != std::string::npos)
	{
		Data.erase(Data.rfind(" #"), Data.length() - Data.rfind(" #"));
	}
	else if (Data.rfind("	#") != std::string::npos)
	{
		Data.erase(Data.rfind("	#"), Data.length() - Data.rfind("	#"));
	}

//Convert horizontal tab/HT to space and delete spaces before or after data.
	for (auto &StringIter:Data)
	{
		if (StringIter == ASCII_HT)
			StringIter = ASCII_SPACE;
	}
	while (!Data.empty() && Data[0] == ASCII_SPACE)
		Data.erase(0, 1U);
	while (!Data.empty() && Data.back() == ASCII_SPACE)
		Data.pop_back();
	while (!Data.empty() && Data.find("  ") != std::string::npos)
		Data.erase(Data.find("  "), 1U);

//Blacklist items
	if (Parameter.Blacklist && LabelType == LABEL_IPFILTER_BLACKLIST)
	{
	//Delete spaces before or after verticals.
		while (Data.find(" |") != std::string::npos || Data.find("| ") != std::string::npos)
		{
			if (Data.find(" |") != std::string::npos)
				Data.erase(Data.find(" |"), 1U);
			if (Data.find("| ") != std::string::npos)
				Data.erase(Data.find("| ") + 1U, 1U);
		}

		return ReadBlacklistData(Data, FileIndex, Line);
	}
//Local Routing items
	else if (Parameter.LocalRouting && LabelType == LABEL_IPFILTER_LOCAL_ROUTING)
	{
		while (Data.find(ASCII_SPACE) != std::string::npos)
			Data.erase(Data.find(ASCII_SPACE), 1U);
		if (Data.length() >= READ_IPFILTER_LOCAL_ROUTING_MINSIZE)
			return ReadLocalRoutingData(Data, FileIndex, Line);
	}
//Main IPFilter items
	else if (Parameter.OperationMode == LISTEN_CUSTOMMODE && LabelType == LABEL_IPFILTER)
	{
		while (Data.find(ASCII_SPACE) != std::string::npos)
			Data.erase(Data.find(ASCII_SPACE), 1U);
		if (Data.length() >= READ_IPFILTER_MINSIZE)
			return ReadMainIPFilterData(Data, FileIndex, Line);
	}

	return EXIT_SUCCESS;
}

//Read Blacklist items in IPFilter file from data
size_t __fastcall ReadBlacklistData(std::string Data, const size_t FileIndex, const size_t Line)
{
//Mark separated location.
	size_t Separated = 0;
	if (Data.find(ASCII_COMMA) != std::string::npos)
	{
	//Delete spaces before or after commas.
		while (Data.find(" ,") != std::string::npos)
			Data.erase(Data.find(" ,"), 1U);
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
		PrintError(LOG_ERROR_IPFILTER, L"Data format error", 0, IPFilterFileList[FileIndex].FileName.c_str(), Line);
		return EXIT_FAILURE;
	}

//Delete all spaces.
	while (Data.find(ASCII_SPACE) != std::string::npos)
		Data.erase(Data.find(ASCII_SPACE), 1U);

//String length check.
	if (Data.length() < READ_IPFILTER_BLACKLIST_MINSIZE || 
		Data.find(ASCII_MINUS) != std::string::npos && Data.find(ASCII_VERTICAL) != std::string::npos && 
		Data.find(ASCII_MINUS) < Separated && Data.find(ASCII_VERTICAL) < Separated && Data.find(ASCII_MINUS) < Data.find(ASCII_VERTICAL))
	{
		PrintError(LOG_ERROR_IPFILTER, L"Data format error", 0, IPFilterFileList[FileIndex].FileName.c_str(), Line);
		return EXIT_FAILURE;
	}

//Initialization
	ADDRESS_RANGE_TABLE AddressRangeTableTemp;
	RESULT_BLACKLIST_TABLE ResultBlacklistTableTemp;
	std::shared_ptr<char> Addr(new char[ADDR_STRING_MAXSIZE]());
	memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
	size_t Index = 0;
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
				PrintError(LOG_ERROR_IPFILTER, L"IPv6 address format error", 0, IPFilterFileList[FileIndex].FileName.c_str(), Line);
				return EXIT_FAILURE;
			}
			else if (Data[0] < ASCII_ZERO || Data[0] > ASCII_COLON && Data[0] < ASCII_UPPERCASE_A || Data[0] > ASCII_UPPERCASE_F && Data[0] < ASCII_LOWERCASE_A || Data[0] > ASCII_LOWERCASE_F)
			{
				return EXIT_FAILURE;
			}

		//Address range format
			if (Data.find(ASCII_MINUS) != std::string::npos && Data.find(ASCII_MINUS) < Separated)
			{
			//Convert address(Begin).
				memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, Data.c_str(), Data.find(ASCII_MINUS));
				if (AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN6)&AddressRangeTableTemp.Begin)->sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_IPFILTER, L"IPv6 address format error", Result, IPFilterFileList[FileIndex].FileName.c_str(), Line);
					return EXIT_FAILURE;
				}
				AddressRangeTableTemp.Begin.ss_family = AF_INET6;

			//Convert address(End).
				memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
				memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, Data.c_str() + Data.find(ASCII_MINUS) + 1U, Separated - Data.find(ASCII_MINUS) - 1U);
				if (AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN6)&AddressRangeTableTemp.End)->sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_IPFILTER, L"IPv6 address format error", Result, IPFilterFileList[FileIndex].FileName.c_str(), Line);
					return EXIT_FAILURE;
				}
				AddressRangeTableTemp.End.ss_family = AF_INET6;

			//Check address range.
				if (CompareAddresses(&((PSOCKADDR_IN6)&AddressRangeTableTemp.Begin)->sin6_addr, &((PSOCKADDR_IN6)&AddressRangeTableTemp.End)->sin6_addr, AF_INET6) > ADDRESS_COMPARE_EQUAL)
				{
					PrintError(LOG_ERROR_IPFILTER, L"IPv6 address range error", WSAGetLastError(), IPFilterFileList[FileIndex].FileName.c_str(), Line);
					return EXIT_FAILURE;
				}
			}
		//Normal format
			else {
			//Convert address.
				memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, Data.c_str(), Separated);
				if (AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN6)&AddressRangeTableTemp.Begin)->sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_IPFILTER, L"IPv6 address format error", Result, IPFilterFileList[FileIndex].FileName.c_str(), Line);
					return EXIT_FAILURE;
				}

			//Check repeating items.
				if (CheckSpecialAddress(&((PSOCKADDR_IN6)&AddressRangeTableTemp.Begin)->sin6_addr, AF_INET6, nullptr))
				{
					PrintError(LOG_ERROR_IPFILTER, L"Repeating items error, this item is not available", 0, IPFilterFileList[FileIndex].FileName.c_str(), Line);
					return EXIT_FAILURE;
				}

				AddressRangeTableTemp.Begin.ss_family = AF_INET6;
				AddressRangeTableTemp.End.ss_family = AF_INET6;
				((PSOCKADDR_IN6)&AddressRangeTableTemp.End)->sin6_addr = ((PSOCKADDR_IN6)&AddressRangeTableTemp.Begin)->sin6_addr;
			}

			ResultBlacklistTableTemp.Addresses.push_back(AddressRangeTableTemp);
		}
	//A records(IPv4)
		else {
		//IPv4 address check
			if (Separated > ADDR_STRING_MAXSIZE)
			{
				PrintError(LOG_ERROR_IPFILTER, L"IPv4 address format error", 0, IPFilterFileList[FileIndex].FileName.c_str(), Line);
				return EXIT_FAILURE;
			}
			else if (Data[0] < ASCII_ZERO || Data[0] > ASCII_NINE)
			{
				return EXIT_FAILURE;
			}

		//Address range format
			if (Data.find(ASCII_MINUS) != std::string::npos && Data.find(ASCII_MINUS) < Separated)
			{
			//Convert address(Begin).
				memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, Data.c_str(), Data.find(ASCII_MINUS));
				if (AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN)&AddressRangeTableTemp.Begin)->sin_addr, AF_INET, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_IPFILTER, L"IPv4 address format error", Result, IPFilterFileList[FileIndex].FileName.c_str(), Line);
					return EXIT_FAILURE;
				}
				AddressRangeTableTemp.Begin.ss_family = AF_INET;

			//Convert address(End).
				memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
				memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, Data.c_str() + Data.find(ASCII_MINUS) + 1U, Separated - Data.find(ASCII_MINUS) - 1U);
				if (AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN)&AddressRangeTableTemp.End)->sin_addr, AF_INET, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_IPFILTER, L"IPv4 address format error", Result, IPFilterFileList[FileIndex].FileName.c_str(), Line);
					return EXIT_FAILURE;
				}
				AddressRangeTableTemp.End.ss_family = AF_INET;

			//Check address range.
				if (CompareAddresses(&((PSOCKADDR_IN)&AddressRangeTableTemp.Begin)->sin_addr, &((PSOCKADDR_IN)&AddressRangeTableTemp.End)->sin_addr, AF_INET) > ADDRESS_COMPARE_EQUAL)
				{
					PrintError(LOG_ERROR_IPFILTER, L"IPv4 address range error", WSAGetLastError(), IPFilterFileList[FileIndex].FileName.c_str(), Line);
					return EXIT_FAILURE;
				}
			}
		//Normal format
			else {
			//Convert address.
				memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, Data.c_str(), Separated);
				if (AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN)&AddressRangeTableTemp.Begin)->sin_addr, AF_INET, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_IPFILTER, L"IPv4 address format error", Result, IPFilterFileList[FileIndex].FileName.c_str(), Line);
					return EXIT_FAILURE;
				}

			//Check repeating items.
				if (CheckSpecialAddress(&((PSOCKADDR_IN)&AddressRangeTableTemp.Begin)->sin_addr, AF_INET, nullptr))
				{
					PrintError(LOG_ERROR_IPFILTER, L"Repeating items error, this item is not available", 0, IPFilterFileList[FileIndex].FileName.c_str(), Line);
					return EXIT_FAILURE;
				}

				AddressRangeTableTemp.Begin.ss_family = AF_INET;
				AddressRangeTableTemp.End.ss_family = AF_INET;
				((PSOCKADDR_IN)&AddressRangeTableTemp.End)->sin_addr = ((PSOCKADDR_IN)&AddressRangeTableTemp.Begin)->sin_addr;
			}

			ResultBlacklistTableTemp.Addresses.push_back(AddressRangeTableTemp);
		}
	}
//Multiple addresses
	else {
		size_t VerticalIndex = 0;

	//AAAA records(IPv6)
		if (Data.find(ASCII_COLON) < Separated)
		{
		//IPv6 addresses check
			if (Data[0] < ASCII_ZERO || Data[0] > ASCII_COLON && Data[0] < ASCII_UPPERCASE_A || Data[0] > ASCII_UPPERCASE_F && Data[0] < ASCII_LOWERCASE_A || Data[0] > ASCII_LOWERCASE_F)
				return EXIT_FAILURE;

			for (Index = 0;Index <= Separated;++Index)
			{
			//Read data.
				if (Data[Index] == ASCII_VERTICAL || Index == Separated)
				{
				//Length check
					if (Index - VerticalIndex > ADDR_STRING_MAXSIZE)
					{
						PrintError(LOG_ERROR_IPFILTER, L"IPv6 address format error", 0, IPFilterFileList[FileIndex].FileName.c_str(), Line);
						return EXIT_FAILURE;
					}

				//Convert addresses.
					memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
					memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, Data.c_str() + VerticalIndex, Index - VerticalIndex);
					if (AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN6)&AddressRangeTableTemp.Begin)->sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
					{
						PrintError(LOG_ERROR_IPFILTER, L"IPv6 address format error", Result, IPFilterFileList[FileIndex].FileName.c_str(), Line);
						return EXIT_FAILURE;
					}

				//Check repeating items.
					if (CheckSpecialAddress(&((PSOCKADDR_IN6)&AddressRangeTableTemp.Begin)->sin6_addr, AF_INET6, nullptr))
					{
						PrintError(LOG_ERROR_IPFILTER, L"Repeating items error, this item is not available", 0, IPFilterFileList[FileIndex].FileName.c_str(), Line);
						return EXIT_FAILURE;
					}

					AddressRangeTableTemp.Begin.ss_family = AF_INET6;
					AddressRangeTableTemp.End.ss_family = AF_INET6;
					((PSOCKADDR_IN6)&AddressRangeTableTemp.End)->sin6_addr = ((PSOCKADDR_IN6)&AddressRangeTableTemp.Begin)->sin6_addr;
					ResultBlacklistTableTemp.Addresses.push_back(AddressRangeTableTemp);
					memset(&AddressRangeTableTemp, 0, sizeof(ADDRESS_RANGE_TABLE));
					VerticalIndex = Index + 1U;
				}
			}
		}
	//A records(IPv4)
		else {
		//IPv4 addresses check
			if (Data[0] < ASCII_ZERO || Data[0] > ASCII_NINE)
				return EXIT_FAILURE;

			for (Index = 0;Index <= Separated;++Index)
			{
			//Read data.
				if (Data[Index] == ASCII_VERTICAL || Index == Separated)
				{
				//Length check
					if (Index - VerticalIndex > ADDR_STRING_MAXSIZE)
					{
						PrintError(LOG_ERROR_IPFILTER, L"IPv4 address format error", 0, IPFilterFileList[FileIndex].FileName.c_str(), Line);
						return EXIT_FAILURE;
					}

				//Convert addresses.
					memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
					memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, Data.c_str() + VerticalIndex, Index - VerticalIndex);
					if (AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN)&AddressRangeTableTemp.Begin)->sin_addr, AF_INET, Result) == EXIT_FAILURE)
					{
						PrintError(LOG_ERROR_IPFILTER, L"IPv4 address format error", Result, IPFilterFileList[FileIndex].FileName.c_str(), Line);
						return EXIT_FAILURE;
					}

				//Check repeating items.
					if (CheckSpecialAddress(&((PSOCKADDR_IN)&AddressRangeTableTemp.Begin)->sin_addr, AF_INET, nullptr))
					{
						PrintError(LOG_ERROR_IPFILTER, L"Repeating items error, this item is not available", 0, IPFilterFileList[FileIndex].FileName.c_str(), Line);
						return EXIT_FAILURE;
					}

					AddressRangeTableTemp.Begin.ss_family = AF_INET;
					AddressRangeTableTemp.End.ss_family = AF_INET;
					((PSOCKADDR_IN)&AddressRangeTableTemp.End)->sin_addr = ((PSOCKADDR_IN)&AddressRangeTableTemp.Begin)->sin_addr;
					ResultBlacklistTableTemp.Addresses.push_back(AddressRangeTableTemp);
					memset(&AddressRangeTableTemp, 0, sizeof(ADDRESS_RANGE_TABLE));
					VerticalIndex = Index + 1U;
				}
			}
		}
	}

	Addr.reset();

//Mark patterns.
	ResultBlacklistTableTemp.PatternString.append(Data, Separated, Data.length() - Separated);

//Block those IP addresses from all requesting.
	if (ResultBlacklistTableTemp.PatternString == ("ALL") || ResultBlacklistTableTemp.PatternString == ("All") || ResultBlacklistTableTemp.PatternString == ("all"))
	{
		ResultBlacklistTableTemp.PatternString.clear();
		ResultBlacklistTableTemp.PatternString.shrink_to_fit();
	}
	else { //Other requesting
		try {
			std::regex PatternTemp(ResultBlacklistTableTemp.PatternString);
			ResultBlacklistTableTemp.Pattern.swap(PatternTemp);
		}
		catch (std::regex_error& Error)
		{
			PrintError(LOG_ERROR_IPFILTER, L"Regular expression pattern error", Error.code(), IPFilterFileList[FileIndex].FileName.c_str(), Line);
			return EXIT_FAILURE;
		}
	}

//Add to global ResultBlacklistTable.
	for (auto &IPFilterFileSetIter:*IPFilterFileSetModificating)
	{
		if (IPFilterFileSetIter.FileIndex == FileIndex)
		{
			IPFilterFileSetIter.ResultBlacklist.push_back(ResultBlacklistTableTemp);
			break;
		}
	}

	return EXIT_SUCCESS;
}

//Read Local Routing items in IPFilter file from data
size_t __fastcall ReadLocalRoutingData(std::string Data, const size_t FileIndex, const size_t Line)
{
//Check format of items.
	if (Data.find("/") == std::string::npos || Data.rfind("/") < 3U || Data.rfind("/") == Data.length() - 1U)
	{
		PrintError(LOG_ERROR_PARAMETER, L"Routing address block format error", 0, IPFilterFileList[FileIndex].FileName.c_str(), Line);
		return EXIT_FAILURE;
	}
	for (auto StringIter:Data)
	{
		if (StringIter < ASCII_PERIOD || StringIter > ASCII_COLON && 
			StringIter < ASCII_UPPERCASE_A || StringIter > ASCII_UPPERCASE_F && StringIter < ASCII_LOWERCASE_A || StringIter > ASCII_LOWERCASE_F)
		{
			PrintError(LOG_ERROR_PARAMETER, L"Routing address block format error", 0, IPFilterFileList[FileIndex].FileName.c_str(), Line);
			return EXIT_FAILURE;
		}
	}

//Initialization
	std::shared_ptr<char> Addr(new char[ADDR_STRING_MAXSIZE]());
	memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
	memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, Data.c_str(), Data.find("/"));
	SSIZE_T Result = 0;

//IPv6
	if (Data.find(":") != std::string::npos) 
	{
		AddressRoutingTable_IPv6 AddressRoutingTableTemp;
		std::shared_ptr<in6_addr> BinaryAddr(new in6_addr());
		memset(BinaryAddr.get(), 0, sizeof(in6_addr));
		Data.erase(0, Data.find("/") + 1U);

	//Convert address.
		if (AddressStringToBinary(Addr.get(), BinaryAddr.get(), AF_INET6, Result) == EXIT_FAILURE)
		{
			PrintError(LOG_ERROR_IPFILTER, L"IPv6 address format error", Result, IPFilterFileList[FileIndex].FileName.c_str(), Line);
			return EXIT_FAILURE;
		}

	//Mark network prefix.
		Result = strtoul(Data.c_str(), nullptr, 0);
		if (Result <= 0 || Result > (SSIZE_T)(sizeof(in6_addr) * BYTES_TO_BITS))
		{
			PrintError(LOG_ERROR_IPFILTER, L"IPv6 Prefix error", 0, IPFilterFileList[FileIndex].FileName.c_str(), Line);
			return EXIT_FAILURE;
		}
		else {
			AddressRoutingTableTemp.Prefix = (size_t)Result;
		}

	//Add to global LocalRoutingList(IPv6).
		uint64_t *AddrFront = (uint64_t *)BinaryAddr.get(), *AddrBack = (uint64_t *)((PUCHAR)BinaryAddr.get() + 8U);
		for (auto &IPFilterFileSetIter:*IPFilterFileSetModificating)
		{
			if (IPFilterFileSetIter.FileIndex == FileIndex)
			{
				if (IPFilterFileSetIter.LocalRoutingList_IPv6.empty())
				{
					goto AddToGlobalList_IPv6;
				}
				for (auto LocalRoutingTableIter = IPFilterFileSetIter.LocalRoutingList_IPv6.begin();LocalRoutingTableIter != IPFilterFileSetIter.LocalRoutingList_IPv6.end();++LocalRoutingTableIter)
				{
					if (LocalRoutingTableIter->Prefix == AddressRoutingTableTemp.Prefix)
					{
						auto AddressRoutingListIter = LocalRoutingTableIter->AddressRoutingList_IPv6.find(hton64(*AddrFront) & (UINT64_MAX << (sizeof(in6_addr) * BYTES_TO_BITS / 2U - AddressRoutingTableTemp.Prefix)));
						if (AddressRoutingListIter != LocalRoutingTableIter->AddressRoutingList_IPv6.end())
						{
							if (!AddressRoutingListIter->second.count(hton64(*AddrBack) & (UINT64_MAX << (sizeof(in6_addr) * BYTES_TO_BITS - AddressRoutingTableTemp.Prefix))))
								AddressRoutingListIter->second.insert(hton64(*AddrBack) & (UINT64_MAX << (sizeof(in6_addr) * BYTES_TO_BITS - AddressRoutingTableTemp.Prefix)));
						}
						else {
							std::set<uint64_t> AddrBackSet;
							if (AddressRoutingTableTemp.Prefix < sizeof(in6_addr) * BYTES_TO_BITS / 2U)
							{
								AddrBackSet.insert(0);
								LocalRoutingTableIter->AddressRoutingList_IPv6.insert(std::pair<uint64_t, std::set<uint64_t>>(hton64(*AddrFront) & (UINT64_MAX << (sizeof(in6_addr) * BYTES_TO_BITS / 2U - AddressRoutingTableTemp.Prefix)), AddrBackSet));
							}
							else {
								AddrBackSet.insert(hton64(*AddrBack) & (UINT64_MAX << (sizeof(in6_addr) * BYTES_TO_BITS - AddressRoutingTableTemp.Prefix)));
								LocalRoutingTableIter->AddressRoutingList_IPv6.insert(std::pair<uint64_t, std::set<uint64_t>>(hton64(*AddrFront), AddrBackSet));
							}
						}

						return EXIT_SUCCESS;
					}
				}

			//Add new item to global list.
				AddToGlobalList_IPv6: 
				std::set<uint64_t> AddrBackSet;
				if (AddressRoutingTableTemp.Prefix < sizeof(in6_addr) * BYTES_TO_BITS / 2U)
				{
					AddrBackSet.insert(0);
					AddressRoutingTableTemp.AddressRoutingList_IPv6.insert(std::pair<uint64_t, std::set<uint64_t>>(hton64(*AddrFront) & (UINT64_MAX << (sizeof(in6_addr) * BYTES_TO_BITS / 2U - AddressRoutingTableTemp.Prefix)), AddrBackSet));
				}
				else {
					AddrBackSet.insert(hton64(*AddrBack) & (UINT64_MAX << (sizeof(in6_addr) * BYTES_TO_BITS - AddressRoutingTableTemp.Prefix)));
					AddressRoutingTableTemp.AddressRoutingList_IPv6.insert(std::pair<uint64_t, std::set<uint64_t>>(hton64(*AddrFront), AddrBackSet));
				}

				IPFilterFileSetIter.LocalRoutingList_IPv6.push_back(AddressRoutingTableTemp);
			}
		}
	}
//IPv4
	else {
		AddressRoutingTable_IPv4 AddressRoutingTableTemp;
		std::shared_ptr<in_addr> BinaryAddr(new in_addr());
		memset(BinaryAddr.get(), 0, sizeof(in_addr));
		Data.erase(0, Data.find("/") + 1U);

	//Convert address.
		if (AddressStringToBinary(Addr.get(), BinaryAddr.get(), AF_INET, Result) == EXIT_FAILURE)
		{
			PrintError(LOG_ERROR_IPFILTER, L"IPv4 address format error", Result, IPFilterFileList[FileIndex].FileName.c_str(), Line);
			return EXIT_FAILURE;
		}

	//Mark network prefix.
		Result = strtoul(Data.c_str(), nullptr, 0);
		if (errno == ERANGE || Result <= 0 || Result > (SSIZE_T)(sizeof(in_addr) * BYTES_TO_BITS))
		{
			PrintError(LOG_ERROR_IPFILTER, L"IPv4 Prefix error", 0, IPFilterFileList[FileIndex].FileName.c_str(), Line);
			return EXIT_FAILURE;
		}
		else {
			AddressRoutingTableTemp.Prefix = (size_t)Result;
		}

	//Add to global LocalRoutingTable(IPv4).
		for (auto &IPFilterFileSetIter:*IPFilterFileSetModificating)
		{
			if (IPFilterFileSetIter.FileIndex == FileIndex)
			{
				if (IPFilterFileSetIter.LocalRoutingList_IPv4.empty())
				{
					goto AddToGlobalList_IPv4;
				}
				for (auto LocalRoutingTableIter = IPFilterFileSetIter.LocalRoutingList_IPv4.begin();LocalRoutingTableIter != IPFilterFileSetIter.LocalRoutingList_IPv4.end();++LocalRoutingTableIter)
				{
					if (LocalRoutingTableIter->Prefix == AddressRoutingTableTemp.Prefix)
					{
						if (!LocalRoutingTableIter->AddressRoutingList_IPv4.count(htonl(BinaryAddr->s_addr)))
							LocalRoutingTableIter->AddressRoutingList_IPv4.insert(htonl(BinaryAddr->s_addr));

						return EXIT_SUCCESS;
					}
				}

			//Add new item to global list.
				AddToGlobalList_IPv4: 
				AddressRoutingTableTemp.AddressRoutingList_IPv4.insert(htonl(BinaryAddr->s_addr));
				IPFilterFileSetIter.LocalRoutingList_IPv4.push_back(AddressRoutingTableTemp);
			}
		}
	}

	return EXIT_SUCCESS;
}

//Read Main IPFilter items in IPFilter file from data
size_t __fastcall ReadMainIPFilterData(std::string Data, const size_t FileIndex, const size_t Line)
{
//Initialization
	ADDRESS_RANGE_TABLE AddressRangeTableTemp;
	SSIZE_T Result = 0;
	size_t Index = 0;

//Check format of items.
	if (Data.find(ASCII_COMMA) != std::string::npos && Data.find(ASCII_COMMA) > Data.find(ASCII_MINUS)) //IPFilter.dat
	{
	//IPv4 spacial delete
		if (Data.find(ASCII_PERIOD) != std::string::npos)
		{
		//Delete all zeros before data.
			for (Index = 0;Index < Data.find(ASCII_MINUS);++Index)
			{
				if (Data[Index] == ASCII_ZERO)
				{
					Data.erase(Index, 1U);
					--Index;
				}
				else {
					break;
				}
			}

		//Delete all zeros before minus or after commas in addresses range.
			while (Data.find(".0") != std::string::npos)
				Data.replace(Data.find(".0"), strlen(".0"), ("."));
			while (Data.find("-0") != std::string::npos)
				Data.replace(Data.find("-0"), strlen("-0"), ("-"));
			while (Data.find("..") != std::string::npos)
				Data.replace(Data.find(".."), strlen(".."), (".0."));
			if (Data.find(".-") != std::string::npos)
				Data.replace(Data.find(".-"), strlen(".-"), (".0-"));
			if (Data.find("-.") != std::string::npos)
				Data.replace(Data.find("-."), strlen("-."), ("-0."));
			if (Data[0] == ASCII_PERIOD)
				Data.replace(0, 1U, ("0."));
		}

	//Delete all zeros before minus or after commas in ipfilter level.
		while (Data.find(",000,") != std::string::npos)
			Data.replace(Data.find(",000,"), strlen(",000,"), (",0,"));
		while (Data.find(",00,") != std::string::npos)
			Data.replace(Data.find(",00,"), strlen(",00,"), (",0,"));
		while (Data.find(",00") != std::string::npos)
			Data.replace(Data.find(",00"), strlen(",00"), (","));
		if (Data.find(",0") != std::string::npos && Data[Data.find(",0") + 2U] != ASCII_COMMA)
			Data.replace(Data.find(",0"), strlen(",0"), (","));

	//Mark ipfilter level.
		std::shared_ptr<char> Level(new char[ADDR_STRING_MAXSIZE]());
		memset(Level.get(), 0, ADDR_STRING_MAXSIZE);
		memcpy_s(Level.get(), ADDR_STRING_MAXSIZE, Data.c_str() + Data.find(ASCII_COMMA) + 1U, Data.find(ASCII_COMMA, Data.find(ASCII_COMMA) + 1U) - Data.find(ASCII_COMMA) - 1U);
		Result = strtoul(Level.get(), nullptr, 0);
		if (errno != ERANGE && Result >= 0 && Result <= UINT16_MAX)
		{
			AddressRangeTableTemp.Level = (size_t)Result;
		}
		else {
			PrintError(LOG_ERROR_IPFILTER, L"Level error", 0, IPFilterFileList[FileIndex].FileName.c_str(), Line);
			return EXIT_FAILURE;
		}

	//Delete all data except addresses range.
		Data.erase(Data.find(ASCII_COMMA));
		if (Data[Data.length() - 1U] == ASCII_PERIOD)
			Data.append("0");
	}
//PeerGuardian Text Lists(P2P) Format(Guarding.P2P), also a little part of IPFilter.dat without level.
	else {
	//IPv4 IPFilter.dat data without level
		if (Data.find(ASCII_COLON) == std::string::npos)
		{
		//Delete all zeros before data.
			for (Index = 0;Index < Data.find(ASCII_MINUS);++Index)
			{
				if (Data[Index] == ASCII_ZERO)
				{
					Data.erase(Index, 1U);
					--Index;
				}
				else {
					break;
				}
			}

		//Delete all zeros before minus or after commas in addresses range.
			while (Data.find(".0") != std::string::npos)
				Data.replace(Data.find(".0"), strlen(".0"), ("."));
			while (Data.find("-0") != std::string::npos)
				Data.replace(Data.find("-0"), strlen("-0"), ("-"));
			while (Data.find("..") != std::string::npos)
				Data.replace(Data.find(".."), strlen(".."), (".0."));
			if (Data.find(".-") != std::string::npos)
				Data.replace(Data.find(".-"), strlen(".-"), (".0-"));
			if (Data.find("-.") != std::string::npos)
				Data.replace(Data.find("-."), strlen("-."), ("-0."));
			if (Data[0] == ASCII_PERIOD)
				Data.replace(0, 1U, ("0."));
			if (Data[Data.length() - 1U] == ASCII_PERIOD)
				Data.append("0");
		}
		else {
		//PeerGuardian Text Lists(P2P) Format(Guarding.P2P)
			if (Data.find(ASCII_COLON) == Data.rfind(ASCII_COLON))
			{
				Data.erase(0, Data.find(ASCII_COLON) + 1U);

			//Delete all zeros before data.
				for (Index = 0;Index < Data.find(ASCII_MINUS);++Index)
				{
					if (Data[Index] == ASCII_ZERO)
					{
						Data.erase(Index, 1U);
						--Index;
					}
					else {
						break;
					}
				}

			//Delete all zeros before minus or after commas in addresses range.
				while (Data.find(".0") != std::string::npos)
					Data.replace(Data.find(".0"), strlen(".0"), ("."));
				while (Data.find("-0") != std::string::npos)
					Data.replace(Data.find("-0"), strlen("-0"), ("-"));
				while (Data.find("..") != std::string::npos)
					Data.replace(Data.find(".."), strlen(".."), (".0."));
				if (Data.find(".-") != std::string::npos)
					Data.replace(Data.find(".-"), strlen(".-"), (".0-"));
				if (Data.find("-.") != std::string::npos)
					Data.replace(Data.find("-."), strlen("-."), ("-0."));
				if (Data[0] == ASCII_PERIOD)
					Data.replace(0, 1U, ("0."));
				if (Data[Data.length() - 1U] == ASCII_PERIOD)
					Data.append("0");
			}
		}
	}

//Read data.
	memset(&AddressRangeTableTemp, 0, sizeof(ADDRESS_RANGE_TABLE));
	std::shared_ptr<char> Addr(new char[ADDR_STRING_MAXSIZE]());
	memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
	if (Data.find(ASCII_COLON) != std::string::npos) //IPv6
	{
	//Begin address
		AddressRangeTableTemp.Begin.ss_family = AF_INET6;
		memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, Data.c_str(), Data.find(ASCII_MINUS));
		if (AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN6)&AddressRangeTableTemp.Begin)->sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
		{
			PrintError(LOG_ERROR_IPFILTER, L"IPv6 address format error", Result, IPFilterFileList[FileIndex].FileName.c_str(), Line);
			return EXIT_FAILURE;
		}

	//End address
		memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
		AddressRangeTableTemp.End.ss_family = AF_INET6;
		memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, Data.c_str() + Data.find(ASCII_MINUS) + 1U, Data.length() - Data.find(ASCII_MINUS));
		if (AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN6)&AddressRangeTableTemp.End)->sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
		{
			PrintError(LOG_ERROR_IPFILTER, L"IPv6 address format error", Result, IPFilterFileList[FileIndex].FileName.c_str(), Line);
			return EXIT_FAILURE;
		}
		Addr.reset();

	//Check address range.
		if (CompareAddresses(&((PSOCKADDR_IN6)&AddressRangeTableTemp.Begin)->sin6_addr, &((PSOCKADDR_IN6)&AddressRangeTableTemp.End)->sin6_addr, AF_INET6) > ADDRESS_COMPARE_EQUAL)
		{
			PrintError(LOG_ERROR_IPFILTER, L"IPv6 address range error", WSAGetLastError(), IPFilterFileList[FileIndex].FileName.c_str(), Line);
			return EXIT_FAILURE;
		}
	}
//IPv4
	else {
	//Begin address
		AddressRangeTableTemp.Begin.ss_family = AF_INET;
		memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, Data.c_str(), Data.find(ASCII_MINUS));
		if (AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN)&AddressRangeTableTemp.Begin)->sin_addr, AF_INET, Result) == EXIT_FAILURE)
		{
			PrintError(LOG_ERROR_IPFILTER, L"IPv4 address format error", Result, IPFilterFileList[FileIndex].FileName.c_str(), Line);
			return EXIT_FAILURE;
		}

	//End address
		memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
		AddressRangeTableTemp.End.ss_family = AF_INET;
		memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, Data.c_str() + Data.find(ASCII_MINUS) + 1U, Data.length() - Data.find(ASCII_MINUS));
		if (AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN)&AddressRangeTableTemp.End)->sin_addr, AF_INET, Result) == EXIT_FAILURE)
		{
			PrintError(LOG_ERROR_IPFILTER, L"IPv4 address format error", Result, IPFilterFileList[FileIndex].FileName.c_str(), Line);
			return EXIT_FAILURE;
		}

		Addr.reset();

	//Check address range.
		if (CompareAddresses(&((PSOCKADDR_IN)&AddressRangeTableTemp.Begin)->sin_addr, &((PSOCKADDR_IN)&AddressRangeTableTemp.End)->sin_addr, AF_INET) > ADDRESS_COMPARE_EQUAL)
		{
			PrintError(LOG_ERROR_IPFILTER, L"IPv4 address range error", 0, IPFilterFileList[FileIndex].FileName.c_str(), Line);
			return EXIT_FAILURE;
		}
	}

//Add to global AddressRangeTable.
	for (auto &IPFilterFileSetIter:*IPFilterFileSetModificating)
	{
		if (IPFilterFileSetIter.FileIndex == FileIndex)
		{
			IPFilterFileSetIter.AddressRange.push_back(AddressRangeTableTemp);
			break;
		}
	}

	return EXIT_SUCCESS;
}

//Read hosts from file
size_t __fastcall ReadHosts(void)
{
//Create file list.
	for (size_t Index = 0;Index < Parameter.Path->size();++Index)
	{
		for (size_t InnerIndex = 0;InnerIndex < Parameter.HostsFileList->size();++InnerIndex)
		{
			FILE_DATA FileDataTemp;
			FileDataTemp.FileName.clear();
		#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			FileDataTemp.sFileName.clear();
		#endif
			FileDataTemp.ModificationTime = 0;

		//Add to global list.
			FileDataTemp.FileName.append(Parameter.Path->at(Index));
			FileDataTemp.FileName.append(Parameter.HostsFileList->at(InnerIndex));
		#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			FileDataTemp.sFileName.append(Parameter.sPath->at(Index));
			FileDataTemp.sFileName.append(Parameter.sHostsFileList->at(InnerIndex));
		#endif
			HostsFileList.push_back(FileDataTemp);
		}
	}

//Files Monitor
	FILE *Input = nullptr;
	size_t FileIndex = 0;
	auto IsFileModified = false;
#if defined(PLATFORM_WIN)
	std::shared_ptr<LARGE_INTEGER> File_LARGE_INTEGER(new LARGE_INTEGER());
	std::shared_ptr<WIN32_FILE_ATTRIBUTE_DATA> File_WIN32_FILE_ATTRIBUTE_DATA(new WIN32_FILE_ATTRIBUTE_DATA());
	memset(File_LARGE_INTEGER.get(), 0, sizeof(LARGE_INTEGER));
	memset(File_WIN32_FILE_ATTRIBUTE_DATA.get(), 0, sizeof(WIN32_FILE_ATTRIBUTE_DATA));
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	std::shared_ptr<struct stat> FileStat(new struct stat());
	memset(FileStat.get(), 0, sizeof(struct stat));
#endif
	std::unique_lock<std::mutex> HostsListMutex(HostsListLock);
	std::unique_lock<std::mutex> AddressHostsListMutex(AddressHostsListLock);
	HostsListMutex.unlock();
	AddressHostsListMutex.unlock();

	for (;;)
	{
		IsFileModified = false;

	//Check File lists.
		for (FileIndex = 0;FileIndex < HostsFileList.size();++FileIndex)
		{
		//Get attributes of file.
		#if defined(PLATFORM_WIN)
			if (GetFileAttributesExW(HostsFileList[FileIndex].FileName.c_str(), GetFileExInfoStandard, File_WIN32_FILE_ATTRIBUTE_DATA.get()) == FALSE)
			{
				memset(File_WIN32_FILE_ATTRIBUTE_DATA.get(), 0, sizeof(WIN32_FILE_ATTRIBUTE_DATA));
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			if (stat(HostsFileList[FileIndex].sFileName.c_str(), FileStat.get()) != 0)
			{
				memset(FileStat.get(), 0, sizeof(struct stat));
		#endif
				if (HostsFileList[FileIndex].ModificationTime > 0)
					IsFileModified = true;
				HostsFileList[FileIndex].ModificationTime = 0;

				ClearListData(READTEXT_HOSTS, FileIndex);
			}
			else {
			//Check whole file size.
			#if defined(PLATFORM_WIN)
				File_LARGE_INTEGER->HighPart = File_WIN32_FILE_ATTRIBUTE_DATA->nFileSizeHigh;
				File_LARGE_INTEGER->LowPart = File_WIN32_FILE_ATTRIBUTE_DATA->nFileSizeLow;
				if (File_LARGE_INTEGER->QuadPart >= DEFAULT_FILE_MAXSIZE)
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				if (FileStat->st_size >= (off_t)DEFAULT_FILE_MAXSIZE)
			#endif
				{
					PrintError(LOG_ERROR_PARAMETER, L"Hosts file size is too large", 0, HostsFileList[FileIndex].FileName.c_str(), 0);

				#if defined(PLATFORM_WIN)
					memset(File_WIN32_FILE_ATTRIBUTE_DATA.get(), 0, sizeof(WIN32_FILE_ATTRIBUTE_DATA));
					memset(File_LARGE_INTEGER.get(), 0, sizeof(LARGE_INTEGER));
				#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
					memset(FileStat.get(), 0, sizeof(struct stat));
				#endif
					if (HostsFileList[FileIndex].ModificationTime > 0)
						IsFileModified = true;
					HostsFileList[FileIndex].ModificationTime = 0;

					ClearListData(READTEXT_HOSTS, FileIndex);
					continue;
				}

			//Check modification time of file.
			#if defined(PLATFORM_WIN)
				memset(File_LARGE_INTEGER.get(), 0, sizeof(LARGE_INTEGER));
				File_LARGE_INTEGER->HighPart = File_WIN32_FILE_ATTRIBUTE_DATA->ftLastWriteTime.dwHighDateTime;
				File_LARGE_INTEGER->LowPart = File_WIN32_FILE_ATTRIBUTE_DATA->ftLastWriteTime.dwLowDateTime;
				if (HostsFileList[FileIndex].ModificationTime == 0 || File_LARGE_INTEGER->QuadPart != HostsFileList[FileIndex].ModificationTime)
				{
					HostsFileList[FileIndex].ModificationTime = File_LARGE_INTEGER->QuadPart;
					memset(File_WIN32_FILE_ATTRIBUTE_DATA.get(), 0, sizeof(WIN32_FILE_ATTRIBUTE_DATA));
					memset(File_LARGE_INTEGER.get(), 0, sizeof(LARGE_INTEGER));
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				if (HostsFileList[FileIndex].ModificationTime == 0 || FileStat->st_mtime != HostsFileList[FileIndex].ModificationTime)
				{
					HostsFileList[FileIndex].ModificationTime = FileStat->st_mtime;
					memset(FileStat.get(), 0, sizeof(struct stat));
			#endif
					ClearListData(READTEXT_HOSTS, FileIndex);
					IsFileModified = true;

				//Read file.
				#if defined(PLATFORM_WIN)
					if (_wfopen_s(&Input, HostsFileList[FileIndex].FileName.c_str(), L"rb") == 0)
					{
				#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
					Input = fopen(HostsFileList[FileIndex].sFileName.c_str(), "rb");
				#endif
						if (Input == nullptr)
						{
							continue;
						}
						else {
						//Scan global list.
							for (auto HostsFileSetIter = HostsFileSetModificating->begin();HostsFileSetIter != HostsFileSetModificating->end();++HostsFileSetIter)
							{
								if (HostsFileSetIter->FileIndex == FileIndex)
								{
									break;
								}
								else if (HostsFileSetIter + 1U == HostsFileSetModificating->end())
								{
									DIFFERNET_HOSTS_FILE_SET HostsFileSetTemp;
									HostsFileSetTemp.FileIndex = FileIndex;
									HostsFileSetModificating->push_back(HostsFileSetTemp);
									break;
								}
							}
							if (HostsFileSetModificating->empty())
							{
								DIFFERNET_HOSTS_FILE_SET HostsFileSetTemp;
								HostsFileSetTemp.FileIndex = FileIndex;
								HostsFileSetModificating->push_back(HostsFileSetTemp);
							}

						//Read data.
							ReadText(Input, READTEXT_HOSTS, FileIndex);
							fclose(Input);
							Input = nullptr;
						}
				#if defined(PLATFORM_WIN)
					}
				#endif
				}
				else {
				#if defined(PLATFORM_WIN)
					memset(File_WIN32_FILE_ATTRIBUTE_DATA.get(), 0, sizeof(WIN32_FILE_ATTRIBUTE_DATA));
					memset(File_LARGE_INTEGER.get(), 0, sizeof(LARGE_INTEGER));
				#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
					memset(FileStat.get(), 0, sizeof(struct stat));
				#endif
				}
			}
		}

	//Update global list.
		if (!IsFileModified)
		{
			Sleep(Parameter.FileRefreshTime);
			continue;
		}

	//EDNS0 Lebal
		if (Parameter.EDNS0Label)
		{
			pdns_record_opt DNS_Record_OPT = nullptr;
			for (auto &HostsFileSetIter:*HostsFileSetModificating)
			{
				for (auto &HostsListIter:HostsFileSetIter.HostsList)
				{
					if (HostsListIter.Length > PACKET_MAXSIZE - sizeof(dns_record_opt))
					{
						PrintError(LOG_ERROR_HOSTS, L"Data is too long when EDNS0 is available", 0, nullptr, 0);
						continue;
					}
					else if (!HostsListIter.Response)
					{
						continue;
					}
					else {
						DNS_Record_OPT = (pdns_record_opt)(HostsListIter.Response.get() + HostsListIter.Length);
						DNS_Record_OPT->Type = htons(DNS_RECORD_OPT);
						DNS_Record_OPT->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
						HostsListIter.Length += sizeof(dns_record_opt);
					}
				}
			}
		}

	//Copy to using list.
		HostsListMutex.lock();
		AddressHostsListMutex.lock();
		*HostsFileSetUsing = *HostsFileSetModificating;
		HostsFileSetUsing->shrink_to_fit();
		HostsListMutex.unlock();
		AddressHostsListMutex.unlock();
		HostsFileSetModificating->shrink_to_fit();

	//Flush DNS cache and Auto-refresh
		FlushSystemDNSCache();
		Sleep(Parameter.FileRefreshTime);
	}

	PrintError(LOG_ERROR_SYSTEM, L"Read Hosts module Monitor terminated", 0, nullptr, 0);
	return EXIT_SUCCESS;
}

//Read hosts data from files
size_t __fastcall ReadHostsData(const char *Buffer, const size_t FileIndex, const size_t Line, size_t &LabelType, bool &IsLabelComments)
{
	std::string Data(Buffer);

//Multi-line comments check, delete comments(Number Sign/NS and double slashs) and check minimum length of hosts items.
	if (ReadMultiLineComments(Buffer, Data, IsLabelComments) == EXIT_FAILURE || Data.find(ASCII_HASHTAG) == 0 || Data.find(ASCII_SLASH) == 0)
		return EXIT_SUCCESS;
	else if (Data.rfind(" //") != std::string::npos)
		Data.erase(Data.rfind(" //"), Data.length() - Data.rfind(" //"));
	else if (Data.rfind("	//") != std::string::npos)
		Data.erase(Data.rfind("	//"), Data.length() - Data.rfind("	//"));
	else if (Data.rfind(" #") != std::string::npos)
		Data.erase(Data.rfind(" #"), Data.length() - Data.rfind(" #"));
	else if (Data.rfind("	#") != std::string::npos)
		Data.erase(Data.rfind("	#"), Data.length() - Data.rfind("	#"));
	if (Data.length() < READ_HOSTS_MINSIZE)
		return FALSE;

//[Base] block
	if (Data.find("[Base]") == 0 || Data.find("[base]") == 0 || 
		Data.find("Version = ") == 0 || Data.find("version = ") == 0 || 
		Data.find("Default TTL = ") == 0 || Data.find("default ttl = ") == 0)
			return EXIT_SUCCESS;

//[Local Hosts] block(A part)
	if (LabelType == 0 && (Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family > 0 || Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family > 0) && 
	#if defined(PLATFORM_WIN) //Case-insensitive on Windows
		(HostsFileList[FileIndex].FileName.rfind(L"whitelist.txt") != std::wstring::npos && HostsFileList[FileIndex].FileName.length() > wcslen(L"whitelist.txt") && 
		HostsFileList[FileIndex].FileName.rfind(L"whitelist.txt") == HostsFileList[FileIndex].FileName.length() - wcslen(L"whitelist.txt") || 
		HostsFileList[FileIndex].FileName.rfind(L"white_list.txt") != std::wstring::npos && HostsFileList[FileIndex].FileName.length() > wcslen(L"white_list.txt") && 
		HostsFileList[FileIndex].FileName.rfind(L"white_list.txt") == HostsFileList[FileIndex].FileName.length() - wcslen(L"white_list.txt")))
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		(HostsFileList[FileIndex].FileName.rfind(L"WhiteList.txt") != std::wstring::npos && HostsFileList[FileIndex].FileName.length() > wcslen(L"WhiteList.txt") && 
		HostsFileList[FileIndex].FileName.rfind(L"WhiteList.txt") == HostsFileList[FileIndex].FileName.length() - wcslen(L"WhiteList.txt") || 
		HostsFileList[FileIndex].FileName.rfind(L"Whitelist.txt") != std::wstring::npos && HostsFileList[FileIndex].FileName.length() > wcslen(L"Whitelist.txt") && 
		HostsFileList[FileIndex].FileName.rfind(L"Whitelist.txt") == HostsFileList[FileIndex].FileName.length() - wcslen(L"Whitelist.txt") || 
		HostsFileList[FileIndex].FileName.rfind(L"whitelist.txt") != std::wstring::npos && HostsFileList[FileIndex].FileName.length() > wcslen(L"whitelist.txt") && 
		HostsFileList[FileIndex].FileName.rfind(L"whitelist.txt") == HostsFileList[FileIndex].FileName.length() - wcslen(L"whitelist.txt") || 
		HostsFileList[FileIndex].FileName.rfind(L"White_List.txt") != std::wstring::npos && HostsFileList[FileIndex].FileName.length() > wcslen(L"White_List.txt") && 
		HostsFileList[FileIndex].FileName.rfind(L"White_List.txt") == HostsFileList[FileIndex].FileName.length() - wcslen(L"White_List.txt") || 
		HostsFileList[FileIndex].FileName.rfind(L"White_list.txt") != std::wstring::npos && HostsFileList[FileIndex].FileName.length() > wcslen(L"White_list.txt") && 
		HostsFileList[FileIndex].FileName.rfind(L"White_list.txt") == HostsFileList[FileIndex].FileName.length() - wcslen(L"White_list.txt") || 
		HostsFileList[FileIndex].FileName.rfind(L"white_list.txt") != std::wstring::npos && HostsFileList[FileIndex].FileName.length() > wcslen(L"white_list.txt") && 
		HostsFileList[FileIndex].FileName.rfind(L"white_list.txt") == HostsFileList[FileIndex].FileName.length() - wcslen(L"white_list.txt")))
	#endif
			LabelType = LABEL_HOSTS_LOCAL;

//[Hosts] block
	if (Data.find("[Hosts]") == 0 || Data.find("[hosts]") == 0)
	{
		LabelType = LABEL_HOSTS;
		return EXIT_SUCCESS;
	}

//[Local Hosts] block(B part)
	else if (Data.find("[Local Hosts]") == 0 || Data.find("[Local hosts]") == 0 || Data.find("[local Hosts]") == 0 || Data.find("[local hosts]") == 0)
	{
		LabelType = LABEL_HOSTS_LOCAL;
		return EXIT_SUCCESS;
	}

//[Address Hosts] block
	else if (Data.find("[Address Hosts]") == 0 || Data.find("[Address hosts]") == 0 || Data.find("[address Hosts]") == 0 || Data.find("[address hosts]") == 0)
	{
		LabelType = LABEL_HOSTS_ADDRESS;
		return EXIT_SUCCESS;
	}

//Temporary stop read.
	else if (Data.find("[Stop]") == 0 || Data.find("[stop]") == 0)
	{
		LabelType = LABEL_STOP;
		return EXIT_SUCCESS;
	}
	if (LabelType == LABEL_STOP)
		return EXIT_SUCCESS;

//Convert horizontal tab/HT to space and delete spaces before or after data.
	for (auto &StringIter:Data)
	{
		if (StringIter == ASCII_HT)
			StringIter = ASCII_SPACE;
	}
	while (!Data.empty() && Data[0] == ASCII_SPACE)
		Data.erase(0, 1U);
	while (!Data.empty() && Data.back() == ASCII_SPACE)
		Data.pop_back();
	while (!Data.empty() && Data.find("  ") != std::string::npos)
		Data.erase(Data.find("  "), 1U);

//Whitelist items
	if (Data.find("NULL ") == 0 || Data.find("NULL	") == 0 || Data.find("NULL,") == 0 || 
		Data.find("Null ") == 0 || Data.find("Null	") == 0 || Data.find("Null,") == 0 || 
		Data.find("null ") == 0 || Data.find("null	") == 0 || Data.find("null,") == 0)
	{
		return ReadWhitelistAndBannedData(Data, FileIndex, Line, LABEL_HOSTS_WHITELIST);
	}

//Banned items
	else if (Data.find("BAN ") == 0 || Data.find("BAN,") == 0 || 
		Data.find("BANNED ") == 0 || Data.find("BANNED,") == 0 || 
		Data.find("Ban ") == 0 || Data.find("Ban,") == 0 || 
		Data.find("Banned ") == 0 || Data.find("Banned,") == 0 || 
		Data.find("ban ") == 0 || Data.find("ban,") == 0 || 
		Data.find("banned ") == 0 || Data.find("banned,") == 0)
	{
		return ReadWhitelistAndBannedData(Data, FileIndex, Line, LABEL_HOSTS_BANNED);
	}

//Type Banned items
	else if (Data.find("BAN") == 0 || Data.find("BANNED") == 0 || Data.find("Ban") == 0 || 
		Data.find("Banned") == 0 || Data.find("ban") == 0 || Data.find("banned") == 0)
	{
		return ReadWhitelistAndBannedData(Data, FileIndex, Line, LABEL_HOSTS_BANNED_TYPE);
	}

//[Local Hosts] block
	else if (LabelType == LABEL_HOSTS_LOCAL)
	{
		if ((Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family > 0 || Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family > 0) && Parameter.LocalHosts && 
			!(Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family == 0 && Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family == 0 && Parameter.LocalMain))
				return ReadLocalHostsData(Data, FileIndex, Line);
	}

//[Address Hosts] block
	else if (LabelType == LABEL_HOSTS_ADDRESS)
	{
	//Delete spaces before or after verticals.
		while (Data.find(" |") != std::string::npos || Data.find("| ") != std::string::npos)
		{
			if (Data.find(" |") != std::string::npos)
				Data.erase(Data.find(" |"), 1U);
			if (Data.find("| ") != std::string::npos)
				Data.erase(Data.find("| ") + 1U, 1U);
		}

		return ReadAddressHostsData(Data, FileIndex, Line);
	}

//[Hosts] block
	else {
	//Delete spaces before or after verticals.
		while (Data.find(" |") != std::string::npos || Data.find("| ") != std::string::npos)
		{
			if (Data.find(" |") != std::string::npos)
				Data.erase(Data.find(" |"), 1U);
			if (Data.find("| ") != std::string::npos)
				Data.erase(Data.find("| ") + 1U, 1U);
		}

		return ReadMainHostsData(Data, FileIndex, Line);
	}

	return EXIT_SUCCESS;
}

//Read Whitelist and Banned items in Hosts file from data
size_t __fastcall ReadWhitelistAndBannedData(std::string Data, const size_t FileIndex, const size_t Line, const size_t LabelType)
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
	if (Separated == 0 || (LabelType == LABEL_HOSTS_BANNED_TYPE && (Data.find(ASCII_COLON) == std::string::npos || Separated <= Data.find(ASCII_COLON) + 1U)))
	{
		PrintError(LOG_ERROR_HOSTS, L"Data format error", 0, HostsFileList[FileIndex].FileName.c_str(), Line);
		return EXIT_FAILURE;
	}

//Delete all spaces.
	while (Data.find(ASCII_SPACE) != std::string::npos)
		Data.erase(Data.find(ASCII_SPACE), 1U);

	HOSTS_TABLE HostsTableTemp;
//Mark banned types.
	if (LabelType == LABEL_HOSTS_BANNED_TYPE)
	{
	//Permit or Deny
		if (Data.find("PERMIT") != std::string::npos && Data.find("PERMIT") <= Separated || 
			Data.find("Permit") != std::string::npos && Data.find("Permit") <= Separated || 
			Data.find("permit") != std::string::npos && Data.find("permit") <= Separated)
				HostsTableTemp.TypeOperation = true;

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
						HostsTableTemp.RecordType.push_back(htons((uint16_t)Result));
					}
					else {
						PrintError(LOG_ERROR_PARAMETER, L"DNS Records type error", 0, HostsFileList[FileIndex].FileName.c_str(), Line);
						return EXIT_FAILURE;
					}
				}
				else { //Name types
					HostsTableTemp.RecordType.push_back(RecordType);
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
		PrintError(LOG_ERROR_HOSTS, L"Regular expression pattern error", Error.code(), HostsFileList[FileIndex].FileName.c_str(), Line);
		return EXIT_FAILURE;
	}

//Mark types.
	if (LabelType == LABEL_HOSTS_BANNED || LabelType == LABEL_HOSTS_BANNED_TYPE)
		HostsTableTemp.Type = HOSTS_BANNED;
	else 
		HostsTableTemp.Type = HOSTS_WHITE;

//Add to global HostsList.
	for (auto &HostsFileSetIter:*HostsFileSetModificating)
	{
		if (HostsFileSetIter.FileIndex == FileIndex)
		{
			HostsFileSetIter.HostsList.push_back(HostsTableTemp);
			break;
		}
	}

	return EXIT_SUCCESS;
}

//Read Local Hosts items in Hosts file from data
size_t __fastcall ReadLocalHostsData(std::string Data, const size_t FileIndex, const size_t Line)
{
	HOSTS_TABLE HostsTableTemp;

//Mark patterns.
	try {
		std::regex PatternHostsTableTemp(HostsTableTemp.PatternString);
		HostsTableTemp.Pattern.swap(PatternHostsTableTemp);
	}
	catch (std::regex_error& Error)
	{
		PrintError(LOG_ERROR_HOSTS, L"Regular expression pattern error", Error.code(), HostsFileList[FileIndex].FileName.c_str(), Line);
		return EXIT_FAILURE;
	}

//Add to global HostsTable.
	HostsTableTemp.Type = HOSTS_LOCAL;
	for (auto &HostsFileSetIter:*HostsFileSetModificating)
	{
		if (HostsFileSetIter.FileIndex == FileIndex)
		{
			HostsFileSetIter.HostsList.push_back(HostsTableTemp);
			break;
		}
	}

	return EXIT_SUCCESS;
}

//Read Address Hosts items in Hosts file from data
size_t __fastcall ReadAddressHostsData(std::string Data, const size_t FileIndex, const size_t Line)
{
//Mark separated location.
	size_t Separated = 0;
	if (Data.find(ASCII_COMMA) != std::string::npos)
	{
	//Delete spaces before or after commas.
		while (Data.find(" ,") != std::string::npos)
			Data.erase(Data.find(" ,"), 1U);
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
		PrintError(LOG_ERROR_HOSTS, L"Data format error", 0, HostsFileList[FileIndex].FileName.c_str(), Line);
		return EXIT_FAILURE;
	}

//Delete all spaces.
	while (Data.find(ASCII_SPACE) != std::string::npos)
		Data.erase(Data.find(ASCII_SPACE), 1U);

//String length check.
	if (Data.length() < READ_HOSTS_ADDRESS_MINSIZE)
	{
		PrintError(LOG_ERROR_HOSTS, L"Data format error", 0, HostsFileList[FileIndex].FileName.c_str(), Line);
		return EXIT_FAILURE;
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
			if (AddressStringToBinary(TargetString.c_str(), &((PSOCKADDR_IN6)SockAddr.get())->sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
			{
				PrintError(LOG_ERROR_HOSTS, L"IPv6 address format error", Result, HostsFileList[FileIndex].FileName.c_str(), Line);
				return EXIT_FAILURE;
			}

		//Add to list.
			SockAddr->ss_family = AF_INET6;
			AddressHostsTableTemp.TargetAddress.push_back(*SockAddr);
		}
	//A record(IPv4)
		else {
		//Convert to binary address.
			if (AddressStringToBinary(TargetString.c_str(), &((PSOCKADDR_IN)SockAddr.get())->sin_addr, AF_INET, Result) == EXIT_FAILURE)
			{
				PrintError(LOG_ERROR_HOSTS, L"IPv4 address format error", Result, HostsFileList[FileIndex].FileName.c_str(), Line);
				return EXIT_FAILURE;
			}

		//Add to list.
			SockAddr->ss_family = AF_INET;
			AddressHostsTableTemp.TargetAddress.push_back(*SockAddr);
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
				if (TargetString[Index] == ASCII_VERTICAL || Index == TargetString.length())
				{
				//Convert addresses.
					memset(SockAddr.get(), 0, sizeof(sockaddr_storage));
					memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
					memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, TargetString.c_str() + VerticalIndex, Index - VerticalIndex);
					if (AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN6)SockAddr.get())->sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
					{
						PrintError(LOG_ERROR_HOSTS, L"IPv6 address format error", Result, HostsFileList[FileIndex].FileName.c_str(), Line);
						return EXIT_FAILURE;
					}

				//Add to list.
					SockAddr->ss_family = AF_INET6;
					AddressHostsTableTemp.TargetAddress.push_back(*SockAddr);
					VerticalIndex = Index + 1U;
				}
			}
		}
	//A records(IPv4)
		else {
			for (Index = 0;Index <= TargetString.length();++Index)
			{
				if (TargetString[Index] == ASCII_VERTICAL || Index == TargetString.length())
				{
				//Convert addresses.
					memset(SockAddr.get(), 0, sizeof(sockaddr_storage));
					memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
					memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, TargetString.c_str() + VerticalIndex, Index - VerticalIndex);
					if (AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN)SockAddr.get())->sin_addr, AF_INET, Result) == EXIT_FAILURE)
					{
						PrintError(LOG_ERROR_HOSTS, L"IPv4 address format error", Result, HostsFileList[FileIndex].FileName.c_str(), Line);
						return EXIT_FAILURE;
					}

				//Add to list.
					SockAddr->ss_family = AF_INET;
					AddressHostsTableTemp.TargetAddress.push_back(*SockAddr);
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
				if (AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN6)&AddressRangeTableTemp.Begin)->sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_HOSTS, L"IPv6 address format error", Result, HostsFileList[FileIndex].FileName.c_str(), Line);
					return EXIT_FAILURE;
				}
				AddressRangeTableTemp.Begin.ss_family = AF_INET6;

			//Convert address(End).
				memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
				memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, SourceString.c_str() + SourceString.find(ASCII_MINUS) + 1U, SourceString.length() - SourceString.find(ASCII_MINUS) - 1U);
				if (AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN6)&AddressRangeTableTemp.End)->sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_HOSTS, L"IPv6 address format error", Result, HostsFileList[FileIndex].FileName.c_str(), Line);
					return EXIT_FAILURE;
				}
				AddressRangeTableTemp.End.ss_family = AF_INET6;

			//Check address range.
				if (CompareAddresses(&((PSOCKADDR_IN6)&AddressRangeTableTemp.Begin)->sin6_addr, &((PSOCKADDR_IN6)&AddressRangeTableTemp.End)->sin6_addr, AF_INET6) > ADDRESS_COMPARE_EQUAL)
				{
					PrintError(LOG_ERROR_HOSTS, L"IPv6 address range error", WSAGetLastError(), HostsFileList[FileIndex].FileName.c_str(), Line);
					return EXIT_FAILURE;
				}
			}
		//Normal format
			else {
			//Convert to binary address.
				if (AddressStringToBinary(SourceString.c_str(), &((PSOCKADDR_IN6)&AddressRangeTableTemp.Begin)->sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_HOSTS, L"IPv6 address format error", Result, HostsFileList[FileIndex].FileName.c_str(), Line);
					return EXIT_FAILURE;
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
				if (AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN)&AddressRangeTableTemp.Begin)->sin_addr, AF_INET, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_HOSTS, L"IPv4 address format error", Result, HostsFileList[FileIndex].FileName.c_str(), Line);
					return EXIT_FAILURE;
				}
				AddressRangeTableTemp.Begin.ss_family = AF_INET;

			//Convert address(End).
				memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
				memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, SourceString.c_str() + SourceString.find(ASCII_MINUS) + 1U, SourceString.length() - SourceString.find(ASCII_MINUS) - 1U);
				if (AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN)&AddressRangeTableTemp.End)->sin_addr, AF_INET, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_HOSTS, L"IPv4 address format error", Result, HostsFileList[FileIndex].FileName.c_str(), Line);
					return EXIT_FAILURE;
				}
				AddressRangeTableTemp.End.ss_family = AF_INET;

			//Check address range.
				if (CompareAddresses(&((PSOCKADDR_IN)&AddressRangeTableTemp.Begin)->sin_addr, &((PSOCKADDR_IN)&AddressRangeTableTemp.End)->sin_addr, AF_INET) > ADDRESS_COMPARE_EQUAL)
				{
					PrintError(LOG_ERROR_HOSTS, L"IPv4 address range error", WSAGetLastError(), HostsFileList[FileIndex].FileName.c_str(), Line);
					return EXIT_FAILURE;
				}
			}
		//Normal format
			else {
			//Convert to binary address.
				if (AddressStringToBinary(SourceString.c_str(), &((PSOCKADDR_IN)&AddressRangeTableTemp.Begin)->sin_addr, AF_INET, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_HOSTS, L"IPv4 address format error", Result, HostsFileList[FileIndex].FileName.c_str(), Line);
					return EXIT_FAILURE;
				}

				AddressRangeTableTemp.Begin.ss_family = AF_INET;
				AddressRangeTableTemp.End = AddressRangeTableTemp.Begin;
			}
		}

		AddressHostsTableTemp.SourceAddress.push_back(AddressRangeTableTemp);
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
				if (SourceString[Index] == ASCII_VERTICAL || Index == SourceString.length())
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
						if (AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN6)&AddressRangeTableTemp.Begin)->sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
						{
							PrintError(LOG_ERROR_HOSTS, L"IPv6 address format error", Result, HostsFileList[FileIndex].FileName.c_str(), Line);
							return EXIT_FAILURE;
						}
						AddressRangeTableTemp.Begin.ss_family = AF_INET6;

					//Convert address(End).
						memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
						memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, ItemString.c_str() + ItemString.find(ASCII_MINUS) + 1U, ItemString.length() - ItemString.find(ASCII_MINUS) - 1U);
						if (AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN6)&AddressRangeTableTemp.End)->sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
						{
							PrintError(LOG_ERROR_HOSTS, L"IPv6 address format error", Result, HostsFileList[FileIndex].FileName.c_str(), Line);
							return EXIT_FAILURE;
						}
						AddressRangeTableTemp.End.ss_family = AF_INET6;

					//Check address range.
						if (CompareAddresses(&((PSOCKADDR_IN6)&AddressRangeTableTemp.Begin)->sin6_addr, &((PSOCKADDR_IN6)&AddressRangeTableTemp.End)->sin6_addr, AF_INET6) > ADDRESS_COMPARE_EQUAL)
						{
							PrintError(LOG_ERROR_HOSTS, L"IPv6 address range error", WSAGetLastError(), HostsFileList[FileIndex].FileName.c_str(), Line);
							return EXIT_FAILURE;
						}
					}
				//Normal format
					else {
					//Convert to binary address.
						if (AddressStringToBinary(ItemString.c_str(), &((PSOCKADDR_IN6)&AddressRangeTableTemp.Begin)->sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
						{
							PrintError(LOG_ERROR_HOSTS, L"IPv6 address format error", Result, HostsFileList[FileIndex].FileName.c_str(), Line);
							return EXIT_FAILURE;
						}

						AddressRangeTableTemp.Begin.ss_family = AF_INET6;
						AddressRangeTableTemp.End = AddressRangeTableTemp.Begin;
					}

				//Add to list.
					AddressHostsTableTemp.SourceAddress.push_back(AddressRangeTableTemp);
					VerticalIndex = Index + 1U;
				}
			}
		}
	//A records(IPv4)
		else {
			for (Index = 0;Index <= SourceString.length();++Index)
			{
				if (SourceString[Index] == ASCII_VERTICAL || Index == SourceString.length())
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
						if (AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN)&AddressRangeTableTemp.Begin)->sin_addr, AF_INET, Result) == EXIT_FAILURE)
						{
							PrintError(LOG_ERROR_HOSTS, L"IPv4 address format error", Result, HostsFileList[FileIndex].FileName.c_str(), Line);
							return EXIT_FAILURE;
						}
						AddressRangeTableTemp.Begin.ss_family = AF_INET;

					//Convert address(End).
						memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
						memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, ItemString.c_str() + ItemString.find(ASCII_MINUS) + 1U, ItemString.length() - ItemString.find(ASCII_MINUS) - 1U);
						if (AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN)&AddressRangeTableTemp.End)->sin_addr, AF_INET, Result) == EXIT_FAILURE)
						{
							PrintError(LOG_ERROR_HOSTS, L"IPv4 address format error", Result, HostsFileList[FileIndex].FileName.c_str(), Line);
							return EXIT_FAILURE;
						}
						AddressRangeTableTemp.End.ss_family = AF_INET;

					//Check address range.
						if (CompareAddresses(&((PSOCKADDR_IN)&AddressRangeTableTemp.Begin)->sin_addr, &((PSOCKADDR_IN)&AddressRangeTableTemp.End)->sin_addr, AF_INET) > ADDRESS_COMPARE_EQUAL)
						{
							PrintError(LOG_ERROR_HOSTS, L"IPv4 address range error", WSAGetLastError(), HostsFileList[FileIndex].FileName.c_str(), Line);
							return EXIT_FAILURE;
						}
					}
				//Normal format
					else {
					//Convert to binary address.
						if (AddressStringToBinary(ItemString.c_str(), &((PSOCKADDR_IN)&AddressRangeTableTemp.Begin)->sin_addr, AF_INET, Result) == EXIT_FAILURE)
						{
							PrintError(LOG_ERROR_HOSTS, L"IPv4 address format error", Result, HostsFileList[FileIndex].FileName.c_str(), Line);
							return EXIT_FAILURE;
						}

						AddressRangeTableTemp.Begin.ss_family = AF_INET;
						AddressRangeTableTemp.End = AddressRangeTableTemp.Begin;
					}

				//Add to list.
					AddressHostsTableTemp.SourceAddress.push_back(AddressRangeTableTemp);
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

	return EXIT_SUCCESS;
}

//Read Main Hosts items in Hosts file from data
size_t __fastcall ReadMainHostsData(std::string Data, const size_t FileIndex, const size_t Line)
{
//Mark separated location.
	size_t Separated = 0;
	if (Data.find(ASCII_COMMA) != std::string::npos)
	{
	//Delete spaces before or after commas.
		while (Data.find(" ,") != std::string::npos)
			Data.erase(Data.find(" ,"), 1U);
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
		PrintError(LOG_ERROR_HOSTS, L"Data format error", 0, HostsFileList[FileIndex].FileName.c_str(), Line);
		return EXIT_FAILURE;
	}

//Delete all spaces and string length check.
	while (Data.find(ASCII_SPACE) != std::string::npos)
		Data.erase(Data.find(ASCII_SPACE), 1U);
	if (Separated < READ_HOSTS_MINSIZE)
		return EXIT_FAILURE;

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
				PrintError(LOG_ERROR_HOSTS, L"IPv6 address format error", 0, HostsFileList[FileIndex].FileName.c_str(), Line);
				return EXIT_FAILURE;
			}
			else if (Data[0] < ASCII_ZERO || Data[0] > ASCII_COLON && Data[0] < ASCII_UPPERCASE_A || Data[0] > ASCII_UPPERCASE_F && Data[0] < ASCII_LOWERCASE_A || Data[0] > ASCII_LOWERCASE_F)
			{
				return EXIT_FAILURE;
			}

		//Make responses.
			DNS_Record_AAAA = (pdns_record_aaaa)HostsTableTemp.Response.get();
			DNS_Record_AAAA->Name = htons(DNS_QUERY_PTR);
			DNS_Record_AAAA->Classes = htons(DNS_CLASS_IN);
			DNS_Record_AAAA->TTL = htonl(Parameter.HostsDefaultTTL);
			DNS_Record_AAAA->Type = htons(DNS_RECORD_AAAA);
			DNS_Record_AAAA->Length = htons(sizeof(in6_addr));

		//Convert addresses.
			memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, Data.c_str(), Separated);
			if (AddressStringToBinary(Addr.get(), &DNS_Record_AAAA->Addr, AF_INET6, Result) == EXIT_FAILURE)
			{
				PrintError(LOG_ERROR_HOSTS, L"IPv6 address format error", Result, HostsFileList[FileIndex].FileName.c_str(), Line);
				return EXIT_FAILURE;
			}

			HostsTableTemp.RecordType.push_back(htons(DNS_RECORD_AAAA));
			HostsTableTemp.Length = sizeof(dns_record_aaaa);
		}
	//A records(IPv4)
		else {
		//IPv4 addresses check
			if (Separated > ADDR_STRING_MAXSIZE)
			{
				PrintError(LOG_ERROR_HOSTS, L"IPv4 address format error", 0, HostsFileList[FileIndex].FileName.c_str(), Line);
				return EXIT_FAILURE;
			}
			else if (Data[0] < ASCII_ZERO || Data[0] > ASCII_NINE)
			{
				return EXIT_FAILURE;
			}

		//Make responses.
			DNS_Record_A = (pdns_record_a)HostsTableTemp.Response.get();
			DNS_Record_A->Name = htons(DNS_QUERY_PTR);
			DNS_Record_A->Classes = htons(DNS_CLASS_IN);
			DNS_Record_A->TTL = htonl(Parameter.HostsDefaultTTL);
			DNS_Record_A->Type = htons(DNS_RECORD_A);
			DNS_Record_A->Length = htons(sizeof(in_addr));

		//Convert addresses.
			memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, Data.c_str(), Separated);
			if (AddressStringToBinary(Addr.get(), &DNS_Record_A->Addr, AF_INET, Result) == EXIT_FAILURE)
			{
				PrintError(LOG_ERROR_HOSTS, L"IPv4 address format error", Result, HostsFileList[FileIndex].FileName.c_str(), Line);
				return EXIT_FAILURE;
			}

			HostsTableTemp.RecordType.push_back(htons(DNS_RECORD_A));
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
			if (Data[0] < ASCII_ZERO || Data[0] > ASCII_COLON && Data[0] < ASCII_UPPERCASE_A || Data[0] > ASCII_UPPERCASE_F && Data[0] < ASCII_LOWERCASE_A || Data[0] > ASCII_LOWERCASE_F)
				return EXIT_FAILURE;

			HostsTableTemp.RecordType.push_back(htons(DNS_RECORD_AAAA));
			for (Index = 0, ResultCount = 0;Index <= Separated;++Index)
			{
			//Read data.
				if (Data[Index] == ASCII_VERTICAL || Index == Separated)
				{
					++ResultCount;

				//Length check
//					if (HostsTableTemp.Length + sizeof(dns_record_aaaa) > PACKET_MAXSIZE)
					if (ResultCount > DNS_RR_MAXCOUNT_AAAA)
					{
						PrintError(LOG_ERROR_HOSTS, L"Too many Hosts IP addresses", 0, HostsFileList[FileIndex].FileName.c_str(), Line);
						return EXIT_FAILURE;
					}
					else if (Index - VerticalIndex > ADDR_STRING_MAXSIZE)
					{
						PrintError(LOG_ERROR_HOSTS, L"IPv6 address format error", 0, HostsFileList[FileIndex].FileName.c_str(), Line);
						return EXIT_FAILURE;
					}

				//Make responses
					DNS_Record_AAAA = (pdns_record_aaaa)(HostsTableTemp.Response.get() + HostsTableTemp.Length);
					DNS_Record_AAAA->Name = htons(DNS_QUERY_PTR);
					DNS_Record_AAAA->Classes = htons(DNS_CLASS_IN);
					DNS_Record_AAAA->TTL = htonl(Parameter.HostsDefaultTTL);
					DNS_Record_AAAA->Type = htons(DNS_RECORD_AAAA);
					DNS_Record_AAAA->Length = htons(sizeof(in6_addr));

				//Convert addresses.
					memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
					memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, Data.c_str() + VerticalIndex, Index - VerticalIndex);
					if (AddressStringToBinary(Addr.get(), &DNS_Record_AAAA->Addr, AF_INET6, Result) == EXIT_FAILURE)
					{
						PrintError(LOG_ERROR_HOSTS, L"IPv6 address format error", Result, HostsFileList[FileIndex].FileName.c_str(), Line);
						return EXIT_FAILURE;
					}

					HostsTableTemp.Length += sizeof(dns_record_aaaa);
					VerticalIndex = Index + 1U;
				}
			}
		}
	//A records(IPv4)
		else {
		//IPv4 addresses check
			if (Data[0] < ASCII_ZERO || Data[0] > ASCII_NINE)
				return EXIT_FAILURE;

			HostsTableTemp.RecordType.push_back(htons(DNS_RECORD_A));
			for (Index = 0, ResultCount = 0;Index <= Separated;++Index)
			{
			//Read data.
				if (Data[Index] == ASCII_VERTICAL || Index == Separated)
				{
					++ResultCount;

				//Length check
//					if (HostsTableTemp.Length + sizeof(dns_record_a) > PACKET_MAXSIZE)
					if (ResultCount > DNS_RR_MAXCOUNT_A)
					{
						PrintError(LOG_ERROR_HOSTS, L"Too many Hosts IP addresses", 0, HostsFileList[FileIndex].FileName.c_str(), Line);
						return EXIT_FAILURE;
					}
					else if (Index - VerticalIndex > ADDR_STRING_MAXSIZE)
					{
						PrintError(LOG_ERROR_HOSTS, L"IPv4 address format error", 0, HostsFileList[FileIndex].FileName.c_str(), Line);
						return EXIT_FAILURE;
					}

				//Make responses.
					DNS_Record_A = (pdns_record_a)(HostsTableTemp.Response.get() + HostsTableTemp.Length);
					DNS_Record_A->Name = htons(DNS_QUERY_PTR);
					DNS_Record_A->Classes = htons(DNS_CLASS_IN);
					DNS_Record_A->TTL = htonl(Parameter.HostsDefaultTTL);
					DNS_Record_A->Type = htons(DNS_RECORD_A);
					DNS_Record_A->Length = htons(sizeof(in_addr));

				//Convert addresses.
					memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
					memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, Data.c_str() + VerticalIndex, Index - VerticalIndex);
					if (AddressStringToBinary(Addr.get(), &DNS_Record_A->Addr, AF_INET, Result) == EXIT_FAILURE)
					{
						PrintError(LOG_ERROR_HOSTS, L"IPv4 address format error", Result, HostsFileList[FileIndex].FileName.c_str(), Line);
						return EXIT_FAILURE;
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
		PrintError(LOG_ERROR_HOSTS, L"Regular expression pattern error", Error.code(), HostsFileList[FileIndex].FileName.c_str(), Line);
		return EXIT_FAILURE;
	}

//Add to global HostsTable.
	if (HostsTableTemp.Length >= sizeof(dns_qry) + sizeof(in_addr)) //Shortest reply is a A Records with Question part.
	{
		HostsTableTemp.Type = HOSTS_NORMAL;
		for (auto &HostsFileSetIter:*HostsFileSetModificating)
		{
			if (HostsFileSetIter.FileIndex == FileIndex)
			{
				HostsFileSetIter.HostsList.push_back(HostsTableTemp);
				break;
			}
		}
	}

	return EXIT_SUCCESS;
}

//Read file names from data
#if defined(PLATFORM_WIN)
	size_t __fastcall ReadFileName(std::string Data, const size_t DataOffset, std::vector<std::wstring> *ListData)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	size_t ReadFileName(std::string Data, const size_t DataOffset, std::vector<std::wstring> *ListData, std::vector<std::string> *sListData)
#endif
{
//Initialization
	std::string NameStringTemp;
	std::wstring wNameStringTemp;

//Read file name.
	for (SSIZE_T Result = DataOffset;Result < (SSIZE_T)Data.length();++Result)
	{
		if (Result == (SSIZE_T)(Data.length() - 1U))
		{
			NameStringTemp.append(Data, Result, 1U);
		//Case Convert.
		#if defined(PLATFORM_WIN) //Case-insensitive on Windows
			for (auto &StringIter:NameStringTemp)
			{
				if (StringIter > ASCII_AT && StringIter < ASCII_BRACKETS_LEAD)
					StringIter += ASCII_UPPER_TO_LOWER;
			}
		#endif

		//Add to global list.
			MBSToWCSString(wNameStringTemp, NameStringTemp.c_str());
			if (ListData->empty())
			{
				ListData->push_back(wNameStringTemp);
			}
			else {
				for (auto IPFilterFileTableIter = ListData->begin();IPFilterFileTableIter < ListData->end();++IPFilterFileTableIter)
				{
					if (*IPFilterFileTableIter == wNameStringTemp)
						break;

					if (IPFilterFileTableIter + 1U == ListData->end())
					{
						ListData->push_back(wNameStringTemp);
						break;
					}
				}
			}

		#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			if (sListData->empty())
			{
				sListData->push_back(NameStringTemp);
			}
			else {
				for (auto IPFilterFileTableIter = sListData->begin();IPFilterFileTableIter < sListData->end();++IPFilterFileTableIter)
				{
					if (*IPFilterFileTableIter == NameStringTemp)
						break;

					if (IPFilterFileTableIter + 1U == sListData->end())
					{
						sListData->push_back(NameStringTemp);
						break;
					}
				}
			}
		#endif
		}
		else if (Data[Result] == ASCII_VERTICAL)
		{
		//Case Convert.
		#if defined(PLATFORM_WIN) //Case-insensitive on Windows
			for (auto &StringIter:NameStringTemp)
			{
				if (StringIter > ASCII_AT && StringIter < ASCII_BRACKETS_LEAD)
					StringIter += ASCII_UPPER_TO_LOWER;
			}
		#endif

		//Add to global list.
			MBSToWCSString(wNameStringTemp, NameStringTemp.c_str());
			if (ListData->empty())
			{
				ListData->push_back(wNameStringTemp);
			}
			else {
				for (auto IPFilterFileTableIter = ListData->begin();IPFilterFileTableIter < ListData->end();++IPFilterFileTableIter)
				{
					if (*IPFilterFileTableIter == wNameStringTemp)
						break;

					if (IPFilterFileTableIter + 1U == ListData->end())
					{
						ListData->push_back(wNameStringTemp);
						break;
					}
				}
			}

		#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			if (sListData->empty())
			{
				sListData->push_back(NameStringTemp);
			}
			else {
				for (auto IPFilterFileTableIter = sListData->begin();IPFilterFileTableIter < sListData->end();++IPFilterFileTableIter)
				{
					if (*IPFilterFileTableIter == NameStringTemp)
						break;

					if (IPFilterFileTableIter + 1U == sListData->end())
					{
						sListData->push_back(NameStringTemp);
						break;
					}
				}
			}
		#endif

			NameStringTemp.clear();
			wNameStringTemp.clear();
		}
		else {
			NameStringTemp.append(Data, Result, 1U);
		}
	}

	return EXIT_SUCCESS;
}

//Read listen address
size_t __fastcall ReadListenAddress(std::string Data, const size_t DataOffset, const uint16_t Protocol, const size_t FileIndex, const size_t Line)
{
	SSIZE_T Result = 0;

//IPv6
	if (Protocol == AF_INET6)
	{
		if (Data.length() > DataOffset + 6U && (Data.length() < DataOffset + 48U || Data.find(ASCII_VERTICAL) != std::string::npos))
		{
		//IPv6 address and port check.
			if (Data.find(ASCII_BRACKETS_LEAD) == std::string::npos || Data.find(ASCII_BRACKETS_TRAIL) == std::string::npos || 
				Data.find(ASCII_BRACKETS_TRAIL) < DataOffset + IPV6_SHORTEST_ADDRSTRING)
			{
				PrintError(LOG_ERROR_PARAMETER, L"IPv6 Listen address format error", 0, ConfigFileList[FileIndex].c_str(), Line);
				return EXIT_FAILURE;
			}

			std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());
			memset(Target.get(), 0, ADDR_STRING_MAXSIZE);
			std::shared_ptr<sockaddr_storage> SockAddr(new sockaddr_storage());
			memset(SockAddr.get(), 0, sizeof(sockaddr_storage));

		//Multi requesting
			if (Data.find(ASCII_VERTICAL) != std::string::npos)
			{
				Data.erase(0, DataOffset);

			//Delete all front brackets and port colon.
				while (Data.find(ASCII_BRACKETS_LEAD) != std::string::npos)
					Data.erase(Data.find(ASCII_BRACKETS_LEAD), 1U);
				while (Data.find("]:") != std::string::npos)
					Data.erase(Data.find("]:") + 1U, 1U);

			//Read data.
				while (Data.find(ASCII_BRACKETS_TRAIL) != std::string::npos && Data.find(ASCII_VERTICAL) != std::string::npos && Data.find(ASCII_BRACKETS_TRAIL) < Data.find(ASCII_VERTICAL))
				{
				//Convert IPv6 address.
					memcpy_s(Target.get(), ADDR_STRING_MAXSIZE, Data.c_str(), Data.find(ASCII_BRACKETS_TRAIL));
					if (AddressStringToBinary(Target.get(), &((PSOCKADDR_IN6)SockAddr.get())->sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
					{
						PrintError(LOG_ERROR_PARAMETER, L"IPv6 Listen address format error", Result, ConfigFileList[FileIndex].c_str(), Line);
						return EXIT_FAILURE;
					}

				//Convert IPv6 Port.
					Data.erase(0, Data.find(ASCII_BRACKETS_TRAIL) + 1U);
					memset(Target.get(), 0, ADDR_STRING_MAXSIZE);
					memcpy_s(Target.get(), ADDR_STRING_MAXSIZE, Data.c_str(), Data.find(ASCII_VERTICAL));
					Result = ServiceNameToHex(Target.get());
					if (Result == 0)
					{
						Result = strtoul(Target.get(), nullptr, 0);
						if (errno == ERANGE || Result <= 0 || Result > UINT16_MAX)
						{
							PrintError(LOG_ERROR_PARAMETER, L"IPv6 Listen port error", 0, ConfigFileList[FileIndex].c_str(), Line);
							return EXIT_FAILURE;
						}
						else {
							((PSOCKADDR_IN6)SockAddr.get())->sin6_port = htons((uint16_t)Result);
						}
					}
					memset(Target.get(), 0, ADDR_STRING_MAXSIZE);

				//Add to global list.
					SockAddr->ss_family = AF_INET6;
					Parameter.ListenAddress_IPv6->push_back(*SockAddr);
					memset(SockAddr.get(), 0, sizeof(sockaddr_storage));
					Data.erase(0, Data.find(ASCII_VERTICAL) + 1U);
				}

			//Last data
				//Convert IPv6 address.
				if (Data.find(ASCII_BRACKETS_TRAIL) != std::string::npos)
				{
					memcpy_s(Target.get(), ADDR_STRING_MAXSIZE, Data.c_str(), Data.find(ASCII_BRACKETS_TRAIL));
				}
				else {
					PrintError(LOG_ERROR_PARAMETER, L"IPv6 Listen address format error", Result, ConfigFileList[FileIndex].c_str(), Line);
					return EXIT_FAILURE;
				}
				if (AddressStringToBinary(Target.get(), &((PSOCKADDR_IN6)SockAddr.get())->sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_PARAMETER, L"IPv6 Listen address format error", Result, ConfigFileList[FileIndex].c_str(), Line);
					return EXIT_FAILURE;
				}

				//Convert IPv6 Port.
				Data.erase(0, Data.find(ASCII_BRACKETS_TRAIL) + 1U);
				memset(Target.get(), 0, ADDR_STRING_MAXSIZE);
				memcpy_s(Target.get(), ADDR_STRING_MAXSIZE, Data.c_str(), Data.length());
				Result = ServiceNameToHex(Target.get());
				if (Result == 0)
				{
					Result = strtoul(Target.get(), nullptr, 0);
					if (errno == ERANGE || Result <= 0 || Result > UINT16_MAX)
					{
						PrintError(LOG_ERROR_PARAMETER, L"IPv6 Listen port error", 0, ConfigFileList[FileIndex].c_str(), Line);
						return EXIT_FAILURE;
					}
					else {
						((PSOCKADDR_IN6)SockAddr.get())->sin6_port = htons((uint16_t)Result);
					}
				}

			//Add to global list.
				SockAddr->ss_family = AF_INET6;
				Parameter.ListenAddress_IPv6->push_back(*SockAddr);
			}
			else {
			//Convert IPv6 address.
				memcpy_s(Target.get(), ADDR_STRING_MAXSIZE, Data.c_str() + DataOffset + 1U, Data.find(ASCII_BRACKETS_TRAIL) - DataOffset - 1U);
				if (AddressStringToBinary(Target.get(), &((PSOCKADDR_IN6)SockAddr.get())->sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_PARAMETER, L"IPv6 Listen address format error", Result, ConfigFileList[FileIndex].c_str(), Line);
					return EXIT_FAILURE;
				}

			//Convert IPv6 Port.
				Result = ServiceNameToHex(Data.c_str() + Data.find(ASCII_BRACKETS_TRAIL) + 2U);
				if (Result == 0)
				{
					Result = strtoul(Data.c_str() + Data.find(ASCII_BRACKETS_TRAIL) + 2U, nullptr, 0);
					if (errno == ERANGE || Result <= 0 || Result > UINT16_MAX)
					{
						PrintError(LOG_ERROR_PARAMETER, L"IPv6 Listen port error", 0, ConfigFileList[FileIndex].c_str(), Line);
						return EXIT_FAILURE;
					}
					else {
						((PSOCKADDR_IN6)SockAddr.get())->sin6_port = htons((uint16_t)Result);
					}
				}

				SockAddr->ss_family = AF_INET6;
				Parameter.ListenAddress_IPv6->push_back(*SockAddr);
			}
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
			return EXIT_FAILURE;
		}
	}
//IPv4
	else {
		if (Data.length() > DataOffset + 8U && (Data.length() < DataOffset + 22U || Data.find(ASCII_VERTICAL) != std::string::npos))
		{
		//IPv4 address and port check
			if (Data.find(ASCII_COLON) == std::string::npos || Data.find(ASCII_COLON) < DataOffset + IPV4_SHORTEST_ADDRSTRING)
			{
				PrintError(LOG_ERROR_PARAMETER, L"IPv4 Listen address format error", 0, ConfigFileList[FileIndex].c_str(), Line);
				return EXIT_FAILURE;
			}

			std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());
			memset(Target.get(), 0, ADDR_STRING_MAXSIZE);
			std::shared_ptr<sockaddr_storage> SockAddr(new sockaddr_storage());
			memset(SockAddr.get(), 0, sizeof(sockaddr_storage));

		//Multi requesting.
			if (Data.find(ASCII_VERTICAL) != std::string::npos)
			{
				Data.erase(0, DataOffset);

			//Read data.
				while (Data.find(ASCII_COLON) != std::string::npos && Data.find(ASCII_VERTICAL) != std::string::npos && Data.find(ASCII_COLON) < Data.find(ASCII_VERTICAL))
				{
				//Convert IPv4 address.
					memcpy_s(Target.get(), ADDR_STRING_MAXSIZE, Data.c_str(), Data.find(ASCII_COLON));
					if (AddressStringToBinary(Target.get(), &((PSOCKADDR_IN)SockAddr.get())->sin_addr, AF_INET, Result) == EXIT_FAILURE)
					{
						PrintError(LOG_ERROR_PARAMETER, L"IPv4 Listen address format error", Result, ConfigFileList[FileIndex].c_str(), Line);
						return EXIT_FAILURE;
					}

				//Convert IPv4 Port.
					Data.erase(0, Data.find(ASCII_COLON) + 1U);
					memset(Target.get(), 0, ADDR_STRING_MAXSIZE);
					memcpy_s(Target.get(), ADDR_STRING_MAXSIZE, Data.c_str(), Data.find(ASCII_VERTICAL));
					Result = ServiceNameToHex(Target.get());
					if (Result == 0)
					{
						Result = strtoul(Target.get(), nullptr, 0);
						if (errno == ERANGE || Result <= 0 || Result > UINT16_MAX)
						{
							PrintError(LOG_ERROR_PARAMETER, L"IPv4 Listen port error", 0, ConfigFileList[FileIndex].c_str(), Line);
							return EXIT_FAILURE;
						}
						else {
							((PSOCKADDR_IN)SockAddr.get())->sin_port = htons((uint16_t)Result);
						}
					}
					memset(Target.get(), 0, ADDR_STRING_MAXSIZE);

				//Add to global list.
					SockAddr->ss_family = AF_INET;
					Parameter.ListenAddress_IPv4->push_back(*SockAddr);
					memset(SockAddr.get(), 0, sizeof(sockaddr_storage));
					Data.erase(0, Data.find(ASCII_VERTICAL) + 1U);
				}

			//Last data
				//Convert IPv4 address.
				if (Data.find(ASCII_COLON) != std::string::npos)
				{
					memcpy_s(Target.get(), ADDR_STRING_MAXSIZE, Data.c_str(), Data.find(ASCII_COLON));
				}
				else {
					PrintError(LOG_ERROR_PARAMETER, L"IPv4 Listen address format error", Result, ConfigFileList[FileIndex].c_str(), Line);
					return EXIT_FAILURE;
				}
				if (AddressStringToBinary(Target.get(), &((PSOCKADDR_IN)SockAddr.get())->sin_addr, AF_INET, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_PARAMETER, L"IPv4 Listen address format error", Result, ConfigFileList[FileIndex].c_str(), Line);
					return EXIT_FAILURE;
				}

				//Convert IPv4 Port.
				Data.erase(0, Data.find(ASCII_COLON) + 1U);
				memset(Target.get(), 0, ADDR_STRING_MAXSIZE);
				memcpy_s(Target.get(), ADDR_STRING_MAXSIZE, Data.c_str(), Data.length());
				Result = ServiceNameToHex(Target.get());
				if (Result == 0)
				{
					Result = strtoul(Target.get(), nullptr, 0);
					if (errno == ERANGE || Result <= 0 || Result > UINT16_MAX)
					{
						PrintError(LOG_ERROR_PARAMETER, L"IPv4 Listen port error", 0, ConfigFileList[FileIndex].c_str(), Line);
						return EXIT_FAILURE;
					}
					else {
						((PSOCKADDR_IN)SockAddr.get())->sin_port = htons((uint16_t)Result);
					}
				}
				Target.reset();

			//Add to global list.
				SockAddr->ss_family = AF_INET;
				Parameter.ListenAddress_IPv4->push_back(*SockAddr);
			}
			else {
			//Convert IPv4 address.
				memcpy_s(Target.get(), ADDR_STRING_MAXSIZE, Data.c_str() + DataOffset, Data.find(ASCII_COLON) - DataOffset);
				if (AddressStringToBinary(Target.get(), &((PSOCKADDR_IN)SockAddr.get())->sin_addr, AF_INET, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_PARAMETER, L"IPv4 Listen address format error", Result, ConfigFileList[FileIndex].c_str(), Line);
					return EXIT_FAILURE;
				}
				Target.reset();

			//Convert IPv4 Port.
				Result = ServiceNameToHex(Data.c_str() + Data.find(ASCII_COLON) + 1U);
				if (Result == 0)
				{
					Result = strtoul(Data.c_str() + Data.find(ASCII_COLON) + 1U, nullptr, 0);
					if (errno == ERANGE || Result <= 0 || Result > UINT16_MAX)
					{
						PrintError(LOG_ERROR_PARAMETER, L"IPv4 Listen port error", 0, ConfigFileList[FileIndex].c_str(), Line);
						return EXIT_FAILURE;
					}
					else {
						((PSOCKADDR_IN)SockAddr.get())->sin_port = htons((uint16_t)Result);
					}
				}

				SockAddr->ss_family = AF_INET;
				Parameter.ListenAddress_IPv4->push_back(*SockAddr);
			}
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}

//Read single address from data
size_t __fastcall ReadSingleAddress(std::string Data, const size_t DataOffset, sockaddr_storage &SockAddr, const uint16_t Protocol, const size_t FileIndex, const size_t Line)
{
//Initialization
	SSIZE_T Result = 0;
	std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());
	memset(Target.get(), 0, ADDR_STRING_MAXSIZE);

//IPv6
	if (Protocol == AF_INET6)
	{
		if (Data.length() > DataOffset + 6U && Data.length() < DataOffset + 48U)
		{
		//IPv6 address and port check.
			if (Data.find(ASCII_BRACKETS_LEAD) == std::string::npos || Data.find(ASCII_BRACKETS_TRAIL) == std::string::npos || 
				Data.find(ASCII_BRACKETS_TRAIL) < DataOffset + IPV6_SHORTEST_ADDRSTRING)
			{
				PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 address format error", 0, ConfigFileList[FileIndex].c_str(), Line);
				return EXIT_FAILURE;
			}

		//Convert IPv6 address.
			memcpy_s(Target.get(), ADDR_STRING_MAXSIZE, Data.c_str() + DataOffset + 1U, Data.find(ASCII_BRACKETS_TRAIL) - DataOffset - 1U);
			if (AddressStringToBinary(Target.get(), &((PSOCKADDR_IN6)&SockAddr)->sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
			{
				PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 address format error", Result, ConfigFileList[FileIndex].c_str(), Line);
				return EXIT_FAILURE;
			}

		//Convert IPv6 Port.
			Result = ServiceNameToHex(Data.c_str() + Data.find(ASCII_BRACKETS_TRAIL) + 2U);
			if (Result == 0)
			{
				Result = strtoul(Data.c_str() + Data.find(ASCII_BRACKETS_TRAIL) + 2U, nullptr, 0);
				if (errno == ERANGE || Result <= 0 || Result > UINT16_MAX)
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 port error", 0, ConfigFileList[FileIndex].c_str(), Line);
					return EXIT_FAILURE;
				}
				else {
					((PSOCKADDR_IN6)&SockAddr)->sin6_port = htons((uint16_t)Result);
				}
			}

			SockAddr.ss_family = AF_INET6;
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
			return EXIT_FAILURE;
		}
	}
//IPv4
	else {
		if (Data.length() > DataOffset + 8U && Data.length() < DataOffset + 22U)
		{
		//IPv4 address and port check
			if (Data.find(ASCII_COLON) == std::string::npos || Data.find(ASCII_COLON) < DataOffset + IPV4_SHORTEST_ADDRSTRING)
			{
				PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 address format error", 0, ConfigFileList[FileIndex].c_str(), Line);
				return EXIT_FAILURE;
			}

		//Convert IPv4 address.
			memcpy_s(Target.get(), ADDR_STRING_MAXSIZE, Data.c_str() + DataOffset, Data.find(ASCII_COLON) - DataOffset);
			if (AddressStringToBinary(Target.get(), &((PSOCKADDR_IN)&SockAddr)->sin_addr, AF_INET, Result) == EXIT_FAILURE)
			{
				PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 address format error", Result, ConfigFileList[FileIndex].c_str(), Line);
				return EXIT_FAILURE;
			}

		//Convert IPv4 Port.
			Result = ServiceNameToHex(Data.c_str() + Data.find(ASCII_COLON) + 1U);
			if (Result == 0)
			{
				Result = strtoul(Data.c_str() + Data.find(ASCII_COLON) + 1U, nullptr, 0);
				if (errno == ERANGE || Result <= 0 || Result > UINT16_MAX)
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 port error", 0, ConfigFileList[FileIndex].c_str(), Line);
					return EXIT_FAILURE;
				}
				else {
					((PSOCKADDR_IN)&SockAddr)->sin_port = htons((uint16_t)Result);
				}
			}

			SockAddr.ss_family = AF_INET;
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}

//Read multiple addresses from data
size_t __fastcall ReadMultipleAddresses(std::string Data, const size_t DataOffset, sockaddr_storage &SockAddr, const uint16_t Protocol, const size_t FileIndex, const size_t Line)
{
	SSIZE_T Result = 0;

//IPv6
	if (Protocol == AF_INET6)
	{
		if (Data.length() > DataOffset + 6U && (Data.length() < DataOffset + 48U || Data.find(ASCII_VERTICAL) != std::string::npos))
		{
		//IPv6 address and port check.
			if (Data.find(ASCII_BRACKETS_LEAD) == std::string::npos || Data.find(ASCII_BRACKETS_TRAIL) == std::string::npos || 
				Data.find(ASCII_BRACKETS_TRAIL) < DataOffset + IPV6_SHORTEST_ADDRSTRING)
			{
				PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 address format error", 0, ConfigFileList[FileIndex].c_str(), Line);
				return EXIT_FAILURE;
			}

			std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());
			memset(Target.get(), 0, ADDR_STRING_MAXSIZE);
		//Multi requesting
			if (Data.find(ASCII_VERTICAL) != std::string::npos)
			{
				std::shared_ptr<DNS_SERVER_DATA> DNSServerDataTemp(new DNS_SERVER_DATA());
				memset(DNSServerDataTemp.get(), 0, sizeof(DNS_SERVER_DATA));
				Data.erase(0, DataOffset);

			//Delete all front brackets and port colon.
				while (Data.find(ASCII_BRACKETS_LEAD) != std::string::npos)
					Data.erase(Data.find(ASCII_BRACKETS_LEAD), 1U);
				while (Data.find("]:") != std::string::npos)
					Data.erase(Data.find("]:") + 1U, 1U);

			//Read data.
				while (Data.find(ASCII_BRACKETS_TRAIL) != std::string::npos && Data.find(ASCII_VERTICAL) != std::string::npos && Data.find(ASCII_BRACKETS_TRAIL) < Data.find(ASCII_VERTICAL))
				{
				//Convert IPv6 address.
					memcpy_s(Target.get(), ADDR_STRING_MAXSIZE, Data.c_str(), Data.find(ASCII_BRACKETS_TRAIL));
					if (AddressStringToBinary(Target.get(), &DNSServerDataTemp->AddressData.IPv6.sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
					{
						PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 address format error", Result, ConfigFileList[FileIndex].c_str(), Line);
						return EXIT_FAILURE;
					}

				//Convert IPv6 Port.
					Data.erase(0, Data.find(ASCII_BRACKETS_TRAIL) + 1U);
					memset(Target.get(), 0, ADDR_STRING_MAXSIZE);
					memcpy_s(Target.get(), ADDR_STRING_MAXSIZE, Data.c_str(), Data.find(ASCII_VERTICAL));
					Result = ServiceNameToHex(Target.get());
					if (Result == 0)
					{
						Result = strtoul(Target.get(), nullptr, 0);
						if (errno == ERANGE || Result <= 0 || Result > UINT16_MAX)
						{
							PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 port error", 0, ConfigFileList[FileIndex].c_str(), Line);
							return EXIT_FAILURE;
						}
						else {
							DNSServerDataTemp->AddressData.IPv6.sin6_port = htons((uint16_t)Result);
						}
					}
					memset(Target.get(), 0, ADDR_STRING_MAXSIZE);

				//Add to global list.
					DNSServerDataTemp->AddressData.Storage.ss_family = AF_INET6;
					Parameter.DNSTarget.IPv6_Multi->push_back(*DNSServerDataTemp);
					memset(DNSServerDataTemp.get(), 0, sizeof(DNS_SERVER_DATA));
					Data.erase(0, Data.find(ASCII_VERTICAL) + 1U);
				}

			//Last data
				//Convert IPv6 address.
				if (Data.find(ASCII_BRACKETS_TRAIL) != std::string::npos)
				{
					memcpy_s(Target.get(), ADDR_STRING_MAXSIZE, Data.c_str(), Data.find(ASCII_BRACKETS_TRAIL));
				}
				else {
					PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 address format error", Result, ConfigFileList[FileIndex].c_str(), Line);
					return EXIT_FAILURE;
				}
				if (AddressStringToBinary(Target.get(), &DNSServerDataTemp->AddressData.IPv6.sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 address format error", Result, ConfigFileList[FileIndex].c_str(), Line);
					return EXIT_FAILURE;
				}

			//Convert IPv6 Port.
				Data.erase(0, Data.find(ASCII_BRACKETS_TRAIL) + 1U);
				memset(Target.get(), 0, ADDR_STRING_MAXSIZE);
				memcpy_s(Target.get(), ADDR_STRING_MAXSIZE, Data.c_str(), Data.length());
				Result = ServiceNameToHex(Target.get());
				if (Result == 0)
				{
					Result = strtoul(Target.get(), nullptr, 0);
					if (errno == ERANGE || Result <= 0 || Result > UINT16_MAX)
					{
						PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 port error", 0, ConfigFileList[FileIndex].c_str(), Line);
						return EXIT_FAILURE;
					}
					else {
						DNSServerDataTemp->AddressData.IPv6.sin6_port = htons((uint16_t)Result);
					}
				}

			//Add to global list.
				DNSServerDataTemp->AddressData.Storage.ss_family = AF_INET6;
				Parameter.DNSTarget.IPv6_Multi->push_back(*DNSServerDataTemp);
			}
			else {
			//Convert IPv6 address.
				memcpy_s(Target.get(), ADDR_STRING_MAXSIZE, Data.c_str() + DataOffset + 1U, Data.find(ASCII_BRACKETS_TRAIL) - DataOffset - 1U);
				if (AddressStringToBinary(Target.get(), &((PSOCKADDR_IN6)&SockAddr)->sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 address format error", Result, ConfigFileList[FileIndex].c_str(), Line);
					return EXIT_FAILURE;
				}

			//Convert IPv6 Port.
				Result = ServiceNameToHex(Data.c_str() + Data.find(ASCII_BRACKETS_TRAIL) + 2U);
				if (Result == 0)
				{
					Result = strtoul(Data.c_str() + Data.find(ASCII_BRACKETS_TRAIL) + 2U, nullptr, 0);
					if (errno == ERANGE || Result <= 0 || Result > UINT16_MAX)
					{
						PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 port error", 0, ConfigFileList[FileIndex].c_str(), Line);
						return EXIT_FAILURE;
					}
					else {
						((PSOCKADDR_IN6)&SockAddr)->sin6_port = htons((uint16_t)Result);
					}
				}

				SockAddr.ss_family = AF_INET6;
			}
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
			return EXIT_FAILURE;
		}
	}
//IPv4
	else {
		if (Data.length() > DataOffset + 8U && (Data.length() < DataOffset + 22U || Data.find(ASCII_VERTICAL) != std::string::npos))
		{
		//IPv4 address and port check
			if (Data.find(ASCII_COLON) == std::string::npos || Data.find(ASCII_COLON) < DataOffset + IPV4_SHORTEST_ADDRSTRING)
			{
				PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 address format error", 0, ConfigFileList[FileIndex].c_str(), Line);
				return EXIT_FAILURE;
			}

			std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());
			memset(Target.get(), 0, ADDR_STRING_MAXSIZE);
		//Multi requesting.
			if (Data.find(ASCII_VERTICAL) != std::string::npos)
			{
				std::shared_ptr<DNS_SERVER_DATA> DNSServerDataTemp(new DNS_SERVER_DATA());
				memset(DNSServerDataTemp.get(), 0, sizeof(DNS_SERVER_DATA));
				Data.erase(0, DataOffset);

			//Read data.
				while (Data.find(ASCII_COLON) != std::string::npos && Data.find(ASCII_VERTICAL) != std::string::npos && Data.find(ASCII_COLON) < Data.find(ASCII_VERTICAL))
				{
				//Convert IPv4 address.
					memcpy_s(Target.get(), ADDR_STRING_MAXSIZE, Data.c_str(), Data.find(ASCII_COLON));
					if (AddressStringToBinary(Target.get(), &DNSServerDataTemp->AddressData.IPv4.sin_addr, AF_INET, Result) == EXIT_FAILURE)
					{
						PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 address format error", Result, ConfigFileList[FileIndex].c_str(), Line);
						return EXIT_FAILURE;
					}

				//Convert IPv4 Port.
					Data.erase(0, Data.find(ASCII_COLON) + 1U);
					memset(Target.get(), 0, ADDR_STRING_MAXSIZE);
					memcpy_s(Target.get(), ADDR_STRING_MAXSIZE, Data.c_str(), Data.find(ASCII_VERTICAL));
					Result = ServiceNameToHex(Target.get());
					if (Result == 0)
					{
						Result = strtoul(Target.get(), nullptr, 0);
						if (errno == ERANGE || Result <= 0 || Result > UINT16_MAX)
						{
							PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 port error", 0, ConfigFileList[FileIndex].c_str(), Line);
							return EXIT_FAILURE;
						}
						else {
							DNSServerDataTemp->AddressData.IPv4.sin_port = htons((uint16_t)Result);
						}
					}
					memset(Target.get(), 0, ADDR_STRING_MAXSIZE);

				//Add to global list.
					DNSServerDataTemp->AddressData.Storage.ss_family = AF_INET;
					Parameter.DNSTarget.IPv4_Multi->push_back(*DNSServerDataTemp);
					memset(DNSServerDataTemp.get(), 0, sizeof(DNS_SERVER_DATA));
					Data.erase(0, Data.find(ASCII_VERTICAL) + 1U);
				}

			//Last data
				//Convert IPv4 address.
				if (Data.find(ASCII_COLON) != std::string::npos)
				{
					memcpy_s(Target.get(), ADDR_STRING_MAXSIZE, Data.c_str(), Data.find(ASCII_COLON));
				}
				else {
					PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 address format error", Result, ConfigFileList[FileIndex].c_str(), Line);
					return EXIT_FAILURE;
				}
				if (AddressStringToBinary(Target.get(), &DNSServerDataTemp->AddressData.IPv4.sin_addr, AF_INET, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 address format error", Result, ConfigFileList[FileIndex].c_str(), Line);
					return EXIT_FAILURE;
				}

			//Convert IPv4 Port.
				Data.erase(0, Data.find(ASCII_COLON) + 1U);
				memset(Target.get(), 0, ADDR_STRING_MAXSIZE);
				memcpy_s(Target.get(), ADDR_STRING_MAXSIZE, Data.c_str(), Data.length());
				Result = ServiceNameToHex(Target.get());
				if (Result == 0)
				{
					Result = strtoul(Target.get(), nullptr, 0);
					if (errno == ERANGE || Result <= 0 || Result > UINT16_MAX)
					{
						PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 port error", 0, ConfigFileList[FileIndex].c_str(), Line);
						return EXIT_FAILURE;
					}
					else {
						DNSServerDataTemp->AddressData.IPv4.sin_port = htons((uint16_t)Result);
					}
				}
				Target.reset();

			//Add to global list.
				DNSServerDataTemp->AddressData.Storage.ss_family = AF_INET;
				Parameter.DNSTarget.IPv4_Multi->push_back(*DNSServerDataTemp);
			}
			else {
			//Convert IPv4 address.
				memcpy_s(Target.get(), ADDR_STRING_MAXSIZE, Data.c_str() + DataOffset, Data.find(ASCII_COLON) - DataOffset);
				if (AddressStringToBinary(Target.get(), &((PSOCKADDR_IN)&SockAddr)->sin_addr, AF_INET, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 address format error", Result, ConfigFileList[FileIndex].c_str(), Line);
					return EXIT_FAILURE;
				}
				Target.reset();

			//Convert IPv4 Port.
				Result = ServiceNameToHex(Data.c_str() + Data.find(ASCII_COLON) + 1U);
				if (Result == 0)
				{
					Result = strtoul(Data.c_str() + Data.find(ASCII_COLON) + 1U, nullptr, 0);
					if (errno == ERANGE || Result <= 0 || Result > UINT16_MAX)
					{
						PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 port error", 0, ConfigFileList[FileIndex].c_str(), Line);
						return EXIT_FAILURE;
					}
					else {
						((PSOCKADDR_IN)&SockAddr)->sin_port = htons((uint16_t)Result);
					}
				}

				SockAddr.ss_family = AF_INET;
			}
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}

//Read TTL or HopLimit from data
size_t __fastcall ReadHopLimitData(std::string Data, const size_t DataOffset, uint8_t &HopLimit, const uint16_t Protocol, const size_t FileIndex, const size_t Line)
{
	SSIZE_T Result = 0;
	if (Data.length() > DataOffset && Data.length() < DataOffset + ADDR_STRING_MAXSIZE)
	{
		if (Data.find(ASCII_VERTICAL) == std::string::npos)
		{
			Result = strtoul(Data.c_str() + DataOffset, nullptr, 0);
			if (errno != ERANGE && Result > 0 && Result < UINT8_MAX)
				HopLimit = (uint8_t)Result;
		}
		else {
			std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());
			memset(Target.get(), 0, ADDR_STRING_MAXSIZE);
			Data.erase(0, DataOffset);
			size_t Index = 0;

			while (Data.find(ASCII_VERTICAL) != std::string::npos && Data.find(ASCII_VERTICAL) > 0)
			{
				memset(Target.get(), 0, ADDR_STRING_MAXSIZE);
				memcpy_s(Target.get(), ADDR_STRING_MAXSIZE, Data.c_str(), Data.find(ASCII_VERTICAL));
				Data.erase(0, Data.find(ASCII_VERTICAL) + 1U);
				Result = strtoul(Target.get(), nullptr, 0);

			//Mark TTL or HopLimit.
				if (Protocol == AF_INET6) //IPv6
				{
					if (errno != ERANGE && Result > 0 && Result < UINT8_MAX && Parameter.DNSTarget.IPv6_Multi->size() > Index)
						Parameter.DNSTarget.IPv6_Multi->at(Index).HopLimitData.TTL = (uint8_t)Result;
				}
				else { //IPv4
					if (errno != ERANGE && Result > 0 && Result < UINT8_MAX && Parameter.DNSTarget.IPv4_Multi->size() > Index)
						Parameter.DNSTarget.IPv4_Multi->at(Index).HopLimitData.TTL = (uint8_t)Result;
				}

				++Index;
			}

		//Last item
			memset(Target.get(), 0, ADDR_STRING_MAXSIZE);
			memcpy_s(Target.get(), ADDR_STRING_MAXSIZE, Data.c_str(), Data.length());
			Result = strtoul(Target.get(), nullptr, 0);
			if (Protocol == AF_INET6) //IPv6
			{
				if (errno != ERANGE && Result > 0 && Result < UINT8_MAX && Parameter.DNSTarget.IPv6_Multi->size() > Index)
					Parameter.DNSTarget.IPv6_Multi->at(Index).HopLimitData.TTL = (uint8_t)Result;
			}
			else { //IPv4
				if (errno != ERANGE && Result > 0 && Result < UINT8_MAX && Parameter.DNSTarget.IPv4_Multi->size() > Index)
					Parameter.DNSTarget.IPv4_Multi->at(Index).HopLimitData.TTL = (uint8_t)Result;
			}
		}
	}
	else {
		PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

//Read Provider Name of DNSCurve server
#if defined(ENABLE_LIBSODIUM)
size_t __fastcall ReadDNSCurveProviderName(std::string Data, const size_t DataOffset, PSTR ProviderNameData, const size_t FileIndex, const size_t Line)
{
	if (Data.length() > DataOffset + DOMAIN_MINSIZE && Data.length() < DataOffset + DOMAIN_DATA_MAXSIZE)
	{
		for (SSIZE_T Result = DataOffset;Result < (SSIZE_T)(Data.length() - DataOffset);++Result)
		{
			for (size_t Index = 0;Index < strnlen_s(Parameter.DomainTable, DOMAIN_MAXSIZE);++Index)
			{
				if (Index == strnlen_s(Parameter.DomainTable, DOMAIN_MAXSIZE) - 1U && Data[Result] != Parameter.DomainTable[Index])
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNSCurve Provider Names error", 0, ConfigFileList[FileIndex].c_str(), Line);
					return EXIT_FAILURE;
				}
				if (Data[Result] == Parameter.DomainTable[Index])
					break;
			}
		}

		memcpy_s(ProviderNameData, DOMAIN_MAXSIZE, Data.c_str() + DataOffset, Data.length() - DataOffset);
	}
	else {
		PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

//Read DNSCurve secret keys, public keys and fingerprints
size_t __fastcall ReadDNSCurveKey(std::string Data, const size_t DataOffset, PUINT8 KeyData, const size_t FileIndex, const size_t Line)
{
//Initialization
	std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());
	memset(Target.get(), 0, ADDR_STRING_MAXSIZE);
	size_t ResultLength = 0;
	PSTR ResultPointer = nullptr;

//Convert to hexs.
	if (Data.length() > DataOffset + crypto_box_PUBLICKEYBYTES * 2U && Data.length() < DataOffset + crypto_box_PUBLICKEYBYTES * 3U)
	{
		SSIZE_T Result = sodium_hex2bin((PUCHAR)Target.get(), ADDR_STRING_MAXSIZE, Data.c_str() + DataOffset, Data.length() - DataOffset, ": ", &ResultLength, (const char **)&ResultPointer);
		if (Result == 0 && ResultLength == crypto_box_PUBLICKEYBYTES && ResultPointer != nullptr)
		{
			memcpy_s(KeyData, crypto_box_SECRETKEYBYTES, Target.get(), crypto_box_PUBLICKEYBYTES);
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"DNSCurve Keys error", 0, ConfigFileList[FileIndex].c_str(), Line);
			return EXIT_FAILURE;
		}
	}
	else {
		PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

//Read DNSCurve magic number
size_t __fastcall ReadMagicNumber(std::string Data, const size_t DataOffset, PSTR MagicNumber, const size_t FileIndex, const size_t Line)
{
	if (Data.length() == DataOffset + DNSCURVE_MAGIC_QUERY_LEN)
	{
		memcpy_s(MagicNumber, DNSCURVE_MAGIC_QUERY_LEN, Data.c_str() + DataOffset, DNSCURVE_MAGIC_QUERY_LEN);
	}
	else {
		PrintError(LOG_ERROR_PARAMETER, L"Data length error", 0, ConfigFileList[FileIndex].c_str(), Line);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
#endif

//Clear data in list
void __fastcall ClearListData(const size_t ClearType, const size_t FileIndex)
{
//Clear Hosts set.
	if (ClearType == READTEXT_HOSTS)
	{
		for (auto HostsFileSetIter = HostsFileSetModificating->begin();HostsFileSetIter != HostsFileSetModificating->end();++HostsFileSetIter)
		{
			if (HostsFileSetIter->FileIndex == FileIndex)
			{
				HostsFileSetModificating->erase(HostsFileSetIter);
				break;
			}
		}
	}

//Clear IPFilter set.
	else if (ClearType == READTEXT_IPFILTER)
	{
		for (auto IPFilterFileSetIter = IPFilterFileSetModificating->begin();IPFilterFileSetIter != IPFilterFileSetModificating->end();++IPFilterFileSetIter)
		{
			if (IPFilterFileSetIter->FileIndex == FileIndex)
			{
				IPFilterFileSetModificating->erase(IPFilterFileSetIter);
				break;
			}
		}
	}

	return;
}

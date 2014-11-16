// This code is part of Pcap_DNSProxy(Windows)
// Pcap_DNSProxy, A local DNS server base on WinPcap and LibPcap.
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

/* Old version(2014-07-03)
//Next line type define
#define NEXTLINETYPE_CRLF 1U          //Windows
#define NEXTLINETYPE_LF   2U          //Unix
#define NEXTLINETYPE_CR   3U          //Macintosh
*/

//Read Texts input types defines
#define READTEXT_PARAMETER     0
#define READTEXT_HOSTS         1U
#define READTEXT_IPFILTER      2U

//Compare addresses own defines
#define ADDRESS_COMPARE_LESS      1U
#define ADDRESS_COMPARE_EQUAL     2U
#define ADDRESS_COMPARE_GREATER   3U

extern Configuration Parameter;
extern std::vector<uint16_t> AcceptTypeList;
extern std::vector<HostsTable> *HostsListUsing, *HostsListModificating;
extern std::vector<AddressRange> *AddressRangeUsing, *AddressRangeModificating;
extern std::vector<ResultBlacklistTable> *ResultBlacklistUsing, *ResultBlacklistModificating;
extern DNSCurveConfiguration DNSCurveParameter;
extern std::mutex HostsListLock, AddressRangeLock, ResultBlacklistLock;

//Read texts
inline bool __fastcall ReadText(const FILE *Input, const size_t InputType, const PWSTR FileName)
{
//Initialization
	std::shared_ptr<char> FileBuffer(new char[FILE_BUFFER_SIZE]()), TextBuffer(new char[FILE_BUFFER_SIZE]()), Text(new char[FILE_BUFFER_SIZE]());
//	size_t FileLocation = 0, Encoding = 0, NextLineType = 0, ReadLength = 0, AdditionLength = 0, Line = 1U, Index = 0, Start = 0
	size_t ReadLength = 0, Index = 0, TextLength = 0, TextBufferLength = 0, Line = 0;
	auto CRLF_Length = false, /* LastRead = false, */ EraseBOM = true, Comments = false, Blacklist = false, Local = false;
	bool StopTemp[] = {false, false};

//Read data.
	while (!feof((FILE *)Input))
	{
	//Read file and Mark last read.
		ReadLength = fread_s(FileBuffer.get(), FILE_BUFFER_SIZE, sizeof(char), FILE_BUFFER_SIZE, (FILE *)Input);

	//Erase BOM of Unicode Transformation Format/UTF at first.
		if (EraseBOM)
		{
			if (ReadLength <= 4U)
			{
				PrintError(LOG_ERROR_PARAMETER, L"Data of a line is too short", NULL, FileName, Line);
				return false;
			}
			else {
				EraseBOM = false;
			}

		//8-bit Unicode Transformation Format/UTF-8 with BOM
//			if (FileBuffer.get()[0] == 0xFFFFFFEF && FileBuffer.get()[1U] == 0xFFFFFFBB && FileBuffer.get()[2U] == 0xFFFFFFBF) //0xEF, 0xBB, 0xBF(Unsigned char)
			if ((UCHAR)FileBuffer.get()[0] == 0xEF && (UCHAR)FileBuffer.get()[1U] == 0xBB && (UCHAR)FileBuffer.get()[2U] == 0xBF) //0xEF, 0xBB, 0xBF
			{
				memmove(FileBuffer.get(), FileBuffer.get() + BOM_UTF_8_LENGTH, FILE_BUFFER_SIZE - BOM_UTF_8_LENGTH);
				memset(FileBuffer.get() + FILE_BUFFER_SIZE - BOM_UTF_8_LENGTH, 0, BOM_UTF_8_LENGTH);
				ReadLength -= BOM_UTF_8_LENGTH;
			}
		//32-bit Unicode Transformation Format/UTF-32 Little Endian/LE
//			else if (FileBuffer.get()[0] == 0xFFFFFFFF && FileBuffer.get()[1U] == 0xFFFFFFFE && FileBuffer.get()[2U] == 0 && FileBuffer.get()[3U] == 0) //0xFF, 0xFE, 0x00, 0x00(Unsigned char)
			else if ((UCHAR)FileBuffer.get()[0] == 0xFF && (UCHAR)FileBuffer.get()[1U] == 0xFE && FileBuffer.get()[2U] == 0 && FileBuffer.get()[3U] == 0) //0xFF, 0xFE, 0x00, 0x00
			{
				memmove(FileBuffer.get(), FileBuffer.get() + BOM_UTF_32_LENGTH, FILE_BUFFER_SIZE - BOM_UTF_32_LENGTH);
				memset(FileBuffer.get() + FILE_BUFFER_SIZE - BOM_UTF_32_LENGTH, 0, BOM_UTF_32_LENGTH);
				ReadLength -= BOM_UTF_32_LENGTH;
			}
		//32-bit Unicode Transformation Format/UTF-32 Big Endian/BE
//			else if (FileBuffer.get()[0] == 0 && FileBuffer.get()[1U] == 0 && FileBuffer.get()[2U] == 0xFFFFFFFE && FileBuffer.get()[3U] == 0xFFFFFFFF) //0x00, 0x00, 0xFE, 0xFF(Unsigned char)
			else if (FileBuffer.get()[0] == 0 && FileBuffer.get()[1U] == 0 && (UCHAR)FileBuffer.get()[2U] == 0xFE && (UCHAR)FileBuffer.get()[3U] == 0xFF) //0x00, 0x00, 0xFE, 0xFF
			{
				memmove(FileBuffer.get(), FileBuffer.get() + BOM_UTF_32_LENGTH, FILE_BUFFER_SIZE - BOM_UTF_32_LENGTH);
				memset(FileBuffer.get() + FILE_BUFFER_SIZE - BOM_UTF_32_LENGTH, 0, BOM_UTF_32_LENGTH);
				ReadLength -= BOM_UTF_32_LENGTH;
			}
		//16-bit Unicode Transformation Format/UTF-16 Little Endian/LE
//			else if (FileBuffer.get()[0] == 0xFFFFFFFF && FileBuffer.get()[1U] == 0xFFFFFFFE) //0xFF, 0xFE(Unsigned char)
			else if ((UCHAR)FileBuffer.get()[0] == 0xFF && (UCHAR)FileBuffer.get()[1U] == 0xFE) //0xFF, 0xFE
			{
				memmove(FileBuffer.get(), FileBuffer.get() + BOM_UTF_16_LENGTH, FILE_BUFFER_SIZE - BOM_UTF_16_LENGTH);
				memset(FileBuffer.get() + FILE_BUFFER_SIZE - BOM_UTF_16_LENGTH, 0, BOM_UTF_16_LENGTH);
				ReadLength -= BOM_UTF_16_LENGTH;
			}
		//16-bit Unicode Transformation Format/UTF-16 Big Endian/BE
//			else if (FileBuffer.get()[0] == 0xFFFFFFFE && FileBuffer.get()[1U] == 0xFFFFFFFF) //0xFE, 0xFF(Unsigned char)
			else if ((UCHAR)FileBuffer.get()[0] == 0xFE && (UCHAR)FileBuffer.get()[1U] == 0xFF) //0xFE, 0xFF
			{
				memmove(FileBuffer.get(), FileBuffer.get() + BOM_UTF_16_LENGTH, FILE_BUFFER_SIZE - BOM_UTF_16_LENGTH);
				memset(FileBuffer.get() + FILE_BUFFER_SIZE - BOM_UTF_16_LENGTH, 0, BOM_UTF_16_LENGTH);
				ReadLength -= BOM_UTF_16_LENGTH;
			}
		//8-bit Unicode Transformation Format/UTF-8 without BOM/Microsoft Windows ANSI Codepages
//			else {
//				;
//			}
		}

	//Mark words.
		for (Index = 0;Index < ReadLength;Index++)
		{
			if (FileBuffer.get()[Index] != 0)
			{
				if (!CRLF_Length && (FileBuffer.get()[Index] == ASCII_CR || FileBuffer.get()[Index] == ASCII_LF))
					CRLF_Length = true;

				TextBuffer.get()[TextBufferLength] = FileBuffer.get()[Index];
				TextBufferLength++;
			}
		}

	//Lines length check
		if (!CRLF_Length)
		{
			if (InputType == READTEXT_HOSTS) //ReadHosts
				PrintError(LOG_ERROR_HOSTS, L"Data of a line is too long", NULL, FileName, Line);
			else if (InputType == READTEXT_IPFILTER) //ReadIPFilter
				PrintError(LOG_ERROR_IPFILTER, L"Data of a line is too long", NULL, FileName, Line);
			else //ReadParameter
				PrintError(LOG_ERROR_PARAMETER, L"Data of a line is too long", NULL, FileName, Line);

			return false;
		}
		else {
			CRLF_Length = false;
		}

		memset(FileBuffer.get(), 0, FILE_BUFFER_SIZE);
		memcpy(FileBuffer.get(), TextBuffer.get(), TextBufferLength);
		ReadLength = TextBufferLength;
		memset(TextBuffer.get(), 0, FILE_BUFFER_SIZE);
		TextBufferLength = 0;

/* Old version(2014-07-03)
	//Read Next Line Type.
		if (NextLineType == 0 && !ReadNextLineType(FileBuffer.get(), ReadLength, NextLineType))
		{
			if (InputType == READTEXT_HOSTS) //ReadHosts
				PrintError(LOG_ERROR_HOSTS, L"Text encoding error", NULL, FileName, Line);
			else if (InputType == READTEXT_IPFILTER) //ReadIPFilter
				PrintError(LOG_ERROR_IPFILTER, L"Text encoding error", NULL, FileName, Line);
			else //ReadParameter
				PrintError(LOG_ERROR_PARAMETER, L"Text encoding error", NULL, FileName, Line);

			return false;
		}
*/
	//Read data.
		for (Index = 0;Index < ReadLength;Index++)
		{
			if (FileBuffer.get()[Index] == ASCII_CR) //Macintosh format.
			{
				Line++;

			//Read texts.
				if (TextLength > 2U)
				{
				//ReadHosts
					if (InputType == READTEXT_HOSTS)
					{
						ReadHostsData(Text.get(), FileName, Line, Comments, Local, StopTemp[0]);
					}
				//ReadIPFilter
					else if (InputType == READTEXT_IPFILTER)
					{
						ReadIPFilterData(Text.get(), FileName, Line, Comments, Blacklist, StopTemp[1U]);
					}
				//ReadParameter
					else {
						if (ReadParameterData(Text.get(), FileName, Line, Comments) == EXIT_FAILURE)
							return false;
					}
				}

				memset(Text.get(), 0, FILE_BUFFER_SIZE);
				TextLength = 0;
			}
			else if (FileBuffer.get()[Index] == ASCII_LF) //Unix format.
			{
				if (Index > 0 && FileBuffer.get()[Index - 1U] != ASCII_CR) //Windows format.
					Line++;

			//Read texts.
				if (TextLength > 2U)
				{
				//ReadHosts
					if (InputType == READTEXT_HOSTS)
					{
						ReadHostsData(Text.get(), FileName, Line, Comments, Local, StopTemp[0]);
					}
				//ReadIPFilter
					else if (InputType == READTEXT_IPFILTER)
					{
						ReadIPFilterData(Text.get(), FileName, Line, Comments, Blacklist, StopTemp[1U]);
					}
				//ReadParameter
					else {
						if (ReadParameterData(Text.get(), FileName, Line, Comments) == EXIT_FAILURE)
							return false;
					}
				}

				memset(Text.get(), 0, FILE_BUFFER_SIZE);
				TextLength = 0;
			}
			else if (Index == ReadLength - 1U && feof((FILE *)Input)) //Last line
			{
				Line++;
				Text.get()[TextLength] = FileBuffer.get()[Index];

			//Read texts.
				if (TextLength > 2U)
				{
				//ReadHosts
					if (InputType == READTEXT_HOSTS)
					{
						if (ReadHostsData(Text.get(), FileName, Line, Comments, Local, StopTemp[0]) == EXIT_FAILURE)
							return false;
					}
				//ReadIPFilter
					else if (InputType == READTEXT_IPFILTER)
					{
						if (ReadIPFilterData(Text.get(), FileName, Line, Comments, Blacklist, StopTemp[1U]) == EXIT_FAILURE)
							return false;
					}
				//ReadParameter
					else {
						if (ReadParameterData(Text.get(), FileName, Line, Comments) == EXIT_FAILURE)
							return false;
					}
				}

				return true;
			}
			else {
				Text.get()[TextLength] = FileBuffer.get()[Index];
				TextLength++;
			}
		}

		memset(FileBuffer.get(), 0, FILE_BUFFER_SIZE);

/* Old version(2014-07-03)
	//Read data.
		if (NextLineType == NEXTLINETYPE_CRLF) //Windows format
		{
			for (Index = 0;Index < ReadLength;Index++)
			{
				if (FileBuffer.get()[Index] == ASCII_CR)
				{
				//Read texts.
					if (TextLength > 2U)
					{
						if (InputType == READTEXT_HOSTS) //ReadHosts
						{
							if (ReadHostsData(Text.get(), FileName, Line, Comments, Local) == EXIT_FAILURE)
							{
								Line++;
								memset(Text.get(), 0, FILE_BUFFER_SIZE);
								TextLength = 0;
								continue;
							}
							else {
								Line++;
							}
						}
						else if (InputType == READTEXT_IPFILTER) //ReadIPFilter
						{
							if (ReadIPFilterData(Text.get(), FileName, Line, Comments) == EXIT_FAILURE)
							{
								Line++;
								memset(Text.get(), 0, FILE_BUFFER_SIZE);
								TextLength = 0;
								continue;
							}
							else {
								Line++;
							}
						}
						else { //ReadParameter
							if (ReadParameterData(Text.get(), FileName, Line, Comments) == EXIT_FAILURE)
								return false;
							else 
								Line++;
						}

						memset(Text.get(), 0, FILE_BUFFER_SIZE);
						TextLength = 0;
					}
					else {
						Line++;
						continue;
					}
				}
				else if (Index == ReadLength - 1U && LastRead) //Last line
				{
					Text.get()[TextLength] = FileBuffer.get()[Index];

				//Read texts.
					if (TextLength > 2U)
					{
						if (InputType == READTEXT_HOSTS) //ReadHosts
						{
							if (ReadHostsData(Text.get(), FileName, Line, Comments, Local) == EXIT_FAILURE)
								return false;
						}
						else if (InputType == READTEXT_IPFILTER) //ReadIPFilter
						{
							if (ReadIPFilterData(Text.get(), FileName, Line, Comments) == EXIT_FAILURE)
								return false;
						}
						else { //ReadParameter
							if (ReadParameterData(Text.get(), FileName, Line, Comments) == EXIT_FAILURE)
								return false;
						}
					}

					return true;
				}
				else {
					if (FileBuffer.get()[Index] != ASCII_LF)
					{
						Text.get()[TextLength] = FileBuffer.get()[Index];
						TextLength++;
					}
				}
			}
		}
		else if (NextLineType == NEXTLINETYPE_LF) //Unix format
		{
			for (Index = 0;Index < ReadLength;Index++)
			{
				if (FileBuffer.get()[Index] == ASCII_LF)
				{
				//Read texts.
					if (TextLength > 2U)
					{
						if (InputType == READTEXT_HOSTS) //ReadHosts
						{
							if (ReadHostsData(Text.get(), FileName, Line, Comments, Local) == EXIT_FAILURE)
							{
								Line++;
								memset(Text.get(), 0, FILE_BUFFER_SIZE);
								TextLength = 0;
								continue;
							}
							else {
								Line++;
							}
						}
						else if (InputType == READTEXT_IPFILTER) //ReadIPFilter
						{
							if (ReadIPFilterData(Text.get(), FileName, Line, Comments) == EXIT_FAILURE)
							{
								Line++;
								memset(Text.get(), 0, FILE_BUFFER_SIZE);
								TextLength = 0;
								continue;
							}
							else {
								Line++;
							}
						}
						else { //ReadParameter
							if (ReadParameterData(Text.get(), FileName, Line, Comments) == EXIT_FAILURE)
								return false;
							else 
								Line++;
						}

						memset(Text.get(), 0, FILE_BUFFER_SIZE);
						TextLength = 0;
					}
					else {
						Line++;
						continue;
					}
				}
				else if (Index == ReadLength - 1U && LastRead) //Last line
				{
					Text.get()[TextLength] = FileBuffer.get()[Index];

				//Read texts.
					if (TextLength > 2U)
					{
						if (InputType == READTEXT_HOSTS) //ReadHosts
						{
							if (ReadHostsData(Text.get(), FileName, Line, Comments, Local) == EXIT_FAILURE)
								return false;
						}
						else if (InputType == READTEXT_IPFILTER) //ReadIPFilter
						{
							if (ReadIPFilterData(Text.get(), FileName, Line, Comments) == EXIT_FAILURE)
								return false;
						}
						else { //ReadParameter
							if (ReadParameterData(Text.get(), FileName, Line, Comments) == EXIT_FAILURE)
								return false;
						}
					}

					return true;
				}
				else {
					Text.get()[TextLength] = FileBuffer.get()[Index];
					TextLength++;
				}
			}
		}
		else { //Macintosh format
			for (Index = 0;Index < ReadLength;Index++)
			{
				if (FileBuffer.get()[Index] == ASCII_CR)
				{
				//Read texts.
					if (TextLength > 2U)
					{
						if (InputType == READTEXT_HOSTS) //ReadHosts
						{
							if (ReadHostsData(Text.get(), FileName, Line, Comments, Local) == EXIT_FAILURE)
							{
								Line++;
								memset(Text.get(), 0, FILE_BUFFER_SIZE);
								TextLength = 0;
								continue;
							}
							else {
								Line++;
							}
						}
						else if (InputType == READTEXT_IPFILTER) //ReadIPFilter
						{
							if (ReadIPFilterData(Text.get(), FileName, Line, Comments) == EXIT_FAILURE)
							{
								Line++;
								memset(Text.get(), 0, FILE_BUFFER_SIZE);
								TextLength = 0;
								continue;
							}
							else {
								Line++;
							}
						}
						else { //ReadParameter
							if (ReadParameterData(Text.get(), FileName, Line, Comments) == EXIT_FAILURE)
								return false;
							else 
								Line++;
						}

						memset(Text.get(), 0, FILE_BUFFER_SIZE);
						TextLength = 0;
					}
					else {
						Line++;
						continue;
					}
				}
				else if (Index == ReadLength - 1U && LastRead) //Last line
				{
					Text.get()[TextLength] = FileBuffer.get()[Index];

				//Read texts.
					if (TextLength > 2U)
					{
						if (InputType == READTEXT_HOSTS) //ReadHosts
						{
							if (ReadHostsData(Text.get(), FileName, Line, Comments, Local) == EXIT_FAILURE)
								return false;
						}
						else if (InputType == READTEXT_IPFILTER) //ReadIPFilter
						{
							if (ReadIPFilterData(Text.get(), FileName, Line, Comments) == EXIT_FAILURE)
								return false;
						}
						else { //ReadParameter
							if (ReadParameterData(Text.get(), FileName, Line, Comments) == EXIT_FAILURE)
								return false;
						}
					}

					return true;
				}
				else {
					Text.get()[TextLength] = FileBuffer.get()[Index];
					TextLength++;
				}
			}
		}

/* Old version before v0.4 Beta
		memset(Buffer.get(), 0, FILE_BUFFER_SIZE);
		ReadLength = fread_s(Buffer.get(), FILE_BUFFER_SIZE, sizeof(char), FILE_BUFFER_SIZE, (FILE *)Input);
		if (Encoding == NULL)
		{
			ReadEncoding(Buffer.get(), ReadLength, Encoding, NextLineType); //Read encoding
			ReadEncoding(Buffer.get(), ReadLength, Encoding, NextLineType); //Read next line type
			if (Encoding == UTF_8)
			{
				memcpy(Addition.get(), Buffer.get() + 3U, FILE_BUFFER_SIZE - 3U);
				memset(Buffer.get(), 0, FILE_BUFFER_SIZE);
				memcpy(Buffer.get(), Addition.get(), FILE_BUFFER_SIZE - 3U);
				memset(Addition.get(), 0, FILE_BUFFER_SIZE);
				ReadLength -= 3U;
			}
			else if (Encoding == UTF_16_LE || Encoding == UTF_16_BE)
			{
				memcpy(Addition.get(), Buffer.get() + 2U, FILE_BUFFER_SIZE - 2U);
				memset(Buffer.get(), 0, FILE_BUFFER_SIZE);
				memcpy(Buffer.get(), Addition.get(), FILE_BUFFER_SIZE - 2U);
				memset(Addition.get(), 0, FILE_BUFFER_SIZE);
				ReadLength -= 2U;
			}
			else if (Encoding == UTF_32_LE || Encoding == UTF_32_BE)
			{
				memcpy(Addition.get(), Buffer.get() + 4U, FILE_BUFFER_SIZE - 4U);
				memset(Buffer.get(), 0, FILE_BUFFER_SIZE);
				memcpy(Buffer.get(), Addition.get(), FILE_BUFFER_SIZE - 4U);
				memset(Addition.get(), 0, FILE_BUFFER_SIZE);
				ReadLength -= 4U;
			}
		}

		for (Index = 0, Start = 0;Index < ReadLength;Index++)
		{
		//CR/Carriage Return and LF/Line Feed
			if ((Encoding == UTF_8 || Encoding == ANSI || 
				(Encoding == UTF_16_LE || Encoding == UTF_32_LE) && Buffer.get()[Index + 1U] == 0 || 
				(Encoding == UTF_16_BE || Encoding == UTF_32_BE) && Buffer.get()[Index - 1U] == 0) && 
				(Buffer.get()[Index] == ASCII_CR || Buffer.get()[Index] == ASCII_LF))
			{
				if (InputType == READTEXT_HOSTS) //ReadHosts
				{
					if (Index - Start > 2U) //Minimum length of IPv6 addresses and regular expression
					{
						if (ReadHostsData(Addition.get(), FileName, Line, Local, Comments) == EXIT_FAILURE)
						{
							Line++;
							memset(Addition.get(), 0, FILE_BUFFER_SIZE);
							continue;
						}
					}
				}
				else if (InputType == READTEXT_IPFILTER) //ReadIPFilter
				{
					if (Index - Start > 2U) //Minimum length of comment
					{
						if (ReadIPFilterData(Addition.get(), FileName, Line, Comments) == EXIT_FAILURE)
						{
							Line++;
							memset(Addition.get(), 0, FILE_BUFFER_SIZE);
							continue;
						}
					}
				}
				else { //ReadParameter
					if (Index - Start > 2U) //Minimum length of rules
					{
						if (ReadParameterData(Addition.get(), FileName, Line, Comments) == EXIT_FAILURE)
							return false;
					}
				}

				memset(Addition.get(), 0, FILE_BUFFER_SIZE);
				AdditionLength = 0;
				Start = Index;
			//Mark lines.
				if (NextLineType == NEXTLINETYPE_CRLF || NextLineType == NEXTLINETYPE_CR)
				{
					if (Buffer.get()[Index] == ASCII_CR)
						Line++;
				}
				else {
					if (Buffer.get()[Index] == ASCII_LF)
						Line++;
				}

				continue;
			}
		//Last line
			else if (Index == ReadLength - 1U && ReadLength < FILE_BUFFER_SIZE - 4U) //BOM of UTF
			{
				Addition.get()[strlen(Addition.get())] = Buffer.get()[Index];
				if (InputType == READTEXT_HOSTS) //ReadHosts
				{
					if (ReadHostsData(Addition.get(), FileName, Line, Local, Comments) == EXIT_FAILURE)
					{
						memset(Addition.get(), 0, FILE_BUFFER_SIZE);
						AdditionLength = 0;
						break;
					}
				}
				else if (InputType == READTEXT_IPFILTER) //ReadIPFilter
				{
					if (ReadIPFilterData(Addition.get(), FileName, Line, Comments) == EXIT_FAILURE)
					{
						memset(Addition.get(), 0, FILE_BUFFER_SIZE);
						AdditionLength = 0;
						break;
					}
				}
				else { //ReadParameter
					if (ReadParameterData(Addition.get(), FileName, Line, Comments) == EXIT_FAILURE)
						return false;
				}
			}
		//ASCII data
			else if (Buffer.get()[Index] != 0)
			{
				if (AdditionLength < FILE_BUFFER_SIZE)
				{
					Addition.get()[AdditionLength] = Buffer.get()[Index];
					AdditionLength++;
				}
				else {
					if (InputType == READTEXT_HOSTS) //ReadHosts
					{
						PrintError(LOG_ERROR_HOSTS, L"Data of a line is too long", NULL, FileName, Line);

						memset(Addition.get(), 0, FILE_BUFFER_SIZE);
						AdditionLength = 0;
						continue;
					}
					else if (InputType == READTEXT_IPFILTER) //ReadIPFilter
					{
						PrintError(LOG_ERROR_IPFILTER, L"Data of a line is too long", NULL, FileName, Line);

						memset(Addition.get(), 0, FILE_BUFFER_SIZE);
						AdditionLength = 0;
						continue;
					}
					else { //ReadParameter
						PrintError(LOG_ERROR_PARAMETER, L"Data of a line is too long", NULL, FileName, Line);
						return false;
					}
				}
			}
		}
*/
	}

	return true;
}

//Read parameter from file
size_t __fastcall ReadParameter(void)
{
	//Initialization
	FILE *Input = nullptr;
	size_t Index = 0;

	//Open file.
	std::wstring ConfigPath[] = { *Parameter.Path, *Parameter.Path, *Parameter.Path };
	ConfigPath[0].append(L"Config.ini");
	ConfigPath[1U].append(L"Config.conf");
	ConfigPath[2U].append(L"Config");
	for (Index = 0; Index < sizeof(ConfigPath) / sizeof(std::wstring); Index++)
	{
		if (_wfopen_s(&Input, ConfigPath[Index].c_str(), L"rb") == 0)
		{
			if (Input != nullptr)
				break;
		}

		//Check all configuration files.
		if (Index == sizeof(ConfigPath) / sizeof(std::wstring) - 1U)
		{
			PrintError(LOG_ERROR_PARAMETER, L"Cannot open any configuration files", NULL, nullptr, NULL);
			return EXIT_FAILURE;
		}
	}

	//Check whole file size.
	HANDLE ConfigFileHandle = CreateFileW(ConfigPath[Index].c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (ConfigFileHandle != INVALID_HANDLE_VALUE)
	{
		LARGE_INTEGER ConfigFileSize = {0 };
		if (GetFileSizeEx(ConfigFileHandle, &ConfigFileSize) == 0)
		{
			CloseHandle(ConfigFileHandle);
		}
		else {
			CloseHandle(ConfigFileHandle);
			if (ConfigFileSize.QuadPart >= DEFAULT_FILE_MAXSIZE)
			{
				PrintError(LOG_ERROR_PARAMETER, L"Configuration file size is too large", NULL, (PWSTR)ConfigPath[Index].c_str(), NULL);
				return EXIT_FAILURE;
			}
		}
	}

	//Read data
	if (!ReadText(Input, 0, /* READTEXT_PARAMETER , */ (PWSTR)ConfigPath[Index].c_str()))
		return EXIT_FAILURE;
	fclose(Input);

	//Check parameters.
	if (Parameter.Version > INI_VERSION) //Version check
	{
		PrintError(LOG_ERROR_PARAMETER, L"Configuration file version error", NULL, (PWSTR)ConfigPath[Index].c_str(), NULL);
		return EXIT_FAILURE;
	}
	else if (Parameter.Version < INI_VERSION)
	{
		PrintError(LOG_ERROR_PARAMETER, L"Configuration file is not the latest version", NULL, (PWSTR)ConfigPath[Index].c_str(), NULL);
	}

	//Cleanup when Print Running Log is disable.
	if (Parameter.PrintStatus == 0)
	{
		delete Parameter.RunningLogPath;
		Parameter.RunningLogPath = nullptr;
	}

	//Log max size check
	if (Parameter.LogMaxSize == 0)
	{
		Parameter.LogMaxSize = DEFAULT_LOG_MAXSIZE;
	}
	else if (Parameter.LogMaxSize < DEFAULT_LOG_MINSIZE || Parameter.LogMaxSize > DEFAULT_FILE_MAXSIZE)
	{
		PrintError(LOG_ERROR_PARAMETER, L"Log file size error", NULL, (PWSTR)ConfigPath[Index].c_str(), NULL);
		return EXIT_FAILURE;
	}

	//DNS and Alternate Targets check
	if (!Parameter.DNSTarget.IPv6_Multi->empty())
	{
		Parameter.AlternateMultiRequest = true;

		//Copy DNS Server Data when Main or Alternate data are empty.
		if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family == NULL)
		{
			uint8_t HopLimitTemp = 0;
			if (Parameter.DNSTarget.IPv6.HopLimitData.HopLimit != 0)
				HopLimitTemp = Parameter.DNSTarget.IPv6.HopLimitData.HopLimit;
			Parameter.DNSTarget.IPv6 = Parameter.DNSTarget.IPv6_Multi->front();
			Parameter.DNSTarget.IPv6.HopLimitData.HopLimit = HopLimitTemp;
			Parameter.DNSTarget.IPv6_Multi->erase(Parameter.DNSTarget.IPv6_Multi->begin());
		}

		if (Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family == NULL && !Parameter.DNSTarget.IPv6_Multi->empty())
		{
			uint8_t HopLimitTemp = 0;
			if (Parameter.DNSTarget.Alternate_IPv6.HopLimitData.HopLimit != 0)
				HopLimitTemp = Parameter.DNSTarget.Alternate_IPv6.HopLimitData.HopLimit;
			Parameter.DNSTarget.Alternate_IPv6 = Parameter.DNSTarget.IPv6_Multi->front();
			Parameter.DNSTarget.Alternate_IPv6.HopLimitData.HopLimit = HopLimitTemp;
			Parameter.DNSTarget.IPv6_Multi->erase(Parameter.DNSTarget.IPv6_Multi->begin());
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
		if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family == NULL)
		{
			uint8_t TTLTemp = 0;
			if (Parameter.DNSTarget.IPv4.HopLimitData.TTL != 0)
				TTLTemp = Parameter.DNSTarget.IPv4.HopLimitData.TTL;
			Parameter.DNSTarget.IPv4 = Parameter.DNSTarget.IPv4_Multi->front();
			Parameter.DNSTarget.IPv4.HopLimitData.TTL = TTLTemp;
			Parameter.DNSTarget.IPv4_Multi->erase(Parameter.DNSTarget.IPv4_Multi->begin());
		}

		if (Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family == NULL && !Parameter.DNSTarget.IPv4_Multi->empty())
		{
			uint8_t TTLTemp = 0;
			if (Parameter.DNSTarget.Alternate_IPv4.HopLimitData.TTL != 0)
				TTLTemp = Parameter.DNSTarget.Alternate_IPv4.HopLimitData.TTL;
			Parameter.DNSTarget.Alternate_IPv4 = Parameter.DNSTarget.IPv4_Multi->front();
			Parameter.DNSTarget.Alternate_IPv4.HopLimitData.TTL = TTLTemp;
			Parameter.DNSTarget.IPv4_Multi->erase(Parameter.DNSTarget.IPv4_Multi->begin());
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
	if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family == NULL && Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL)
	{
		Parameter.DNSTarget.IPv6 = Parameter.DNSTarget.Alternate_IPv6;
		memset(&Parameter.DNSTarget.Alternate_IPv6, 0, sizeof(DNSServerData));
	}
	if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family == NULL && Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL)
	{
		Parameter.DNSTarget.IPv4 = Parameter.DNSTarget.Alternate_IPv4;
		memset(&Parameter.DNSTarget.Alternate_IPv4, 0, sizeof(DNSServerData));
	}
	if (Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family == NULL && Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family != NULL)
	{
		Parameter.DNSTarget.Local_IPv6 = Parameter.DNSTarget.Alternate_Local_IPv6;
		memset(&Parameter.DNSTarget.Alternate_Local_IPv6, 0, sizeof(DNSServerData));
	}
	if (Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family == NULL && Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage.ss_family != NULL)
	{
		Parameter.DNSTarget.Local_IPv4 = Parameter.DNSTarget.Alternate_Local_IPv4;
		memset(&Parameter.DNSTarget.Alternate_Local_IPv4, 0, sizeof(DNSServerData));
	}
	if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family == NULL && Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family == NULL ||
		//Check repeating items.
		Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family != NULL && Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL && Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr.S_un.S_addr == Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr.S_un.S_addr ||
		Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family != NULL && Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage.ss_family != NULL && Parameter.DNSTarget.Local_IPv4.AddressData.IPv4.sin_addr.S_un.S_addr == Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.IPv4.sin_addr.S_un.S_addr ||
		Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family != NULL && Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL && memcmp(&Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr, &Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr, sizeof(in6_addr)) == 0 ||
		Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family != NULL && Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family != NULL && memcmp(&Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_addr, &Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6.sin6_addr, sizeof(in6_addr)) == 0)
	{
		PrintError(LOG_ERROR_PARAMETER, L"DNS Targets error", NULL, (PWSTR)ConfigPath[Index].c_str(), NULL);
		return EXIT_FAILURE;
	}

	//Hop Limit or TTL Fluctuations check
	if (Parameter.HopLimitFluctuation > 0)
	{
		//IPv4
		if (Parameter.DNSTarget.IPv4.HopLimitData.TTL > 0 &&
			((size_t)Parameter.DNSTarget.IPv4.HopLimitData.TTL + (size_t)Parameter.HopLimitFluctuation > U8_MAXNUM ||
			(SSIZE_T)Parameter.DNSTarget.IPv4.HopLimitData.TTL < (SSIZE_T)Parameter.HopLimitFluctuation + 1) ||
			Parameter.DNSTarget.Alternate_IPv4.HopLimitData.TTL > 0 &&
			((size_t)Parameter.DNSTarget.Alternate_IPv4.HopLimitData.TTL + (size_t)Parameter.HopLimitFluctuation > U8_MAXNUM ||
			(SSIZE_T)Parameter.DNSTarget.Alternate_IPv4.HopLimitData.TTL < (SSIZE_T)Parameter.HopLimitFluctuation + 1) ||
			//IPv6
			Parameter.DNSTarget.IPv6.HopLimitData.HopLimit > 0 &&
			((size_t)Parameter.DNSTarget.IPv6.HopLimitData.HopLimit + (size_t)Parameter.HopLimitFluctuation > U8_MAXNUM ||
			(SSIZE_T)Parameter.DNSTarget.IPv6.HopLimitData.HopLimit < (SSIZE_T)Parameter.HopLimitFluctuation + 1) ||
			Parameter.DNSTarget.Alternate_IPv6.HopLimitData.HopLimit > 0 &&
			((size_t)Parameter.DNSTarget.Alternate_IPv6.HopLimitData.HopLimit + (size_t)Parameter.HopLimitFluctuation > U8_MAXNUM ||
			(SSIZE_T)Parameter.DNSTarget.Alternate_IPv6.HopLimitData.HopLimit < (SSIZE_T)Parameter.HopLimitFluctuation + 1))
		{
			PrintError(LOG_ERROR_PARAMETER, L"Hop Limit or TTL Fluctuations error", NULL, (PWSTR)ConfigPath[Index].c_str(), NULL); //Hop Limit and TTL must between 1 and 255.
			return EXIT_FAILURE;
		}
	}

	//Other error which need to print to log.
	if (!Parameter.PcapCapture && !Parameter.HostsOnly && !Parameter.DNSCurve && Parameter.RquestMode != REQUEST_TCPMODE)
	{
		PrintError(LOG_ERROR_PARAMETER, L"Pcap Capture error", NULL, (PWSTR)ConfigPath[Index].c_str(), NULL);
		return EXIT_FAILURE;
	}
	if (Parameter.LocalMain && Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family == NULL && Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family)
	{
		PrintError(LOG_ERROR_PARAMETER, L"Local Main error", NULL, (PWSTR)ConfigPath[Index].c_str(), NULL);
		return EXIT_FAILURE;
	}
	if (Parameter.CacheType != 0 && Parameter.CacheParameter == 0)
	{
		PrintError(LOG_ERROR_PARAMETER, L"DNS Cache error", NULL, (PWSTR)ConfigPath[Index].c_str(), NULL);
		return EXIT_FAILURE;
	}
	if (Parameter.EDNS0PayloadSize < OLD_DNS_MAXSIZE)
	{
		if (Parameter.EDNS0PayloadSize > 0)
			PrintError(LOG_ERROR_PARAMETER, L"EDNS0 PayloadSize must longer than 512 bytes(Old DNS packets minimum supported size)", NULL, (PWSTR)ConfigPath[Index].c_str(), NULL);
		Parameter.EDNS0PayloadSize = EDNS0_MINSIZE; //Default UDP maximum payload size.
	}
	else if (Parameter.EDNS0PayloadSize >= PACKET_MAXSIZE - sizeof(ipv6_hdr) - sizeof(udp_hdr))
	{
		PrintError(LOG_ERROR_PARAMETER, L"EDNS0 PayloadSize may be too long", NULL, (PWSTR)ConfigPath[Index].c_str(), NULL);
		Parameter.EDNS0PayloadSize = EDNS0_MINSIZE;
	}
	if (Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family == NULL && Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family == NULL &&
		Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage.ss_family == NULL && Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family == NULL &&
		Parameter.DNSCurve && DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family == NULL && DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family == NULL)
	{
		PrintError(LOG_ERROR_PARAMETER, L"Alternate Multi requesting error", NULL, (PWSTR)ConfigPath[Index].c_str(), NULL);
		return EXIT_FAILURE;
	}
	if (Parameter.MultiRequestTimes > MULTI_REQUEST_TIMES_MAXNUM)
	{
		PrintError(LOG_ERROR_PARAMETER, L"Multi requesting times error", NULL, (PWSTR)ConfigPath[Index].c_str(), NULL);
		return EXIT_FAILURE;
	}
	else if (Parameter.MultiRequestTimes < 1U)
	{
		Parameter.MultiRequestTimes = 1U;
	}

	//Only check and set.
	if (Parameter.RquestMode != REQUEST_TCPMODE) //TCP Mode options check
		Parameter.TCPDataCheck = false;
	if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family == NULL)
		Parameter.IPv4DataCheck = false;
	if (Parameter.DNSCurve) //DNSCurve options check
	{
		//Libsodium initialization
		if (sodium_init() != 0)
		{
			PrintError(LOG_ERROR_DNSCURVE, L"Libsodium initialization error", NULL, (PWSTR)ConfigPath[Index].c_str(), NULL);
			return EXIT_FAILURE;
		}

		//Client keys check
		if (!CheckEmptyBuffer(DNSCurveParameter.Client_PublicKey, crypto_box_PUBLICKEYBYTES) && !CheckEmptyBuffer(DNSCurveParameter.Client_SecretKey, crypto_box_SECRETKEYBYTES) &&
			!VerifyKeypair(DNSCurveParameter.Client_PublicKey, DNSCurveParameter.Client_SecretKey))
		{
			PrintError(LOG_ERROR_DNSCURVE, L"Client keypair(public key and secret key) error", NULL, (PWSTR)ConfigPath[Index].c_str(), NULL);
			return EXIT_FAILURE;
		}
		else if (DNSCurveParameter.Encryption)
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

		//DNSCurve target(s) check
		if (DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family == NULL && DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL)
		{
			DNSCurveParameter.DNSCurveTarget.IPv4 = DNSCurveParameter.DNSCurveTarget.Alternate_IPv4;
			memset(&DNSCurveParameter.DNSCurveTarget.Alternate_IPv4, 0, sizeof(DNSCurveServerData));
		}
		if (DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family == NULL && DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL)
		{
			DNSCurveParameter.DNSCurveTarget.IPv6 = DNSCurveParameter.DNSCurveTarget.Alternate_IPv6;
			memset(&DNSCurveParameter.DNSCurveTarget.Alternate_IPv6, 0, sizeof(DNSCurveServerData));
		}

		if (DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family == NULL && DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family == NULL ||
			//Check repeating items.
			DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family != NULL && DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL && DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_addr.S_un.S_addr == DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_addr.S_un.S_addr ||
			DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family != NULL && DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL && memcmp(&DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_addr, &DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr, sizeof(in6_addr) == 0))
		{
			PrintError(LOG_ERROR_PARAMETER, L"DNSCurve Targets error", NULL, (PWSTR)ConfigPath[Index].c_str(), NULL);
			return EXIT_FAILURE;
		}

		//Eencryption options check
		if (DNSCurveParameter.EncryptionOnly && !DNSCurveParameter.Encryption)
		{
			DNSCurveParameter.Encryption = true;
			PrintError(LOG_ERROR_PARAMETER, L"DNSCurve encryption options error", NULL, (PWSTR)ConfigPath[Index].c_str(), NULL);
		}

		//Main(IPv6)
		if (DNSCurveParameter.Encryption && DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family != NULL)
		{
			//Empty Server Fingerprint
			if (CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES))
			{
				//Encryption Only mode check
				if (DNSCurveParameter.EncryptionOnly &&
					CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNSCurve Encryption Only mode error", NULL, (PWSTR)ConfigPath[Index].c_str(), NULL);
					return EXIT_FAILURE;
				}

				//Empty Provider Name
				if (CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.ProviderName, DOMAIN_MAXSIZE))
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNSCurve empty Provider Name error", NULL, (PWSTR)ConfigPath[Index].c_str(), NULL);
					return EXIT_FAILURE;
				}

				//Empty Public Key
				if (CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES))
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNSCurve empty Public Key error", NULL, (PWSTR)ConfigPath[Index].c_str(), NULL);
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
		if (DNSCurveParameter.Encryption && DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family != NULL)
		{
			//Empty Server Fingerprint
			if (CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES))
			{
				//Encryption Only mode check
				if (DNSCurveParameter.EncryptionOnly &&
					CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNSCurve Encryption Only mode error", NULL, (PWSTR)ConfigPath[Index].c_str(), NULL);
					return EXIT_FAILURE;
				}

				//Empty Provider Name
				if (CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.ProviderName, DOMAIN_MAXSIZE))
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNSCurve empty Provider Name error", NULL, (PWSTR)ConfigPath[Index].c_str(), NULL);
					return EXIT_FAILURE;
				}

				//Empty Public Key
				if (CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES))
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNSCurve empty Public Key error", NULL, (PWSTR)ConfigPath[Index].c_str(), NULL);
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
		if (DNSCurveParameter.Encryption && DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL)
		{
			//Empty Server Fingerprint
			if (CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES))
			{
				//Encryption Only mode check
				if (DNSCurveParameter.EncryptionOnly &&
					CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNSCurve Encryption Only mode error", NULL, (PWSTR)ConfigPath[Index].c_str(), NULL);
					return EXIT_FAILURE;
				}

				//Empty Provider Name
				if (CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ProviderName, DOMAIN_MAXSIZE))
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNSCurve empty Provider Name error", NULL, (PWSTR)ConfigPath[Index].c_str(), NULL);
					return EXIT_FAILURE;
				}

				//Empty Public Key
				if (CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES))
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNSCurve empty Public Key error", NULL, (PWSTR)ConfigPath[Index].c_str(), NULL);
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
		if (DNSCurveParameter.Encryption && DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL)
		{
			//Empty Server Fingerprint
			if (CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES))
			{
				//Encryption Only mode check
				if (DNSCurveParameter.EncryptionOnly &&
					CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNSCurve Encryption Only mode error", NULL, (PWSTR)ConfigPath[Index].c_str(), NULL);
					return EXIT_FAILURE;
				}

				//Empty Provider Name
				if (CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ProviderName, DOMAIN_MAXSIZE))
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNSCurve empty Provider Name error", NULL, (PWSTR)ConfigPath[Index].c_str(), NULL);
					return EXIT_FAILURE;
				}

				//Empty Public Key
				if (CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES))
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNSCurve empty Public Key error", NULL, (PWSTR)ConfigPath[Index].c_str(), NULL);
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

	//Default settings
	if (Parameter.ListenPort == 0)
		Parameter.ListenPort = htons(IPPORT_DNS);
	if (!Parameter.EDNS0Label)
	{
		if (Parameter.DNSSECRequest)
		{
			PrintError(LOG_ERROR_PARAMETER, L"EDNS0 Label must trun ON when request DNSSEC", NULL, (PWSTR)ConfigPath[Index].c_str(), NULL);
			Parameter.EDNS0Label = true;
		}

		if (Parameter.DNSCurve)
		{
			PrintError(LOG_ERROR_PARAMETER, L"EDNS0 Label must trun ON when request DNSCurve", NULL, (PWSTR)ConfigPath[Index].c_str(), NULL);
			Parameter.EDNS0Label = true;
		}
	}
	if (Parameter.CompressionPointerMutation && Parameter.EDNS0Label)
	{
		PrintError(LOG_ERROR_PARAMETER, L"Compression Pointer Mutation must trun OFF when request EDNS0 Label", NULL, (PWSTR)ConfigPath[Index].c_str(), NULL);
		Parameter.CompressionPointerMutation = false;
	}

	if (Parameter.ICMPOptions.ICMPSpeed > 0)
	{
		if (ntohs(Parameter.ICMPOptions.ICMPID) <= 0)
			Parameter.ICMPOptions.ICMPID = htons((uint16_t)GetCurrentProcessId()); //Default ICMP ID is current process ID.
		if (ntohs(Parameter.ICMPOptions.ICMPSequence) <= 0)
			Parameter.ICMPOptions.ICMPSequence = htons(DEFAULT_SEQUENCE);
	}

	if (Parameter.DomainTestOptions.DomainTestSpeed <= SHORTEST_DOMAINTEST_INTERVAL_TIME)
		Parameter.DomainTestOptions.DomainTestSpeed = DEFAULT_DOMAINTEST_INTERVAL_TIME * SECOND_TO_MILLISECOND;
	if (ntohs(Parameter.DomainTestOptions.DomainTestID) <= 0)
		Parameter.DomainTestOptions.DomainTestID = htons((uint16_t)GetCurrentProcessId()); //Default DNS ID is current process ID.
	if (CheckEmptyBuffer(Parameter.DomainTestOptions.DomainTestData, DOMAIN_MAXSIZE))
	{
		delete[] Parameter.DomainTestOptions.DomainTestData;
		Parameter.DomainTestOptions.DomainTestData = nullptr;
	}

	if (Parameter.ICMPOptions.PaddingDataLength <= 0)
	{
		Parameter.ICMPOptions.PaddingDataLength = strlen(DEFAULT_PADDINGDATA) + 1U;
		memcpy(Parameter.ICMPOptions.PaddingData, DEFAULT_PADDINGDATA, Parameter.ICMPOptions.PaddingDataLength - 1U); //Load default padding data from Microsoft Windows Ping.
	}

	if (Parameter.LocalServerOptions.LocalFQDNLength <= 0) //Default Local DNS server name
	{
		Parameter.LocalServerOptions.LocalFQDNLength = CharToDNSQuery(DEFAULT_LOCAL_SERVERNAME, Parameter.LocalServerOptions.LocalFQDN);
		Parameter.LocalServerOptions.LocalFQDNString = DEFAULT_LOCAL_SERVERNAME;
	}

	Parameter.HostsDefaultTTL = DEFAULT_HOSTS_TTL;

	//Set Local DNS server PTR response.
	if (Parameter.LocalServerOptions.LocalPTRResponseLength <= 0)
	{
		auto pdns_ptr_record = (dns_ptr_record *)Parameter.LocalServerOptions.LocalPTRResponse;
		pdns_ptr_record->PTR = htons(DNS_QUERY_PTR);
		pdns_ptr_record->Classes = htons(DNS_CLASS_IN);
		pdns_ptr_record->TTL = htonl(Parameter.HostsDefaultTTL);
		pdns_ptr_record->Type = htons(DNS_PTR_RECORDS);
		pdns_ptr_record->Length = htons((uint16_t)Parameter.LocalServerOptions.LocalFQDNLength);
		Parameter.LocalServerOptions.LocalPTRResponseLength += sizeof(dns_ptr_record);

		memcpy(Parameter.LocalServerOptions.LocalPTRResponse + Parameter.LocalServerOptions.LocalPTRResponseLength, Parameter.LocalServerOptions.LocalFQDN, Parameter.LocalServerOptions.LocalFQDNLength);
		Parameter.LocalServerOptions.LocalPTRResponseLength += Parameter.LocalServerOptions.LocalFQDNLength;

	//EDNS0 Label
		if (Parameter.EDNS0Label)
		{
			auto pdns_edns0_label = (dns_edns0_label *)(Parameter.LocalServerOptions.LocalPTRResponse + Parameter.LocalServerOptions.LocalPTRResponseLength);
			pdns_edns0_label->Type = htons(DNS_EDNS0_RECORDS);
			pdns_edns0_label->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
			Parameter.LocalServerOptions.LocalPTRResponseLength += sizeof(dns_edns0_label);
		}
	}

	if (Parameter.DNSCurve && DNSCurveParameter.Encryption) //DNSCurve default settings
	{
	//DNSCurve PayloadSize check
		if (DNSCurveParameter.DNSCurvePayloadSize < OLD_DNS_MAXSIZE)
		{
			if (DNSCurveParameter.DNSCurvePayloadSize > 0)
				PrintError(LOG_ERROR_PARAMETER, L"DNSCurve PayloadSize must longer than 512 bytes(Old DNS packets minimum supported size)", NULL, (PWSTR)ConfigPath[Index].c_str(), NULL);
			DNSCurveParameter.DNSCurvePayloadSize = OLD_DNS_MAXSIZE; //Default DNSCurve UDP maximum payload size.
		}
		else if (DNSCurveParameter.DNSCurvePayloadSize >= PACKET_MAXSIZE - sizeof(ipv6_hdr) - sizeof(udp_hdr))
		{
			PrintError(LOG_ERROR_PARAMETER, L"DNSCurve PayloadSize may be too long", NULL, (PWSTR)ConfigPath[Index].c_str(), NULL);
			DNSCurveParameter.DNSCurvePayloadSize = EDNS0_MINSIZE;
		}

	//Main(IPv6)
		if (DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family != NULL && CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
			memcpy(DNSCurveParameter.DNSCurveTarget.IPv6.ReceiveMagicNumber, DNSCRYPT_RECEIVE_MAGIC, DNSCURVE_MAGIC_QUERY_LEN);

	//Main(IPv4)
		if (DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family != NULL && CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
			memcpy(DNSCurveParameter.DNSCurveTarget.IPv4.ReceiveMagicNumber, DNSCRYPT_RECEIVE_MAGIC, DNSCURVE_MAGIC_QUERY_LEN);

	//Alternate(IPv6)
		if (DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL && CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
			memcpy(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ReceiveMagicNumber, DNSCRYPT_RECEIVE_MAGIC, DNSCURVE_MAGIC_QUERY_LEN);

	//Alternate(IPv4)
		if (DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL && CheckEmptyBuffer(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
			memcpy(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ReceiveMagicNumber, DNSCRYPT_RECEIVE_MAGIC, DNSCURVE_MAGIC_QUERY_LEN);

	//DNSCurve key(s) recheck time
		if (DNSCurveParameter.KeyRecheckTime == 0)
			DNSCurveParameter.KeyRecheckTime = DEFAULT_DNSCURVE_RECHECK_TIME * SECOND_TO_MILLISECOND;
	}

//Print global parameter list.
	if (Parameter.PrintStatus >= LOG_STATUS_LEVEL1)
		PrintParameterList();

	return EXIT_SUCCESS;
}

//Read parameter data from file(s)
size_t __fastcall ReadParameterData(const PSTR Buffer, const PWSTR FileName, const size_t Line, bool &Comments)
{
	std::string Data(Buffer);
//Multi-line comments check
	if (Comments)
	{
		if (Data.find("*/") != std::string::npos)
		{
			Data = Buffer + Data.find("*/") + 2U;
			Comments = false;
		}
		else {
			return FALSE;
		}
	}
	while (Data.find("/*") != std::string::npos)
	{
		if (Data.find("*/") == std::string::npos)
		{
			Data.erase(Data.find("/*"), Data.length() - Data.find("/*"));
			Comments = true;
			break;
		}
		else {
			Data.erase(Data.find("/*"), Data.find("*/") - Data.find("/*") + 2U);
		}
	}

	SSIZE_T Result = 0;
//Parameter version less than 0.4 compatible support.
	if (Parameter.Version < INI_VERSION && Data.find("Hop Limits/TTL Fluctuation = ") == 0)
	{
		if (Data.length() == strlen("Hop Limits/TTL Fluctuation = "))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() < strlen("Hop Limits/TTL Fluctuation = ") + 4U)
		{
			Result = strtol(Data.c_str() + strlen("Hop Limits/TTL Fluctuation = "), nullptr, NULL);
			if (Result > 0 && Result < U8_MAXNUM)
				Parameter.HopLimitFluctuation = (uint8_t)Result;
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
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
	if (Data.length() < 8U)
		return FALSE;

//[Base] block
	if (Data.find("Version=") == 0)
	{
		if (Data.length() > strlen("Version=") && Data.length() < strlen("Version=") + 8U)
		{
			Parameter.Version = atof(Data.c_str() + strlen("Version="));
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
//Parameter version less than 0.4 compatible support.
	else if (Parameter.Version < INI_VERSION)
	{
	//[Base] block
		if (Parameter.FileRefreshTime == 0 && Data.find("Hosts=") == 0)
		{
			if (Data.length() == strlen("Hosts="))
			{
				return EXIT_SUCCESS;
			}
			else if (Data.length() < strlen("Hosts=") + 6U)
			{
				Result = strtol(Data.c_str() + strlen("Hosts="), nullptr, NULL);
				if (Result >= DEFAULT_FILEREFRESH_TIME)
					Parameter.FileRefreshTime = Result * SECOND_TO_MILLISECOND;
				else if (Result > 0 && Result < DEFAULT_FILEREFRESH_TIME)
					Parameter.FileRefreshTime = DEFAULT_FILEREFRESH_TIME * SECOND_TO_MILLISECOND;
//				else 
//					Parameter.FileRefreshTime = 0; //Read file again Disable.
			}
			else {
				PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
				return EXIT_FAILURE;
			}
		}
		else if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family == NULL && Data.find("IPv4DNSAddress=") == 0)
		{
			if (Data.length() == strlen("IPv4DNSAddress="))
			{
				return EXIT_SUCCESS;
			}
			else if (Data.length() > strlen("IPv4DNSAddress=") + 6U && Data.length() < strlen("IPv4DNSAddress=") + 20U)
			{
			//Convert IPv4 Address and Port.
				std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());
				memcpy(Target.get(), Data.c_str() + strlen("IPv4DNSAddress="), Data.length() - strlen("IPv4DNSAddress="));
				if (AddressStringToBinary(Target.get(), &Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr, AF_INET, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 Address format error", Result, FileName, Line);
					return EXIT_FAILURE;
				}

				Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_port = htons(IPPORT_DNS);
				Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family = AF_INET;
			}
			else {
				PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
				return EXIT_FAILURE;
			}
		}
		else if (Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family == NULL && Data.find("IPv4LocalDNSAddress=") == 0)
		{
			if (Data.length() == strlen("IPv4LocalDNSAddress="))
			{
				return EXIT_SUCCESS;
			}
			else if (Data.length() > strlen("IPv4LocalDNSAddress=") + 6U && Data.length() < strlen("IPv4LocalDNSAddress=") + 20U)
			{
			//Convert IPv4 Address and Port.
				std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());
				memcpy(Target.get(), Data.c_str() + strlen("IPv4LocalDNSAddress="), Data.length() - strlen("IPv4LocalDNSAddress="));
				if (AddressStringToBinary(Target.get(), &Parameter.DNSTarget.Local_IPv4.AddressData.IPv4.sin_addr, AF_INET, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 Address format error", Result, FileName, Line);
					return EXIT_FAILURE;
				}

				Parameter.DNSTarget.Local_IPv4.AddressData.IPv4.sin_port = htons(IPPORT_DNS);
				Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family = AF_INET;
			}
		}
		else if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family == NULL && Data.find("IPv6DNSAddress=") == 0)
		{
			if (Data.length() == strlen("IPv6DNSAddress="))
			{
				return EXIT_SUCCESS;
			}
			else if (Data.length() > strlen("IPv6DNSAddress=") + 1U && Data.length() < strlen("IPv6DNSAddress=") + 40U)
			{
			//Convert IPv6 Address and Port.
				std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());
				memcpy(Target.get(), Data.c_str() + strlen("IPv6DNSAddress="), Data.length() - strlen("IPv6DNSAddress="));
				if (AddressStringToBinary(Target.get(), &Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 Address format error", Result, FileName, Line);
					return EXIT_FAILURE;
				}

				Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_port = htons(IPPORT_DNS);
				Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family = AF_INET6;
			}
			else {
				PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
				return EXIT_FAILURE;
			}
		}
		else if (Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family == NULL && Data.find("IPv6LocalDNSAddress=") == 0)
		{
			if (Data.length() == strlen("IPv6LocalDNSAddress="))
			{
				return EXIT_SUCCESS;
			}
			else if (Data.length() > strlen("IPv6LocalDNSAddress=") + 1U && Data.length() < strlen("IPv6LocalDNSAddress=") + 40U)
			{
			//Convert IPv6 Address and Port.
				std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());
				memcpy(Target.get(), Data.c_str() + strlen("IPv6LocalDNSAddress="), Data.length() - strlen("IPv6LocalDNSAddress="));
				if (AddressStringToBinary(Target.get(), &Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 Address format error", Result, FileName, Line);
					return EXIT_FAILURE;
				}

				Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_port = htons(IPPORT_DNS);
				Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family = AF_INET6;
			}
			else {
				PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
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
		else if (Parameter.DomainTestOptions.DomainTestSpeed == 0 && Data.find("DomainTestSpeed=") == 0)
		{
			if (Data.length() == strlen("DomainTestSpeed="))
			{
				return EXIT_SUCCESS;
			}
			else if (Data.length() < strlen("DomainTestSpeed=") + 6U)
			{
				Result = strtol(Data.c_str() + strlen("DomainTestSpeed="), nullptr, NULL);
				if (Result > 0)
					Parameter.DomainTestOptions.DomainTestSpeed = Result * SECOND_TO_MILLISECOND;
			}
			else {
				PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
				return EXIT_FAILURE;
			}
		}
	}
	else if (Data.find("FileRefreshTime=") == 0)
	{
		if (Data.length() == strlen("FileRefreshTime="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() < strlen("FileRefreshTime=") + 6U)
		{
			Result = strtol(Data.c_str() + strlen("FileRefreshTime="), nullptr, NULL);
			if (Result >= DEFAULT_FILEREFRESH_TIME)
				Parameter.FileRefreshTime = Result * SECOND_TO_MILLISECOND;
			else if (Result > 0 && Result < DEFAULT_FILEREFRESH_TIME)
				Parameter.FileRefreshTime = DEFAULT_FILEREFRESH_TIME * SECOND_TO_MILLISECOND;
//			else 
//				Parameter.FileRefreshTime = 0; //Read file again Disable.
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("FileHash=1") == 0)
	{
		Parameter.FileHash = true;
	}

//[Log] block
	else if (Data.find("PrintError=0") == 0)
	{
		Parameter.PrintError = false;
		delete Parameter.ErrorLogPath;
		Parameter.ErrorLogPath = nullptr;
	}
	else if (Data.find("PrintRunningLog=") == 0)
	{
		if (Data.length() == strlen("PrintRunningLog="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() < strlen("PrintRunningLog=") + 2U)
		{
			Result = strtol(Data.c_str() + strlen("PrintRunningLog="), nullptr, NULL);
			if (Result > LOG_STATUS_CLOSED)
			{
				Parameter.PrintStatus = Result;

			//Get path of running status log file and delete the old one.
				*Parameter.RunningLogPath = *Parameter.Path;
				Parameter.RunningLogPath->append(L"Running.log");
				DeleteFileW(Parameter.RunningLogPath->c_str());

			//Print status.
				switch (Result)
				{
					case LOG_STATUS_LEVEL1:
					{
						PrintStatus(L"Print Running Log Level 1");
					}break;
					case LOG_STATUS_LEVEL2:
					{
						PrintStatus(L"Print Running Log Level 2");
					}break;
					case LOG_STATUS_LEVEL3:
					{
						PrintStatus(L"Print Running Log Level 3");
					}break;
					default:
					{
						PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
						return EXIT_FAILURE;
					}break;
				}
			}
//			else 
//				Parameter.PrintStatus = 0; //Print running status Disable.
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("LogMaximumSize=") == 0)
	{
		if (Data.length() == strlen("LogMaximumSize="))
		{
			return EXIT_SUCCESS;
		}
		else {
			if (Data.find("KB") != std::string::npos || Data.find("Kb") != std::string::npos || Data.find("kB") != std::string::npos || Data.find("kb") != std::string::npos)
			{
				Data.erase(Data.length() - 2U, 2U);

			//Mark.
				Result = strtol(Data.c_str() + strlen("LogMaximumSize="), nullptr, NULL);
				if (Result >= 0)
				{
					Parameter.LogMaxSize = Result * KILOBYTE_TIMES;
				}
				else {
					PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
					return EXIT_FAILURE;
				}
			}
			else if (Data.find("MB") != std::string::npos || Data.find("Mb") != std::string::npos || Data.find("mB") != std::string::npos || Data.find("mb") != std::string::npos)
			{
				Data.erase(Data.length() - 2U, 2U);

			//Mark.
				Result = strtol(Data.c_str() + strlen("LogMaximumSize="), nullptr, NULL);
				if (Result >= 0)
				{
					Parameter.LogMaxSize = Result * MEGABYTE_TIMES;
				}
				else {
					PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
					return EXIT_FAILURE;
				}
			}
			else if (Data.find("GB") != std::string::npos || Data.find("Gb") != std::string::npos || Data.find("gB") != std::string::npos || Data.find("gb") != std::string::npos)
			{
				Data.erase(Data.length() - 2U, 2U);

			//Mark.
				Result = strtol(Data.c_str() + strlen("LogMaximumSize="), nullptr, NULL);
				if (Result >= 0)
				{
					Parameter.LogMaxSize = Result * GIGABYTE_TIMES;
				}
				else {
					PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
					return EXIT_FAILURE;
				}
			}
			else {
			//Check number.
				for (auto StringIter = Data.begin() + strlen("LogMaximumSize=");StringIter != Data.end();StringIter++)
				{
					if (*StringIter < ASCII_ZERO || *StringIter > ASCII_NINE)
					{
						PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
						return EXIT_FAILURE;
					}
				}

			//Mark.
				Result = strtol(Data.c_str() + strlen("LogMaximumSize="), nullptr, NULL);
				if (Result >= 0)
				{
					Parameter.LogMaxSize = Result;
				}
				else {
					PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
					return EXIT_FAILURE;
				}
			}
		}
	}

//[DNS] block
//	else if (Data.find("Protocol=") == 0)
	else if (Data.find("Protocol=TCP") == 0 || Data.find("Protocol=Tcp") == 0 || Data.find("Protocol=tcp") == 0)
	{
//		if (Data.find("Protocol=TCP") == 0 || Data.find("Protocol=Tcp") == 0 || Data.find("Protocol=tcp") == 0)
			Parameter.RquestMode = REQUEST_TCPMODE;
//		else 
//			Parameter.RquestMode = REQUEST_UDPMODE;
	}
	else if (Data.find("HostsOnly=1") == 0)
	{
		Parameter.HostsOnly = true;
	}
	else if (Data.find("LocalMain=1") == 0)
	{
		Parameter.LocalMain = true;
	}
	else if (Data.find("CacheType=") == 0 && Data.length() > strlen(("CacheType=")))
	{
		if (Data.find("CacheType=Timer") == 0)
			Parameter.CacheType = CACHE_TIMER;
		else if (Data.find("CacheType=Queue") == 0)
			Parameter.CacheType = CACHE_QUEUE;
	}
	else if (Parameter.CacheType != 0 && Data.find("CacheParameter=") == 0 && Data.length() > strlen("CacheParameter="))
	{
		Result = strtol(Data.c_str() + strlen("CacheParameter="), nullptr, NULL);
		if (Result > 0)
		{
			if (Parameter.CacheType == CACHE_TIMER)
				Parameter.CacheParameter = Result * SECOND_TO_MILLISECOND;
			else //CACHE_QUEUE
				Parameter.CacheParameter = Result;
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
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
		if (Data.find("OperationMode=Private") == 0 || Data.find("OperationMode=private") == 0)
			Parameter.OperationMode = LISTEN_PRIVATEMODE;
		else if (Data.find("OperationMode=Server") == 0 || Data.find("OperationMode=server") == 0)
			Parameter.OperationMode = LISTEN_SERVERMODE;
		else if (Data.find("OperationMode=Custom") == 0 || Data.find("OperationMode=custom") == 0)
			Parameter.OperationMode = LISTEN_CUSTOMMODE;
//		else 
//			Parameter.OperationMode = LISTEN_PROXYMODE;
	}
	else if (Data.find("ListenProtocol=") == 0)
	{
		if (Data.find("IPv6") != std::string::npos || Data.find("IPV6") != std::string::npos || Data.find("ipv6") != std::string::npos)
		{
			if (Data.find("IPv4") != std::string::npos || Data.find("IPV4") != std::string::npos || Data.find("ipv4") != std::string::npos)
				Parameter.ListenProtocol = LISTEN_IPV4_IPV6;
			else 
				Parameter.ListenProtocol = LISTEN_IPV6;
		}
//		else {
//			Parameter.ListenProtocol = LISTEN_IPV4;
//		}
	}
	else if (Data.find("ListenPort=") == 0)
	{
		if (Data.length() == strlen("ListenPort="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() < strlen("ListenPort=") + 6U)
		{
			Result = ServiceNameToPort((PSTR)Data.c_str() + strlen("ListenPort="));
			if (Result == 0)
			{
				Result = strtol(Data.c_str() + strlen("ListenPort="), nullptr, NULL);
				if (Result > 0 && Result <= U16_MAXNUM)
				{
					Parameter.ListenPort = htons((uint16_t)Result);
				}
				else {
					PrintError(LOG_ERROR_PARAMETER, L"Localhost server listening Port error", NULL, FileName, Line);
					return EXIT_FAILURE;
				}
			}
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
//	else if (Data.find("IPFilterType=") == 0)
	else if (Data.find("IPFilterType=Permit") == 0 || Data.find("IPFilterType=permit") == 0)
	{
		Parameter.IPFilterOptions.Type = true;
	}
	else if (Data.find("IPFilterLevel<") == 0)
	{
		if (Data.length() == strlen("IPFilterLevel<"))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() < strlen("IPFilterLevel<") + 4U)
		{
			Result = strtol(Data.c_str() + strlen("IPFilterLevel<"), nullptr, NULL);
			if (Result > 0 && Result <= U16_MAXNUM)
			{
				Parameter.IPFilterOptions.IPFilterLevel = (size_t)Result;
			}
			else {
				PrintError(LOG_ERROR_PARAMETER, L"IPFilter Level error", NULL, FileName, Line);
				return EXIT_FAILURE;
			}
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("AcceptType=") == 0)
	{
		if (Data.length() == strlen("AcceptType="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.find(ASCII_COLON) == std::string::npos)
		{
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
		else {
		//Permit or Deny.
			if (Data.find("Permit:") != std::string::npos || Data.find("permit:") != std::string::npos)
				Parameter.AcceptType = true;
//			else 
//				Parameter.AcceptType = false;

			std::string TypeString(Data, Data.find(ASCII_COLON) + 1U);
		//Add to global list.
			if (TypeString.empty())
			{
				PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
				return EXIT_FAILURE;
			}
			else if (TypeString.find(ASCII_COMMA) == std::string::npos && TypeString.find(ASCII_VERTICAL) == std::string::npos)
			{
				Result = DNSTypeNameToID((PSTR)TypeString.c_str());
				if (Result == 0)
				{
				//Number types
					Result = strtol(TypeString.c_str(), nullptr, NULL);
					if (Result > 0 && Result <= U16_MAXNUM)
					{
						AcceptTypeList.push_back(htons((uint16_t)Result));
					}
					else {
						PrintError(LOG_ERROR_PARAMETER, L"DNS Records type error", NULL, FileName, Line);
						return EXIT_FAILURE;
					}
				}
				else {
					AcceptTypeList.push_back((uint16_t)Result);
				}
			}
			else {
				std::string TypeStringTemp;
				Result = 0;
				for (size_t Index = 0;Index < TypeString.length();Index++)
				{
					if (Index == TypeString.length() - 1U) //Last value
					{
						TypeStringTemp.append(TypeString, Result, (SSIZE_T)Index - Result + 1U);
						Result = DNSTypeNameToID((PSTR)TypeString.c_str());
						if (Result == 0) 
						{
						//Number types
							Result = strtol(TypeString.c_str(), nullptr, NULL);
							if (Result > 0 && Result <= U16_MAXNUM)
							{
								AcceptTypeList.push_back(htons((uint16_t)Result));
							}
							else {
								PrintError(LOG_ERROR_PARAMETER, L"DNS Records type error", NULL, FileName, Line);
								return EXIT_FAILURE;
							}
						}
						else {
							AcceptTypeList.push_back((uint16_t)Result);
						}
					}
					else if (TypeString[Index] == ASCII_COMMA || TypeString[Index] == ASCII_VERTICAL)
					{
						TypeStringTemp.append(TypeString, Result, (SSIZE_T)Index - Result);
						Result = DNSTypeNameToID((PSTR)TypeString.c_str());
						if (Result == 0)
						{
						//Number types
							Result = strtol(TypeString.c_str(), nullptr, NULL);
							if (Result > 0 && Result <= U16_MAXNUM)
							{
								AcceptTypeList.push_back(htons((uint16_t)Result));
							}
							else {
								PrintError(LOG_ERROR_PARAMETER, L"DNS Records type error", NULL, FileName, Line);
								return EXIT_FAILURE;
							}
						}
						else {
							AcceptTypeList.push_back((uint16_t)Result);
						}

						TypeStringTemp.clear();
						Result = Index + 1U;
					}
				}
			}
		}
	}

//[Addresses] block
	else if (Data.find("IPv4DNSAddress=") == 0)
	{
		if (Data.length() == strlen("IPv4DNSAddress="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() > strlen("IPv4DNSAddress=") + 8U && (Data.length() < strlen("IPv4DNSAddress=") + 22U || Data.find(ASCII_VERTICAL) != std::string::npos))
		{
		//IPv4 Address and Port check
			if (Data.find(ASCII_COLON) == std::string::npos || Data.find(ASCII_COLON) < IPV4_SHORTEST_ADDRSTRING)
			{
				PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 Address format error", NULL, FileName, Line);
				return EXIT_FAILURE;
			}

			std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());
		//Multi requesting.
			if (Data.find(ASCII_VERTICAL) != std::string::npos)
			{
				DNSServerData DNSServerDataTemp;
				Data.erase(0, strlen("IPv4DNSAddress="));

			//Read data.
				while (Data.find(ASCII_COLON) != std::string::npos && Data.find(ASCII_VERTICAL) != std::string::npos && Data.find(ASCII_COLON) < Data.find(ASCII_VERTICAL))
				{
				//Convert IPv4 Address.
					memcpy(Target.get(), Data.c_str(), Data.find(ASCII_COLON));
					if (AddressStringToBinary(Target.get(), &DNSServerDataTemp.AddressData.IPv4.sin_addr, AF_INET, Result) == EXIT_FAILURE)
					{
						PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 Address format error", Result, FileName, Line);
						return EXIT_FAILURE;
					}

				//Convert IPv4 Port.
					Data.erase(0, Data.find(ASCII_COLON) + 1U);
					memset(Target.get(), 0, ADDR_STRING_MAXSIZE);
					memcpy(Target.get(), Data.c_str(), Data.find(ASCII_VERTICAL));
					Result = ServiceNameToPort(Target.get());
					if (Result == 0)
					{
						Result = strtol(Target.get(), nullptr, NULL);
						if (Result <= 0 || Result > U16_MAXNUM)
						{
							PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 Port error", NULL, FileName, Line);
							return EXIT_FAILURE;
						}
						else {
							DNSServerDataTemp.AddressData.IPv4.sin_port = htons((uint16_t)Result);
						}
					}
					memset(Target.get(), 0, ADDR_STRING_MAXSIZE);

				//Add to global list.
					DNSServerDataTemp.AddressData.Storage.ss_family = AF_INET;
					Parameter.DNSTarget.IPv4_Multi->push_back(DNSServerDataTemp);
					memset(&DNSServerDataTemp, 0, sizeof(DNSServerData));
					Data.erase(0, Data.find(ASCII_VERTICAL) + 1U);
				}

			//Last data
				//Convert IPv4 Address.
				memcpy(Target.get(), Data.c_str(), Data.find(ASCII_COLON));
				if (AddressStringToBinary(Target.get(), &DNSServerDataTemp.AddressData.IPv4.sin_addr, AF_INET, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 Address format error", Result, FileName, Line);
					return EXIT_FAILURE;
				}

				//Convert IPv4 Port.
				Data.erase(0, Data.find(ASCII_COLON) + 1U);
				memset(Target.get(), 0, ADDR_STRING_MAXSIZE);
				memcpy(Target.get(), Data.c_str(), Data.length());
				Result = ServiceNameToPort(Target.get());
				if (Result == 0)
				{
					Result = strtol(Target.get(), nullptr, NULL);
					if (Result <= 0 || Result > U16_MAXNUM)
					{
						PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 Port error", NULL, FileName, Line);
						return EXIT_FAILURE;
					}
					else {
						DNSServerDataTemp.AddressData.IPv4.sin_port = htons((uint16_t)Result);
					}
				}
				Target.reset();

				//Add to global list.
				DNSServerDataTemp.AddressData.Storage.ss_family = AF_INET;
				Parameter.DNSTarget.IPv4_Multi->push_back(DNSServerDataTemp);
			}
			else {
			//Convert IPv4 Address.
				memcpy(Target.get(), Data.c_str() + strlen("IPv4DNSAddress="), Data.find(ASCII_COLON) - strlen("IPv4DNSAddress="));
				if (AddressStringToBinary(Target.get(), &Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr, AF_INET, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 Address format error", Result, FileName, Line);
					return EXIT_FAILURE;
				}
				Target.reset();

			//Convert IPv4 Port.
				Result = ServiceNameToPort((PSTR)Data.c_str() + Data.find(ASCII_COLON) + 1U);
				if (Result == 0)
				{
					Result = strtol(Data.c_str() + Data.find(ASCII_COLON) + 1U, nullptr, NULL);
					if (Result <= 0 || Result > U16_MAXNUM)
					{
						PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 Port error", NULL, FileName, Line);
						return EXIT_FAILURE;
					}
					else {
						Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_port = htons((uint16_t)Result);
					}
				}

				Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family = AF_INET;
			}
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("IPv4AlternateDNSAddress=") == 0)
	{
		if (Data.length() == strlen("IPv4AlternateDNSAddress="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() > strlen("IPv4AlternateDNSAddress=") + 8U && (Data.length() < strlen("IPv4AlternateDNSAddress=") + 22U || Data.find(ASCII_VERTICAL) != std::string::npos))
		{
		//IPv4 Address and Port check
			if (Data.find(ASCII_COLON) == std::string::npos || Data.find(ASCII_COLON) < IPV4_SHORTEST_ADDRSTRING)
			{
				PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 Address format error", NULL, FileName, Line);
				return EXIT_FAILURE;
			}

			std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());
		//Multi requesting.
			if (Data.find(ASCII_VERTICAL) != std::string::npos)
			{
				DNSServerData DNSServerDataTemp;
				Data.erase(0, strlen("IPv4AlternateDNSAddress="));

			//Read data.
				while (Data.find(ASCII_COLON) != std::string::npos && Data.find(ASCII_VERTICAL) != std::string::npos && Data.find(ASCII_COLON) < Data.find(ASCII_VERTICAL))
				{
				//Convert IPv4 Address.
					memcpy(Target.get(), Data.c_str(), Data.find(ASCII_COLON));
					if (AddressStringToBinary(Target.get(), &DNSServerDataTemp.AddressData.IPv4.sin_addr, AF_INET, Result) == EXIT_FAILURE)
					{
						PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 Address format error", Result, FileName, Line);
						return EXIT_FAILURE;
					}

				//Convert IPv4 Port.
					Data.erase(0, Data.find(ASCII_COLON) + 1U);
					memset(Target.get(), 0, ADDR_STRING_MAXSIZE);
					memcpy(Target.get(), Data.c_str(), Data.find(ASCII_VERTICAL));
					Result = ServiceNameToPort(Target.get());
					if (Result == 0)
					{
						Result = strtol(Target.get(), nullptr, NULL);
						if (Result <= 0 || Result > U16_MAXNUM)
						{
							PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 Port error", NULL, FileName, Line);
							return EXIT_FAILURE;
						}
						else {
							DNSServerDataTemp.AddressData.IPv4.sin_port = htons((uint16_t)Result);
						}
					}
					memset(Target.get(), 0, ADDR_STRING_MAXSIZE);

				//Add to global list.
					DNSServerDataTemp.AddressData.Storage.ss_family = AF_INET;
					Parameter.DNSTarget.IPv4_Multi->push_back(DNSServerDataTemp);
					memset(&DNSServerDataTemp, 0, sizeof(DNSServerData));
					Data.erase(0, Data.find(ASCII_VERTICAL) + 1U);
				}

			//Last data
				//Convert IPv4 Address.
				memcpy(Target.get(), Data.c_str(), Data.find(ASCII_COLON));
				if (AddressStringToBinary(Target.get(), &DNSServerDataTemp.AddressData.IPv4.sin_addr, AF_INET, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 Address format error", Result, FileName, Line);
					return EXIT_FAILURE;
				}

				//Convert IPv4 Port.
				Data.erase(0, Data.find(ASCII_COLON) + 1U);
				memset(Target.get(), 0, ADDR_STRING_MAXSIZE);
				memcpy(Target.get(), Data.c_str(), Data.length());
				Result = ServiceNameToPort(Target.get());
				if (Result == 0)
				{
					Result = strtol(Target.get(), nullptr, NULL);
					if (Result <= 0 || Result > U16_MAXNUM)
					{
						PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 Port error", NULL, FileName, Line);
						return EXIT_FAILURE;
					}
					else {
						DNSServerDataTemp.AddressData.IPv4.sin_port = htons((uint16_t)Result);
					}
				}
				Target.reset();

				//Add to global list.
				DNSServerDataTemp.AddressData.Storage.ss_family = AF_INET;
				Parameter.DNSTarget.IPv4_Multi->push_back(DNSServerDataTemp);
			}
			else {
			//Convert IPv4 Address.
				memcpy(Target.get(), Data.c_str() + strlen("IPv4AlternateDNSAddress="), Data.find(ASCII_COLON) - strlen("IPv4AlternateDNSAddress="));
				if (AddressStringToBinary(Target.get(), &Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr, AF_INET, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 Address format error", Result, FileName, Line);
					return EXIT_FAILURE;
				}
				Target.reset();

			//Convert IPv4 Port.
				Result = ServiceNameToPort((PSTR)Data.c_str() + Data.find(ASCII_COLON) + 1U);
				if (Result == 0)
				{
					Result = strtol(Data.c_str() + Data.find(ASCII_COLON) + 1U, nullptr, NULL);
					if (Result <= 0 || Result > U16_MAXNUM)
					{
						PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 Port error", NULL, FileName, Line);
						return EXIT_FAILURE;
					}
					else {
						Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_port = htons((uint16_t)Result);
					}
				}

				Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family = AF_INET;
			}
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("IPv4LocalDNSAddress=") == 0)
	{
		if (Data.length() == strlen("IPv4LocalDNSAddress="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() > strlen("IPv4LocalDNSAddress=") + 8U && Data.length() < strlen("IPv4LocalDNSAddress=") + 22U)
		{
		//IPv4 Address and Port check
			if (Data.find(ASCII_COLON) == std::string::npos || Data.find(ASCII_COLON) < IPV4_SHORTEST_ADDRSTRING)
			{
				PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 Address format error", NULL, FileName, Line);
				return EXIT_FAILURE;
			}

		//Convert IPv4 Address.
			std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());
			memcpy(Target.get(), Data.c_str() + strlen("IPv4LocalDNSAddress="), Data.find(ASCII_COLON) - strlen("IPv4LocalDNSAddress="));
			if (AddressStringToBinary(Target.get(), &Parameter.DNSTarget.Local_IPv4.AddressData.IPv4.sin_addr, AF_INET, Result) == EXIT_FAILURE)
			{
				PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 Address format error", Result, FileName, Line);
				return EXIT_FAILURE;
			}

		//Convert IPv4 Port.
			Result = ServiceNameToPort((PSTR)Data.c_str() + Data.find(ASCII_COLON) + 1U);
			if (Result == 0)
			{
				Result = strtol(Data.c_str() + Data.find(ASCII_COLON) + 1U, nullptr, NULL);
				if (Result <= 0 || Result > U16_MAXNUM)
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 Port error", NULL, FileName, Line);
					return EXIT_FAILURE;
				}
				else {
					Parameter.DNSTarget.Local_IPv4.AddressData.IPv4.sin_port = htons((uint16_t)Result);
				}
			}

			Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family = AF_INET;
		}
	}
	else if (Data.find("IPv4LocalAlternateDNSAddress=") == 0)
	{
		if (Data.length() == strlen("IPv4LocalAlternateDNSAddress="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() > strlen("IPv4LocalAlternateDNSAddress=") + 8U && Data.length() < strlen("IPv4LocalAlternateDNSAddress=") + 22U)
		{
		//IPv4 Address and Port check
			if (Data.find(ASCII_COLON) == std::string::npos || Data.find(ASCII_COLON) < IPV4_SHORTEST_ADDRSTRING) //IPv4 Address(".") and Port(":")
			{
				PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 Address format error", NULL, FileName, Line);
				return EXIT_FAILURE;
			}

		//Convert IPv4 Address.
			std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());
			memcpy(Target.get(), Data.c_str() + strlen("IPv4LocalAlternateDNSAddress="), Data.find(ASCII_COLON) - strlen("IPv4LocalAlternateDNSAddress="));
			if (AddressStringToBinary(Target.get(), &Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.IPv4.sin_addr, AF_INET, Result) == EXIT_FAILURE)
			{
				PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 Address format error", Result, FileName, Line);
				return EXIT_FAILURE;
			}

		//Convert IPv4 Port.
			Result = ServiceNameToPort((PSTR)Data.c_str() + Data.find(ASCII_COLON) + 1U);
			if (Result == 0)
			{
				Result = strtol(Data.c_str() + Data.find(ASCII_COLON) + 1U, nullptr, NULL);
				if (Result <= 0 || Result > U16_MAXNUM)
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 Port error", NULL, FileName, Line);
					return EXIT_FAILURE;
				}
				else {
					Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.IPv4.sin_port = htons((uint16_t)Result);
				}
			}

			Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage.ss_family = AF_INET;
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("IPv6DNSAddress=") == 0)
	{
		if (Data.length() == strlen("IPv6DNSAddress="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() > strlen("IPv6DNSAddress=") + 6U && (Data.length() < strlen("IPv6DNSAddress=") + 48U || Data.find(ASCII_VERTICAL) != std::string::npos))
		{
		//IPv6 Address and Port check.
			if (Data.find(ASCII_BRACKETS_LEAD) == std::string::npos || Data.find(ASCII_BRACKETS_TRAIL) == std::string::npos || Data.find(ASCII_BRACKETS_TRAIL) < IPV6_SHORTEST_ADDRSTRING)
			{
				PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 Address format error", NULL, FileName, Line);
				return EXIT_FAILURE;
			}

			std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());
		//Multi requesting
			if (Data.find(ASCII_VERTICAL) != std::string::npos)
			{
				DNSServerData DNSServerDataTemp;
				Data.erase(0, strlen("IPv6DNSAddress="));

			//Delete all front brackets and port colon.
				while (Data.find(ASCII_BRACKETS_LEAD) != std::string::npos)
					Data.erase(Data.find(ASCII_BRACKETS_LEAD), 1U);
				while (Data.find("]:") != std::string::npos)
					Data.erase(Data.find("]:") + 1U, 1U);

			//Read data.
				while (Data.find(ASCII_BRACKETS_TRAIL) != std::string::npos && Data.find(ASCII_VERTICAL) != std::string::npos && Data.find(ASCII_BRACKETS_TRAIL) < Data.find(ASCII_VERTICAL))
				{
				//Convert IPv6 Address.
					memcpy(Target.get(), Data.c_str(), Data.find(ASCII_BRACKETS_TRAIL));
					if (AddressStringToBinary(Target.get(), &DNSServerDataTemp.AddressData.IPv6.sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
					{
						PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 Address format error", Result, FileName, Line);
						return EXIT_FAILURE;
					}

				//Convert IPv6 Port.
					Data.erase(0, Data.find(ASCII_BRACKETS_TRAIL) + 1U);
					memset(Target.get(), 0, ADDR_STRING_MAXSIZE);
					memcpy(Target.get(), Data.c_str(), Data.find(ASCII_VERTICAL));
					Result = ServiceNameToPort(Target.get());
					if (Result == 0)
					{
						Result = strtol(Target.get(), nullptr, NULL);
						if (Result <= 0 || Result > U16_MAXNUM)
						{
							PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 Port error", NULL, FileName, Line);
							return EXIT_FAILURE;
						}
						else {
							DNSServerDataTemp.AddressData.IPv6.sin6_port = htons((uint16_t)Result);
						}
					}
					memset(Target.get(), 0, ADDR_STRING_MAXSIZE);

				//Add to global list.
					DNSServerDataTemp.AddressData.Storage.ss_family = AF_INET6;
					Parameter.DNSTarget.IPv6_Multi->push_back(DNSServerDataTemp);
					memset(&DNSServerDataTemp, 0, sizeof(DNSServerData));
					Data.erase(0, Data.find(ASCII_VERTICAL) + 1U);
				}

			//Last data
				//Convert IPv6 Address.
				memcpy(Target.get(), Data.c_str(), Data.find(ASCII_BRACKETS_TRAIL));
				if (AddressStringToBinary(Target.get(), &DNSServerDataTemp.AddressData.IPv6.sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 Address format error", Result, FileName, Line);
					return EXIT_FAILURE;
				}

				//Convert IPv6 Port.
				Data.erase(0, Data.find(ASCII_BRACKETS_TRAIL) + 1U);
				memset(Target.get(), 0, ADDR_STRING_MAXSIZE);
				memcpy(Target.get(), Data.c_str(), Data.length());
				Result = ServiceNameToPort(Target.get());
				if (Result == 0)
				{
					Result = strtol(Target.get(), nullptr, NULL);
					if (Result <= 0 || Result > U16_MAXNUM)
					{
						PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 Port error", NULL, FileName, Line);
						return EXIT_FAILURE;
					}
					else {
						DNSServerDataTemp.AddressData.IPv6.sin6_port = htons((uint16_t)Result);
					}
				}

				//Add to global list.
				DNSServerDataTemp.AddressData.Storage.ss_family = AF_INET6;
				Parameter.DNSTarget.IPv6_Multi->push_back(DNSServerDataTemp);
			}
			else {
			//Convert IPv6 Address.
				memcpy(Target.get(), Data.c_str() + strlen("IPv6DNSAddress=") + 1U, Data.find(ASCII_BRACKETS_TRAIL) - strlen("IPv6DNSAddress=") - 1U);
				if (AddressStringToBinary(Target.get(), &Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 Address format error", Result, FileName, Line);
					return EXIT_FAILURE;
				}

			//Convert IPv6 Port.
				Result = ServiceNameToPort((PSTR)Data.c_str() + Data.find(ASCII_BRACKETS_TRAIL) + 2U);
				if (Result == 0)
				{
					Result = strtol(Data.c_str() + Data.find(ASCII_BRACKETS_TRAIL) + 2U, nullptr, NULL);
					if (Result <= 0 || Result > U16_MAXNUM)
					{
						PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 Port error", NULL, FileName, Line);
						return EXIT_FAILURE;
					}
					else {
						Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_port = htons((uint16_t)Result);
					}
				}

				Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family = AF_INET6;
			}
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("IPv6AlternateDNSAddress=") == 0)
	{
		if (Data.length() == strlen("IPv6AlternateDNSAddress="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() > strlen("IPv6AlternateDNSAddress=") + 6U && (Data.length() < strlen("IPv6AlternateDNSAddress=") + 48U || Data.find(ASCII_VERTICAL) != std::string::npos))
		{
		//IPv6 Address and Port check.
			if (Data.find(ASCII_BRACKETS_LEAD) == std::string::npos || Data.find(ASCII_BRACKETS_TRAIL) == std::string::npos || Data.find(ASCII_BRACKETS_TRAIL) < IPV6_SHORTEST_ADDRSTRING)
			{
				PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 Address format error", NULL, FileName, Line);
				return EXIT_FAILURE;
			}

			std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());
		//Multi requesting
			if (Data.find(ASCII_VERTICAL) != std::string::npos)
			{
				DNSServerData DNSServerDataTemp;
				Data.erase(0, strlen("IPv6AlternateDNSAddress="));

			//Delete all front brackets and port colon.
				while (Data.find(ASCII_BRACKETS_LEAD) != std::string::npos)
					Data.erase(Data.find(ASCII_BRACKETS_LEAD), 1U);
				while (Data.find("]:") != std::string::npos)
					Data.erase(Data.find("]:") + 1U, 1U);

			//Read data.
				while (Data.find(ASCII_BRACKETS_TRAIL) != std::string::npos && Data.find(ASCII_VERTICAL) != std::string::npos && Data.find(ASCII_BRACKETS_TRAIL) < Data.find(ASCII_VERTICAL))
				{
				//Convert IPv6 Address.
					memcpy(Target.get(), Data.c_str(), Data.find(ASCII_BRACKETS_TRAIL));
					if (AddressStringToBinary(Target.get(), &DNSServerDataTemp.AddressData.IPv6.sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
					{
						PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 Address format error", Result, FileName, Line);
						return EXIT_FAILURE;
					}

				//Convert IPv6 Port.
					Data.erase(0, Data.find(ASCII_BRACKETS_TRAIL) + 1U);
					memset(Target.get(), 0, ADDR_STRING_MAXSIZE);
					memcpy(Target.get(), Data.c_str(), Data.find(ASCII_VERTICAL));
					Result = ServiceNameToPort(Target.get());
					if (Result == 0)
					{
						Result = strtol(Target.get(), nullptr, NULL);
						if (Result <= 0 || Result > U16_MAXNUM)
						{
							PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 Port error", NULL, FileName, Line);
							return EXIT_FAILURE;
						}
						else {
							DNSServerDataTemp.AddressData.IPv6.sin6_port = htons((uint16_t)Result);
						}
					}
					memset(Target.get(), 0, ADDR_STRING_MAXSIZE);

				//Add to global list.
					DNSServerDataTemp.AddressData.Storage.ss_family = AF_INET6;
					Parameter.DNSTarget.IPv6_Multi->push_back(DNSServerDataTemp);
					memset(&DNSServerDataTemp, 0, sizeof(DNSServerData));
					Data.erase(0, Data.find(ASCII_VERTICAL) + 1U);
				}

			//Last data
				//Convert IPv6 Address.
				memcpy(Target.get(), Data.c_str(), Data.find(ASCII_BRACKETS_TRAIL));
				if (AddressStringToBinary(Target.get(), &DNSServerDataTemp.AddressData.IPv6.sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 Address format error", Result, FileName, Line);
					return EXIT_FAILURE;
				}

				//Convert IPv6 Port.
				Data.erase(0, Data.find(ASCII_BRACKETS_TRAIL) + 1U);
				memset(Target.get(), 0, ADDR_STRING_MAXSIZE);
				memcpy(Target.get(), Data.c_str(), Data.length());
				Result = ServiceNameToPort(Target.get());
				if (Result == 0)
				{
					Result = strtol(Target.get(), nullptr, NULL);
					if (Result <= 0 || Result > U16_MAXNUM)
					{
						PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 Port error", NULL, FileName, Line);
						return EXIT_FAILURE;
					}
					else {
						DNSServerDataTemp.AddressData.IPv6.sin6_port = htons((uint16_t)Result);
					}
				}

				//Add to global list.
				DNSServerDataTemp.AddressData.Storage.ss_family = AF_INET6;
				Parameter.DNSTarget.IPv6_Multi->push_back(DNSServerDataTemp);
			}
			else {
			//Convert IPv6 Address
				memcpy(Target.get(), Data.c_str() + strlen("IPv6AlternateDNSAddress=") + 1U, Data.find(ASCII_BRACKETS_TRAIL) - strlen("IPv6AlternateDNSAddress=") - 1U);
				if (AddressStringToBinary(Target.get(), &Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 Address format error", Result, FileName, Line);
					return EXIT_FAILURE;
				}

			//Convert IPv6 Port.
				Result = ServiceNameToPort((PSTR)Data.c_str() + Data.find(ASCII_BRACKETS_TRAIL) + 2U);
				if (Result == 0)
				{
					Result = strtol(Data.c_str() + Data.find(ASCII_BRACKETS_TRAIL) + 2U, nullptr, NULL);
					if (Result <= 0 || Result > U16_MAXNUM)
					{
						PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 Port error", NULL, FileName, Line);
						return EXIT_FAILURE;
					}
					else {
						Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_port = htons((uint16_t)Result);
					}
				}

				Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family = AF_INET6;
			}
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("IPv6LocalDNSAddress=") == 0)
	{
		if (Data.length() == strlen("IPv6LocalDNSAddress="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() > strlen("IPv6LocalDNSAddress=") + 6U && Data.length() < strlen("IPv6LocalDNSAddress=") + 48U)
		{
		//IPv6 Address and Port check.
			if (Data.find(ASCII_BRACKETS_LEAD) == std::string::npos || Data.find(ASCII_BRACKETS_TRAIL) == std::string::npos || Data.find(ASCII_BRACKETS_TRAIL) < IPV6_SHORTEST_ADDRSTRING)
			{
				PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 Address format error", NULL, FileName, Line);
				return EXIT_FAILURE;
			}

		//Convert IPv6 Address.
			std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());
			memcpy(Target.get(), Data.c_str() + strlen("IPv6LocalDNSAddress=") + 1U, Data.find(ASCII_BRACKETS_TRAIL) - strlen("IPv6LocalDNSAddress=") - 1U);
			if (AddressStringToBinary(Target.get(), &Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
			{
				PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 Address format error", Result, FileName, Line);
				return EXIT_FAILURE;
			}

		//Convert IPv6 Port.
			Result = ServiceNameToPort((PSTR)Data.c_str() + Data.find(ASCII_BRACKETS_TRAIL) + 2U);
			if (Result == 0)
			{
				Result = strtol(Data.c_str() + Data.find(ASCII_BRACKETS_TRAIL) + 2U, nullptr, NULL);
				if (Result <= 0 || Result > U16_MAXNUM)
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 Port error", NULL, FileName, Line);
					return EXIT_FAILURE;
				}
				else {
					Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_port = htons((uint16_t)Result);
				}
			}

			Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family = AF_INET6;
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("IPv6LocalAlternateDNSAddress=") == 0)
	{
		if (Data.length() == strlen("IPv6LocalAlternateDNSAddress="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() > strlen("IPv6LocalAlternateDNSAddress=") + 6U && Data.length() < strlen("IPv6LocalAlternateDNSAddress=") + 48U)
		{
		//IPv6 Address and Port check
			if (Data.find(ASCII_BRACKETS_LEAD) == std::string::npos || Data.find(ASCII_BRACKETS_TRAIL) == std::string::npos || Data.find(ASCII_BRACKETS_TRAIL) < IPV6_SHORTEST_ADDRSTRING)
			{
				PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 Address format error", NULL, FileName, Line);
				return EXIT_FAILURE;
			}

		//Convert IPv6 Address.
			std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());
			memcpy(Target.get(), Data.c_str() + strlen("IPv6LocalAlternateDNSAddress=") + 1U, Data.find(ASCII_BRACKETS_TRAIL) - strlen("IPv6LocalAlternateDNSAddress=") - 1U);
			if (AddressStringToBinary(Target.get(), &Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6.sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
			{
				PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 Address format error", Result, FileName, Line);
				return EXIT_FAILURE;
			}

		//Convert IPv6 Port.
			Result = ServiceNameToPort((PSTR)Data.c_str() + Data.find(ASCII_BRACKETS_TRAIL) + 2U);
			if (Result == 0)
			{
				Result = strtol(Data.c_str() + Data.find(ASCII_BRACKETS_TRAIL) + 2U, nullptr, NULL);
				if (Result <= 0 || Result > U16_MAXNUM)
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 Port error", NULL, FileName, Line);
					return EXIT_FAILURE;
				}
				else {
					Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6.sin6_port = htons((uint16_t)Result);
				}
			}

			Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family = AF_INET6;
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}

//[Values] block
	else if (Data.find("EDNS0PayloadSize=") == 0)
	{
		if (Data.length() == strlen("EDNS0PayloadSize="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() < strlen("EDNS0PayloadSize=") + 6U)
		{
			Result = strtol(Data.c_str() + strlen("EDNS0PayloadSize="), nullptr, NULL);
			if (Result >= 0)
				Parameter.EDNS0PayloadSize = Result;
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("IPv4TTL=") == 0)
	{
		if (Data.length() == strlen("IPv4TTL="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() > strlen("IPv4TTL=") && Data.length() < ADDR_STRING_MAXSIZE)
		{
			if (Data.find(ASCII_VERTICAL) == std::string::npos)
			{
				Result = strtol(Data.c_str() + strlen("IPv4TTL="), nullptr, NULL);
				if (Result > 0 && Result < U8_MAXNUM)
					Parameter.DNSTarget.IPv4.HopLimitData.TTL = (uint8_t)Result;
			}
			else {
				std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());
				Data.erase(0, strlen("IPv4TTL="));
				size_t Index = 0;

				while (Data.find(ASCII_VERTICAL) != std::string::npos && Data.find(ASCII_VERTICAL) > 0)
				{
					memset(Target.get(), 0, ADDR_STRING_MAXSIZE);
					memcpy(Target.get(), Data.c_str(), Data.find(ASCII_VERTICAL));
					Data.erase(0, Data.find(ASCII_VERTICAL) + 1U);
					Result = strtol(Target.get(), nullptr, NULL);

				//Mark TTL.
					if (Result > 0 && Result < U8_MAXNUM && Parameter.DNSTarget.IPv4_Multi->size() > Index)
						Parameter.DNSTarget.IPv4_Multi->at(Index).HopLimitData.TTL = (uint8_t)Result;
					
					Index++;
				}

			//Last item
				memset(Target.get(), 0, ADDR_STRING_MAXSIZE);
				memcpy(Target.get(), Data.c_str(), Data.length());
				Result = strtol(Target.get(), nullptr, NULL);
				if (Result > 0 && Result < U8_MAXNUM && Parameter.DNSTarget.IPv4_Multi->size() > Index)
					Parameter.DNSTarget.IPv4_Multi->at(Index).HopLimitData.TTL = (uint8_t)Result;
			}
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("IPv6HopLimits=") == 0)
	{
		if (Data.length() == strlen("IPv6HopLimits="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() > strlen("IPv6HopLimits=") && Data.length() < ADDR_STRING_MAXSIZE)
		{
			if (Data.find(ASCII_VERTICAL) == std::string::npos)
			{
				Result = strtol(Data.c_str() + strlen("IPv6HopLimits="), nullptr, NULL);
				if (Result > 0 && Result < U8_MAXNUM)
					Parameter.DNSTarget.IPv6.HopLimitData.HopLimit = (uint8_t)Result;
			}
			else {
				std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());
				Data.erase(0, strlen("IPv6HopLimits="));
				size_t Index = 0;

				while (Data.find(ASCII_VERTICAL) != std::string::npos && Data.find(ASCII_VERTICAL) > 0)
				{
					memset(Target.get(), 0, ADDR_STRING_MAXSIZE);
					memcpy(Target.get(), Data.c_str(), Data.find(ASCII_VERTICAL));
					Data.erase(0, Data.find(ASCII_VERTICAL) + 1U);
					Result = strtol(Target.get(), nullptr, NULL);

				//Mark TTL.
					if (Result > 0 && Result < U8_MAXNUM && Parameter.DNSTarget.IPv6_Multi->size() > Index)
						Parameter.DNSTarget.IPv6_Multi->at(Index).HopLimitData.HopLimit = (uint8_t)Result;
					
					Index++;
				}

			//Last item
				memset(Target.get(), 0, ADDR_STRING_MAXSIZE);
				memcpy(Target.get(), Data.c_str(), Data.length());
				Result = strtol(Target.get(), nullptr, NULL);
				if (Result > 0 && Result < U8_MAXNUM && Parameter.DNSTarget.IPv6_Multi->size() > Index)
					Parameter.DNSTarget.IPv6_Multi->at(Index).HopLimitData.HopLimit = (uint8_t)Result;
			}
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("IPv4AlternateTTL=") == 0)
	{
		if (Data.length() == strlen("IPv4AlternateTTL="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() > strlen("IPv4AlternateTTL=") && Data.length() < ADDR_STRING_MAXSIZE)
		{
			if (Data.find(ASCII_VERTICAL) == std::string::npos)
			{
				Result = strtol(Data.c_str() + strlen("IPv4AlternateTTL="), nullptr, NULL);
				if (Result > 0 && Result < U8_MAXNUM)
					Parameter.DNSTarget.Alternate_IPv4.HopLimitData.TTL = (uint8_t)Result;
			}
			else {
				std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());
				Data.erase(0, strlen("IPv4AlternateTTL="));
				size_t Index = 0;
				for (size_t InnerIndex = 0;InnerIndex < Parameter.DNSTarget.IPv4_Multi->size();InnerIndex++)
				{
					if (Parameter.DNSTarget.IPv4_Multi->at(InnerIndex).HopLimitData.TTL != 0)
						Index = InnerIndex;
				}

				while (Data.find(ASCII_VERTICAL) != std::string::npos && Data.find(ASCII_VERTICAL) > 0)
				{
					memset(Target.get(), 0, ADDR_STRING_MAXSIZE);
					memcpy(Target.get(), Data.c_str(), Data.find(ASCII_VERTICAL));
					Data.erase(0, Data.find(ASCII_VERTICAL) + 1U);
					Result = strtol(Target.get(), nullptr, NULL);

				//Mark TTL.
					if (Result > 0 && Result < U8_MAXNUM && Parameter.DNSTarget.IPv4_Multi->size() > Index)
						Parameter.DNSTarget.IPv4_Multi->at(Index).HopLimitData.TTL = (uint8_t)Result;
					
					Index++;
				}

			//Last item
				memset(Target.get(), 0, ADDR_STRING_MAXSIZE);
				memcpy(Target.get(), Data.c_str(), Data.length());
				Result = strtol(Target.get(), nullptr, NULL);
				if (Result > 0 && Result < U8_MAXNUM && Parameter.DNSTarget.IPv4_Multi->size() > Index)
					Parameter.DNSTarget.IPv4_Multi->at(Index).HopLimitData.TTL = (uint8_t)Result;
			}
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("IPv6AlternateHopLimits=") == 0)
	{
		if (Data.length() == strlen("IPv6AlternateHopLimits="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() > strlen("IPv6AlternateHopLimits=") && Data.length() < ADDR_STRING_MAXSIZE)
		{
			if (Data.find(ASCII_VERTICAL) == std::string::npos)
			{
				Result = strtol(Data.c_str() + strlen("IPv6AlternateHopLimits="), nullptr, NULL);
				if (Result > 0 && Result < U8_MAXNUM)
					Parameter.DNSTarget.Alternate_IPv6.HopLimitData.HopLimit = (uint8_t)Result;
			}
			else {
				std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());
				Data.erase(0, strlen("IPv6AlternateHopLimits="));
				size_t Index = 0;
				for (size_t InnerIndex = 0;InnerIndex < Parameter.DNSTarget.IPv6_Multi->size();InnerIndex++)
				{
					if (Parameter.DNSTarget.IPv6_Multi->at(InnerIndex).HopLimitData.HopLimit != 0)
						Index = InnerIndex;
				}

				while (Data.find(ASCII_VERTICAL) != std::string::npos && Data.find(ASCII_VERTICAL) > 0)
				{
					memset(Target.get(), 0, ADDR_STRING_MAXSIZE);
					memcpy(Target.get(), Data.c_str(), Data.find(ASCII_VERTICAL));
					Data.erase(0, Data.find(ASCII_VERTICAL) + 1U);
					Result = strtol(Target.get(), nullptr, NULL);

				//Mark TTL.
					if (Result > 0 && Result < U8_MAXNUM && Parameter.DNSTarget.IPv6_Multi->size() > Index)
						Parameter.DNSTarget.IPv6_Multi->at(Index).HopLimitData.HopLimit = (uint8_t)Result;
					
					Index++;
				}

			//Last item
				memset(Target.get(), 0, ADDR_STRING_MAXSIZE);
				memcpy(Target.get(), Data.c_str(), Data.length());
				Result = strtol(Target.get(), nullptr, NULL);
				if (Result > 0 && Result < U8_MAXNUM && Parameter.DNSTarget.IPv6_Multi->size() > Index)
					Parameter.DNSTarget.IPv6_Multi->at(Index).HopLimitData.HopLimit = (uint8_t)Result;
			}
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("HopLimitsFluctuation=") == 0)
	{
		if (Data.length() == strlen("HopLimitsFluctuation="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() < strlen("HopLimitsFluctuation=") + 4U)
		{
			Result = strtol(Data.c_str() + strlen("HopLimitsFluctuation="), nullptr, NULL);
			if (Result > 0 && Result < U8_MAXNUM)
				Parameter.HopLimitFluctuation = (uint8_t)Result;
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("ICMPTest=") == 0)
	{
		if (Data.length() == strlen("ICMPTest="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() < strlen("ICMPTest=") + 6U)
		{
			Result = strtol(Data.c_str() + strlen("ICMPTest="), nullptr, NULL);
			if (Result >= 5)
				Parameter.ICMPOptions.ICMPSpeed = Result * SECOND_TO_MILLISECOND;
			else if (Result > 0 && Result < DEFAULT_ICMPTEST_TIME)
				Parameter.ICMPOptions.ICMPSpeed = DEFAULT_ICMPTEST_TIME * SECOND_TO_MILLISECOND;
			else 
				Parameter.ICMPOptions.ICMPSpeed = 0; //ICMP Test Disable.
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("DomainTest=") == 0)
	{
		if (Data.length() == strlen("DomainTest="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() < strlen("DomainTest=") + 6U)
		{
			Result = strtol(Data.c_str() + strlen("DomainTest="), nullptr, NULL);
			if (Result > 0)
				Parameter.DomainTestOptions.DomainTestSpeed = Result * SECOND_TO_MILLISECOND;
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);

			return EXIT_FAILURE;
		}
	}
	else if (Data.find("AlternateTimes=") == 0)
	{
		if (Data.length() == strlen("AlternateTimes="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() < strlen("AlternateTimes=") + 6U)
		{
			Result = strtol(Data.c_str() + strlen("AlternateTimes="), nullptr, NULL);
			if (Result > 0)
				Parameter.AlternateOptions.AlternateTimes = Result;
			else 
				Parameter.AlternateOptions.AlternateTimes = DEFAULT_ALTERNATE_TIMES;
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("AlternateTimeRange=") == 0)
	{
		if (Data.length() == strlen("AlternateTimeRange="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() < strlen("AlternateTimeRange=") + 6U)
		{
			Result = strtol(Data.c_str() + strlen("AlternateTimeRange="), nullptr, NULL);
			if (Result >= DEFAULT_ALTERNATE_RANGE)
				Parameter.AlternateOptions.AlternateTimeRange = Result * SECOND_TO_MILLISECOND;
			else 
				Parameter.AlternateOptions.AlternateTimeRange = DEFAULT_ALTERNATE_RANGE * SECOND_TO_MILLISECOND;
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("AlternateResetTime=") == 0)
	{
		if (Data.length() == strlen("AlternateResetTime="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() < strlen("AlternateResetTime=") + 6U)
		{
			Result = strtol(Data.c_str() + strlen("AlternateResetTime="), nullptr, NULL);
			if (Result >= DEFAULT_ALTERNATERESET_TIME)
				Parameter.AlternateOptions.AlternateResetTime = Result * SECOND_TO_MILLISECOND;
			else 
				Parameter.AlternateOptions.AlternateResetTime = DEFAULT_ALTERNATERESET_TIME * SECOND_TO_MILLISECOND;
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("MultiRequestTimes=") == 0)
	{
		if (Data.length() == strlen("MultiRequestTimes="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() < strlen("MultiRequestTimes=") + 6U)
		{
			Result = strtol(Data.c_str() + strlen("MultiRequestTimes="), nullptr, NULL);
			if (Result > 0)
				Parameter.MultiRequestTimes = Result + 1U;
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}

//[Switches] block
	else if (Data.find("DomainCaseConversion=1") == 0)
	{
		Parameter.DomainCaseConversion = true;
	}
	else if (Data.find("CompressionPointerMutation=1") == 0)
	{
		Parameter.CompressionPointerMutation = true;
	}
//	else if (Data.find("EDNS0Label=") == 0)
	else if (Data.find("EDNS0Label=1") == 0)
	{
		Parameter.EDNS0Label = true;
	}
//	else if (Data.find("DNSSECRequest=") == 0)
	else if (Data.find("DNSSECRequest=1") == 0)
	{
		Parameter.DNSSECRequest = true;
	}
	else if (Data.find("AlternateMultiRequest=1") == 0)
	{
		Parameter.AlternateMultiRequest = true;
	}
//	else if (Data.find("IPv4DataFilter=") == 0)
	else if (Data.find("IPv4DataFilter=1") == 0)
	{
		Parameter.IPv4DataCheck = true;
	}
//	else if (Data.find("TCPDataFilter=") == 0)
	else if (Data.find("TCPDataFilter=1") == 0)
	{
		Parameter.TCPDataCheck = true;
	}
//	else if (Data.find("DNSDataFilter=") == 0)
	else if (Data.find("DNSDataFilter=1") == 0)
	{
		Parameter.DNSDataCheck = true;
	}
//	else if (Data.find("BlacklistFilter=") == 0)
	else if (Data.find("BlacklistFilter=1") == 0)
	{
		Parameter.Blacklist = true;
	}

//[Data] block
	else if (Data.find("ICMPID=") == 0)
	{
		if (Data.length() == strlen("ICMPID="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() < strlen("ICMPID=") + 7U)
		{
			Result = strtol(Data.c_str() + strlen("ICMPID="), nullptr, NULL);
			if (Result > 0)
				Parameter.ICMPOptions.ICMPID = htons((uint16_t)Result);
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("ICMPSequence=") == 0)
	{
		if (Data.length() == strlen("ICMPSequence="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() < strlen("ICMPSequence=") + 7U)
		{
			Result = strtol(Data.c_str() + strlen("ICMPSequence="), nullptr, NULL);
			if (Result > 0)
				Parameter.ICMPOptions.ICMPSequence = htons((uint16_t)Result);
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("ICMPPaddingData=") == 0)
	{
		if (Data.length() == strlen("ICMPPaddingData="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() > strlen("ICMPPaddingData=") + 17U && Data.length() < strlen("ICMPPaddingData=") + ICMP_PADDING_MAXSIZE - 1U) //Length of ICMP padding data must between 18 bytes and 1464 bytes(Ethernet MTU - IPv4 Standard Header - ICMP Header).
		{
			Parameter.ICMPOptions.PaddingDataLength = Data.length() - strlen("ICMPPaddingData=") - 1U;
			memcpy(Parameter.ICMPOptions.PaddingData, Data.c_str() + strlen("ICMPPaddingData="), Data.length() - strlen("ICMPPaddingData="));
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("DomainTestID=") == 0)
	{
		if (Data.length() == strlen("DomainTestID="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() < strlen("DomainTestID=") + 7U)
		{
			Result = strtol(Data.c_str() + strlen("DomainTestID="), nullptr, NULL);
			if (Result > 0)
				Parameter.DomainTestOptions.DomainTestID = htons((uint16_t)Result);
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("DomainTestData=") == 0)
	{
		if (Data.length() == strlen("DomainTestData="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() > strlen("DomainTestData=") + 2U && Data.length() < strlen("DomainTestData=") + 253U) //Maximum length of whole level domain is 253 bytes(Section 2.3.1 in RFC 1035).
		{
			memcpy(Parameter.DomainTestOptions.DomainTestData, Data.c_str() + strlen("DomainTestData="), Data.length() - strlen("DomainTestData="));
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("LocalhostServerName=") == 0)
	{
		if (Data.length() == strlen("LocalhostServerName="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() > strlen("LocalhostServerName=") + 2U && Data.length() < strlen("LocalhostServerName=") + 253U) //Maximum length of whole level domain is 253 bytes(Section 2.3.1 in RFC 1035).
		{
/* Old version
			std::shared_ptr<int> Point(new int[DOMAIN_MAXSIZE]());
			std::shared_ptr<char> LocalFQDN(new char[DOMAIN_MAXSIZE]());
			size_t Index = 0;
			Parameter.LocalServerOptions.LocalFQDNLength = Data.length() - strlen("LocalhostServerName=");

		//Convert from char to DNS query.
			LocalFQDN.get()[0] = 46;
			memcpy(LocalFQDN.get() + 1U, Data.c_str() + strlen("LocalhostServerName="), Parameter.LocalServerOptions.LocalFQDNLength);
			for (Index = 0;Index < Data.length() - strlen("LocalhostServerName=") - 1U;Index++)
			{
			//Preferred name syntax(Section 2.3.1 in RFC 1035)
				if (LocalFQDN.get()[Index] == 45 || LocalFQDN.get()[Index] == 46 || 
					LocalFQDN.get()[Index] > 47 && LocalFQDN.get()[Index] < 58 || 
					LocalFQDN.get()[Index] > 64 && LocalFQDN.get()[Index] < 91 || 
					LocalFQDN.get()[Index] > 96 && LocalFQDN.get()[Index] < 123)
				{
					if (LocalFQDN.get()[Index] == 46)
					{
						Point.get()[Result] = (int)Index;
						Result++;
					}

					continue;
				}
				else {
					PrintError(LOG_ERROR_PARAMETER, L"Localhost server name format error", NULL, FileName, Line);
					Parameter.LocalServerOptions.LocalFQDNLength = 0;
					break;
				}
			}

			if (Parameter.LocalServerOptions.LocalFQDNLength > 2U)
			{
				std::shared_ptr<char> LocalFQDNName(new char[DOMAIN_MAXSIZE]());
				for (Index = 0;Index < (size_t)Result;Index++)
				{
					if (Index + 1 == Result)
					{
						LocalFQDNName.get()[Point.get()[Index]] = (int)(Parameter.LocalServerOptions.LocalFQDNLength - Point.get()[Index]);
						memcpy(LocalFQDNName.get() + Point.get()[Index] + 1U, LocalFQDN.get() + Point.get()[Index] + 1U, Parameter.LocalServerOptions.LocalFQDNLength - Point.get()[Index]);
					}
					else {
						LocalFQDNName.get()[Point.get()[Index]] = Point.get()[Index + 1U] - Point.get()[Index] - 1U;
						memcpy(LocalFQDNName.get() + Point.get()[Index] + 1U, LocalFQDN.get() + Point.get()[Index] + 1U, Point.get()[Index + 1U] - Point.get()[Index]);
					}
				}

				memcpy(Parameter.LocalServerOptions.LocalFQDN, LocalFQDNName.get(), Parameter.LocalServerOptions.LocalFQDNLength + 1U);

			}
*/
			std::shared_ptr<char> LocalFQDN(new char[DOMAIN_MAXSIZE]());
			Parameter.LocalServerOptions.LocalFQDNLength = Data.length() - strlen("LocalhostServerName=");
			memcpy(LocalFQDN.get(), Data.c_str() + strlen("LocalhostServerName="), Parameter.LocalServerOptions.LocalFQDNLength);
			Parameter.LocalServerOptions.LocalFQDNString = LocalFQDN.get();
			Result = CharToDNSQuery(LocalFQDN.get(), Parameter.LocalServerOptions.LocalFQDN);
			if (Result > 2U) //Domain length is between 3 and 63(Labels must be 63 characters/bytes or less, Section 2.3.1 in RFC 1035).
			{
				Parameter.LocalServerOptions.LocalFQDNLength = Result;
			}
			else {
				Parameter.LocalServerOptions.LocalFQDNLength = 0;
				memset(Parameter.LocalServerOptions.LocalFQDN, 0, DOMAIN_MAXSIZE);
				Parameter.LocalServerOptions.LocalFQDNString.clear();
			}
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}

//[DNSCurve] block
	else if (Data.find("DNSCurve=1") == 0)
	{
		Parameter.DNSCurve = true;
	}
	else if (Data.find("DNSCurveProtocol=TCP") == 0 || Data.find("DNSCurveProtocol=Tcp") == 0 || Data.find("DNSCurveProtocol=tcp") == 0)
	{
		DNSCurveParameter.DNSCurveMode = DNSCURVE_REQUEST_TCPMODE;
	}
	else if (Data.find("DNSCurvePayloadSize=") == 0)
	{
		if (Data.length() == strlen("DNSCurvePayloadSize="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() > strlen("DNSCurvePayloadSize=") + 2U)
		{
			Result = strtol(Data.c_str() + strlen("DNSCurvePayloadSize="), nullptr, NULL);
			if (Result > sizeof(eth_hdr) + sizeof(ipv4_hdr) + sizeof(udp_hdr) + sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES)
				DNSCurveParameter.DNSCurvePayloadSize = Result;
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("Encryption=1") == 0)
	{
		DNSCurveParameter.Encryption = true;
	}
	else if (Data.find("EncryptionOnly=1") == 0)
	{
		DNSCurveParameter.EncryptionOnly = true;
	}
	else if (Data.find("KeyRecheckTime=") == 0)
	{
		if (Data.length() == strlen("KeyRecheckTime="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() < strlen("KeyRecheckTime=") + 6U)
		{
			Result = strtol(Data.c_str() + strlen("KeyRecheckTime="), nullptr, NULL);
			if (Result >= SHORTEST_DNSCURVE_RECHECK_TIME && Result < DEFAULT_DNSCURVE_RECHECK_TIME)
				DNSCurveParameter.KeyRecheckTime = Result * SECOND_TO_MILLISECOND;
			else 
				DNSCurveParameter.KeyRecheckTime = DEFAULT_DNSCURVE_RECHECK_TIME * SECOND_TO_MILLISECOND;
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}

//[DNSCurve Addresses] block
	else if (Data.find("DNSCurveIPv4DNSAddress=") == 0)
	{
		if (Data.length() == strlen("DNSCurveIPv4DNSAddress="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() > strlen("DNSCurveIPv4DNSAddress=") + 8U && Data.length() < strlen("DNSCurveIPv4DNSAddress=") + 22U)
		{
		//IPv4 Address and Port check
			if (Data.find(ASCII_COLON) == std::string::npos || Data.find(ASCII_COLON) < IPV4_SHORTEST_ADDRSTRING)
			{
				PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 Address format error", NULL, FileName, Line);
				return EXIT_FAILURE;
			}

		//Convert IPv4 Address.
			std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());
			memcpy(Target.get(), Data.c_str() + strlen("DNSCurveIPv4DNSAddress="), Data.find(ASCII_COLON) - strlen("DNSCurveIPv4DNSAddress="));
			if (AddressStringToBinary(Target.get(), &DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_addr, AF_INET, Result) == EXIT_FAILURE)
			{
				PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 Address format error", Result, FileName, Line);
				return EXIT_FAILURE;
			}

		//Convert IPv4 Port.
			Result = ServiceNameToPort((PSTR)Data.c_str() + Data.find(ASCII_COLON) + 1U);
			if (Result == 0)
			{
				Result = strtol(Data.c_str() + Data.find(ASCII_COLON) + 1U, nullptr, NULL);
				if (Result <= 0 || Result > U16_MAXNUM)
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 Port error", NULL, FileName, Line);
					return EXIT_FAILURE;
				}
				else {
					DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4.sin_port = htons((uint16_t)Result);
				}
			}

			DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family = AF_INET;
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("DNSCurveIPv4AlternateDNSAddress=") == 0)
	{
		if (Data.length() == strlen("DNSCurveIPv4AlternateDNSAddress="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() > strlen("DNSCurveIPv4AlternateDNSAddress=") + 8U && Data.length() < strlen("DNSCurveIPv4AlternateDNSAddress=") + 22U)
		{
		//IPv4 Address and Port check
			if (Data.find(ASCII_COLON) == std::string::npos || Data.find(ASCII_COLON) < IPV4_SHORTEST_ADDRSTRING)
			{
				PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 Address format error", NULL, FileName, Line);
				return EXIT_FAILURE;
			}

		//Convert IPv4 Address.
			std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());
			memcpy(Target.get(), Data.c_str() + strlen("DNSCurveIPv4AlternateDNSAddress="), Data.find(ASCII_COLON) - strlen("DNSCurveIPv4AlternateDNSAddress="));
			if (AddressStringToBinary(Target.get(), &DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_addr, AF_INET, Result) == EXIT_FAILURE)
			{
				PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 Address format error", Result, FileName, Line);
				return EXIT_FAILURE;
			}

		//Convert IPv4 Port.
			Result = ServiceNameToPort((PSTR)Data.c_str() + Data.find(ASCII_COLON) + 1U);
			if (Result == 0)
			{
				Result = strtol(Data.c_str() + Data.find(ASCII_COLON) + 1U, nullptr, NULL);
				if (Result <= 0 || Result > U16_MAXNUM)
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv4 Port error", NULL, FileName, Line);
					return EXIT_FAILURE;
				}
				else {
					DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4.sin_port = htons((uint16_t)Result);
				}
			}

			DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family = AF_INET;
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("DNSCurveIPv6DNSAddress=") == 0)
	{
		if (Data.length() == strlen("DNSCurveIPv6DNSAddress="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() > strlen("DNSCurveIPv6DNSAddress=") + 6U && Data.length() < strlen("DNSCurveIPv6DNSAddress=") + 48U)
		{
		//IPv6 Address and Port check
			if (Data.find(ASCII_BRACKETS_LEAD) == std::string::npos || Data.find(ASCII_BRACKETS_TRAIL) == std::string::npos || Data.find(ASCII_BRACKETS_TRAIL) < IPV6_SHORTEST_ADDRSTRING)
			{
				PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 Address format error", NULL, FileName, Line);
				return EXIT_FAILURE;
			}

		//Convert IPv6 Address.
			std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());
			memcpy(Target.get(), Data.c_str() + strlen("DNSCurveIPv6DNSAddress=") + 1U, Data.find(ASCII_BRACKETS_TRAIL) - strlen("DNSCurveIPv6DNSAddress=") - 1U);
			if (AddressStringToBinary(Target.get(), &DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
			{
				PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 Address format error", Result, FileName, Line);
				return EXIT_FAILURE;
			}

		//Convert IPv6 Port.
			Result = ServiceNameToPort((PSTR)Data.c_str() + Data.find(ASCII_BRACKETS_TRAIL) + 2U);
			if (Result == 0)
			{
				Result = strtol(Data.c_str() + Data.find(ASCII_BRACKETS_TRAIL) + 2U, nullptr, NULL);
				if (Result <= 0 || Result > U16_MAXNUM)
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 Port error", NULL, FileName, Line);
					return EXIT_FAILURE;
				}
				else {
					DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6.sin6_port = htons((uint16_t)Result);
				}
			}

			DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family = AF_INET6;
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("DNSCurveIPv6AlternateDNSAddress=") == 0)
	{
		if (Data.length() == strlen("DNSCurveIPv6AlternateDNSAddress="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() > strlen("DNSCurveIPv6AlternateDNSAddress=") + 6U && Data.length() < strlen("DNSCurveIPv6AlternateDNSAddress=") + 48U)
		{
		//IPv6 Address and Port check
			if (Data.find(ASCII_BRACKETS_LEAD) == std::string::npos || Data.find(ASCII_BRACKETS_TRAIL) == std::string::npos || Data.find(ASCII_BRACKETS_TRAIL) < IPV6_SHORTEST_ADDRSTRING)
			{
				PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 Address format error", NULL, FileName, Line);
				return EXIT_FAILURE;
			}

		//Convert IPv6 Address.
			std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());
			memcpy(Target.get(), Data.c_str() + strlen("DNSCurveIPv6AlternateDNSAddress=") + 1U, Data.find(ASCII_BRACKETS_TRAIL) - strlen("DNSCurveIPv6AlternateDNSAddress=") - 1U);
			if (AddressStringToBinary(Target.get(), &DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
			{
				PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 Address format error", Result, FileName, Line);
				return EXIT_FAILURE;
			}

		//Convert IPv6 Port.
			Result = ServiceNameToPort((PSTR)Data.c_str() + Data.find(ASCII_BRACKETS_TRAIL) + 2U);
			if (Result == 0)
			{
				Result = strtol(Data.c_str() + Data.find(ASCII_BRACKETS_TRAIL) + 2U, nullptr, NULL);
				if (Result <= 0 || Result > U16_MAXNUM)
				{
					PrintError(LOG_ERROR_PARAMETER, L"DNS server IPv6 Port error", NULL, FileName, Line);
					return EXIT_FAILURE;
				}
				else {
					DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6.sin6_port = htons((uint16_t)Result);
				}
			}

			DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family = AF_INET6;
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}

	else if (Data.find("DNSCurveIPv4ProviderName=") == 0)
	{
		if (Data.length() == strlen("DNSCurveIPv4ProviderName="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() > strlen("DNSCurveIPv4ProviderName=") + 2U && Data.length() < strlen("DNSCurveIPv4ProviderName=") + 253U) //Maximum length of whole level domain is 253 bytes(Section 2.3.1 in RFC 1035).
		{
			for (Result = strlen("DNSCurveIPv4ProviderName=");Result < (SSIZE_T)(Data.length() - strlen("DNSCurveIPv4ProviderName="));Result++)
			{
				for (size_t Index = 0;Index < strlen(Parameter.DomainTable);Index++)
				{
					if (Index == strlen(Parameter.DomainTable) - 1U && Data[Result] != Parameter.DomainTable[Index])
					{
						PrintError(LOG_ERROR_PARAMETER, L"DNSCurve Provider Name(s) error", NULL, FileName, Line);
						return EXIT_FAILURE;
					}
					if (Data[Result] == Parameter.DomainTable[Index])
						break;
				}
			}

			memcpy(DNSCurveParameter.DNSCurveTarget.IPv4.ProviderName, Data.c_str() + strlen("DNSCurveIPv4ProviderName="), Data.length() - strlen("DNSCurveIPv4ProviderName="));
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("DNSCurveIPv4AlternateProviderName=") == 0)
	{
		if (Data.length() == strlen("DNSCurveIPv4AlternateProviderName="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() > strlen("DNSCurveIPv4AlternateProviderName=") + 2U && Data.length() < strlen("DNSCurveIPv4AlternateProviderName=") + 253U) //Maximum length of whole level domain is 253 bytes(Section 2.3.1 in RFC 1035).
		{
			for (Result = strlen("DNSCurveIPv4AlternateProviderName=");Result < (SSIZE_T)(Data.length() - strlen("DNSCurveIPv4AlternateProviderName="));Result++)
			{
				for (size_t Index = 0;Index < strlen(Parameter.DomainTable);Index++)
				{
					if (Index == strlen(Parameter.DomainTable) - 1U && Data[Result] != Parameter.DomainTable[Index])
					{
						PrintError(LOG_ERROR_PARAMETER, L"DNSCurve Provider Name(s) error", NULL, FileName, Line);
						return EXIT_FAILURE;
					}
					if (Data[Result] == Parameter.DomainTable[Index])
						break;
				}
			}

			memcpy(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ProviderName, Data.c_str() + strlen("DNSCurveIPv4AlternateProviderName="), Data.length() - strlen("DNSCurveIPv4AlternateProviderName="));
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("DNSCurveIPv6ProviderName=") == 0)
	{
		if (Data.length() == strlen("DNSCurveIPv6ProviderName="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() > strlen("DNSCurveIPv6ProviderName=") + 2U && Data.length() < strlen("DNSCurveIPv6ProviderName=") + 253U) //Maximum length of whole level domain is 253 bytes(Section 2.3.1 in RFC 1035).
		{
			for (Result = strlen("DNSCurveIPv6ProviderName=");Result < (SSIZE_T)(Data.length() - strlen("DNSCurveIPv6ProviderName="));Result++)
			{
				for (size_t Index = 0;Index < strlen(Parameter.DomainTable);Index++)
				{
					if (Index == strlen(Parameter.DomainTable) - 1U && Data[Result] != Parameter.DomainTable[Index])
					{
						PrintError(LOG_ERROR_PARAMETER, L"DNSCurve Provider Name(s) error", NULL, FileName, Line);
						return EXIT_FAILURE;
					}
					if (Data[Result] == Parameter.DomainTable[Index])
						break;
				}
			}

			memcpy(DNSCurveParameter.DNSCurveTarget.IPv6.ProviderName, Data.c_str() + strlen("DNSCurveIPv6ProviderName="), Data.length() - strlen("DNSCurveIPv6ProviderName="));
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("DNSCurveIPv6AlternateProviderName=") == 0)
	{
		if (Data.length() == strlen("DNSCurveIPv6AlternateProviderName="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() > strlen("DNSCurveIPv6AlternateProviderName=") + 2U && Data.length() < strlen("DNSCurveIPv6AlternateProviderName=") + 253U) //Maximum length of whole level domain is 253 bytes(Section 2.3.1 in RFC 1035).
		{
			for (Result = strlen("DNSCurveIPv6AlternateProviderName=");Result < (SSIZE_T)(Data.length() - strlen("DNSCurveIPv6AlternateProviderName="));Result++)
			{
				for (size_t Index = 0;Index < strlen(Parameter.DomainTable);Index++)
				{
					if (Index == strlen(Parameter.DomainTable) - 1U && Data[Result] != Parameter.DomainTable[Index])
					{
						PrintError(LOG_ERROR_PARAMETER, L"DNSCurve Provider Name(s) error", NULL, FileName, Line);
						return EXIT_FAILURE;
					}
					if (Data[Result] == Parameter.DomainTable[Index])
						break;
				}
			}

			memcpy(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ProviderName, Data.c_str() + strlen("DNSCurveIPv6AlternateProviderName="), Data.length() - strlen("DNSCurveIPv6AlternateProviderName="));
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}

//[DNSCurve Keys] block
	else if (Data.find("ClientPublicKey=") == 0)
	{
		if (Data.length() == strlen("ClientPublicKey="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() > strlen("ClientPublicKey=") + crypto_box_PUBLICKEYBYTES * 2U && Data.length() < strlen("ClientPublicKey=") + crypto_box_PUBLICKEYBYTES * 3U)
		{
			size_t ResultLength = 0;
			PSTR ResultPointer = nullptr;
			std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());

//			Result = HexToBinary((PUINT8)Target.get(), (const PSTR)(Data.c_str() + strlen("ClientPublicKey=")), Data.length() - strlen("ClientPublicKey="));
			Result = sodium_hex2bin((PUCHAR)Target.get(), ADDR_STRING_MAXSIZE, Data.c_str() + strlen("ClientPublicKey="), Data.length() - strlen("ClientPublicKey="), ": ", &ResultLength, (const char **)&ResultPointer);
			if ( /* Result == crypto_box_PUBLICKEYBYTES */ Result == 0 && ResultLength == crypto_box_PUBLICKEYBYTES && ResultPointer != nullptr)
			{
				memcpy(DNSCurveParameter.Client_PublicKey, Target.get(), crypto_box_PUBLICKEYBYTES);
			}
			else {
				PrintError(LOG_ERROR_PARAMETER, L"DNSCurve Key(s) error", NULL, FileName, Line);
				return EXIT_FAILURE;
			}
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("ClientSecretKey=") == 0)
	{
		if (Data.length() == strlen("ClientSecretKey="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() > strlen("ClientSecretKey=") + crypto_box_SECRETKEYBYTES * 2U && Data.length() < strlen("ClientSecretKey=") + crypto_box_SECRETKEYBYTES * 3U)
		{
			size_t ResultLength = 0;
			PSTR ResultPointer = nullptr;
			std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());

//			Result = HexToBinary((PUINT8)Target.get(), (const PSTR)(Data.c_str() + strlen("ClientSecretKey=")), Data.length() - strlen("ClientSecretKey="));
			Result = sodium_hex2bin((PUCHAR)Target.get(), ADDR_STRING_MAXSIZE, Data.c_str() + strlen("ClientSecretKey="), Data.length() - strlen("ClientSecretKey="), ": ", &ResultLength, (const char **)&ResultPointer);
			if ( /* Result == crypto_box_PUBLICKEYBYTES */ Result == 0 && ResultLength == crypto_box_SECRETKEYBYTES && ResultPointer != nullptr)
			{
				memcpy(DNSCurveParameter.Client_SecretKey, Target.get(), crypto_box_SECRETKEYBYTES);
			}
			else {
				PrintError(LOG_ERROR_PARAMETER, L"DNSCurve Key(s) error", NULL, FileName, Line);
				return EXIT_FAILURE;
			}
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("IPv4DNSPublicKey=") == 0)
	{
		if (Data.length() == strlen("IPv4DNSPublicKey="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() > strlen("IPv4DNSPublicKey=") + crypto_box_PUBLICKEYBYTES * 2U && Data.length() < strlen("IPv4DNSPublicKey=") + crypto_box_PUBLICKEYBYTES * 3U)
		{
			size_t ResultLength = 0;
			PSTR ResultPointer = nullptr;
			std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());

//			Result = HexToBinary((PUINT8)Target.get(), (const PSTR)(Data.c_str() + strlen("IPv4DNSPublicKey=")), Data.length() - strlen("IPv4DNSPublicKey="));
			Result = sodium_hex2bin((PUCHAR)Target.get(), ADDR_STRING_MAXSIZE, Data.c_str() + strlen("IPv4DNSPublicKey="), Data.length() - strlen("IPv4DNSPublicKey="), ": ", &ResultLength, (const char **)&ResultPointer);
			if ( /* Result == crypto_box_PUBLICKEYBYTES */ Result == 0 && ResultLength == crypto_box_PUBLICKEYBYTES && ResultPointer != nullptr)
			{
				memcpy(DNSCurveParameter.DNSCurveTarget.IPv4.ServerPublicKey, Target.get(), crypto_box_PUBLICKEYBYTES);
			}
			else {
				PrintError(LOG_ERROR_PARAMETER, L"DNSCurve Key(s) error", NULL, FileName, Line);
				return EXIT_FAILURE;
			}
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("IPv4AlternateDNSPublicKey=") == 0)
	{
		if (Data.length() == strlen("IPv4AlternateDNSPublicKey="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() > strlen("IPv4AlternateDNSPublicKey=") + crypto_box_PUBLICKEYBYTES * 2U && Data.length() < strlen("IPv4AlternateDNSPublicKey=") + crypto_box_PUBLICKEYBYTES * 3U)
		{
			size_t ResultLength = 0;
			PSTR ResultPointer = nullptr;
			std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());

//			Result = HexToBinary((PUINT8)Target.get(), (const PSTR)(Data.c_str() + strlen("IPv4AlternateDNSPublicKey=")), Data.length() - strlen("IPv4AlternateDNSPublicKey="));
			Result = sodium_hex2bin((PUCHAR)Target.get(), ADDR_STRING_MAXSIZE, Data.c_str() + strlen("IPv4AlternateDNSPublicKey="), Data.length() - strlen("IPv4AlternateDNSPublicKey="), ": ", &ResultLength, (const char **)&ResultPointer);
			if ( /* Result == crypto_box_PUBLICKEYBYTES */ Result == 0 && ResultLength == crypto_box_PUBLICKEYBYTES && ResultPointer != nullptr)
			{
				memcpy(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ServerPublicKey, Target.get(), crypto_box_PUBLICKEYBYTES);
			}
			else {
				PrintError(LOG_ERROR_PARAMETER, L"DNSCurve Key(s) error", NULL, FileName, Line);
				return EXIT_FAILURE;
			}
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("IPv6DNSPublicKey=") == 0)
	{
		if (Data.length() == strlen("IPv6DNSPublicKey="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() > strlen("IPv6DNSPublicKey=") + crypto_box_PUBLICKEYBYTES * 2U && Data.length() < strlen("IPv6DNSPublicKey=") + crypto_box_PUBLICKEYBYTES * 3U)
		{
			size_t ResultLength = 0;
			PSTR ResultPointer = nullptr;
			std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());

//			Result = HexToBinary((PUINT8)Target.get(), (const PSTR)(Data.c_str() + strlen("IPv6DNSPublicKey=")), Data.length() - strlen("IPv6DNSPublicKey="));
			Result = sodium_hex2bin((PUCHAR)Target.get(), ADDR_STRING_MAXSIZE, Data.c_str() + strlen("IPv6DNSPublicKey="), Data.length() - strlen("IPv6DNSPublicKey="), ": ", &ResultLength, (const char **)&ResultPointer);
			if ( /* Result == crypto_box_PUBLICKEYBYTES */ Result == 0 && ResultLength == crypto_box_PUBLICKEYBYTES && ResultPointer != nullptr)
			{
				memcpy(DNSCurveParameter.DNSCurveTarget.IPv6.ServerPublicKey, Target.get(), crypto_box_PUBLICKEYBYTES);
			}
			else {
				PrintError(LOG_ERROR_PARAMETER, L"DNSCurve Key(s) error", NULL, FileName, Line);
				return EXIT_FAILURE;
			}
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("IPv6AlternateDNSPublicKey=") == 0)
	{
		if (Data.length() == strlen("IPv6AlternateDNSPublicKey="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() > strlen("IPv6AlternateDNSPublicKey=") + crypto_box_PUBLICKEYBYTES * 2U && Data.length() < strlen("IPv6AlternateDNSPublicKey=") + crypto_box_PUBLICKEYBYTES * 3U)
		{
			size_t ResultLength = 0;
			PSTR ResultPointer = nullptr;
			std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());

//			Result = HexToBinary((PUINT8)Target.get(), (const PSTR)(Data.c_str() + strlen("IPv6AlternateDNSPublicKey=")), Data.length() - strlen("IPv6AlternateDNSPublicKey="));
			Result = sodium_hex2bin((PUCHAR)Target.get(), ADDR_STRING_MAXSIZE, Data.c_str() + strlen("IPv6AlternateDNSPublicKey="), Data.length() - strlen("IPv6AlternateDNSPublicKey="), ": ", &ResultLength, (const char **)&ResultPointer);
			if ( /* Result == crypto_box_PUBLICKEYBYTES */ Result == 0 && ResultLength == crypto_box_PUBLICKEYBYTES && ResultPointer != nullptr)
			{
				memcpy(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ServerPublicKey, Target.get(), crypto_box_PUBLICKEYBYTES);
			}
			else {
				PrintError(LOG_ERROR_PARAMETER, L"DNSCurve Key(s) error", NULL, FileName, Line);
				return EXIT_FAILURE;
			}
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("IPv4DNSFingerprint=") == 0)
	{
		if (Data.length() == strlen("IPv4DNSFingerprint="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() > strlen("IPv4DNSFingerprint=") + crypto_box_PUBLICKEYBYTES * 2U && Data.length() < strlen("IPv4DNSFingerprint=") + crypto_box_PUBLICKEYBYTES * 3U)
		{
			size_t ResultLength = 0;
			PSTR ResultPointer = nullptr;
			std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());

//			Result = HexToBinary((PUINT8)Target.get(), (const PSTR)(Data.c_str() + strlen("IPv4DNSFingerprint=")), Data.length() - strlen("IPv4DNSFingerprint="));
			Result = sodium_hex2bin((PUCHAR)Target.get(), ADDR_STRING_MAXSIZE, Data.c_str() + strlen("IPv4DNSFingerprint="), Data.length() - strlen("IPv4DNSFingerprint="), ": ", &ResultLength, (const char **)&ResultPointer);
			if ( /* Result == crypto_box_PUBLICKEYBYTES */ Result == 0 && ResultLength == crypto_box_PUBLICKEYBYTES && ResultPointer != nullptr)
			{
				memcpy(DNSCurveParameter.DNSCurveTarget.IPv4.ServerFingerprint, Target.get(), crypto_box_PUBLICKEYBYTES);
			}
			else {
				PrintError(LOG_ERROR_PARAMETER, L"DNSCurve Key(s) error", NULL, FileName, Line);
				return EXIT_FAILURE;
			}
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("IPv4AlternateDNSFingerprint=") == 0)
	{
		if (Data.length() == strlen("IPv4AlternateDNSFingerprint="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() > strlen("IPv4AlternateDNSFingerprint=") + crypto_box_PUBLICKEYBYTES * 2U && Data.length() < strlen("IPv4AlternateDNSFingerprint=") + crypto_box_PUBLICKEYBYTES * 3U)
		{
			size_t ResultLength = 0;
			PSTR ResultPointer = nullptr;
			std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());

//			Result = HexToBinary((PUINT8)Target.get(), (const PSTR)(Data.c_str() + strlen("IPv4AlternateDNSFingerprint=")), Data.length() - strlen("IPv4AlternateDNSFingerprint="));
			Result = sodium_hex2bin((PUCHAR)Target.get(), ADDR_STRING_MAXSIZE, Data.c_str() + strlen("IPv4AlternateDNSFingerprint="), Data.length() - strlen("IPv4AlternateDNSFingerprint="), ": ", &ResultLength, (const char **)&ResultPointer);
			if ( /* Result == crypto_box_PUBLICKEYBYTES */ Result == 0 && ResultLength == crypto_box_PUBLICKEYBYTES && ResultPointer != nullptr)
			{
				memcpy(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ServerFingerprint, Target.get(), crypto_box_PUBLICKEYBYTES);
			}
			else {
				PrintError(LOG_ERROR_PARAMETER, L"DNSCurve Key(s) error", NULL, FileName, Line);
				return EXIT_FAILURE;
			}
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("IPv6DNSFingerprint=") == 0)
	{
		if (Data.length() == strlen("IPv6DNSFingerprint="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() > strlen("IPv6DNSFingerprint=") + crypto_box_PUBLICKEYBYTES * 2U && Data.length() < strlen("IPv6DNSFingerprint=") + crypto_box_PUBLICKEYBYTES * 3U)
		{
			size_t ResultLength = 0;
			PSTR ResultPointer = nullptr;
			std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());

//			Result = HexToBinary((PUINT8)Target.get(), (const PSTR)(Data.c_str() + strlen("IPv6DNSFingerprint=")), Data.length() - strlen("IPv6DNSFingerprint="));
			Result = sodium_hex2bin((PUCHAR)Target.get(), ADDR_STRING_MAXSIZE, Data.c_str() + strlen("IPv6DNSFingerprint="), Data.length() - strlen("IPv6DNSFingerprint="), ": ", &ResultLength, (const char **)&ResultPointer);
			if ( /* Result == crypto_box_PUBLICKEYBYTES */ Result == 0 && ResultLength == crypto_box_PUBLICKEYBYTES && ResultPointer != nullptr)
			{
				memcpy(DNSCurveParameter.DNSCurveTarget.IPv6.ServerFingerprint, Target.get(), crypto_box_PUBLICKEYBYTES);
			}
			else {
				PrintError(LOG_ERROR_PARAMETER, L"DNSCurve Key(s) error", NULL, FileName, Line);
				return EXIT_FAILURE;
			}
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("IPv6AlternateDNSFingerprint=") == 0)
	{
		if (Data.length() == strlen("IPv6AlternateDNSFingerprint="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() > strlen("IPv6AlternateDNSFingerprint=") + crypto_box_PUBLICKEYBYTES * 2U && Data.length() < strlen("IPv6AlternateDNSFingerprint=") + crypto_box_PUBLICKEYBYTES * 3U)
		{
			size_t ResultLength = 0;
			PSTR ResultPointer = nullptr;
			std::shared_ptr<char> Target(new char[ADDR_STRING_MAXSIZE]());

//			Result = HexToBinary((PUINT8)Target.get(), (const PSTR)(Data.c_str() + strlen("IPv6AlternateDNSFingerprint=")), Data.length() - strlen("IPv6AlternateDNSFingerprint="));
			Result = sodium_hex2bin((PUCHAR)Target.get(), ADDR_STRING_MAXSIZE, Data.c_str() + strlen("IPv6AlternateDNSFingerprint="), Data.length() - strlen("IPv6AlternateDNSFingerprint="), ": ", &ResultLength, (const char **)&ResultPointer);
			if ( /* Result == crypto_box_PUBLICKEYBYTES */ Result == 0 && ResultLength == crypto_box_PUBLICKEYBYTES && ResultPointer != nullptr)
			{
				memcpy(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ServerFingerprint, Target.get(), crypto_box_PUBLICKEYBYTES);
			}
			else {
				PrintError(LOG_ERROR_PARAMETER, L"DNSCurve Key(s) error", NULL, FileName, Line);
				return EXIT_FAILURE;
			}
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}

//[DNSCurve Magic Number] block
	else if (Data.find("IPv4ReceiveMagicNumber=") == 0)
	{
		if (Data.length() == strlen("IPv4ReceiveMagicNumber="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() == strlen("IPv4ReceiveMagicNumber=") + DNSCURVE_MAGIC_QUERY_LEN)
		{
			memcpy(DNSCurveParameter.DNSCurveTarget.IPv4.ReceiveMagicNumber, Data.c_str() + strlen("IPv4ReceiveMagicNumber="), DNSCURVE_MAGIC_QUERY_LEN);
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("IPv4AlternateReceiveMagicNumber=") == 0)
	{
		if (Data.length() == strlen("IPv4AlternateReceiveMagicNumber="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() == strlen("IPv4AlternateReceiveMagicNumber=") + DNSCURVE_MAGIC_QUERY_LEN)
		{
			memcpy(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.ReceiveMagicNumber, Data.c_str() + strlen("IPv4AlternateReceiveMagicNumber="), DNSCURVE_MAGIC_QUERY_LEN);
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("IPv6ReceiveMagicNumber=") == 0)
	{
		if (Data.length() == strlen("IPv6ReceiveMagicNumber="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() == strlen("IPv6ReceiveMagicNumber=") + DNSCURVE_MAGIC_QUERY_LEN)
		{
			memcpy(DNSCurveParameter.DNSCurveTarget.IPv6.ReceiveMagicNumber, Data.c_str() + strlen("IPv6ReceiveMagicNumber="), DNSCURVE_MAGIC_QUERY_LEN);
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("IPv6AlternateReceiveMagicNumber=") == 0)
	{
		if (Data.length() == strlen("IPv6AlternateReceiveMagicNumber="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() == strlen("IPv6AlternateReceiveMagicNumber=") + DNSCURVE_MAGIC_QUERY_LEN)
		{
			memcpy(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.ReceiveMagicNumber, Data.c_str() + strlen("IPv6AlternateReceiveMagicNumber="), DNSCURVE_MAGIC_QUERY_LEN);
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("IPv4DNSMagicNumber=") == 0)
	{
		if (Data.length() == strlen("IPv4DNSMagicNumber="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() == strlen("IPv4DNSMagicNumber=") + DNSCURVE_MAGIC_QUERY_LEN)
		{
			memcpy(DNSCurveParameter.DNSCurveTarget.IPv4.SendMagicNumber, Data.c_str() + strlen("IPv4DNSMagicNumber="), DNSCURVE_MAGIC_QUERY_LEN);
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("IPv4AlternateDNSMagicNumber=") == 0)
	{
		if (Data.length() == strlen("IPv4AlternateDNSMagicNumber="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() == strlen("IPv4AlternateDNSMagicNumber=") + DNSCURVE_MAGIC_QUERY_LEN)
		{
			memcpy(DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.SendMagicNumber, Data.c_str() + strlen("IPv4AlternateDNSMagicNumber="), DNSCURVE_MAGIC_QUERY_LEN);
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("IPv6DNSMagicNumber=") == 0)
	{
		if (Data.length() == strlen("IPv6DNSMagicNumber="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() == strlen("IPv6DNSMagicNumber=") + DNSCURVE_MAGIC_QUERY_LEN)
		{
			memcpy(DNSCurveParameter.DNSCurveTarget.IPv6.SendMagicNumber, Data.c_str() + strlen("IPv6DNSMagicNumber="), DNSCURVE_MAGIC_QUERY_LEN);
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}
	else if (Data.find("IPv6AlternateDNSMagicNumber=") == 0)
	{
		if (Data.length() == strlen("IPv6AlternateDNSMagicNumber="))
		{
			return EXIT_SUCCESS;
		}
		else if (Data.length() == strlen("IPv6AlternateDNSMagicNumber=") + DNSCURVE_MAGIC_QUERY_LEN)
		{
			memcpy(DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.SendMagicNumber, Data.c_str() + strlen("IPv6AlternateDNSMagicNumber="), DNSCURVE_MAGIC_QUERY_LEN);
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Item length error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}

//Read ipfilter from file
size_t __fastcall ReadIPFilter(void)
{
	SSIZE_T Index = 0;

//Initialization(Available when file hash check is ON.)
	std::shared_ptr<char> Buffer;
	FileData FileDataTemp[7U];
	if (Parameter.FileHash)
	{
		std::shared_ptr<char> FileDataBufferTemp(new char[FILE_BUFFER_SIZE]());
		Buffer.swap(FileDataBufferTemp);
		FileDataBufferTemp.reset();

		for (Index = 0;Index < sizeof(FileDataTemp) / sizeof(FileData);Index++)
		{
			std::shared_ptr<BitSequence> FileDataBufferTemp_SHA3(new BitSequence[SHA3_512_SIZE]());
			FileDataTemp[Index].Result.swap(FileDataBufferTemp_SHA3);
		}
	}

//Open file.
	FILE *Input = nullptr;
	std::vector<FileData> FileList;
	for (Index = 0;Index < sizeof(FileDataTemp) / sizeof(FileData);Index++)
		FileDataTemp[Index].FileName = *Parameter.Path;
	FileDataTemp[0].FileName.append(L"IPFilter.ini");
	FileDataTemp[1U].FileName.append(L"IPFilter.conf");
	FileDataTemp[2U].FileName.append(L"IPFilter.dat");
	FileDataTemp[3U].FileName.append(L"IPFilter.csv");
	FileDataTemp[4U].FileName.append(L"IPFilter");
	FileDataTemp[5U].FileName.append(L"Guarding.P2P");
	FileDataTemp[6U].FileName.append(L"Guarding");
	for (Index = 0;Index < sizeof(FileDataTemp) / sizeof(FileData);Index++)
		FileList.push_back(FileDataTemp[Index]);

//File(s) monitor
	size_t ReadLength = 0;;
	auto HashChanged = false;
	std::vector<FileData>::iterator FileListIter;
	Keccak_HashInstance HashInstance = {0};
	std::vector<AddressRange>::iterator AddressRangeIter[2U];
	std::vector<ResultBlacklistTable>::iterator ResultBlacklistIter[2U];
	std::vector<sockaddr_storage>::iterator SockAddrIter[2U];

	in6_addr IPv6NextAddress = {0};
	in_addr IPv4NextAddress = {0};
	HANDLE IPFilterHandle = nullptr;
	LARGE_INTEGER IPFilterFileSize = {0};
	while (true)
	{
		HashChanged = false;
		for (FileListIter = FileList.begin();FileListIter != FileList.end();FileListIter++)
		{
			if (_wfopen_s(&Input, FileListIter->FileName.c_str(), L"rb") != 0)
			{
			//Cleanup hash(s)
				if (Parameter.FileHash)
				{
					FileListIter->Available = false;
					memset(FileListIter->Result.get(), 0, SHA3_512_SIZE);
				}

				continue;
			}
			else {
				if (Input == nullptr)
					continue;

			//Check whole file size.
				IPFilterHandle = CreateFileW(FileListIter->FileName.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
				if (IPFilterHandle != INVALID_HANDLE_VALUE)
				{
					memset(&IPFilterFileSize, 0, sizeof(LARGE_INTEGER));
					if (GetFileSizeEx(IPFilterHandle, &IPFilterFileSize) == 0)
					{
						CloseHandle(IPFilterHandle);
					}
					else {
						CloseHandle(IPFilterHandle);
						if (IPFilterFileSize.QuadPart >= DEFAULT_FILE_MAXSIZE)
						{
							PrintError(LOG_ERROR_PARAMETER, L"IPFilter file size is too large", NULL, (PWSTR)FileListIter->FileName.c_str(), NULL);

							fclose(Input);
							Input = nullptr;
							continue;
						}
					}
				}

			//Mark or check file(s) hash.
				if (Parameter.FileHash)
				{
					memset(Buffer.get(), 0, FILE_BUFFER_SIZE);
					memset(&HashInstance, 0, sizeof(Keccak_HashInstance));
					Keccak_HashInitialize_SHA3_512(&HashInstance);
					while (!feof(Input))
					{
						ReadLength = fread_s(Buffer.get(), FILE_BUFFER_SIZE, sizeof(char), FILE_BUFFER_SIZE, Input);
						Keccak_HashUpdate(&HashInstance, (BitSequence *)Buffer.get(), ReadLength * BYTES_TO_BITS);
					}
					memset(Buffer.get(), 0, FILE_BUFFER_SIZE);
					Keccak_HashFinal(&HashInstance, (BitSequence *)Buffer.get());

				//Set file pointer(s) to the beginning of file.
					if (_fseeki64(Input, 0, SEEK_SET) != 0)
					{
						PrintError(LOG_ERROR_IPFILTER, L"Read file(s) error", NULL, (PWSTR)FileListIter->FileName.c_str(), NULL);

						fclose(Input);
						Input = nullptr;
						continue;
					}
					else {
						if (FileListIter->Available)
						{
							if (memcmp(FileListIter->Result.get(), Buffer.get(), SHA3_512_SIZE) == 0)
							{
								fclose(Input);
								Input = nullptr;
								continue;
							}
							else {
								memcpy(FileListIter->Result.get(), Buffer.get(), SHA3_512_SIZE);
							}
						}
						else {
							FileListIter->Available = true;
							memcpy(FileListIter->Result.get(), Buffer.get(), SHA3_512_SIZE);
						}
					}
				}
			}

			HashChanged = true;
		//Read data.
			ReadText(Input, READTEXT_IPFILTER, (PWSTR)FileListIter->FileName.c_str());
			fclose(Input);
			Input = nullptr;
		}

	//Update AddressRange list.
		if (!HashChanged)
		{
		//Auto-refresh
			Sleep((DWORD)Parameter.FileRefreshTime);
			continue;
		}

	//Blacklist part
		if (!ResultBlacklistModificating->empty())
		{
		//Empty vector
			if (!Parameter.Blacklist)
			{
				ResultBlacklistModificating->clear();
				ResultBlacklistModificating->shrink_to_fit();
			}
			else {
			//Check repeating items.
				for (ResultBlacklistIter[0] = ResultBlacklistModificating->begin();ResultBlacklistIter[0] != ResultBlacklistModificating->end();ResultBlacklistIter[0]++)
				{
					for (ResultBlacklistIter[1U] = ResultBlacklistIter[0] + 1U;ResultBlacklistIter[1U] != ResultBlacklistModificating->end();ResultBlacklistIter[1U]++)
					{
						if (ResultBlacklistIter[0]->Addresses.front().ss_family == ResultBlacklistIter[1U]->Addresses.front().ss_family && 
							ResultBlacklistIter[0]->PatternString == ResultBlacklistIter[1U]->PatternString)
						{
						//IPv6
							if (ResultBlacklistIter[0]->Addresses.front().ss_family == AF_INET6)
							{
								for (SockAddrIter[0] = ResultBlacklistIter[1U]->Addresses.begin();SockAddrIter[0] != ResultBlacklistIter[1U]->Addresses.end();SockAddrIter[0]++)
								{
									for (SockAddrIter[1U] = ResultBlacklistIter[0]->Addresses.begin();SockAddrIter[1U] != ResultBlacklistIter[0]->Addresses.end();SockAddrIter[1U]++)
									{
										if (memcmp(&((PSOCKADDR_IN6)&SockAddrIter[0])->sin6_addr, &((PSOCKADDR_IN6)&SockAddrIter[1U])->sin6_addr, sizeof(in6_addr)) == 0)
										{
											break;
										}
										else if (SockAddrIter[1U] == ResultBlacklistIter[0]->Addresses.end() - 1U)
										{
											ResultBlacklistIter[0]->Addresses.push_back(*SockAddrIter[0]);
											break;
										}
									}
								}
							}
						//IPv4
							else {
								for (SockAddrIter[0] = ResultBlacklistIter[1U]->Addresses.begin();SockAddrIter[0] != ResultBlacklistIter[1U]->Addresses.end();SockAddrIter[0]++)
								{
									for (SockAddrIter[1U] = ResultBlacklistIter[0]->Addresses.begin();SockAddrIter[1U] != ResultBlacklistIter[0]->Addresses.end();SockAddrIter[1U]++)
									{
										if (((PSOCKADDR_IN)&SockAddrIter[0])->sin_addr.S_un.S_addr == ((PSOCKADDR_IN)&SockAddrIter[1U])->sin_addr.S_un.S_addr)
										{
											break;
										}
										else if (SockAddrIter[1U] == ResultBlacklistIter[0]->Addresses.end() - 1U)
										{
											ResultBlacklistIter[0]->Addresses.push_back(*SockAddrIter[0]);
											break;
										}
									}
								}
							}

							ResultBlacklistIter[0] = ResultBlacklistModificating->erase(ResultBlacklistIter[1U]);
							break;
						}
					}
				}

			//Swap(or cleanup) using list.
				ResultBlacklistModificating->shrink_to_fit();
				std::unique_lock<std::mutex> ResultBlacklistMutex(ResultBlacklistLock);
				ResultBlacklistUsing->swap(*ResultBlacklistModificating);
				ResultBlacklistMutex.unlock();
				ResultBlacklistModificating->clear();
				ResultBlacklistModificating->shrink_to_fit();
			}
		}
		else { //ResultBlacklist Table is empty.
			std::unique_lock<std::mutex> ResultBlacklistMutex(ResultBlacklistLock);
			ResultBlacklistUsing->clear();
			ResultBlacklistUsing->shrink_to_fit();
			ResultBlacklistMutex.unlock();
			ResultBlacklistModificating->clear();
			ResultBlacklistModificating->shrink_to_fit();
		}

	//Address Range part
		if (!AddressRangeModificating->empty())
		{
		//Empty vector
			if (Parameter.OperationMode != LISTEN_CUSTOMMODE)
			{
				AddressRangeModificating->clear();
				AddressRangeModificating->shrink_to_fit();
			}
			else {
			//Check repeating ranges.
				for (AddressRangeIter[0] = AddressRangeModificating->begin();AddressRangeIter[0] != AddressRangeModificating->end();AddressRangeIter[0]++)
				{
					for (AddressRangeIter[1U] = AddressRangeIter[0] + 1U;AddressRangeIter[1U] != AddressRangeModificating->end();AddressRangeIter[1U]++)
					{
					//IPv6
						if (AddressRangeIter[0]->Begin.ss_family == AF_INET6 && AddressRangeIter[1U]->Begin.ss_family == AF_INET6)
						{
						//A-Range is not same as B-Range.
							if (CompareAddresses(&((PSOCKADDR_IN6)&AddressRangeIter[0]->End)->sin6_addr, &((PSOCKADDR_IN6)&AddressRangeIter[1U]->Begin)->sin6_addr, AF_INET6) == ADDRESS_COMPARE_LESS)
							{
								IPv6NextAddress = ((PSOCKADDR_IN6)&AddressRangeIter[0]->End)->sin6_addr;
							//Check next address.
								for (Index = sizeof(in6_addr) / sizeof(uint16_t) - 1U;Index >= 0;Index--)
								{
									if (IPv6NextAddress.u.Word[Index] == U16_MAXNUM)
									{
										if (Index == 0)
											break;

										IPv6NextAddress.u.Word[Index] = 0;
										continue;
									}
									else {
										IPv6NextAddress.u.Word[Index] = htons(ntohs(IPv6NextAddress.u.Word[Index]) + 1U);
										break;
									}
								}
								if (memcmp(&IPv6NextAddress, &((PSOCKADDR_IN6)&AddressRangeIter[1U]->Begin)->sin6_addr, sizeof(in6_addr)) == 0)
								{
									AddressRangeIter[0]->End = AddressRangeIter[1U]->End;
									AddressRangeIter[0] = AddressRangeModificating->erase(AddressRangeIter[1U]);
									AddressRangeIter[0]--;
								}

								break;
							}
						//B-Range is not same as A-Range.
							else if (CompareAddresses(&AddressRangeIter[0]->Begin, &((PSOCKADDR_IN6)&AddressRangeIter[1U]->End)->sin6_addr, AF_INET6) == ADDRESS_COMPARE_GREATER)
							{
								IPv6NextAddress = ((PSOCKADDR_IN6)&AddressRangeIter[1U]->End)->sin6_addr;
							//Check next address.
								for (Index = sizeof(in6_addr) / sizeof(uint16_t) - 1U;Index >= 0;Index--)
								{
									if (IPv6NextAddress.u.Word[Index] == U16_MAXNUM)
									{
										if (Index == 0)
											break;

										IPv6NextAddress.u.Word[Index] = 0;
										continue;
									}
									else {
										IPv6NextAddress.u.Word[Index] = htons(ntohs(IPv6NextAddress.u.Word[Index]) + 1U);
										break;
									}
								}
								if (memcmp(&IPv6NextAddress, &AddressRangeIter[0]->Begin, sizeof(in6_addr)) == 0)
								{
									AddressRangeIter[0]->Begin = AddressRangeIter[1U]->Begin;
									AddressRangeIter[0] = AddressRangeModificating->erase(AddressRangeIter[1U]);
									AddressRangeIter[0]--;
								}

								break;
							}
						//A-Range is same as B-Range.
							else if (CompareAddresses(&AddressRangeIter[0]->Begin, &((PSOCKADDR_IN6)&AddressRangeIter[1U]->Begin)->sin6_addr, AF_INET6) == ADDRESS_COMPARE_EQUAL && 
								CompareAddresses(&((PSOCKADDR_IN6)&AddressRangeIter[0]->End)->sin6_addr, &((PSOCKADDR_IN6)&AddressRangeIter[1U]->End)->sin6_addr, AF_INET6) == ADDRESS_COMPARE_EQUAL)
							{
								AddressRangeIter[0] = AddressRangeModificating->erase(AddressRangeIter[1U]);
								AddressRangeIter[0]--;
								break;
							}
						//A-Range connect B-Range or B-Range connect A-Range.
							else if (CompareAddresses(&((PSOCKADDR_IN6)&AddressRangeIter[0]->End)->sin6_addr, &((PSOCKADDR_IN6)&AddressRangeIter[1U]->Begin)->sin6_addr, AF_INET6) == ADDRESS_COMPARE_EQUAL)
							{
								AddressRangeIter[0]->End = AddressRangeIter[1U]->End;
								AddressRangeIter[0] = AddressRangeModificating->erase(AddressRangeIter[1U]);
								AddressRangeIter[0]--;
								break;
							}
							else if (CompareAddresses(&((PSOCKADDR_IN6)&AddressRangeIter[1U]->End)->sin6_addr, &AddressRangeIter[0]->Begin, AF_INET6) == ADDRESS_COMPARE_EQUAL)
							{
								AddressRangeIter[0]->Begin = AddressRangeIter[1U]->Begin;
								AddressRangeIter[0] = AddressRangeModificating->erase(AddressRangeIter[1U]);
								AddressRangeIter[0]--;
								break;
							}
						//A-Range include B-Range or B-Range include A-Range.
							else if (CompareAddresses(&AddressRangeIter[0]->Begin, &((PSOCKADDR_IN6)&AddressRangeIter[1U]->Begin)->sin6_addr, AF_INET6) == ADDRESS_COMPARE_LESS && 
								CompareAddresses(&((PSOCKADDR_IN6)&AddressRangeIter[0]->End)->sin6_addr, &((PSOCKADDR_IN6)&AddressRangeIter[1U]->End)->sin6_addr, AF_INET6) == ADDRESS_COMPARE_GREATER)
							{
								AddressRangeIter[0] = AddressRangeModificating->erase(AddressRangeIter[1U]);
								AddressRangeIter[0]--;
								break;
							}
							else if (CompareAddresses(&AddressRangeIter[0]->Begin, &((PSOCKADDR_IN6)&AddressRangeIter[1U]->Begin)->sin6_addr, AF_INET6) == ADDRESS_COMPARE_GREATER && 
								CompareAddresses(&((PSOCKADDR_IN6)&AddressRangeIter[0]->End)->sin6_addr, &((PSOCKADDR_IN6)&AddressRangeIter[1U]->End)->sin6_addr, AF_INET6) == ADDRESS_COMPARE_LESS)
							{
								*AddressRangeIter[0] = *AddressRangeIter[1U];
								AddressRangeIter[0] = AddressRangeModificating->erase(AddressRangeIter[1U]);
								AddressRangeIter[0]--;
								break;
							}
						//A part of A-Range or B-Range is same as a part of B-Range or A-Range, also begin or end of A-Range or B-Range is same as begin or end of A-Range or B-Range.
							if (CompareAddresses(&AddressRangeIter[0]->Begin, &((PSOCKADDR_IN6)&AddressRangeIter[1U]->Begin)->sin6_addr, AF_INET6) == ADDRESS_COMPARE_EQUAL)
							{
								if (CompareAddresses(&((PSOCKADDR_IN6)&AddressRangeIter[0]->End)->sin6_addr, &((PSOCKADDR_IN6)&AddressRangeIter[1U]->End)->sin6_addr, AF_INET6) == ADDRESS_COMPARE_LESS)
									*AddressRangeIter[0] = *AddressRangeIter[1U];

								AddressRangeIter[0] = AddressRangeModificating->erase(AddressRangeIter[1U]);
								AddressRangeIter[0]--;
								break;
							}
							else if (CompareAddresses(&((PSOCKADDR_IN6)&AddressRangeIter[0]->End)->sin6_addr, &((PSOCKADDR_IN6)&AddressRangeIter[1U]->End)->sin6_addr, AF_INET6) == ADDRESS_COMPARE_EQUAL)
							{
								if (CompareAddresses(&AddressRangeIter[0]->Begin, &((PSOCKADDR_IN6)&AddressRangeIter[1U]->Begin)->sin6_addr, AF_INET6) != ADDRESS_COMPARE_LESS)
									*AddressRangeIter[0] = *AddressRangeIter[1U];

								AddressRangeIter[0] = AddressRangeModificating->erase(AddressRangeIter[1U]);
								AddressRangeIter[0]--;
								break;
							}
						//A part of A-Range or B-Range is same as a part of B-Range or A-Range.
							else if (CompareAddresses(&((PSOCKADDR_IN6)&AddressRangeIter[0]->End)->sin6_addr, &((PSOCKADDR_IN6)&AddressRangeIter[1U]->Begin)->sin6_addr, AF_INET6) == ADDRESS_COMPARE_GREATER)
							{
								AddressRangeIter[0]->End = AddressRangeIter[1U]->End;
								AddressRangeIter[0] = AddressRangeModificating->erase(AddressRangeIter[1U]);
								AddressRangeIter[0]--;
								break;
							}
							else if (CompareAddresses(&((PSOCKADDR_IN6)&AddressRangeIter[1U]->End)->sin6_addr, &AddressRangeIter[0]->Begin, AF_INET6) == ADDRESS_COMPARE_GREATER)
							{
								AddressRangeIter[0]->Begin = AddressRangeIter[1U]->Begin;
								AddressRangeIter[0] = AddressRangeModificating->erase(AddressRangeIter[1U]);
								AddressRangeIter[0]--;
								break;
							}
						}
					//IPv4
						else if (AddressRangeIter[0]->Begin.ss_family == AF_INET && AddressRangeIter[1U]->Begin.ss_family == AF_INET)
						{
						//A-Range is not same as B-Range.
							if (CompareAddresses(&((PSOCKADDR_IN)&AddressRangeIter[0]->End)->sin_addr, &((PSOCKADDR_IN)&AddressRangeIter[1U]->Begin)->sin_addr, AF_INET) == ADDRESS_COMPARE_LESS)
							{
								IPv4NextAddress = ((PSOCKADDR_IN)&AddressRangeIter[0]->End)->sin_addr;
							//Check next address.
								IPv4NextAddress.S_un.S_addr = htonl(ntohl(IPv4NextAddress.S_un.S_addr) + 1U);
								if (IPv4NextAddress.S_un.S_addr == ((PSOCKADDR_IN)&AddressRangeIter[1U]->Begin)->sin_addr.S_un.S_addr)
								{
									AddressRangeIter[0]->End = AddressRangeIter[1U]->End;
									AddressRangeIter[0] = AddressRangeModificating->erase(AddressRangeIter[1U]);
									AddressRangeIter[0]--;
								}

								break;
							}
						//B-Range is not same as A-Range.
							else if (CompareAddresses(&((PSOCKADDR_IN)&AddressRangeIter[0]->Begin)->sin_addr, &((PSOCKADDR_IN)&AddressRangeIter[1U]->End)->sin_addr, AF_INET) == ADDRESS_COMPARE_GREATER)
							{
								IPv4NextAddress = ((PSOCKADDR_IN)&AddressRangeIter[1U]->End)->sin_addr;
							//Check next address.
								IPv4NextAddress.S_un.S_addr = htonl(ntohl(IPv4NextAddress.S_un.S_addr) + 1U);
								if (IPv4NextAddress.S_un.S_addr == ((PSOCKADDR_IN)&AddressRangeIter[0]->Begin)->sin_addr.S_un.S_addr)
								{
									AddressRangeIter[0]->Begin = AddressRangeIter[1U]->Begin;
									AddressRangeIter[0] = AddressRangeModificating->erase(AddressRangeIter[1U]);
									AddressRangeIter[0]--;
								}

								break;
							}
						//A-Range is same as B-Range.
							else if (CompareAddresses(&((PSOCKADDR_IN)&AddressRangeIter[0]->Begin)->sin_addr, &((PSOCKADDR_IN)&AddressRangeIter[1U]->Begin)->sin_addr, AF_INET) == ADDRESS_COMPARE_EQUAL && 
								CompareAddresses(&((PSOCKADDR_IN)&AddressRangeIter[0]->End)->sin_addr, &((PSOCKADDR_IN)&AddressRangeIter[1U]->End)->sin_addr, AF_INET) == ADDRESS_COMPARE_EQUAL)
							{
								AddressRangeIter[0] = AddressRangeModificating->erase(AddressRangeIter[1U]);
								break;
							}
						//A-Range connect B-Range or B-Range connect A-Range.
							else if (CompareAddresses(&((PSOCKADDR_IN)&AddressRangeIter[0]->End)->sin_addr, &((PSOCKADDR_IN)&AddressRangeIter[1U]->Begin)->sin_addr, AF_INET) == ADDRESS_COMPARE_EQUAL)
							{
								AddressRangeIter[0]->End = AddressRangeIter[1U]->End;
								AddressRangeIter[0] = AddressRangeModificating->erase(AddressRangeIter[1U]);
								AddressRangeIter[0]--;
								break;
							}
							else if (CompareAddresses(&((PSOCKADDR_IN)&AddressRangeIter[1U]->End)->sin_addr, &((PSOCKADDR_IN)&AddressRangeIter[0]->Begin)->sin_addr, AF_INET) == ADDRESS_COMPARE_EQUAL)
							{
								AddressRangeIter[0]->Begin = AddressRangeIter[1U]->Begin;
								AddressRangeIter[0] = AddressRangeModificating->erase(AddressRangeIter[1U]);
								AddressRangeIter[0]--;
								break;
							}
						//A-Range include B-Range or B-Range include A-Range.
							else if (CompareAddresses(&((PSOCKADDR_IN)&AddressRangeIter[0]->Begin)->sin_addr, &((PSOCKADDR_IN)&AddressRangeIter[1U]->Begin)->sin_addr, AF_INET) == ADDRESS_COMPARE_LESS && 
								CompareAddresses(&((PSOCKADDR_IN)&AddressRangeIter[0]->End)->sin_addr, &((PSOCKADDR_IN)&AddressRangeIter[1U]->End)->sin_addr, AF_INET) == ADDRESS_COMPARE_GREATER)
							{
								AddressRangeIter[0] = AddressRangeModificating->erase(AddressRangeIter[1U]);
								AddressRangeIter[0]--;
								break;
							}
							else if (CompareAddresses(&((PSOCKADDR_IN)&AddressRangeIter[0]->Begin)->sin_addr, &((PSOCKADDR_IN)&AddressRangeIter[1U]->Begin)->sin_addr, AF_INET) == ADDRESS_COMPARE_GREATER && 
								CompareAddresses(&((PSOCKADDR_IN)&AddressRangeIter[0]->End)->sin_addr, &((PSOCKADDR_IN)&AddressRangeIter[1U]->End)->sin_addr, AF_INET) == ADDRESS_COMPARE_LESS)
							{
								*AddressRangeIter[0] = *AddressRangeIter[1U];
								AddressRangeIter[0] = AddressRangeModificating->erase(AddressRangeIter[1U]);
								AddressRangeIter[0]--;
								break;
							}
						//A part of A-Range or B-Range is same as a part of B-Range or A-Range, also begin or end of A-Range or B-Range is same as begin or end of A-Range or B-Range.
							if (CompareAddresses(&((PSOCKADDR_IN)&AddressRangeIter[0]->Begin)->sin_addr, &((PSOCKADDR_IN)&AddressRangeIter[1U]->Begin)->sin_addr, AF_INET) == ADDRESS_COMPARE_EQUAL)
							{
								if (CompareAddresses(&((PSOCKADDR_IN)&AddressRangeIter[0]->End)->sin_addr, &((PSOCKADDR_IN)&AddressRangeIter[1U]->End)->sin_addr, AF_INET) == ADDRESS_COMPARE_LESS)
									*AddressRangeIter[0] = *AddressRangeIter[1U];

								AddressRangeIter[0] = AddressRangeModificating->erase(AddressRangeIter[1U]);
								AddressRangeIter[0]--;
								break;
							}
							else if (CompareAddresses(&((PSOCKADDR_IN)&AddressRangeIter[0]->End)->sin_addr, &((PSOCKADDR_IN)&AddressRangeIter[1U]->End)->sin_addr, AF_INET) == ADDRESS_COMPARE_EQUAL)
							{
								if (CompareAddresses(&((PSOCKADDR_IN)&AddressRangeIter[0]->Begin)->sin_addr, &((PSOCKADDR_IN)&AddressRangeIter[1U]->Begin)->sin_addr, AF_INET) != ADDRESS_COMPARE_LESS)
									*AddressRangeIter[0] = *AddressRangeIter[1U];

								AddressRangeIter[0] = AddressRangeModificating->erase(AddressRangeIter[1U]);
								AddressRangeIter[0]--;
								break;
							}
						//A part of A-Range or B-Range is same as a part of B-Range or A-Range.
							else if (CompareAddresses(&((PSOCKADDR_IN)&AddressRangeIter[0]->End)->sin_addr, &((PSOCKADDR_IN)&AddressRangeIter[1U]->Begin)->sin_addr, AF_INET) == ADDRESS_COMPARE_GREATER)
							{
								AddressRangeIter[0]->End = AddressRangeIter[1U]->End;
								AddressRangeIter[0] = AddressRangeModificating->erase(AddressRangeIter[1U]);
								AddressRangeIter[0]--;
								break;
							}
							else if (CompareAddresses(&((PSOCKADDR_IN)&AddressRangeIter[1U]->End)->sin_addr, &((PSOCKADDR_IN)&AddressRangeIter[0]->Begin)->sin_addr, AF_INET) == ADDRESS_COMPARE_GREATER)
							{
								AddressRangeIter[0]->Begin = AddressRangeIter[1U]->Begin;
								AddressRangeIter[0] = AddressRangeModificating->erase(AddressRangeIter[1U]);
								AddressRangeIter[0]--;
								break;
							}
						}
					}
				}

			//Swap(or cleanup) using list.
				AddressRangeModificating->shrink_to_fit();
				std::unique_lock<std::mutex> AddressRangeMutex(AddressRangeLock);
				AddressRangeUsing->swap(*AddressRangeModificating);
				AddressRangeMutex.unlock();
				AddressRangeModificating->clear();
				AddressRangeModificating->shrink_to_fit();
			}
		}
		else { //AddressRange Table is empty.
			std::unique_lock<std::mutex> AddressRangeMutex(AddressRangeLock);
			AddressRangeUsing->clear();
			AddressRangeUsing->shrink_to_fit();
			AddressRangeMutex.unlock();
			AddressRangeModificating->clear();
			AddressRangeModificating->shrink_to_fit();
		}
		
	//Auto-refresh
		Sleep((DWORD)Parameter.FileRefreshTime);
	}

	return EXIT_SUCCESS;
}

//Read ipfilter data from file(s)
size_t __fastcall ReadIPFilterData(const PSTR Buffer, const PWSTR FileName, const size_t Line, bool &Comments, bool &Blacklist, bool &TempStop)
{
	std::string Data(Buffer);
//Multi-line comments check
	if (Comments)
	{
		if (Data.find("*/") != std::string::npos)
		{
			Data = Buffer + Data.find("*/") + 2U;
			Comments = false;
		}
		else {
			return FALSE;
		}
	}
	while (Data.find("/*") != std::string::npos)
	{
		if (Data.find("*/") == std::string::npos)
		{
			Data.erase(Data.find("/*"), Data.length() - Data.find("/*"));
			Comments = true;
			break;
		}
		else {
			Data.erase(Data.find("/*"), Data.find("*/") - Data.find("/*") + 2U);
		}
	}

//Delete spaces, horizontal tab/HT, check comments(Number Sign/NS and double slashs) and check minimum length of ipfilter items.
	if (Data.find(ASCII_HASHTAG) == 0 || Data.find(ASCII_SLASH) == 0)
	{
		return EXIT_SUCCESS;
	}
	else if (Data.find("[Base]") == 0 || Data.find("[base]") == 0 || 
		Data.find("[IPFilter]") == 0 || Data.find("[IPfilter]") == 0 || Data.find("[ipfilter]") == 0)
	{
		TempStop = false;
		Blacklist = false;
		return EXIT_SUCCESS;
	}
	else if (Data.find("[Blacklist]") == 0 || Data.find("[blacklist]") == 0)
	{
		TempStop = false;
		Blacklist = true;
		return EXIT_SUCCESS;
	}
	else if (Data.find("Version = ") == 0 || Data.find("version = ") == 0)
	{
		if (Data.length() < strlen("Version = ") + 8U)
		{
			double ReadVersion = atof(Data.c_str() + strlen("Version = "));
			if (ReadVersion > IPFILTER_VERSION)
			{
				PrintError(LOG_ERROR_IPFILTER, L"IPFilter file version error", NULL, FileName, Line);
				return EXIT_FAILURE;
			}
		}

		return EXIT_SUCCESS;
	}
	else if (Data.find("[Stop]") == 0 || Data.find("[stop]") == 0)
	{
		TempStop = true;
		return EXIT_SUCCESS;
	}
	else if (TempStop)
	{
		return EXIT_SUCCESS;
	}
	else if (!Blacklist && Data.find(ASCII_MINUS) == std::string::npos)
	{
		PrintError(LOG_ERROR_IPFILTER, L"Item format error", NULL, FileName, Line);
		return EXIT_FAILURE;
	}
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

	SSIZE_T Result = 0;
	size_t Index = 0;
//Blacklist
	if (Blacklist)
	{
		size_t Separated = 0;

	//Delete space(s) and horizontal tab/HT before data.
		while (!Data.empty() && (Data[0] == ASCII_HT || Data[0] == ASCII_SPACE))
			Data.erase(0, 1U);

	//Delete space(s) and horizontal tab/HT before or after vertical(s).
		while (Data.find("	|") != std::string::npos || Data.find("|	") != std::string::npos || 
				Data.find(" |") != std::string::npos || Data.find("| ") != std::string::npos)
		{
			if (Data.find("	|") != std::string::npos)
				Data.erase(Data.find("	|"), 1U);
			if (Data.find("|	") != std::string::npos)
				Data.erase(Data.find("|	") + 1U, 1U);
			if (Data.find(" |") != std::string::npos)
				Data.erase(Data.find(" |"), 1U);
			if (Data.find("| ") != std::string::npos)
				Data.erase(Data.find("| ") + 1U, 1U);
		}

	//Mark separated location.
		if (Data.find(ASCII_COMMA) != std::string::npos)
		{
		//Delete space(s) and horizontal tab/HT before comma(s).
			while (Data.find("	,") != std::string::npos || Data.find(" ,") != std::string::npos)
			{
				if (Data.find("	,") != std::string::npos)
					Data.erase(Data.find("	,"), 1U);
				if (Data.find(" ,") != std::string::npos)
					Data.erase(Data.find(" ,"), 1U);
			}

		//Delete space(s) and horizontal tab/HT after comma(s).
			while (Data.find(ASCII_HT) != std::string::npos && Data.find(ASCII_HT) > Data.find(ASCII_COMMA))
				Data.erase(Data.find(ASCII_HT), 1U);
			while (Data.find(ASCII_SPACE) != std::string::npos && Data.find(ASCII_SPACE) > Data.find(ASCII_COMMA))
				Data.erase(Data.find(ASCII_SPACE), 1U);

		//Common format
			if (Data.find(ASCII_HT) != std::string::npos && Data.find(ASCII_SPACE) != std::string::npos)
			{
				if (Data.find(ASCII_HT) < Data.find(ASCII_SPACE))
					Separated = Data.find(ASCII_HT);
				else 
					Separated = Data.find(ASCII_SPACE);
			}
			else if (Data.find(ASCII_HT) != std::string::npos)
			{
				Separated = Data.find(ASCII_HT);
			}
			else if (Data.find(ASCII_SPACE) != std::string::npos)
			{
				Separated = Data.find(ASCII_SPACE);
			}
		//Comma-Separated Values/CSV, RFC 4180(https://tools.ietf.org/html/rfc4180), Common Format and MIME Type for Comma-Separated Values (CSV) Files).
			else {
				Separated = Data.find(ASCII_COMMA);
				Data.erase(Separated, 1U);
			}
		}
	//Common format
		else {
			if (Data.find(ASCII_HT) != std::string::npos && Data.find(ASCII_SPACE) != std::string::npos)
			{
				if (Data.find(ASCII_HT) < Data.find(ASCII_SPACE))
					Separated = Data.find(ASCII_HT);
				else 
					Separated = Data.find(ASCII_SPACE);
			}
			else if (Data.find(ASCII_HT) != std::string::npos)
			{
				Separated = Data.find(ASCII_HT);
			}
			else if (Data.find(ASCII_SPACE) != std::string::npos)
			{
				Separated = Data.find(ASCII_SPACE);
			}
			else {
				PrintError(LOG_ERROR_IPFILTER, L"Item format error", NULL, FileName, Line);
				return EXIT_FAILURE;
			}
		}

	//Delete space(s) and horizontal tab/HT.
		while (Data.find(ASCII_HT) != std::string::npos)
			Data.erase(Data.find(ASCII_HT), 1U);
		while (Data.find(ASCII_SPACE) != std::string::npos)
			Data.erase(Data.find(ASCII_SPACE), 1U);

	//String length check.
		if (Data.length() < 3U)
		{
			PrintError(LOG_ERROR_IPFILTER, L"Item format error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}

/* Old version(2014-07-16)
	//Mark or delete space(s), horizontal tab/HT, and read Comma-Separated Values/CSV.
		while (!Data.empty() && (Data[0] == 9 || Data[0] == 32))
			Data.erase(0, 1U);

		if (Data.find(ASCII_COMMA) != std::string::npos && //Comma-Separated Values/CSV, RFC 4180(https://tools.ietf.org/html/rfc4180), Common Format and MIME Type for Comma-Separated Values (CSV) Files).
			(Data.find(" ,") != std::string::npos || Data.find("	,") != std::string::npos || 
			Data.find(ASCII_HT) != std::string::npos && Data.find(ASCII_HT) > Data.find(ASCII_COMMA) || 
			Data.find(ASCII_SPACE) != std::string::npos && Data.find(ASCII_SPACE) > Data.find(ASCII_COMMA)))
		{
		//Delete space(s) and horizontal tab/HT
			while (Data.find(ASCII_HT) != std::string::npos)
				Data.erase(Data.find(ASCII_HT), 1U);
			while (Data.find(ASCII_SPACE) != std::string::npos)
				Data.erase(Data.find(ASCII_SPACE), 1U);
		//Mark separated values.
			Separated = Data.find(ASCII_COMMA);
			Data.erase(Data.find(ASCII_COMMA), 1U);
		}
		else if (Data.find(ASCII_COMMA) == std::string::npos || 
			Data.find(ASCII_COMMA) != std::string::npos && (Data.find(ASCII_HT) < Data.find(ASCII_COMMA) || Data.find(ASCII_SPACE) < Data.find(ASCII_COMMA))) //Normal
		{
		//Mark separated values.
			for (Separated = 0;Separated < Data.length();Separated++)
			{
				if (Data[Separated] == 9 || Data[Separated] == 32)
					break;
			}
		
		//Delete space(s) and horizontal tab/HT
			while (Data.find(ASCII_HT) != std::string::npos)
				Data.erase(Data.find(ASCII_HT), 1U);
			while (Data.find(ASCII_SPACE) != std::string::npos)
				Data.erase(Data.find(ASCII_SPACE), 1U);
		}
		else {
			PrintError(LOG_ERROR_IPFILTER, L"Item format error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
*/
		ResultBlacklistTable ResultBlacklistTableTemp;
		sockaddr_storage AddressTemp = {0};
		std::shared_ptr<char> Addr(new char[ADDR_STRING_MAXSIZE]());

	//Single address
		if (Data.find(ASCII_VERTICAL) == std::string::npos)
		{
		//AAAA Records(IPv6)
			if (Data.find(ASCII_COLON) < Separated)
			{
			//IPv6 addresses check
				if (Separated > ADDR_STRING_MAXSIZE)
				{
					PrintError(LOG_ERROR_IPFILTER, L"IPv6 Address format error", NULL, FileName, Line);
					return EXIT_FAILURE;
				}
				else if (Data[0] < ASCII_ZERO || Data[0] > ASCII_COLON && Data[0] < ASCII_UPPERCASE_A || Data[0] > ASCII_UPPERCASE_F && Data[0] < ASCII_LOWERCASE_A || Data[0] > ASCII_LOWERCASE_F)
				{
					return EXIT_FAILURE;
				}

			//Convert addresses.
				memcpy(Addr.get(), Data.c_str(), Separated);
				if (AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN6)&AddressTemp)->sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_IPFILTER, L"IPv6 Address format error", Result, FileName, Line);
					return EXIT_FAILURE;
				}

				AddressTemp.ss_family = AF_INET6;
				ResultBlacklistTableTemp.Addresses.push_back(AddressTemp);
			}
		//A Records(IPv4)
			else {
			//IPv4 addresses check
				if (Separated > ADDR_STRING_MAXSIZE)
				{
					PrintError(LOG_ERROR_IPFILTER, L"IPv4 Address format error", NULL, FileName, Line);
					return EXIT_FAILURE;
				}
				else if (Data[0] < ASCII_ZERO || Data[0] > ASCII_NINE)
				{
					return EXIT_FAILURE;
				}

			//Convert addresses.
				memcpy(Addr.get(), Data.c_str(), Separated);
				if (AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN)&AddressTemp)->sin_addr, AF_INET, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_IPFILTER, L"IPv4 Address format error", Result, FileName, Line);
					return EXIT_FAILURE;
				}

				AddressTemp.ss_family = AF_INET;
				ResultBlacklistTableTemp.Addresses.push_back(AddressTemp);
			}
		}
	//Multiple Addresses
		else {
			size_t VerticalIndex = 0;

		//AAAA Records(IPv6)
			if (Data.find(ASCII_COLON) < Separated)
			{
			//IPv6 addresses check
				if (Data[0] < ASCII_ZERO || Data[0] > ASCII_COLON && Data[0] < ASCII_UPPERCASE_A || Data[0] > ASCII_UPPERCASE_F && Data[0] < ASCII_LOWERCASE_A || Data[0] > ASCII_LOWERCASE_F)
					return EXIT_FAILURE;

				for (Index = 0;Index <= Separated;Index++)
				{
				//Read data.
					if (Data[Index] == ASCII_VERTICAL || Index == Separated)
					{
					//Length check
						if (Index - VerticalIndex > ADDR_STRING_MAXSIZE)
						{
							PrintError(LOG_ERROR_IPFILTER, L"IPv6 Address format error", NULL, FileName, Line);
							return EXIT_FAILURE;
						}

					//Convert addresses.
						memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
						memcpy(Addr.get(), Data.c_str() + VerticalIndex, Index - VerticalIndex);
						if (AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN6)&AddressTemp)->sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
						{
							PrintError(LOG_ERROR_IPFILTER, L"IPv6 Address format error", Result, FileName, Line);
							return EXIT_FAILURE;
						}

						AddressTemp.ss_family = AF_INET6;
						ResultBlacklistTableTemp.Addresses.push_back(AddressTemp);
						memset(&AddressTemp, 0, sizeof(sockaddr_storage));
						VerticalIndex = Index + 1U;
					}
				}
			}
		//A Records(IPv4)
			else {
			//IPv4 addresses check
				if (Data[0] < ASCII_ZERO || Data[0] > ASCII_NINE)
					return EXIT_FAILURE;

				for (Index = 0;Index <= Separated;Index++)
				{
				//Read data.
					if (Data[Index] == ASCII_VERTICAL || Index == Separated)
					{
					//Length check
						if (Index - VerticalIndex > ADDR_STRING_MAXSIZE)
						{
							PrintError(LOG_ERROR_IPFILTER, L"IPv4 Address format error", NULL, FileName, Line);
							return EXIT_FAILURE;
						}

					//Convert addresses.
						memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
						memcpy(Addr.get(), Data.c_str() + VerticalIndex, Index - VerticalIndex);
						if (AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN)&AddressTemp)->sin_addr, AF_INET, Result) == EXIT_FAILURE)
						{
							PrintError(LOG_ERROR_IPFILTER, L"IPv4 Address format error", Result, FileName, Line);
							return EXIT_FAILURE;
						}

						AddressTemp.ss_family = AF_INET;
						ResultBlacklistTableTemp.Addresses.push_back(AddressTemp);
						memset(&AddressTemp, 0, sizeof(sockaddr_storage));
						VerticalIndex = Index + 1U;
					}
				}
			}
		}

	//Mark patterns.
		ResultBlacklistTableTemp.PatternString.append(Data, Separated, Data.length() - Separated);
		try {
			std::regex PatternTemp(ResultBlacklistTableTemp.PatternString /* , std::regex_constants::extended */ );
			ResultBlacklistTableTemp.Pattern.swap(PatternTemp);
		}
		catch (std::regex_error)
		{
			PrintError(LOG_ERROR_IPFILTER, L"Regular expression pattern error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}

	//Check repeating items.
		for (auto SockAddrIter = ResultBlacklistTableTemp.Addresses.begin();SockAddrIter != ResultBlacklistTableTemp.Addresses.end();SockAddrIter++)
		{
			if (SockAddrIter != ResultBlacklistTableTemp.Addresses.end() - 1U && !ResultBlacklistTableTemp.Addresses.empty())
			{
			//IPv6
				if (ResultBlacklistTableTemp.Addresses.front().ss_family == AF_INET6)
				{
					for (auto InnerSockAddrIter = SockAddrIter + 1U;InnerSockAddrIter != ResultBlacklistTableTemp.Addresses.end();InnerSockAddrIter++)
					{
						if (memcmp(&((PSOCKADDR_IN6)&SockAddrIter)->sin6_addr, &((PSOCKADDR_IN6)&InnerSockAddrIter)->sin6_addr, sizeof(in6_addr)) == 0)
						{
							InnerSockAddrIter = ResultBlacklistTableTemp.Addresses.erase(InnerSockAddrIter);
							break;
						}
					}
				}
			//IPv4
				else {
					for (auto InnerSockAddrIter = SockAddrIter + 1U;InnerSockAddrIter != ResultBlacklistTableTemp.Addresses.end();InnerSockAddrIter++)
					{
						if (((PSOCKADDR_IN)&SockAddrIter)->sin_addr.S_un.S_addr == ((PSOCKADDR_IN)&InnerSockAddrIter)->sin_addr.S_un.S_addr)
						{
							InnerSockAddrIter = ResultBlacklistTableTemp.Addresses.erase(InnerSockAddrIter);
							break;
						}
					}
				}
			}
		}

	//Add to global ResultBlacklistTable.
		ResultBlacklistModificating->push_back(ResultBlacklistTableTemp);
		return EXIT_SUCCESS;
	}

//Main check
	while (Data.find(ASCII_HT) != std::string::npos)
		Data.erase(Data.find(ASCII_HT), 1U);
	while (Data.find(ASCII_SPACE) != std::string::npos)
		Data.erase(Data.find(ASCII_SPACE), 1U);
	if (Data.length() < 5U)
		return EXIT_SUCCESS;

//Delete space(s), horizontal tab/HT before data.
	while (!Data.empty() && (Data[0] == ASCII_HT || Data[0] == ASCII_SPACE))
		Data.erase(0, 1U);

//Check format of item(s).
	AddressRange AddressRangeTemp;
	if (Data.find(ASCII_COMMA) != std::string::npos && Data.find(ASCII_COMMA) > Data.find(ASCII_MINUS)) //IPFilter.dat
	{
	//IPv4 spacial delete
		if (Data.find(ASCII_PERIOD) != std::string::npos)
		{
		//Delete all zero(s) before data.
			for (Index = 0;Index < Data.find(ASCII_MINUS);Index++)
			{
				if (Data[Index] == ASCII_ZERO)
				{
					Data.erase(Index, 1U);
					Index--;
				}
				else {
					break;
				}
			}

		//Delete all zero(s) before minus or after comma(s) in addresses range.
			while (Data.find(".0") != std::string::npos)
				Data.replace((size_t)Data.find(".0"), strlen(".0"), ("."));
			while (Data.find("-0") != std::string::npos)
				Data.replace((size_t)Data.find("-0"), strlen("-0"), ("-"));
			while (Data.find("..") != std::string::npos)
				Data.replace((size_t)Data.find(".."), strlen(".."), (".0."));
			if (Data.find(".-") != std::string::npos)
				Data.replace((size_t)Data.find(".-"), strlen(".-"), (".0-"));
			if (Data.find("-.") != std::string::npos)
				Data.replace((size_t)Data.find("-."), strlen("-."), ("-0."));
			if (Data[0] == ASCII_PERIOD)
				Data.replace(0, 1U, ("0."));
		}

	//Delete all zero(s) before minus or after comma(s) in ipfilter level.
		while (Data.find(",000,") != std::string::npos)
			Data.replace((size_t)Data.find(",000,"), strlen(",000,"), (",0,"));
		while (Data.find(",00,") != std::string::npos)
			Data.replace((size_t)Data.find(",00,"), strlen(",00,"), (",0,"));
		while (Data.find(",00") != std::string::npos)
			Data.replace((size_t)Data.find(",00"), strlen(",00"), (","));
		if (Data.find(",0") != std::string::npos && Data[Data.find(",0") + 2U] != ASCII_COMMA)
			Data.replace((size_t)Data.find(",0"), strlen(",0"), (","));

	//Mark ipfilter level.
		std::shared_ptr<char> Level(new char[ADDR_STRING_MAXSIZE]());
		memcpy(Level.get(), Data.c_str() + Data.find(ASCII_COMMA) + 1U, Data.find(ASCII_COMMA, Data.find(ASCII_COMMA) + 1U) - Data.find(ASCII_COMMA) - 1U);
		Result = strtol(Level.get(), nullptr, NULL);
		if (Result >= 0 && Result <= U16_MAXNUM)
		{
			AddressRangeTemp.Level = (size_t)Result;
		}
		else {
			PrintError(LOG_ERROR_IPFILTER, L"Level error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}

	//Delete all data except addresses range.
		Data.erase(Data.find(ASCII_COMMA));
		if (Data[Data.length() - 1U] == ASCII_PERIOD)
			Data.append("0");
	}
	else { //PeerGuardian Text Lists(P2P) Format(Guarding.P2P), also a little part of IPFilter.dat without level.
	//IPv4 IPFilter.dat data without level
		if (Data.find(ASCII_COLON) == std::string::npos)
		{
		//Delete all zero(s) before data
			for (Index = 0;Index < Data.find(ASCII_MINUS);Index++)
			{
				if (Data[Index] == ASCII_ZERO)
				{
					Data.erase(Index, 1U);
					Index--;
				}
				else {
					break;
				}
			}

		//Delete all zero(s) before minus or after comma(s) in addresses range.
			while (Data.find(".0") != std::string::npos)
				Data.replace((size_t)Data.find(".0"), strlen(".0"), ("."));
			while (Data.find("-0") != std::string::npos)
				Data.replace((size_t)Data.find("-0"), strlen("-0"), ("-"));
			while (Data.find("..") != std::string::npos)
				Data.replace((size_t)Data.find(".."), strlen(".."), (".0."));
			if (Data.find(".-") != std::string::npos)
				Data.replace((size_t)Data.find(".-"), strlen(".-"), (".0-"));
			if (Data.find("-.") != std::string::npos)
				Data.replace((size_t)Data.find("-."), strlen("-."), ("-0."));
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

			//Delete all zero(s) before data.
				for (Index = 0;Index < Data.find(ASCII_MINUS);Index++)
				{
					if (Data[Index] == ASCII_ZERO)
					{
						Data.erase(Index, 1U);
						Index--;
					}
					else {
						break;
					}
				}

			//Delete all zero(s) before minus or after comma(s) in addresses range.
				while (Data.find(".0") != std::string::npos)
					Data.replace((size_t)Data.find(".0"), strlen(".0"), ("."));
				while (Data.find("-0") != std::string::npos)
					Data.replace((size_t)Data.find("-0"), strlen("-0"), ("-"));
				while (Data.find("..") != std::string::npos)
					Data.replace((size_t)Data.find(".."), strlen(".."), (".0."));
				if (Data.find(".-") != std::string::npos)
					Data.replace((size_t)Data.find(".-"), strlen(".-"), (".0-"));
				if (Data.find("-.") != std::string::npos)
					Data.replace((size_t)Data.find("-."), strlen("-."), ("-0."));
				if (Data[0] == ASCII_PERIOD)
					Data.replace(0, 1U, ("0."));
				if (Data[Data.length() - 1U] == ASCII_PERIOD)
					Data.append("0");
			}
//			else { 
//				//IPv6 IPFilter.dat data without level
//			}
		}
	}

//Read data
	std::shared_ptr<char> Address(new char[ADDR_STRING_MAXSIZE]);
	if (Data.find(ASCII_COLON) != std::string::npos) //IPv6
	{
	//Begin address
		AddressRangeTemp.Begin.ss_family = AF_INET6;
		memcpy(Address.get(), Data.c_str(), Data.find(ASCII_MINUS));
		if (AddressStringToBinary((PSTR)Address.get(), &((PSOCKADDR_IN6)&AddressRangeTemp.Begin)->sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
		{
			PrintError(LOG_ERROR_IPFILTER, L"IPv6 Address format error", Result, FileName, Line);
			return EXIT_FAILURE;
		}
		memset(Address.get(), 0, ADDR_STRING_MAXSIZE);

	//End address
		AddressRangeTemp.End.ss_family = AF_INET6;
		memcpy(Address.get(), Data.c_str() + Data.find(ASCII_MINUS) + 1U, Data.length() - Data.find(ASCII_MINUS));
		if (AddressStringToBinary((PSTR)Address.get(), &((PSOCKADDR_IN6)&AddressRangeTemp.End)->sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
		{
			PrintError(LOG_ERROR_IPFILTER, L"IPv6 Address format error", Result, FileName, Line);
			return EXIT_FAILURE;
		}
		Address.reset();

	//Check addresses range.
		for (Index = 0;Index < sizeof(in6_addr) / sizeof(uint16_t);Index++)
		{
			if (ntohs(((PSOCKADDR_IN6)&AddressRangeTemp.End)->sin6_addr.u.Word[Index]) < ntohs(((PSOCKADDR_IN6)&AddressRangeTemp.Begin)->sin6_addr.u.Word[Index]))
			{
				PrintError(LOG_ERROR_IPFILTER, L"IPv6 Addresses range error", WSAGetLastError(), FileName, Line);
				return EXIT_FAILURE;
			}
			else if (ntohs(((PSOCKADDR_IN6)&AddressRangeTemp.End)->sin6_addr.u.Word[Index]) > ntohs(((PSOCKADDR_IN6)&AddressRangeTemp.Begin)->sin6_addr.u.Word[Index]))
			{
				break;
			}
			else {
				continue;
			}
		}
	}
	else { //IPv4
	//Begin address
		AddressRangeTemp.Begin.ss_family = AF_INET;
		memcpy(Address.get(), Data.c_str(), Data.find(ASCII_MINUS));
		if (AddressStringToBinary((PSTR)Address.get(), &((PSOCKADDR_IN)&AddressRangeTemp.Begin)->sin_addr, AF_INET, Result) == EXIT_FAILURE)
		{
			PrintError(LOG_ERROR_IPFILTER, L"IPv4 Address format error", Result, FileName, Line);
			return EXIT_FAILURE;
		}
		memset(Address.get(), 0, ADDR_STRING_MAXSIZE);

	//End address
		AddressRangeTemp.End.ss_family = AF_INET;
		memcpy(Address.get(), Data.c_str() + Data.find(ASCII_MINUS) + 1U, Data.length() - Data.find(ASCII_MINUS));
		if (AddressStringToBinary((PSTR)Address.get(), &((PSOCKADDR_IN)&AddressRangeTemp.End)->sin_addr, AF_INET, Result) == EXIT_FAILURE)
		{
			PrintError(LOG_ERROR_IPFILTER, L"IPv4 Address format error", Result, FileName, Line);
			return EXIT_FAILURE;
		}
		Address.reset();
		
	//Check addresses range.
		if (((PSOCKADDR_IN)&AddressRangeTemp.End)->sin_addr.S_un.S_un_b.s_b1 < ((PSOCKADDR_IN)&AddressRangeTemp.Begin)->sin_addr.S_un.S_un_b.s_b1)
		{
			PrintError(LOG_ERROR_IPFILTER, L"IPv4 Addresses range error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}
		else if (((PSOCKADDR_IN)&AddressRangeTemp.End)->sin_addr.S_un.S_un_b.s_b1 == ((PSOCKADDR_IN)&AddressRangeTemp.Begin)->sin_addr.S_un.S_un_b.s_b1)
		{
			if (((PSOCKADDR_IN)&AddressRangeTemp.End)->sin_addr.S_un.S_un_b.s_b2 < ((PSOCKADDR_IN)&AddressRangeTemp.Begin)->sin_addr.S_un.S_un_b.s_b2)
			{
				PrintError(LOG_ERROR_IPFILTER, L"IPv4 Addresses range error", NULL, FileName, Line);
				return EXIT_FAILURE;
			}
			else if (((PSOCKADDR_IN)&AddressRangeTemp.End)->sin_addr.S_un.S_un_b.s_b2 == ((PSOCKADDR_IN)&AddressRangeTemp.Begin)->sin_addr.S_un.S_un_b.s_b2)
			{
				if (((PSOCKADDR_IN)&AddressRangeTemp.End)->sin_addr.S_un.S_un_b.s_b3 < ((PSOCKADDR_IN)&AddressRangeTemp.Begin)->sin_addr.S_un.S_un_b.s_b3)
				{
					PrintError(LOG_ERROR_IPFILTER, L"IPv4 Addresses range error", NULL, FileName, Line);
					return EXIT_FAILURE;
				}
				else if (((PSOCKADDR_IN)&AddressRangeTemp.End)->sin_addr.S_un.S_un_b.s_b3 == ((PSOCKADDR_IN)&AddressRangeTemp.Begin)->sin_addr.S_un.S_un_b.s_b3)
				{
					if (((PSOCKADDR_IN)&AddressRangeTemp.End)->sin_addr.S_un.S_un_b.s_b4 < ((PSOCKADDR_IN)&AddressRangeTemp.Begin)->sin_addr.S_un.S_un_b.s_b4)
					{
						PrintError(LOG_ERROR_IPFILTER, L"IPv4 Addresses range error", NULL, FileName, Line);
						return EXIT_FAILURE;
					}
				}
			}
		}
	}

//Add to global AddressRangeTable.
	AddressRangeModificating->push_back(AddressRangeTemp);
	return EXIT_SUCCESS;
}

//Read hosts from file
size_t __fastcall ReadHosts(void)
{
	size_t Index = 0;

//Initialization(Available when file hash check is ON.)
	std::shared_ptr<char> Buffer;
	FileData FileDataTemp[5U];
	if (Parameter.FileHash)
	{
		std::shared_ptr<char> FileDataBufferTemp(new char[FILE_BUFFER_SIZE]());
		Buffer.swap(FileDataBufferTemp);
		FileDataBufferTemp.reset();

		for (Index = 0;Index < sizeof(FileDataTemp) / sizeof(FileData);Index++)
		{
			std::shared_ptr<BitSequence> FileDataBufferTemp_SHA3(new BitSequence[SHA3_512_SIZE]());
			FileDataTemp[Index].Result.swap(FileDataBufferTemp_SHA3);
		}
	}

//Open file.
	FILE *Input = nullptr;
	std::vector<FileData> FileList;
	for (Index = 0;Index < sizeof(FileDataTemp) / sizeof(FileData);Index++)
		FileDataTemp[Index].FileName = *Parameter.Path;
	FileDataTemp[0].FileName.append(L"Hosts.ini");
	FileDataTemp[1U].FileName.append(L"Hosts.conf");
	FileDataTemp[2U].FileName.append(L"Hosts");
	FileDataTemp[3U].FileName.append(L"Hosts.txt");
	FileDataTemp[4U].FileName.append(L"Hosts.csv");
	for (Index = 0;Index < sizeof(FileDataTemp) / sizeof(FileData);Index++)
		FileList.push_back(FileDataTemp[Index]);

//File(s) monitor
	size_t ReadLength = 0, InnerIndex = 0;
	std::vector<FileData>::iterator FileListIter;
	Keccak_HashInstance HashInstance = {0};
	auto HashChanged = false;
	std::vector<HostsTable>::iterator HostsListIter;
	std::vector<HostsTable> Sorting;

	HANDLE HostsHandle = nullptr;
	LARGE_INTEGER HostsFileSize = {0};
	while (true)
	{
		HashChanged = false;
		for (FileListIter = FileList.begin();FileListIter != FileList.end();FileListIter++)
		{
			if (_wfopen_s(&Input, FileListIter->FileName.c_str(), L"rb") != 0)
			{
			//Cleanup hash result(s)
				if (Parameter.FileHash)
				{
					FileListIter->Available = false;
					memset(FileListIter->Result.get(), 0, SHA3_512_SIZE);
				}

				continue;
			}
			else {
				if (Input == nullptr)
					continue;

			//Check whole file size.
				HostsHandle = CreateFileW(FileListIter->FileName.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
				if (HostsHandle != INVALID_HANDLE_VALUE)
				{
					memset(&HostsFileSize, 0, sizeof(LARGE_INTEGER));
					if (GetFileSizeEx(HostsHandle, &HostsFileSize) == 0)
					{
						CloseHandle(HostsHandle);
					}
					else {
						CloseHandle(HostsHandle);
						if (HostsFileSize.QuadPart >= DEFAULT_FILE_MAXSIZE)
						{
							PrintError(LOG_ERROR_PARAMETER, L"Hosts file size is too large", NULL, (PWSTR)FileListIter->FileName.c_str(), NULL);

							fclose(Input);
							Input = nullptr;
							continue;
						}
					}
				}

			//Mark or check file(s) hash.
				if (Parameter.FileHash)
				{
					memset(Buffer.get(), 0, FILE_BUFFER_SIZE);
					memset(&HashInstance, 0, sizeof(Keccak_HashInstance));
					Keccak_HashInitialize_SHA3_512(&HashInstance);
					while (!feof(Input))
					{
						ReadLength = fread_s(Buffer.get(), FILE_BUFFER_SIZE, sizeof(char), FILE_BUFFER_SIZE, Input);
						Keccak_HashUpdate(&HashInstance, (BitSequence *)Buffer.get(), ReadLength * BYTES_TO_BITS);
					}
					memset(Buffer.get(), 0, FILE_BUFFER_SIZE);
					Keccak_HashFinal(&HashInstance, (BitSequence *)Buffer.get());

				//Set file pointer(s) to the beginning of file.
					if (_fseeki64(Input, 0, SEEK_SET) != 0)
					{
						PrintError(LOG_ERROR_HOSTS, L"Read file(s) error", NULL, (PWSTR)FileListIter->FileName.c_str(), NULL);

						fclose(Input);
						Input = nullptr;
						continue;
					}
					else {
						if (FileListIter->Available)
						{
							if (memcmp(FileListIter->Result.get(), Buffer.get(), SHA3_512_SIZE) == 0)
							{
								fclose(Input);
								Input = nullptr;
								continue;
							}
							else {
								memcpy(FileListIter->Result.get(), Buffer.get(), SHA3_512_SIZE);
							}
						}
						else {
							FileListIter->Available = true;
							memcpy(FileListIter->Result.get(), Buffer.get(), SHA3_512_SIZE);
						}
					}
				}
			}

			HashChanged = true;
		//Read data.
			ReadText(Input, READTEXT_HOSTS, (PWSTR)FileListIter->FileName.c_str());
			fclose(Input);
			Input = nullptr;
		}

	//Update Hosts list.
		if (!HashChanged)
		{
		//Auto-refresh
			Sleep((DWORD)Parameter.FileRefreshTime);
			continue;
		}
		else if (!HostsListModificating->empty())
		{
		//Check repeating items.
			for (HostsListIter = HostsListModificating->begin();HostsListIter != HostsListModificating->end();HostsListIter++)
			{
				if (HostsListIter->Type == HOSTS_NORMAL)
				{
				//AAAA Records(IPv6)
					if (HostsListIter->Protocol == AF_INET6 && HostsListIter->Length > sizeof(dns_aaaa_record))
					{
						for (Index = 0;Index < HostsListIter->Length / sizeof(dns_aaaa_record);Index++)
						{
							for (InnerIndex = Index + 1U;InnerIndex < HostsListIter->Length / sizeof(dns_aaaa_record);InnerIndex++)
							{
								if (memcmp(HostsListIter->Response.get() + sizeof(dns_aaaa_record) * Index,
									HostsListIter->Response.get() + sizeof(dns_aaaa_record) * InnerIndex, sizeof(dns_aaaa_record)) == 0)
								{
									memmove(HostsListIter->Response.get() + sizeof(dns_aaaa_record) * InnerIndex, HostsListIter->Response.get() + sizeof(dns_aaaa_record) * (InnerIndex + 1U), sizeof(dns_aaaa_record) * (HostsListIter->Length / sizeof(dns_aaaa_record) - InnerIndex));
									HostsListIter->Length -= sizeof(dns_aaaa_record);
									InnerIndex--;
								}
							}
						}
					}
				//A Records(IPv4)
					else {
						for (Index = 0;Index < HostsListIter->Length / sizeof(dns_a_record);Index++)
						{
							for (InnerIndex = Index + 1U;InnerIndex < HostsListIter->Length / sizeof(dns_a_record);InnerIndex++)
							{
								if (memcmp(HostsListIter->Response.get() + sizeof(dns_a_record) * Index,
									HostsListIter->Response.get() + sizeof(dns_a_record) * InnerIndex, sizeof(dns_a_record)) == 0)
								{
									memmove(HostsListIter->Response.get() + sizeof(dns_a_record) * InnerIndex, HostsListIter->Response.get() + sizeof(dns_a_record) * (InnerIndex + 1U), sizeof(dns_a_record) * (HostsListIter->Length / sizeof(dns_a_record) - InnerIndex));
									HostsListIter->Length -= sizeof(dns_a_record);
									InnerIndex--;
								}
							}
						}
					}
				}
			}

		//EDNS0 Lebal
			if (Parameter.EDNS0Label)
			{
				dns_edns0_label *EDNS0 = nullptr;

				for (HostsListIter = HostsListModificating->begin();HostsListIter != HostsListModificating->end();HostsListIter++)
				{
					if (HostsListIter->Length > PACKET_MAXSIZE - sizeof(dns_edns0_label))
					{
						PrintError(LOG_ERROR_HOSTS, L"Data is too long when EDNS0 is available", NULL, nullptr, NULL);
						continue;
					}
					else if (!HostsListIter->Response)
					{
						continue;
					}
					else {
						EDNS0 = (dns_edns0_label *)(HostsListIter->Response.get() + HostsListIter->Length);
						EDNS0->Type = htons(DNS_EDNS0_RECORDS);
						EDNS0->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
						HostsListIter->Length += sizeof(dns_edns0_label);
					}
				}
			}

		//Sort list.
			for (HostsListIter = HostsListModificating->begin();HostsListIter != HostsListModificating->end();HostsListIter++)
			{
				if (HostsListIter->Type == HOSTS_BANNED)
					Sorting.push_back(*HostsListIter);
			}
			for (HostsListIter = HostsListModificating->begin();HostsListIter != HostsListModificating->end();HostsListIter++)
			{
				if (HostsListIter->Type == HOSTS_WHITE)
					Sorting.push_back(*HostsListIter);
			}
			for (HostsListIter = HostsListModificating->begin();HostsListIter != HostsListModificating->end();HostsListIter++)
			{
				if (HostsListIter->Type == HOSTS_NORMAL)
					Sorting.push_back(*HostsListIter);
			}
			for (HostsListIter = HostsListModificating->begin();HostsListIter != HostsListModificating->end();HostsListIter++)
			{
				if (HostsListIter->Type == HOSTS_LOCAL)
					Sorting.push_back(*HostsListIter);
			}
			HostsListModificating->clear();
			HostsListModificating->swap(Sorting);
			Sorting.clear();
			Sorting.shrink_to_fit();

		//Swap(or cleanup) using list.
			HostsListModificating->shrink_to_fit();
			std::unique_lock<std::mutex> HostsListMutex(HostsListLock);
			HostsListUsing->swap(*HostsListModificating);
			HostsListMutex.unlock();
			HostsListModificating->clear();
			HostsListModificating->shrink_to_fit();
		}
		else { //Hosts Table is empty.
			std::unique_lock<std::mutex> HostsListMutex(HostsListLock);
			HostsListUsing->clear();
			HostsListUsing->shrink_to_fit();
			HostsListMutex.unlock();
			HostsListModificating->clear();
			HostsListModificating->shrink_to_fit();
		}

	//Flush DNS cache.
		if (Parameter.FileHash)
			FlushDNSResolverCache();
		
	//Auto-refresh
		Sleep((DWORD)Parameter.FileRefreshTime);
	}

	return EXIT_SUCCESS;
}

//Read hosts data from file(s)
size_t __fastcall ReadHostsData(const PSTR Buffer, const PWSTR FileName, const size_t Line, bool &Comments, bool &Local, bool &TempStop)
{
	std::string Data(Buffer);
//Multi-line comments check
	if (Comments)
	{
		if (Data.find("*/") != std::string::npos)
		{
			Data = Buffer + Data.find("*/") + 2U;
			Comments = false;
		}
		else {
			return FALSE;
		}
	}
	while (Data.find("/*") != std::string::npos)
	{
		if (Data.find("*/") == std::string::npos)
		{
			Data.erase(Data.find("/*"), Data.length() - Data.find("/*"));
			Comments = true;
			break;
		}
		else {
			Data.erase(Data.find("/*"), Data.find("*/") - Data.find("/*") + 2U);
		}
	}

//Delete comments(Number Sign/NS and double slashs) and check minimum length of hosts items.
	if (Data.find(ASCII_HASHTAG) == 0 || Data.find(ASCII_SLASH) == 0)
		return EXIT_SUCCESS;
	else if (Data.rfind(" //") != std::string::npos)
		Data.erase(Data.rfind(" //"), Data.length() - Data.rfind(" //"));
	else if (Data.rfind("	//") != std::string::npos)
		Data.erase(Data.rfind("	//"), Data.length() - Data.rfind("	//"));
	else if (Data.rfind(" #") != std::string::npos)
		Data.erase(Data.rfind(" #"), Data.length() - Data.rfind(" #"));
	else if (Data.rfind("	#") != std::string::npos)
		Data.erase(Data.rfind("	#"), Data.length() - Data.rfind("	#"));
	if (Data.length() < 3U)
		return FALSE;

	auto Whitelist = false, Banned = false;
	SSIZE_T Result = 0;
//[Base] block
	if (Data.find("[Base]") == 0 || Data.find("[base]") == 0)
	{
		TempStop = false;
		Local = false;
		return EXIT_SUCCESS;
	}
	else if (Data.find("Version = ") == 0 || Data.find("version = ") == 0)
	{
		if (Data.length() < strlen("Version = ") + 8U)
		{
			double ReadVersion = atof(Data.c_str() + strlen("Version = "));
			if (ReadVersion > HOSTS_VERSION)
			{
				PrintError(LOG_ERROR_HOSTS, L"Hosts file version error", NULL, FileName, Line);
				return EXIT_FAILURE;
			}
		}

		return EXIT_SUCCESS;
	}
	else if (Data.find("Default TTL = ") == 0 || Data.find("Default ttl = ") == 0 || Data.find("default TTL = ") == 0 || Data.find("default ttl = ") == 0)
	{
		if (Data.length() < strlen("Default TTL = ") + 4U)
		{
			Result = strtol(Data.c_str() + strlen("Default TTL = "), nullptr, NULL);
			if (Result > 0 && Result < U8_MAXNUM)
			{
				if (Parameter.HostsDefaultTTL == 0)
				{
					Parameter.HostsDefaultTTL = (uint32_t)Result;
				}
				else if (Parameter.HostsDefaultTTL != (uint32_t)Result)
				{
					PrintError(LOG_ERROR_HOSTS, L"Default TTL redefinition", NULL, FileName, Line);
					return EXIT_FAILURE;
				}
			}
		}

		return EXIT_SUCCESS;
	}

//Main hosts list
	else if (Data.find("[Hosts]") == 0 || Data.find("[hosts]") == 0)
	{
		TempStop = false;
		Local = false;
		return EXIT_SUCCESS;
	}

//Local hosts list
	else if (Data.find("[Local Hosts]") == 0 || Data.find("[Local hosts]") == 0 || Data.find("[local Hosts]") == 0 || Data.find("[local hosts]") == 0)
	{
		if (Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family != NULL || Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family != NULL)
			Local = true;
		
		TempStop = false;
		return EXIT_SUCCESS;
	}

//Temporary stop read.
	else if (Data.find("[Stop]") == 0 || Data.find("[stop]") == 0)
	{
		TempStop = true;
		return EXIT_SUCCESS;
	}
	else if (TempStop)
	{
		return EXIT_SUCCESS;
	}

//Whitelist
	else if (Data.find("NULL ") == 0 || Data.find("NULL	") == 0 || Data.find("NULL,") == 0 || 
			Data.find("Null ") == 0 || Data.find("Null	") == 0 || Data.find("Null,") == 0 || 
			Data.find("null ") == 0 || Data.find("null	") == 0 || Data.find("null,") == 0)
	{
		Whitelist = true;
	}

//Banned list
	else if (Data.find("BAN ") == 0 || Data.find("BAN	") == 0 || Data.find("BAN,") == 0 || 
		Data.find("BANNED ") == 0 || Data.find("BANNED	") == 0 || Data.find("BANNED,") == 0 || 
		Data.find("Ban ") == 0 || Data.find("Ban	") == 0 || Data.find("Ban,") == 0 || 
		Data.find("Banned ") == 0 || Data.find("Banned	") == 0 || Data.find("Banned,") == 0 || 
		Data.find("ban ") == 0 || Data.find("ban	") == 0 || Data.find("ban,") == 0 || 
		Data.find("banned ") == 0 || Data.find("banned	") == 0 || Data.find("banned,") == 0)
	{
		Banned = true;
	}

	std::shared_ptr<char> Addr(new char[ADDR_STRING_MAXSIZE]());
	size_t Separated = 0;

/*
/* Old version(2014-07-16)
	size_t Front = 0, Rear = 0;
	if (Data.find(ASCII_COMMA) != std::string::npos && //Comma-Separated Values/CSV, RFC 4180(https://tools.ietf.org/html/rfc4180), Common Format and MIME Type for Comma-Separated Values (CSV) Files).
		(Data.find(" ,") != std::string::npos || Data.find("	,") != std::string::npos || 
		Data.find(ASCII_HT) != std::string::npos && Data.find(ASCII_HT) > Data.find(ASCII_COMMA) || 
		Data.find(ASCII_SPACE) != std::string::npos && Data.find(ASCII_SPACE) > Data.find(ASCII_COMMA)))
	{
	//Delete space(s) and horizontal tab/HT.
		while (Data.find(ASCII_HT) != std::string::npos)
			Data.erase(Data.find(ASCII_HT), 1U);
		while (Data.find(ASCII_SPACE) != std::string::npos)
			Data.erase(Data.find(ASCII_SPACE), 1U);

/* Old version(2014-06-12)
		while (Data.find(ASCII_HT) != std::string::npos)
			Data.erase(Data.find(ASCII_HT), 1U);
		while (Data.find(ASCII_SPACE) != std::string::npos)
			Data.erase(Data.find(ASCII_SPACE), 1U);
		Front = Data.find(ASCII_COMMA);
		Rear = Front;
		if (Data.find(ASCII_COMMA) == Data.length() - 1U)
		{
			Data.erase(Data.rfind(ASCII_COMMA));
			Front = 0;
			Rear = 0;
		}
		else if (Data.find(ASCII_COMMA) != Data.rfind(ASCII_COMMA))
		{
			Data.erase(Data.rfind(ASCII_COMMA));
		}

	//Mark separated values.
		Separated = Data.find(ASCII_COMMA);
		Data.erase(Data.find(ASCII_COMMA), 1U);
	}
	else if (Data.find(ASCII_COMMA) == std::string::npos || 
		Data.find(ASCII_COMMA) != std::string::npos && (Data.find(ASCII_HT) < Data.find(ASCII_COMMA) || Data.find(ASCII_SPACE) < Data.find(ASCII_COMMA))) //Normal
	{
/* Old version(2014-06-12)
		if (Data.find(ASCII_SPACE) != std::string::npos) //Space
		{
			Front = Data.find(ASCII_SPACE);
			if (Data.rfind(32) > Front)
				Rear = Data.rfind(32);
			else 
				Rear = Front;
		}
		if (Data.find(ASCII_HT) != std::string::npos) //Horizontal Tab/HT
		{
			if (Front == 0)
				Front = Data.find(ASCII_HT);
			else if (Front > Data.find(ASCII_HT))
				Front = Data.find(ASCII_HT);
			if (Data.rfind(9) > Front)
				Rear = Data.rfind(9);
			else 
				Rear = Front;
		}

	//Mark separated values.
		for (Separated = 0;Separated < Data.length();Separated++)
		{
			if (Data[Separated) == 9 || Data[Separated) == 32)
				break;
		}
		
	//Delete space(s) and horizontal tab/HT.
		while (Data.find(ASCII_HT) != std::string::npos)
			Data.erase(Data.find(ASCII_HT), 1U);
		while (Data.find(ASCII_SPACE) != std::string::npos)
			Data.erase(Data.find(ASCII_SPACE), 1U);
	}
	else {
		PrintError(LOG_ERROR_HOSTS, L"Item format error", NULL, FileName, Line);
		return EXIT_FAILURE;
	}
*/

	HostsTable HostsTableTemp;
//Whitelist part
	if (Whitelist || Banned)
	{
	//Mark separated location.
		if (Data.find(ASCII_HT) != std::string::npos && Data.find(ASCII_SPACE) != std::string::npos)
		{
			if (Data.find(ASCII_HT) < Data.find(ASCII_SPACE))
				Separated = Data.find(ASCII_HT);
			else 
				Separated = Data.find(ASCII_SPACE);
		}
		else if (Data.find(ASCII_HT) != std::string::npos)
		{
			Separated = Data.find(ASCII_HT);
		}
		else if (Data.find(ASCII_SPACE) != std::string::npos)
		{
			Separated = Data.find(ASCII_SPACE);
		}
		else {
			PrintError(LOG_ERROR_HOSTS, L"Item format error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}

	//Delete space(s) and horizontal tab/HT.
		while (Data.find(ASCII_HT) != std::string::npos)
			Data.erase(Data.find(ASCII_HT), 1U);
		while (Data.find(ASCII_SPACE) != std::string::npos)
			Data.erase(Data.find(ASCII_SPACE), 1U);

	//Mark patterns
		HostsTableTemp.PatternString.append(Data, Separated, Data.length() - Separated);
		try {
			std::regex PatternHostsTableTemp(HostsTableTemp.PatternString /* , std::regex_constants::extended */ );
			HostsTableTemp.Pattern.swap(PatternHostsTableTemp);
		}
		catch(std::regex_error)
		{
			PrintError(LOG_ERROR_HOSTS, L"Regular expression pattern error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}

	//Check repeating items.
		for (auto HostsTableIter:*HostsListModificating)
		{
			if (HostsTableIter.PatternString == HostsTableTemp.PatternString)
			{
				if (HostsTableIter.Type == HOSTS_NORMAL || HostsTableIter.Type == HOSTS_WHITE && !Whitelist || 
					HostsTableIter.Type == HOSTS_LOCAL || HostsTableIter.Type == HOSTS_BANNED && !Banned)
						PrintError(LOG_ERROR_HOSTS, L"Repeating items error, the item is not available", NULL, FileName, Line);

				return EXIT_FAILURE;
			}
		}

	//Mark types.
		if (Banned)
			HostsTableTemp.Type = HOSTS_BANNED;
		else 
			HostsTableTemp.Type = HOSTS_WHITE;
		HostsListModificating->push_back(HostsTableTemp);
	}

//Main hosts block
	else if (!Local)
	{
	//Delete space(s) and horizontal tab/HT before data.
		while (!Data.empty() && (Data[0] == ASCII_HT || Data[0] == ASCII_SPACE))
			Data.erase(0, 1U);

	//Delete space(s) and horizontal tab/HT before or after vertical(s).
		while (Data.find("	|") != std::string::npos || Data.find("|	") != std::string::npos || 
				Data.find(" |") != std::string::npos || Data.find("| ") != std::string::npos)
		{
			if (Data.find("	|") != std::string::npos)
				Data.erase(Data.find("	|"), 1U);
			if (Data.find("|	") != std::string::npos)
				Data.erase(Data.find("|	") + 1U, 1U);
			if (Data.find(" |") != std::string::npos)
				Data.erase(Data.find(" |"), 1U);
			if (Data.find("| ") != std::string::npos)
				Data.erase(Data.find("| ") + 1U, 1U);
		}

	//Mark separated location.
		if (Data.find(ASCII_COMMA) != std::string::npos)
		{
		//Delete space(s) and horizontal tab/HT before comma(s).
			while (Data.find("	,") != std::string::npos || Data.find(" ,") != std::string::npos)
			{
				if (Data.find("	,") != std::string::npos)
					Data.erase(Data.find("	,"), 1U);
				if (Data.find(" ,") != std::string::npos)
					Data.erase(Data.find(" ,"), 1U);
			}

		//Delete space(s) and horizontal tab/HT after comma(s).
			while (Data.find(ASCII_HT) != std::string::npos && Data.find(ASCII_HT) > Data.find(ASCII_COMMA))
				Data.erase(Data.find(ASCII_HT), 1U);
			while (Data.find(ASCII_SPACE) != std::string::npos && Data.find(ASCII_SPACE) > Data.find(ASCII_COMMA))
				Data.erase(Data.find(ASCII_SPACE), 1U);

		//Common format
			if (Data.find(ASCII_HT) != std::string::npos && Data.find(ASCII_SPACE) != std::string::npos)
			{
				if (Data.find(ASCII_HT) < Data.find(ASCII_SPACE))
					Separated = Data.find(ASCII_HT);
				else 
					Separated = Data.find(ASCII_SPACE);
			}
			else if (Data.find(ASCII_HT) != std::string::npos)
			{
				Separated = Data.find(ASCII_HT);
			}
			else if (Data.find(ASCII_SPACE) != std::string::npos)
			{
				Separated = Data.find(ASCII_SPACE);
			}
		//Comma-Separated Values/CSV, RFC 4180(https://tools.ietf.org/html/rfc4180), Common Format and MIME Type for Comma-Separated Values (CSV) Files).
			else {
				Separated = Data.find(ASCII_COMMA);
				Data.erase(Separated, 1U);
			}
		}
	//Common format
		else {
			if (Data.find(ASCII_HT) != std::string::npos && Data.find(ASCII_SPACE) != std::string::npos)
			{
				if (Data.find(ASCII_HT) < Data.find(ASCII_SPACE))
					Separated = Data.find(ASCII_HT);
				else 
					Separated = Data.find(ASCII_SPACE);
			}
			else if (Data.find(ASCII_HT) != std::string::npos)
			{
				Separated = Data.find(ASCII_HT);
			}
			else if (Data.find(ASCII_SPACE) != std::string::npos)
			{
				Separated = Data.find(ASCII_SPACE);
			}
			else {
				PrintError(LOG_ERROR_HOSTS, L"Item format error", NULL, FileName, Line);
				return EXIT_FAILURE;
			}
		}

	//Delete space(s) and horizontal tab/HT.
		while (Data.find(ASCII_HT) != std::string::npos)
			Data.erase(Data.find(ASCII_HT), 1U);
		while (Data.find(ASCII_SPACE) != std::string::npos)
			Data.erase(Data.find(ASCII_SPACE), 1U);

	//String length check
		if (Separated < 3U) 
			return EXIT_FAILURE;
	
	//Response initialization
		std::shared_ptr<char> BufferHostsTableTemp(new char[PACKET_MAXSIZE]());
		HostsTableTemp.Response.swap(BufferHostsTableTemp);
		BufferHostsTableTemp.reset();
		dns_aaaa_record *pdns_aaaa_rsp = nullptr;
		dns_a_record *pdns_a_rsp = nullptr;

	//Single address
		if (Data.find(ASCII_VERTICAL) == std::string::npos)
		{
		//AAAA Records(IPv6)
			if (Data.find(ASCII_COLON) < Separated)
			{
			//IPv6 addresses check
				if (Separated > ADDR_STRING_MAXSIZE)
				{
					PrintError(LOG_ERROR_HOSTS, L"IPv6 Address format error", NULL, FileName, Line);
					return EXIT_FAILURE;
				}
				else if (Data[0] < ASCII_ZERO || Data[0] > ASCII_COLON && Data[0] < ASCII_UPPERCASE_A || Data[0] > ASCII_UPPERCASE_F && Data[0] < ASCII_LOWERCASE_A || Data[0] > ASCII_LOWERCASE_F)
				{
					return EXIT_FAILURE;
				}

			//Make responses.
				pdns_aaaa_rsp = (dns_aaaa_record *)HostsTableTemp.Response.get();
				pdns_aaaa_rsp->Name = htons(DNS_QUERY_PTR);
				pdns_aaaa_rsp->Classes = htons(DNS_CLASS_IN);
				pdns_aaaa_rsp->TTL = htonl(Parameter.HostsDefaultTTL);
				pdns_aaaa_rsp->Type = htons(DNS_AAAA_RECORDS);
				pdns_aaaa_rsp->Length = htons(sizeof(in6_addr));
			
			//Convert addresses.
				memcpy(Addr.get(), Data.c_str(), Separated);
				if (AddressStringToBinary(Addr.get(), &pdns_aaaa_rsp->Addr, AF_INET6, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_HOSTS, L"IPv6 Address format error", Result, FileName, Line);
					return EXIT_FAILURE;
				}

				HostsTableTemp.Protocol = AF_INET6;
				HostsTableTemp.Length = sizeof(dns_aaaa_record);
			}
		//A Records(IPv4)
			else {
			//IPv4 addresses check
				if (Separated > ADDR_STRING_MAXSIZE)
				{
					PrintError(LOG_ERROR_HOSTS, L"IPv4 Address format error", NULL, FileName, Line);
					return EXIT_FAILURE;
				}
				else if (Data[0] < ASCII_ZERO || Data[0] > ASCII_NINE)
				{
					return EXIT_FAILURE;
				}

			//Make responses.
				pdns_a_rsp = (dns_a_record *)HostsTableTemp.Response.get();
				pdns_a_rsp->Name = htons(DNS_QUERY_PTR);
				pdns_a_rsp->Classes = htons(DNS_CLASS_IN);
				pdns_a_rsp->TTL = htonl(Parameter.HostsDefaultTTL);
				pdns_a_rsp->Type = htons(DNS_A_RECORDS);
				pdns_a_rsp->Length = htons(sizeof(in_addr));
			
			//Convert addresses.
				memcpy(Addr.get(), Data.c_str(), Separated);
				if (AddressStringToBinary(Addr.get(), &pdns_a_rsp->Addr, AF_INET, Result) == EXIT_FAILURE)
				{
					PrintError(LOG_ERROR_HOSTS, L"IPv4 Address format error", Result, FileName, Line);
					return EXIT_FAILURE;
				}

				HostsTableTemp.Protocol = AF_INET;
				HostsTableTemp.Length = sizeof(dns_a_record);
			}
		}
	//Multiple Addresses
		else {
			size_t Index = 0, VerticalIndex = 0;

		//AAAA Records(IPv6)
			if (Data.find(ASCII_COLON) < Separated)
			{
			//IPv6 addresses check
				if (Data[0] < ASCII_ZERO || Data[0] > ASCII_COLON && Data[0] < ASCII_UPPERCASE_A || Data[0] > ASCII_UPPERCASE_F && Data[0] < ASCII_LOWERCASE_A || Data[0] > ASCII_LOWERCASE_F)
					return EXIT_FAILURE;

				HostsTableTemp.Protocol = AF_INET6;
				for (Index = 0;Index <= Separated;Index++)
				{
				//Read data.
					if (Data[Index] == ASCII_VERTICAL || Index == Separated)
					{
					//Length check
						if (HostsTableTemp.Length + sizeof(dns_aaaa_record) > PACKET_MAXSIZE)
						{
							PrintError(LOG_ERROR_HOSTS, L"Too many Hosts IP addresses", NULL, FileName, Line);
							return EXIT_FAILURE;
						}
						else if (Index - VerticalIndex > ADDR_STRING_MAXSIZE)
						{
							PrintError(LOG_ERROR_HOSTS, L"IPv6 Address format error", NULL, FileName, Line);
							return EXIT_FAILURE;
						}

					//Make responses
						pdns_aaaa_rsp = (dns_aaaa_record *)(HostsTableTemp.Response.get() + HostsTableTemp.Length);
						pdns_aaaa_rsp->Name = htons(DNS_QUERY_PTR);
						pdns_aaaa_rsp->Classes = htons(DNS_CLASS_IN);
						pdns_aaaa_rsp->TTL = htonl(Parameter.HostsDefaultTTL);
						pdns_aaaa_rsp->Type = htons(DNS_AAAA_RECORDS);
						pdns_aaaa_rsp->Length = htons(sizeof(in6_addr));

					//Convert addresses.
						memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
						memcpy(Addr.get(), Data.c_str() + VerticalIndex, Index - VerticalIndex);
						if (AddressStringToBinary(Addr.get(), &pdns_aaaa_rsp->Addr, AF_INET6, Result) == EXIT_FAILURE)
						{
							PrintError(LOG_ERROR_HOSTS, L"IPv6 Address format error", Result, FileName, Line);
							return EXIT_FAILURE;
						}

						HostsTableTemp.Length += sizeof(dns_aaaa_record);
						VerticalIndex = Index + 1U;
					}
				}
			}
		//A Records(IPv4)
			else {
			//IPv4 addresses check
				if (Data[0] < ASCII_ZERO || Data[0] > ASCII_NINE)
					return EXIT_FAILURE;

				HostsTableTemp.Protocol = AF_INET;
				for (Index = 0;Index <= Separated;Index++)
				{
				//Read data.
					if (Data[Index] == ASCII_VERTICAL || Index == Separated)
					{
					//Length check
						if (HostsTableTemp.Length + sizeof(dns_a_record) > PACKET_MAXSIZE)
						{
							PrintError(LOG_ERROR_HOSTS, L"Too many Hosts IP addresses", NULL, FileName, Line);
							return EXIT_FAILURE;
						}
						else if (Index - VerticalIndex > ADDR_STRING_MAXSIZE)
						{
							PrintError(LOG_ERROR_HOSTS, L"IPv4 Address format error", NULL, FileName, Line);
							return EXIT_FAILURE;
						}

					//Make responses.
						pdns_a_rsp = (dns_a_record *)(HostsTableTemp.Response.get() + HostsTableTemp.Length);
						pdns_a_rsp->Name = htons(DNS_QUERY_PTR);
						pdns_a_rsp->Classes = htons(DNS_CLASS_IN);
						pdns_a_rsp->TTL = htonl(Parameter.HostsDefaultTTL);
						pdns_a_rsp->Type = htons(DNS_A_RECORDS);
						pdns_a_rsp->Length = htons(sizeof(in_addr));

					//Convert addresses.
						memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
						memcpy(Addr.get(), Data.c_str() + VerticalIndex, Index - VerticalIndex);
						if (AddressStringToBinary(Addr.get(), &pdns_a_rsp->Addr, AF_INET, Result) == EXIT_FAILURE)
						{
							PrintError(LOG_ERROR_HOSTS, L"IPv4 Address format error", Result, FileName, Line);
							return EXIT_FAILURE;
						}

						HostsTableTemp.Length += sizeof(dns_a_record);
						VerticalIndex = Index + 1U;
					}
				}
			}
		}

	//Mark patterns.
		HostsTableTemp.PatternString.append(Data, Separated, Data.length() - Separated);
		try {
			std::regex PatternHostsTableTemp(HostsTableTemp.PatternString /* , std::regex_constants::extended */ );
			HostsTableTemp.Pattern.swap(PatternHostsTableTemp);
		}
		catch (std::regex_error)
		{
			PrintError(LOG_ERROR_HOSTS, L"Regular expression pattern error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}

	//Check repeating items.
		for (auto HostsListIter = HostsListModificating->begin();HostsListIter != HostsListModificating->end();HostsListIter++)
		{
			if (HostsListIter->PatternString == HostsTableTemp.PatternString)
			{
				if (HostsListIter->Type != HOSTS_NORMAL || HostsListIter->Protocol == 0)
				{
					PrintError(LOG_ERROR_HOSTS, L"Repeating items error, the item is not available", NULL, FileName, Line);
					return EXIT_FAILURE;
				}
				else {
					if (HostsListIter->Protocol == HostsTableTemp.Protocol)
					{
						if (HostsListIter->Length + HostsTableTemp.Length < PACKET_MAXSIZE)
						{
							memcpy(HostsListIter->Response.get() + HostsListIter->Length, HostsTableTemp.Response.get(), HostsTableTemp.Length);
							HostsListIter->Length += HostsTableTemp.Length;
						}

						return EXIT_SUCCESS;
					}
					else {
						continue;
					}
				}
			}
		}

	//Add to global HostsTable.
		if (HostsTableTemp.Length >= sizeof(dns_qry) + sizeof(in_addr)) //Shortest reply is a A Records with Question part
			HostsListModificating->push_back(HostsTableTemp);
	}

//[Local hosts] block
	else if (Local && (Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family != NULL || Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family != NULL))
	{
	//Local Main mode
		if (Parameter.LocalMain)
			return EXIT_SUCCESS;

	//Delete space(s) and horizontal tab/HT.
		while (Data.find(ASCII_HT) != std::string::npos)
			Data.erase(Data.find(ASCII_HT), 1U);
		while (Data.find(ASCII_SPACE) != std::string::npos)
			Data.erase(Data.find(ASCII_SPACE), 1U);

	//Mark patterns.
		HostsTableTemp.PatternString = Data;
		try {
			std::regex PatternHostsTableTemp(HostsTableTemp.PatternString /* , std::regex_constants::extended */ );
			HostsTableTemp.Pattern.swap(PatternHostsTableTemp);
		}
		catch(std::regex_error)
		{
			PrintError(LOG_ERROR_HOSTS, L"Regular expression pattern error", NULL, FileName, Line);
			return EXIT_FAILURE;
		}

	//Check repeating items.
		for (auto HostsTableIter:*HostsListModificating)
		{
			if (HostsTableIter.PatternString == HostsTableTemp.PatternString)
			{
				if (HostsTableIter.Type != HOSTS_LOCAL)
					PrintError(LOG_ERROR_HOSTS, L"Repeating items error, the item is not available", NULL, FileName, Line);

				return EXIT_FAILURE;
			}
		}

	//Mark types.
		HostsTableTemp.Type = HOSTS_LOCAL;
		HostsListModificating->push_back(HostsTableTemp);
	}

	return EXIT_SUCCESS;
}

/* Old version(2014-07-03)
//Read encoding of file
inline bool __fastcall ReadNextLineType(const PSTR Buffer, const size_t Length, size_t &Encoding, size_t &NextLineType)
{
//Read next line type.
	for (size_t Index = 0;Index < Length - 1U;Index++)
	{
		if (Buffer[Index] == ASCII_CR && Buffer[Index + 1U] == ASCII_LF)
		{
			NextLineType = NEXTLINETYPE_CRLF;
			return true;
		}
		else if (Buffer[Index] == ASCII_LF)
		{
			NextLineType = NEXTLINETYPE_LF;
			return true;
		}
		else if (Buffer[Index] == ASCII_CR)
		{
			NextLineType = NEXTLINETYPE_CR;
			return true;
		}
	}

	for (size_t Index = 4U;Index < Length - 3U;Index++)
	{
		if (Buffer[Index] == ASCII_LF && 
			((Encoding == ANSI || Encoding == UTF_8) && Buffer[Index - 1U] == ASCII_CR || 
			(Encoding == UTF_16_LE || Encoding == UTF_16_BE) && Buffer[Index - 2U] == ASCII_CR || 
			(Encoding == UTF_32_LE || Encoding == UTF_32_BE) && Buffer[Index - 4U] == ASCII_CR))
		{
			NextLineType = NEXTLINETYPE_CRLF;
			return;
		}
		else if (Buffer[Index] == ASCII_LF && 
			((Encoding == ANSI || Encoding == UTF_8) && Buffer[Index - 1U] != ASCII_CR || 
			(Encoding == UTF_16_LE || Encoding == UTF_16_BE) && Buffer[Index - 2U] != ASCII_CR || 
			(Encoding == UTF_32_LE || Encoding == UTF_32_BE) && Buffer[Index - 4U] != ASCII_CR))
		{
			NextLineType = NEXTLINETYPE_LF;
			return;
		}
		else if (Buffer[Index] == ASCII_CR && 
			((Encoding == ANSI || Encoding == UTF_8) && Buffer[Index + 1U] != ASCII_LF || 
			(Encoding == UTF_16_LE || Encoding == UTF_16_BE) && Buffer[Index + 2U] != ASCII_LF || 
			(Encoding == UTF_32_LE || Encoding == UTF_32_BE) && Buffer[Index + 4U] != ASCII_LF))
		{
			NextLineType = NEXTLINETYPE_CR;
			return;
		}
	}

//8-bit Unicode Transformation Format/UTF-8 with BOM
	if (Buffer[0] == 0xFFFFFFEF && Buffer[1U] == 0xFFFFFFBB && Buffer[2U] == 0xFFFFFFBF) //0xEF, 0xBB, 0xBF(Unsigned char)
		Encoding = UTF_8;
//32-bit Unicode Transformation Format/UTF-32 Little Endian/LE
	else if (Buffer[0] == 0xFFFFFFFF && Buffer[1U] == 0xFFFFFFFE && Buffer[2U] == 0 && Buffer[3U] == 0) //0xFF, 0xFE, 0x00, 0x00(Unsigned char)
		Encoding = UTF_32_LE;
//32-bit Unicode Transformation Format/UTF-32 Big Endian/BE
	else if (Buffer[0] == 0 && Buffer[1U] == 0 && Buffer[2U] == 0xFFFFFFFE && Buffer[3U] == 0xFFFFFFFF) //0x00, 0x00, 0xFE, 0xFF(Unsigned char)
		Encoding = UTF_32_BE;
//16-bit Unicode Transformation Format/UTF-16 Little Endian/LE
	else if (Buffer[0] == 0xFFFFFFFF && Buffer[1U] == 0xFFFFFFFE) //0xFF, 0xFE(Unsigned char)
		Encoding = UTF_16_LE;
//16-bit Unicode Transformation Format/UTF-16 Big Endian/BE
	else if (Buffer[0] == 0xFFFFFFFE && Buffer[1U] == 0xFFFFFFFF) //0xFE, 0xFF(Unsigned char)
		Encoding = UTF_16_BE;
//8-bit Unicode Transformation Format/UTF-8 without BOM/Microsoft Windows ANSI Codepages
	else 
		Encoding = ANSI;
	return false;
}
*/

//Compare two addresses
inline size_t __fastcall CompareAddresses(const void *vAddrBegin, const void *vAddrEnd, const uint16_t Protocol)
{
	if (Protocol == AF_INET6) //IPv6
	{
		auto AddrBegin = (in6_addr *)vAddrBegin, AddrEnd = (in6_addr *)vAddrEnd;
		for (size_t Index = 0;Index < sizeof(in6_addr) / sizeof(uint16_t);Index++)
		{
			if (ntohs(AddrBegin->u.Word[Index]) > ntohs(AddrEnd->u.Word[Index]))
			{
				return ADDRESS_COMPARE_GREATER;
			}
			else if (AddrBegin->u.Word[Index] == AddrEnd->u.Word[Index])
			{
				if (Index == sizeof(in6_addr) / sizeof(uint16_t) - 1U)
					return ADDRESS_COMPARE_EQUAL;
				else 
					continue;
			}
			else {
				return ADDRESS_COMPARE_LESS;
			}
		}
	}
	else { //IPv4
		auto AddrBegin = (in_addr *)vAddrBegin, AddrEnd = (in_addr *)vAddrEnd;
		if (AddrBegin->S_un.S_un_b.s_b1 > AddrEnd->S_un.S_un_b.s_b1)
		{
			return ADDRESS_COMPARE_GREATER;
		}
		else if (AddrBegin->S_un.S_un_b.s_b1 == AddrEnd->S_un.S_un_b.s_b1)
		{
			if (AddrBegin->S_un.S_un_b.s_b2 > AddrEnd->S_un.S_un_b.s_b2)
			{
				return ADDRESS_COMPARE_GREATER;
			}
			else if (AddrBegin->S_un.S_un_b.s_b2 == AddrEnd->S_un.S_un_b.s_b2)
			{
				if (AddrBegin->S_un.S_un_b.s_b3 > AddrEnd->S_un.S_un_b.s_b3)
				{
					return ADDRESS_COMPARE_GREATER;
				}
				else if (AddrBegin->S_un.S_un_b.s_b3 == AddrEnd->S_un.S_un_b.s_b3)
				{
					if (AddrBegin->S_un.S_un_b.s_b4 > AddrEnd->S_un.S_un_b.s_b4)
						return ADDRESS_COMPARE_GREATER;
					else if (AddrBegin->S_un.S_un_b.s_b4 == AddrEnd->S_un.S_un_b.s_b4)
						return ADDRESS_COMPARE_EQUAL;
					else 
						return ADDRESS_COMPARE_LESS;
				}
				else {
					return ADDRESS_COMPARE_LESS;
				}
			}
			else {
				return ADDRESS_COMPARE_LESS;
			}
		}
		else {
			return ADDRESS_COMPARE_LESS;
		}
	}

	return EXIT_SUCCESS;
}

/*
//Convert hex characters to binary.
inline size_t __fastcall HexToBinary(PUINT8 Binary, const PSTR Buffer, const size_t Length)
{
	std::shared_ptr<char> Hex(new char[FILE_BUFFER_SIZE]());
//Delete colons.
	size_t Index = 0, NowLength = 0, MaxLength = 0;
	uint8_t BinaryChar[] = {0, 0, 0};
	for (Index = 0;Index < Length;Index++)
	{
		if (Buffer[Index] != ASCII_COLON)
		{
			Hex.get()[NowLength] = Buffer[Index];
			NowLength++;
		}
	}

	MaxLength = NowLength;
	for (Index = 0, NowLength = 0;Index < MaxLength;Index++)
	{
		memcpy(BinaryChar, Hex.get() + Index, sizeof(uint8_t) * 2U);
		Binary[NowLength] = (uint8_t)strtol((PSTR)&BinaryChar, NULL, NUM_HEX);
		Index++;
		NowLength++;
	}

	return NowLength;
}
*/

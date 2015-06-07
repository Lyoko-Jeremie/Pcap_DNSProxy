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
	auto CRLF_Point = false, IsEraseBOM = true, IsLabelComments = false;

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
				if (InputType == READ_TEXT_HOSTS) //ReadHosts
					PrintError(LOG_ERROR_HOSTS, L"Data of a line is too short", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
				else if (InputType == READ_TEXT_IPFILTER) //ReadIPFilter
					PrintError(LOG_ERROR_IPFILTER, L"Data of a line is too short", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
				else //ReadParameter
					PrintError(LOG_ERROR_PARAMETER, L"Data of a line is too short", 0, ConfigFileList.at(FileIndex).c_str(), Line);

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
				if (!CRLF_Point && (FileBuffer.get()[Index] == ASCII_CR || FileBuffer.get()[Index] == ASCII_LF))
					CRLF_Point = true;

				TextBuffer.get()[TextBufferLength] = FileBuffer.get()[Index];
				++TextBufferLength;
			}
		}

	//Lines length check
		if (!CRLF_Point && ReadLength == FILE_BUFFER_SIZE)
		{
			if (InputType == READ_TEXT_HOSTS) //ReadHosts
				PrintError(LOG_ERROR_HOSTS, L"Data of a line is too long", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
			else if (InputType == READ_TEXT_IPFILTER) //ReadIPFilter
				PrintError(LOG_ERROR_IPFILTER, L"Data of a line is too long", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
			else //ReadParameter
				PrintError(LOG_ERROR_PARAMETER, L"Data of a line is too long", 0, ConfigFileList.at(FileIndex).c_str(), Line);

			return false;
		}
		else {
			CRLF_Point = false;
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
					if (InputType == READ_TEXT_HOSTS)
					{
						ReadHostsData(TextData.get(), FileIndex, Line, LabelType, IsLabelComments);
					}
				//ReadIPFilter
					else if (InputType == READ_TEXT_IPFILTER)
					{
						ReadIPFilterData(TextData.get(), FileIndex, Line, LabelType, IsLabelComments);
					}
				//ReadParameter
					else {
						if (!ReadParameterData(TextData.get(), FileIndex, Line, IsLabelComments))
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
					if (InputType == READ_TEXT_HOSTS)
					{
						ReadHostsData(TextData.get(), FileIndex, Line, LabelType, IsLabelComments);
					}
				//ReadIPFilter
					else if (InputType == READ_TEXT_IPFILTER)
					{
						ReadIPFilterData(TextData.get(), FileIndex, Line, LabelType, IsLabelComments);
					}
				//ReadParameter
					else {
						if (!ReadParameterData(TextData.get(), FileIndex, Line, IsLabelComments))
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
					if (InputType == READ_TEXT_HOSTS)
					{
						ReadHostsData(TextData.get(), FileIndex, Line, LabelType, IsLabelComments);
					}
				//ReadIPFilter
					else if (InputType == READ_TEXT_IPFILTER)
					{
						ReadIPFilterData(TextData.get(), FileIndex, Line, LabelType, IsLabelComments);
					}
				//ReadParameter
					else {
						if (!ReadParameterData(TextData.get(), FileIndex, Line, IsLabelComments))
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
bool __fastcall ReadMultiLineComments(const char *Buffer, std::string &Data, bool &IsLabelComments)
{
	if (IsLabelComments)
	{
		if (Data.find("*/") != std::string::npos)
		{
			Data = Buffer + Data.find("*/") + strlen("*/");
			IsLabelComments = false;
		}
		else {
			return false;
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
			Data.erase(Data.find("/*"), Data.find("*/") - Data.find("/*") + strlen("/*"));
		}
	}

	return true;
}

//Read parameter from file
bool __fastcall ReadParameter(void)
{
//Initialization
	FILE *Input = nullptr;
	size_t Index = 0;

//Open file.
	std::wstring ConfigFileName(Parameter.Path_Global->front());
#if defined(PLATFORM_WIN)
	ConfigFileName.append(L"Config.ini");
	ConfigFileList.push_back(ConfigFileName);
	ConfigFileName = Parameter.Path_Global->front();
	ConfigFileName.append(L"Config.conf");
	ConfigFileList.push_back(ConfigFileName);
	ConfigFileName = Parameter.Path_Global->front();
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	ConfigFileName.append(L"Config.conf");
	ConfigFileList.push_back(ConfigFileName);
	ConfigFileName = Parameter.Path_Global->front();
	ConfigFileName.append(L"Config.ini");
	ConfigFileList.push_back(ConfigFileName);
	ConfigFileName = Parameter.Path_Global->front();
#endif
	ConfigFileName.append(L"Config.cfg");
	ConfigFileList.push_back(ConfigFileName);
	ConfigFileName = Parameter.Path_Global->front();
	ConfigFileName.append(L"Config");
	ConfigFileList.push_back(ConfigFileName);
	ConfigFileName.clear();
	ConfigFileName.shrink_to_fit();
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	std::string sConfigFileName(Parameter.sPath_Global->front());
	sConfigFileName.append("Config.conf");
	sConfigFileList.push_back(sConfigFileName);
	sConfigFileName = Parameter.sPath_Global->front();
	sConfigFileName.append("Config.ini");
	sConfigFileList.push_back(sConfigFileName);
	sConfigFileName = Parameter.sPath_Global->front();
	sConfigFileName.append("Config.cfg");
	sConfigFileList.push_back(sConfigFileName);
	sConfigFileName = Parameter.sPath_Global->front();
	sConfigFileName.append("Config");
	sConfigFileList.push_back(sConfigFileName);
	sConfigFileName.clear();
	sConfigFileName.shrink_to_fit();
#endif
	for (Index = 0;Index < ConfigFileList.size();++Index)
	{
	#if defined(PLATFORM_WIN)
		if (_wfopen_s(&Input, ConfigFileList.at(Index).c_str(), L"rb") != 0 || Input == nullptr)
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		Input = fopen(sConfigFileList.at(Index).c_str(), "rb");
		if (Input == nullptr)
	#endif
		{
		//Check all configuration files.
			if (Index + 1U == ConfigFileList.size())
			{
				PrintError(LOG_ERROR_PARAMETER, L"Cannot open any configuration files", 0, nullptr, 0);
				return false;
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
	if (GetFileAttributesExW(ConfigFileList.at(Index).c_str(), GetFileExInfoStandard, File_WIN32_FILE_ATTRIBUTE_DATA.get()) != FALSE)
	{
		std::shared_ptr<LARGE_INTEGER> ConfigFileSize(new LARGE_INTEGER());
		memset(ConfigFileSize.get(), 0, sizeof(LARGE_INTEGER));
		ConfigFileSize->HighPart = File_WIN32_FILE_ATTRIBUTE_DATA->nFileSizeHigh;
		ConfigFileSize->LowPart = File_WIN32_FILE_ATTRIBUTE_DATA->nFileSizeLow;
		if (ConfigFileSize->QuadPart >= DEFAULT_FILE_MAXSIZE)
		{
			PrintError(LOG_ERROR_PARAMETER, L"Configuration file is too large", 0, ConfigFileList.at(Index).c_str(), 0);
			return false;
		}
	}

	File_WIN32_FILE_ATTRIBUTE_DATA.reset();
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	std::shared_ptr<struct stat> FileStat(new struct stat());
	memset(FileStat.get(), 0, sizeof(struct stat));
	if (stat(sConfigFileList.at(Index).c_str(), FileStat.get()) == 0 && FileStat->st_size >= (off_t)DEFAULT_FILE_MAXSIZE)
	{
		PrintError(LOG_ERROR_PARAMETER, L"Configuration file is too large", 0, ConfigFileList.at(Index).c_str(), 0);
		return false;
	}

	FileStat.reset();
#endif

//Read data.
	if (Input != nullptr)
	{
		if (!ReadText(Input, READ_TEXT_PARAMETER, Index))
			return false;
		fclose(Input);
	}
	else {
		PrintError(LOG_ERROR_PARAMETER, L"Cannot open any configuration files", 0, nullptr, 0);
		return false;
	}

//Check parameter list and set default values.
	return ParameterCheckAndSetting(Index);
}

//Read IPFilter from file
void __fastcall ReadIPFilter(void)
{
//Create file list.
	for (size_t Index = 0;Index < Parameter.Path_Global->size();++Index)
	{
		for (size_t InnerIndex = 0;InnerIndex < Parameter.FileList_IPFilter->size();++InnerIndex)
		{
			FILE_DATA FileDataTemp;
			FileDataTemp.FileName.clear();
		#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			FileDataTemp.sFileName.clear();
		#endif
			FileDataTemp.ModificationTime = 0;

		//Add to global list.
			FileDataTemp.FileName.append(Parameter.Path_Global->at(Index));
			FileDataTemp.FileName.append(Parameter.FileList_IPFilter->at(InnerIndex));
		#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			FileDataTemp.sFileName.append(Parameter.sPath_Global->at(Index));
			FileDataTemp.sFileName.append(Parameter.sFileList_IPFilter->at(InnerIndex));
		#endif
			FileList_IPFilter.push_back(FileDataTemp);
		}
	}

//Files Monitor
	FILE *Input = nullptr;
	size_t FileIndex = 0;
	auto IsFileModified = false, IsLocalServerPrint = false;
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
		for (FileIndex = 0;FileIndex < FileList_IPFilter.size();++FileIndex)
		{
		//Get attributes of file.
		#if defined(PLATFORM_WIN)
			if (GetFileAttributesExW(FileList_IPFilter.at(FileIndex).FileName.c_str(), GetFileExInfoStandard, File_WIN32_FILE_ATTRIBUTE_DATA.get()) == FALSE)
			{
				memset(File_WIN32_FILE_ATTRIBUTE_DATA.get(), 0, sizeof(WIN32_FILE_ATTRIBUTE_DATA));
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			if (stat(FileList_IPFilter.at(FileIndex).sFileName.c_str(), FileStat.get()) != 0)
			{
				memset(FileStat.get(), 0, sizeof(struct stat));
		#endif
				if (FileList_IPFilter.at(FileIndex).ModificationTime > 0)
					IsFileModified = true;
				FileList_IPFilter.at(FileIndex).ModificationTime = 0;

				ClearListData(READ_TEXT_IPFILTER, FileIndex);
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
					PrintError(LOG_ERROR_PARAMETER, L"IPFilter file size is too large", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), 0);

				#if defined(PLATFORM_WIN)
					memset(File_WIN32_FILE_ATTRIBUTE_DATA.get(), 0, sizeof(WIN32_FILE_ATTRIBUTE_DATA));
					memset(File_LARGE_INTEGER.get(), 0, sizeof(LARGE_INTEGER));
				#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
					memset(FileStat.get(), 0, sizeof(struct stat));
				#endif
					if (FileList_IPFilter.at(FileIndex).ModificationTime > 0)
						IsFileModified = true;
					FileList_IPFilter.at(FileIndex).ModificationTime = 0;

					ClearListData(READ_TEXT_IPFILTER, FileIndex);
					continue;
				}

			//Check modification time of file.
			#if defined(PLATFORM_WIN)
				memset(File_LARGE_INTEGER.get(), 0, sizeof(LARGE_INTEGER));
				File_LARGE_INTEGER->HighPart = File_WIN32_FILE_ATTRIBUTE_DATA->ftLastWriteTime.dwHighDateTime;
				File_LARGE_INTEGER->LowPart = File_WIN32_FILE_ATTRIBUTE_DATA->ftLastWriteTime.dwLowDateTime;
				if (FileList_IPFilter.at(FileIndex).ModificationTime == 0 || File_LARGE_INTEGER->QuadPart != FileList_IPFilter.at(FileIndex).ModificationTime)
				{
					FileList_IPFilter.at(FileIndex).ModificationTime = File_LARGE_INTEGER->QuadPart;
					memset(File_WIN32_FILE_ATTRIBUTE_DATA.get(), 0, sizeof(WIN32_FILE_ATTRIBUTE_DATA));
					memset(File_LARGE_INTEGER.get(), 0, sizeof(LARGE_INTEGER));
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				if (FileList_IPFilter.at(FileIndex).ModificationTime == 0 || FileStat->st_mtime != FileList_IPFilter.at(FileIndex).ModificationTime)
				{
					FileList_IPFilter.at(FileIndex).ModificationTime = FileStat->st_mtime;
					memset(FileStat.get(), 0, sizeof(struct stat));
			#endif
					ClearListData(READ_TEXT_IPFILTER, FileIndex);
					IsFileModified = true;

				//Read file.
				#if defined(PLATFORM_WIN)
					if (_wfopen_s(&Input, FileList_IPFilter.at(FileIndex).FileName.c_str(), L"rb") == 0)
					{
				#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
					Input = fopen(FileList_IPFilter.at(FileIndex).sFileName.c_str(), "rb");
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
							ReadText(Input, READ_TEXT_IPFILTER, FileIndex);
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

	//Check local routing of local servers.
		if (!IsLocalServerPrint)
		{
		//Check local routing list(IPv6).
			for (auto IPFilterFileSetIter:*IPFilterFileSetModificating)
			{
				for (auto LocalRoutingTableIter:IPFilterFileSetIter.LocalRoutingList_IPv6)
				{
					IsLocalServerPrint = true;
					break;
				}
			}

		//Check local servers(IPv6).
			if (IsLocalServerPrint)
			{
				if (Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family > 0 && !CheckAddressRouting(&Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_addr, AF_INET6))
					PrintError(LOG_MESSAGE_NOTICE, L"Address of IPv6 Main Local Server is not in Local Routing list", 0, nullptr, 0);
				if (Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family > 0 && !CheckAddressRouting(&Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6.sin6_addr, AF_INET6))
					PrintError(LOG_MESSAGE_NOTICE, L"Address of IPv6 Alternate Local Server is not in Local Routing list", 0, nullptr, 0);
			}

			IsLocalServerPrint = false;

		//Check local routing list(IPv4).
			for (auto IPFilterFileSetIter:*IPFilterFileSetModificating)
			{
				for (auto LocalRoutingTableIter:IPFilterFileSetIter.LocalRoutingList_IPv4)
				{
					IsLocalServerPrint = true;
					break;
				}
			}

		//Check local servers(IPv4).
			if (IsLocalServerPrint)
			{
				if (Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family > 0 && !CheckAddressRouting(&Parameter.DNSTarget.Local_IPv4.AddressData.IPv4.sin_addr, AF_INET))
					PrintError(LOG_MESSAGE_NOTICE, L"Address of IPv4 Main Local Server is not in Local Routing list", 0, nullptr, 0);
				if (Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage.ss_family > 0 && !CheckAddressRouting(&Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.IPv4.sin_addr, AF_INET))
					PrintError(LOG_MESSAGE_NOTICE, L"Address of IPv4 Alternate Local Server is not in Local Routing list", 0, nullptr, 0);
			}

			IsLocalServerPrint = true;
		}

	//Flush DNS cache and Auto-refresh
		FlushAllDNSCache();
		Sleep(Parameter.FileRefreshTime);
	}

	PrintError(LOG_ERROR_SYSTEM, L"Read IPFilter module Monitor terminated", 0, nullptr, 0);
	return;
}

//Read hosts from file
void __fastcall ReadHosts(void)
{
//Create file list.
	for (size_t Index = 0;Index < Parameter.Path_Global->size();++Index)
	{
		for (size_t InnerIndex = 0;InnerIndex < Parameter.FileList_Hosts->size();++InnerIndex)
		{
			FILE_DATA FileDataTemp;
			FileDataTemp.FileName.clear();
		#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			FileDataTemp.sFileName.clear();
		#endif
			FileDataTemp.ModificationTime = 0;

		//Add to global list.
			FileDataTemp.FileName.append(Parameter.Path_Global->at(Index));
			FileDataTemp.FileName.append(Parameter.FileList_Hosts->at(InnerIndex));
		#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			FileDataTemp.sFileName.append(Parameter.sPath_Global->at(Index));
			FileDataTemp.sFileName.append(Parameter.sFileList_Hosts->at(InnerIndex));
		#endif
			FileList_Hosts.push_back(FileDataTemp);
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
		for (FileIndex = 0;FileIndex < FileList_Hosts.size();++FileIndex)
		{
		//Get attributes of file.
		#if defined(PLATFORM_WIN)
			if (GetFileAttributesExW(FileList_Hosts.at(FileIndex).FileName.c_str(), GetFileExInfoStandard, File_WIN32_FILE_ATTRIBUTE_DATA.get()) == FALSE)
			{
				memset(File_WIN32_FILE_ATTRIBUTE_DATA.get(), 0, sizeof(WIN32_FILE_ATTRIBUTE_DATA));
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			if (stat(FileList_Hosts.at(FileIndex).sFileName.c_str(), FileStat.get()) != 0)
			{
				memset(FileStat.get(), 0, sizeof(struct stat));
		#endif
				if (FileList_Hosts.at(FileIndex).ModificationTime > 0)
					IsFileModified = true;
				FileList_Hosts.at(FileIndex).ModificationTime = 0;

				ClearListData(READ_TEXT_HOSTS, FileIndex);
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
					PrintError(LOG_ERROR_PARAMETER, L"Hosts file size is too large", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), 0);

				#if defined(PLATFORM_WIN)
					memset(File_WIN32_FILE_ATTRIBUTE_DATA.get(), 0, sizeof(WIN32_FILE_ATTRIBUTE_DATA));
					memset(File_LARGE_INTEGER.get(), 0, sizeof(LARGE_INTEGER));
				#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
					memset(FileStat.get(), 0, sizeof(struct stat));
				#endif
					if (FileList_Hosts.at(FileIndex).ModificationTime > 0)
						IsFileModified = true;
					FileList_Hosts.at(FileIndex).ModificationTime = 0;

					ClearListData(READ_TEXT_HOSTS, FileIndex);
					continue;
				}

			//Check modification time of file.
			#if defined(PLATFORM_WIN)
				memset(File_LARGE_INTEGER.get(), 0, sizeof(LARGE_INTEGER));
				File_LARGE_INTEGER->HighPart = File_WIN32_FILE_ATTRIBUTE_DATA->ftLastWriteTime.dwHighDateTime;
				File_LARGE_INTEGER->LowPart = File_WIN32_FILE_ATTRIBUTE_DATA->ftLastWriteTime.dwLowDateTime;
				if (FileList_Hosts.at(FileIndex).ModificationTime == 0 || File_LARGE_INTEGER->QuadPart != FileList_Hosts.at(FileIndex).ModificationTime)
				{
					FileList_Hosts.at(FileIndex).ModificationTime = File_LARGE_INTEGER->QuadPart;
					memset(File_WIN32_FILE_ATTRIBUTE_DATA.get(), 0, sizeof(WIN32_FILE_ATTRIBUTE_DATA));
					memset(File_LARGE_INTEGER.get(), 0, sizeof(LARGE_INTEGER));
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				if (FileList_Hosts.at(FileIndex).ModificationTime == 0 || FileStat->st_mtime != FileList_Hosts.at(FileIndex).ModificationTime)
				{
					FileList_Hosts.at(FileIndex).ModificationTime = FileStat->st_mtime;
					memset(FileStat.get(), 0, sizeof(struct stat));
			#endif
					ClearListData(READ_TEXT_HOSTS, FileIndex);
					IsFileModified = true;

				//Read file.
				#if defined(PLATFORM_WIN)
					if (_wfopen_s(&Input, FileList_Hosts.at(FileIndex).FileName.c_str(), L"rb") == 0)
					{
				#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
					Input = fopen(FileList_Hosts.at(FileIndex).sFileName.c_str(), "rb");
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
							ReadText(Input, READ_TEXT_HOSTS, FileIndex);
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

	//EDNS Lebal
		if (Parameter.EDNS_Label)
		{
			pdns_record_opt DNS_Record_OPT = nullptr;
			for (auto &HostsFileSetIter:*HostsFileSetModificating)
			{
				for (auto &HostsListIter:HostsFileSetIter.HostsList)
				{
					if (HostsListIter.Length + sizeof(dns_record_opt) >= PACKET_MAXSIZE)
					{
						PrintError(LOG_ERROR_HOSTS, L"Data is too long when EDNS is available", 0, nullptr, 0);
						continue;
					}
					else if (!HostsListIter.Response)
					{
						continue;
					}
					else {
						DNS_Record_OPT = (pdns_record_opt)(HostsListIter.Response.get() + HostsListIter.Length);
						DNS_Record_OPT->Type = htons(DNS_RECORD_OPT);
						DNS_Record_OPT->UDPPayloadSize = htons((uint16_t)Parameter.EDNSPayloadSize);
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
		FlushAllDNSCache();
		Sleep(Parameter.FileRefreshTime);
	}

	PrintError(LOG_ERROR_SYSTEM, L"Read Hosts module Monitor terminated", 0, nullptr, 0);
	return;
}

//Clear data in list
void __fastcall ClearListData(const size_t ClearType, const size_t FileIndex)
{
//Clear Hosts set.
	if (ClearType == READ_TEXT_HOSTS)
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
	else if (ClearType == READ_TEXT_IPFILTER)
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

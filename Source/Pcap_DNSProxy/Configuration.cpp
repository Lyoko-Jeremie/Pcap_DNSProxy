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
bool __fastcall ReadText(
	const FILE *Input, 
	const size_t InputType, 
	const size_t FileIndex)
{
//Initialization
	std::shared_ptr<char> FileBuffer(new char[FILE_BUFFER_SIZE]()), TextBuffer(new char[FILE_BUFFER_SIZE]());
	memset(FileBuffer.get(), 0, FILE_BUFFER_SIZE);
	memset(TextBuffer.get(), 0, FILE_BUFFER_SIZE);
	std::string TextData;
	size_t ReadLength = 0, Encoding = 0, Index = 0, Line = 0, LabelType = 0;
	auto IsEraseBOM = true, NewLine_Point = false, IsLabelComments = false;

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
				switch (InputType)
				{
					case READ_TEXT_HOSTS: //ReadHosts
					{
						PrintError(LOG_ERROR_HOSTS, L"Data of a line is too short", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					}break;
					case READ_TEXT_IPFILTER: //ReadIPFilter
					{
						PrintError(LOG_ERROR_IPFILTER, L"Data of a line is too short", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
					}break;
					case READ_TEXT_PARAMETER: //ReadParameter
					{
						PrintError(LOG_ERROR_PARAMETER, L"Data of a line is too short", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
					}break;
					case READ_TEXT_PARAMETER_MONITOR: //ReadParameter(Monitor mode)
					{
						PrintError(LOG_ERROR_PARAMETER, L"Data of a line is too short", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
					}break;
				}

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
				Encoding = CODEPAGE_UTF_8;
			}
		//32-bit Unicode Transformation Format/UTF-32 Little Endian/LE
			else if ((UCHAR)FileBuffer.get()[0] == 0xFF && (UCHAR)FileBuffer.get()[1U] == 0xFE && FileBuffer.get()[2U] == 0 && FileBuffer.get()[3U] == 0) //0xFF, 0xFE, 0x00, 0x00
			{
				memmove_s(FileBuffer.get(), FILE_BUFFER_SIZE, FileBuffer.get() + BOM_UTF_32_LENGTH, FILE_BUFFER_SIZE - BOM_UTF_32_LENGTH);
				memset(FileBuffer.get() + FILE_BUFFER_SIZE - BOM_UTF_32_LENGTH, 0, BOM_UTF_32_LENGTH);
				ReadLength -= BOM_UTF_32_LENGTH;
				Encoding = CODEPAGE_UTF_32_LE;
			}
		//32-bit Unicode Transformation Format/UTF-32 Big Endian/BE
			else if (FileBuffer.get()[0] == 0 && FileBuffer.get()[1U] == 0 && (UCHAR)FileBuffer.get()[2U] == 0xFE && (UCHAR)FileBuffer.get()[3U] == 0xFF) //0x00, 0x00, 0xFE, 0xFF
			{
				memmove_s(FileBuffer.get(), FILE_BUFFER_SIZE, FileBuffer.get() + BOM_UTF_32_LENGTH, FILE_BUFFER_SIZE - BOM_UTF_32_LENGTH);
				memset(FileBuffer.get() + FILE_BUFFER_SIZE - BOM_UTF_32_LENGTH, 0, BOM_UTF_32_LENGTH);
				ReadLength -= BOM_UTF_32_LENGTH;
				Encoding = CODEPAGE_UTF_32_BE;
			}
		//16-bit Unicode Transformation Format/UTF-16 Little Endian/LE
			else if ((UCHAR)FileBuffer.get()[0] == 0xFF && (UCHAR)FileBuffer.get()[1U] == 0xFE) //0xFF, 0xFE
			{
				memmove_s(FileBuffer.get(), FILE_BUFFER_SIZE, FileBuffer.get() + BOM_UTF_16_LENGTH, FILE_BUFFER_SIZE - BOM_UTF_16_LENGTH);
				memset(FileBuffer.get() + FILE_BUFFER_SIZE - BOM_UTF_16_LENGTH, 0, BOM_UTF_16_LENGTH);
				ReadLength -= BOM_UTF_16_LENGTH;
				Encoding = CODEPAGE_UTF_16_LE;
			}
		//16-bit Unicode Transformation Format/UTF-16 Big Endian/BE
			else if ((UCHAR)FileBuffer.get()[0] == 0xFE && (UCHAR)FileBuffer.get()[1U] == 0xFF) //0xFE, 0xFF
			{
				memmove_s(FileBuffer.get(), FILE_BUFFER_SIZE, FileBuffer.get() + BOM_UTF_16_LENGTH, FILE_BUFFER_SIZE - BOM_UTF_16_LENGTH);
				memset(FileBuffer.get() + FILE_BUFFER_SIZE - BOM_UTF_16_LENGTH, 0, BOM_UTF_16_LENGTH);
				ReadLength -= BOM_UTF_16_LENGTH;
				Encoding = CODEPAGE_UTF_16_BE;
			}
		//8-bit Unicode Transformation Format/UTF-8 without BOM or other ASCII part of encoding
			else {
				Encoding = CODEPAGE_ASCII;
			}
		}

	//Text check
		if (Encoding == CODEPAGE_ASCII || Encoding == CODEPAGE_UTF_8)
		{
			uint16_t SingleText = 0;
			for (Index = 0;Index < ReadLength;)
			{
			//About this process, see https://en.wikipedia.org/wiki/UTF-8.
				if ((UCHAR)FileBuffer.get()[Index] > 0xE0 && Index >= 3U)
				{
					SingleText = (((uint16_t)(FileBuffer.get()[Index] & 0x0F)) << 12U) + (((uint16_t)(FileBuffer.get()[Index + 1U] & 0x3F)) << 6U) + (uint16_t)(FileBuffer.get()[Index + 2U] & 0x3F);
				
				//Next line format
					if (SingleText == UNICODE_LINE_SEPARATOR || SingleText == UNICODE_PARAGRAPH_SEPARATOR)
					{
						FileBuffer.get()[Index] = 0;
						FileBuffer.get()[Index + 1U] = 0;
						FileBuffer.get()[Index + 2U] = ASCII_LF;
						Index += 3U;
						continue;
					}
				//Space format
					else if (SingleText == UNICODE_MONGOLIAN_VOWEL_SEPARATOR || SingleText == UNICODE_EN_SPACE || SingleText == UNICODE_EM_SPACE || 
						SingleText == UNICODE_THICK_SPACE || SingleText == UNICODE_MID_SPACE || SingleText == UNICODE_SIX_PER_EM_SPACE || 
						SingleText == UNICODE_FIGURE_SPACE || SingleText == UNICODE_PUNCTUATION_SPACE || SingleText == UNICODE_THIN_SPACE || 
						SingleText == UNICODE_HAIR_SPACE || SingleText == UNICODE_ZERO_WIDTH_SPACE || SingleText == UNICODE_ZERO_WIDTH_NON_JOINER || 
						SingleText == UNICODE_ZERO_WIDTH_JOINER || SingleText == UNICODE_NARROW_NO_BREAK_SPACE || SingleText == UNICODE_MEDIUM_MATHEMATICAL_SPACE || 
						SingleText == UNICODE_WORD_JOINER || SingleText == UNICODE_IDEOGRAPHIC_SPACE)
					{
						FileBuffer.get()[Index] = ASCII_SPACE;
						FileBuffer.get()[Index + 1U] = 0;
						FileBuffer.get()[Index + 2U] = 0;
						Index += 3U;
						continue;
					}
				}
				else if ((UCHAR)FileBuffer.get()[Index] > 0xC0 && Index >= 2U)
				{
					SingleText = (((uint16_t)(FileBuffer.get()[Index] & 0x1F)) << 6U) + (uint16_t)(FileBuffer.get()[Index] & 0x3F);

				//Next line format
					if (SingleText == UNICODE_NEXT_LINE)
					{
						FileBuffer.get()[Index] = 0;
						FileBuffer.get()[Index + 1U] = ASCII_LF;
						Index += 2U;
						continue;
					}
				//Space format
					if (SingleText == UNICODE_NO_BREAK_SPACE)
					{
						FileBuffer.get()[Index] = ASCII_SPACE;
						FileBuffer.get()[Index + 1U] = 0;
						Index += 2U;
						continue;
					}
				}
				
			//Delete all Non-ASCII.
				if ((UCHAR)FileBuffer.get()[Index] > ASCII_MAX_NUM)
					FileBuffer.get()[Index] = 0;
			//Next line format
				if (FileBuffer.get()[Index] == ASCII_CR && Index + 1U < ReadLength && FileBuffer.get()[Index + 1U] == ASCII_LF)
					FileBuffer.get()[Index] = 0;
				else if (FileBuffer.get()[Index] == ASCII_CR || FileBuffer.get()[Index] == ASCII_VT || FileBuffer.get()[Index] == ASCII_FF)
					FileBuffer.get()[Index] = ASCII_LF;

			//Next text
				++Index;
			}
		}
		else if (Encoding == CODEPAGE_UTF_16_LE || Encoding == CODEPAGE_UTF_16_BE)
		{
			PUINT16 SingleText = nullptr;
			for (Index = 0;Index < ReadLength;Index += sizeof(uint16_t))
			{
				SingleText = (PUINT16)(FileBuffer.get() + Index);

			//Endian
			#if __BYTE_ORDER == __LITTLE_ENDIAN
				if (Encoding == CODEPAGE_UTF_16_BE)
					*SingleText = ntoh16_Force(*SingleText);
			#else
				if (Encoding == CODEPAGE_UTF_16_LE)
					*SingleText = ntoh16_Force(*SingleText);
			#endif
			//Next line format
				if (*SingleText == ASCII_CR && Index + sizeof(uint16_t) < ReadLength && 
				#if __BYTE_ORDER == __LITTLE_ENDIAN
					(Encoding == CODEPAGE_UTF_16_BE && ntoh16_Force(*(SingleText + 1U)) == ASCII_LF || Encoding == CODEPAGE_UTF_16_LE && *(SingleText + 1U) == ASCII_LF))
				#else
					(Encoding == CODEPAGE_UTF_16_LE && ntoh16_Force(*(SingleText + 1U)) == ASCII_LF || Encoding == CODEPAGE_UTF_16_BE && *(SingleText + 1U) == ASCII_LF))
				#endif
						*SingleText = 0;
				else if (*SingleText == ASCII_CR || *SingleText == ASCII_VT || *SingleText == ASCII_FF || *SingleText == UNICODE_NEXT_LINE || 
					*SingleText == UNICODE_LINE_SEPARATOR || *SingleText == UNICODE_PARAGRAPH_SEPARATOR)
						*SingleText = ASCII_LF;
			//Space format
				else if (*SingleText == UNICODE_NO_BREAK_SPACE || *SingleText == UNICODE_MONGOLIAN_VOWEL_SEPARATOR || *SingleText == UNICODE_EN_SPACE || 
					*SingleText == UNICODE_EM_SPACE || *SingleText == UNICODE_THICK_SPACE || *SingleText == UNICODE_MID_SPACE || 
					*SingleText == UNICODE_SIX_PER_EM_SPACE || *SingleText == UNICODE_FIGURE_SPACE || *SingleText == UNICODE_PUNCTUATION_SPACE || 
					*SingleText == UNICODE_THIN_SPACE || *SingleText == UNICODE_HAIR_SPACE || *SingleText == UNICODE_ZERO_WIDTH_SPACE || 
					*SingleText == UNICODE_ZERO_WIDTH_NON_JOINER || *SingleText == UNICODE_ZERO_WIDTH_JOINER || *SingleText == UNICODE_NARROW_NO_BREAK_SPACE || 
					*SingleText == UNICODE_MEDIUM_MATHEMATICAL_SPACE || *SingleText == UNICODE_WORD_JOINER || *SingleText == UNICODE_IDEOGRAPHIC_SPACE)
						*SingleText = ASCII_SPACE;
			//Delete all Non-ASCII.
				else if (*SingleText > ASCII_MAX_NUM)
					*SingleText = 0;
			}
		}
		else if (Encoding == CODEPAGE_UTF_32_LE || Encoding == CODEPAGE_UTF_32_BE)
		{
			PUINT32 SingleText = nullptr;
			for (Index = 0;Index < ReadLength;Index += sizeof(uint32_t))
			{
				SingleText = (PUINT32)(FileBuffer.get() + Index);

			//Endian
			#if __BYTE_ORDER == __LITTLE_ENDIAN
				if (Encoding == CODEPAGE_UTF_32_BE)
					*SingleText = ntoh32_Force(*SingleText);
			#else
				if (Encoding == CODEPAGE_UTF_32_LE)
					*SingleText = ntoh32_Force(*SingleText);
			#endif
			//Next line format
				if (*SingleText == ASCII_CR && Index + sizeof(uint32_t) < ReadLength && 
				#if __BYTE_ORDER == __LITTLE_ENDIAN
					(Encoding == CODEPAGE_UTF_32_BE && ntoh32_Force(*(SingleText + 1U)) == ASCII_LF || Encoding == CODEPAGE_UTF_32_LE && *(SingleText + 1U) == ASCII_LF))
				#else
					(Encoding == CODEPAGE_UTF_32_LE && ntoh32_Force(*(SingleText + 1U)) == ASCII_LF || Encoding == CODEPAGE_UTF_32_BE && *(SingleText + 1U) == ASCII_LF))
				#endif
						*SingleText = 0;
				else if (*SingleText == ASCII_CR || *SingleText == ASCII_VT || *SingleText == ASCII_FF || *SingleText == UNICODE_NEXT_LINE || 
					*SingleText == UNICODE_LINE_SEPARATOR || *SingleText == UNICODE_PARAGRAPH_SEPARATOR)
						*SingleText = ASCII_LF;
			//Space format
				else if (*SingleText == UNICODE_NO_BREAK_SPACE || *SingleText == UNICODE_MONGOLIAN_VOWEL_SEPARATOR || *SingleText == UNICODE_EN_SPACE || 
					*SingleText == UNICODE_EM_SPACE || *SingleText == UNICODE_THICK_SPACE || *SingleText == UNICODE_MID_SPACE || 
					*SingleText == UNICODE_SIX_PER_EM_SPACE || *SingleText == UNICODE_FIGURE_SPACE || *SingleText == UNICODE_PUNCTUATION_SPACE || 
					*SingleText == UNICODE_THIN_SPACE || *SingleText == UNICODE_HAIR_SPACE || *SingleText == UNICODE_ZERO_WIDTH_SPACE || 
					*SingleText == UNICODE_ZERO_WIDTH_NON_JOINER || *SingleText == UNICODE_ZERO_WIDTH_JOINER || *SingleText == UNICODE_NARROW_NO_BREAK_SPACE || 
					*SingleText == UNICODE_MEDIUM_MATHEMATICAL_SPACE || *SingleText == UNICODE_WORD_JOINER || *SingleText == UNICODE_IDEOGRAPHIC_SPACE)
						*SingleText = ASCII_SPACE;
			//Delete all Non-ASCII.
				else if (*SingleText > ASCII_MAX_NUM)
					*SingleText = 0;
			}
		}
		else {
			switch (InputType)
			{
				case READ_TEXT_HOSTS: //ReadHosts
				{
					PrintError(LOG_ERROR_HOSTS, L"Text encoding error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
				}break;
				case READ_TEXT_IPFILTER: //ReadIPFilter
				{
					PrintError(LOG_ERROR_IPFILTER, L"Text encoding error", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
				}break;
				case READ_TEXT_PARAMETER: //ReadParameter
				{
					PrintError(LOG_ERROR_PARAMETER, L"Text encoding error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
				}break;
				case READ_TEXT_PARAMETER_MONITOR: //ReadParameter(Monitor mode)
				{
					PrintError(LOG_ERROR_PARAMETER, L"Text encoding error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
				}break;
			}
			
			return false;
		}

	//Delete all null characters.
		for (Index = 0;Index < ReadLength;++Index)
		{
			if ((UCHAR)FileBuffer.get()[Index] > 0)
			{
				TextBuffer.get()[strnlen_s(TextBuffer.get(), FILE_BUFFER_SIZE)] = FileBuffer.get()[Index];

			//Mark next line format.
				if (!NewLine_Point && FileBuffer.get()[Index] == ASCII_LF)
					NewLine_Point = true;
			}
		}

		memset(FileBuffer.get(), 0, FILE_BUFFER_SIZE);

	//Lines length check
		if (!NewLine_Point && ReadLength == FILE_BUFFER_SIZE)
		{
			switch (InputType)
			{
				case READ_TEXT_HOSTS: //ReadHosts
				{
					PrintError(LOG_ERROR_HOSTS, L"Data of a line is too long", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
				}break;
				case READ_TEXT_IPFILTER: //ReadIPFilter
				{
					PrintError(LOG_ERROR_IPFILTER, L"Data of a line is too long", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
				}break;
				case READ_TEXT_PARAMETER: //ReadParameter
				{
					PrintError(LOG_ERROR_PARAMETER, L"Data of a line is too long", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
				}break;
				case READ_TEXT_PARAMETER_MONITOR: //ReadParameter(Monitor mode)
				{
					PrintError(LOG_ERROR_PARAMETER, L"Data of a line is too long", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
				}break;
			}

			return false;
		}
		else {
			NewLine_Point = false;
		}

	//Read data.
		for (Index = 0;Index < strnlen_s(TextBuffer.get(), FILE_BUFFER_SIZE);++Index)
		{
		//New line
			if (TextBuffer.get()[Index] == ASCII_LF || Index + 1U == strnlen_s(TextBuffer.get(), FILE_BUFFER_SIZE) && feof((FILE *)Input))
			{
				++Line;

			//Read texts.
				if (TextData.length() > READ_TEXT_MINSIZE)
				{
					switch (InputType)
					{
						case READ_TEXT_HOSTS: //ReadHosts
						{
							ReadHostsData(TextData, FileIndex, Line, LabelType, IsLabelComments);
						}break;
						case READ_TEXT_IPFILTER: //ReadIPFilter
						{
							ReadIPFilterData(TextData, FileIndex, Line, LabelType, IsLabelComments);
						}break;
						case READ_TEXT_PARAMETER: //ReadParameter
						{
							if (!ReadParameterData(TextData, FileIndex, true, Line, IsLabelComments))
								return false;
						}break;
						case READ_TEXT_PARAMETER_MONITOR: //ReadParameter(Monitor mode)
						{
							if (!ReadParameterData(TextData, FileIndex, false, Line, IsLabelComments))
								return false;
						}break;
					}
				}

			//Next step
				if (Index + 1U == strnlen_s(TextBuffer.get(), FILE_BUFFER_SIZE) && feof((FILE *)Input))
					return true;
				else 
					TextData.clear();
			}
			else {
				TextData.append(1U, TextBuffer.get()[Index]);
			}
		}

		memset(TextBuffer.get(), 0, FILE_BUFFER_SIZE);
	}

	return true;
}

//Check Multi-line comments
bool __fastcall ReadMultiLineComments(
	std::string &Data, 
	bool &IsLabelComments)
{
	if (IsLabelComments)
	{
		if (Data.find("*/") != std::string::npos && Data.find("*/") + strlen("*/") < Data.length())
		{
			std::string DataTemp(Data, Data.find("*/") + strlen("*/"), Data.length() - (Data.find("*/") + strlen("*/")));
			Data = DataTemp;
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
bool __fastcall ReadParameter(
	const bool IsFirstRead)
{
	size_t FileIndex = 0;

//Create file list.
	if (IsFirstRead)
	{
		const wchar_t *ConfigFileNameList[]{CONFIG_FILE_NAME_LIST};
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		const char *sConfigFileNameList[]{CONFIG_FILE_NAME_LIST_STRING};
	#endif
		for (FileIndex = 0;FileIndex < sizeof(ConfigFileNameList) / sizeof(PWSTR);++FileIndex)
		{
			FILE_DATA ConfigFileTemp;
			ConfigFileTemp.FileName = GlobalRunningStatus.Path_Global->front();
			ConfigFileTemp.FileName.append(ConfigFileNameList[FileIndex]);
		#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			ConfigFileTemp.sFileName = GlobalRunningStatus.sPath_Global->front();
			ConfigFileTemp.sFileName.append(sConfigFileNameList[FileIndex]);
		#endif

			FileList_Config.push_back(ConfigFileTemp);
		}
	}

//Initialization
	FILE *Input = nullptr;
#if defined(PLATFORM_WIN)
	std::shared_ptr<WIN32_FILE_ATTRIBUTE_DATA> File_WIN32_FILE_ATTRIBUTE_DATA(new WIN32_FILE_ATTRIBUTE_DATA());
	memset(File_WIN32_FILE_ATTRIBUTE_DATA.get(), 0, sizeof(WIN32_FILE_ATTRIBUTE_DATA));
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	std::shared_ptr<struct stat> FileStat(new struct stat());
	memset(FileStat.get(), 0, sizeof(struct stat));
#endif

//Read parameters at first.
	if (IsFirstRead)
	{
	//Open configuration file.
		for (FileIndex = 0;FileIndex < FileList_Config.size();++FileIndex)
		{
		#if defined(PLATFORM_WIN)
			if (_wfopen_s(&Input, FileList_Config.at(FileIndex).FileName.c_str(), L"rb") != EXIT_SUCCESS || Input == nullptr)
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			Input = fopen(FileList_Config.at(FileIndex).sFileName.c_str(), "rb");
			if (Input == nullptr)
		#endif
			{
			//Check all configuration files.
				if (FileIndex + 1U == FileList_Config.size())
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
		if (GetFileAttributesExW(FileList_Config.at(FileIndex).FileName.c_str(), GetFileExInfoStandard, File_WIN32_FILE_ATTRIBUTE_DATA.get()) != FALSE)
		{
			std::shared_ptr<LARGE_INTEGER> ConfigFileSize(new LARGE_INTEGER());
			memset(ConfigFileSize.get(), 0, sizeof(LARGE_INTEGER));
			ConfigFileSize->HighPart = File_WIN32_FILE_ATTRIBUTE_DATA->nFileSizeHigh;
			ConfigFileSize->LowPart = File_WIN32_FILE_ATTRIBUTE_DATA->nFileSizeLow;
			if (ConfigFileSize->QuadPart >= DEFAULT_FILE_MAXSIZE)
			{
				PrintError(LOG_ERROR_PARAMETER, L"Configuration file is too large", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
				return false;
			}
		}
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		if (stat(FileList_Config.at(FileIndex).sFileName.c_str(), FileStat.get()) == EXIT_SUCCESS && FileStat->st_size >= (off_t)DEFAULT_FILE_MAXSIZE)
		{
			PrintError(LOG_ERROR_PARAMETER, L"Configuration file is too large", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
			return false;
		}
	#endif

	//Read data.
		if (Input != nullptr)
		{
			if (!ReadText(Input, READ_TEXT_PARAMETER, FileIndex))
			{
				fclose(Input);
				return false;
			}

			fclose(Input);
		}
		else {
			PrintError(LOG_ERROR_PARAMETER, L"Cannot open any configuration files", 0, nullptr, 0);
			return false;
		}

	//Check parameter list and set default values.
		return ParameterCheckAndSetting(true, FileIndex);
	}
//Monitor mode
	else {
	//Open configuration file.
		for (;;)
		{
			for (FileIndex = 0;FileIndex < FileList_Config.size();++FileIndex)
			{
			#if defined(PLATFORM_WIN)
				if (_wfopen_s(&Input, FileList_Config.at(FileIndex).FileName.c_str(), L"rb") != EXIT_SUCCESS || Input == nullptr)
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				Input = fopen(FileList_Config.at(FileIndex).sFileName.c_str(), "rb");
				if (Input == nullptr)
			#endif
				{
				//Check all configuration files.
					if (FileIndex + 1U == FileList_Config.size())
						PrintError(LOG_ERROR_PARAMETER, L"Cannot open any configuration files", 0, nullptr, 0);

					continue;
				}
				else {
					fclose(Input);
					Input = nullptr;

					goto StopLoop;
				}
			}

			Sleep(Parameter.FileRefreshTime);
		}

	//Jump here to stop loop.
	StopLoop:
	#if defined(PLATFORM_WIN)
		std::shared_ptr<LARGE_INTEGER> File_LARGE_INTEGER(new LARGE_INTEGER());
		memset(File_LARGE_INTEGER.get(), 0, sizeof(LARGE_INTEGER));
	#endif
		auto InnerIsFirstRead = true, IsFileModified = false;

	//File Monitor
		for (;;)
		{
			IsFileModified = false;

		//Get attributes of file.
		#if defined(PLATFORM_WIN)
			if (GetFileAttributesExW(FileList_Config.at(FileIndex).FileName.c_str(), GetFileExInfoStandard, File_WIN32_FILE_ATTRIBUTE_DATA.get()) == FALSE)
			{
				memset(File_WIN32_FILE_ATTRIBUTE_DATA.get(), 0, sizeof(WIN32_FILE_ATTRIBUTE_DATA));
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			if (stat(FileList_Config.at(FileIndex).sFileName.c_str(), FileStat.get()) != EXIT_SUCCESS)
			{
				memset(FileStat.get(), 0, sizeof(struct stat));
		#endif
				FileList_Config.at(FileIndex).ModificationTime = 0;
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
					PrintError(LOG_ERROR_PARAMETER, L"Configuration file size is too large", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);

				#if defined(PLATFORM_WIN)
					memset(File_WIN32_FILE_ATTRIBUTE_DATA.get(), 0, sizeof(WIN32_FILE_ATTRIBUTE_DATA));
					memset(File_LARGE_INTEGER.get(), 0, sizeof(LARGE_INTEGER));
				#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
					memset(FileStat.get(), 0, sizeof(struct stat));
				#endif
					FileList_Config.at(FileIndex).ModificationTime = 0;

					Sleep(Parameter.FileRefreshTime);
					continue;
				}

			//Check modification time of file.
			#if defined(PLATFORM_WIN)
				memset(File_LARGE_INTEGER.get(), 0, sizeof(LARGE_INTEGER));
				File_LARGE_INTEGER->HighPart = File_WIN32_FILE_ATTRIBUTE_DATA->ftLastWriteTime.dwHighDateTime;
				File_LARGE_INTEGER->LowPart = File_WIN32_FILE_ATTRIBUTE_DATA->ftLastWriteTime.dwLowDateTime;
				if (FileList_Config.at(FileIndex).ModificationTime == 0 || File_LARGE_INTEGER->QuadPart != FileList_Config.at(FileIndex).ModificationTime)
				{
					FileList_Config.at(FileIndex).ModificationTime = File_LARGE_INTEGER->QuadPart;
					memset(File_WIN32_FILE_ATTRIBUTE_DATA.get(), 0, sizeof(WIN32_FILE_ATTRIBUTE_DATA));
					memset(File_LARGE_INTEGER.get(), 0, sizeof(LARGE_INTEGER));
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				if (FileList_Config.at(FileIndex).ModificationTime == 0 || FileStat->st_mtime != FileList_Config.at(FileIndex).ModificationTime)
				{
					FileList_Config.at(FileIndex).ModificationTime = FileStat->st_mtime;
					memset(FileStat.get(), 0, sizeof(struct stat));
			#endif
					IsFileModified = true;

				//Read file.
				#if defined(PLATFORM_WIN)
					if (_wfopen_s(&Input, FileList_Config.at(FileIndex).FileName.c_str(), L"rb") == EXIT_SUCCESS)
					{
				#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
					Input = fopen(FileList_Config.at(FileIndex).sFileName.c_str(), "rb");
				#endif
						if (Input == nullptr)
						{
							Sleep(Parameter.FileRefreshTime);
							continue;
						}
						else {
							if (!InnerIsFirstRead)
							{
							//Read data.
								if (ReadText(Input, READ_TEXT_PARAMETER_MONITOR, FileIndex))
								{
								//Copy to global list.
									if (ParameterCheckAndSetting(false, FileIndex))
									{
										ParameterModificating.MonitorItemToUsing(&Parameter);
									#if defined(ENABLE_LIBSODIUM)
										if (Parameter.DNSCurve)
											DNSCurveParameterModificating.MonitorItemToUsing(&DNSCurveParameter);
									#endif
									}
								}

							//Reset modificating list.
								ParameterModificating.MonitorItemReset();
							#if defined(ENABLE_LIBSODIUM)
								if (Parameter.DNSCurve)
									DNSCurveParameterModificating.MonitorItemReset();
							#endif
							}
							else {
								InnerIsFirstRead = false;
							}

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

		//Flush DNS cache and Auto-refresh
			if (IsFileModified)
				FlushAllDNSCache();

			Sleep(Parameter.FileRefreshTime);
		}
	}

//Monitor terminated
	PrintError(LOG_ERROR_SYSTEM, L"Read Parameter module Monitor terminated", 0, nullptr, 0);
	return false;
}

//Read IPFilter from file
void __fastcall ReadIPFilter(
	void)
{
	size_t FileIndex = 0;

//Create file list.
	for (size_t Index = 0;Index < GlobalRunningStatus.Path_Global->size();++Index)
	{
		FILE_DATA FileDataTemp;
		for (FileIndex = 0;FileIndex < GlobalRunningStatus.FileList_IPFilter->size();++FileIndex)
		{
			FileDataTemp.ModificationTime = 0;

		//Add to global list.
			FileDataTemp.FileName = GlobalRunningStatus.Path_Global->at(Index);
			FileDataTemp.FileName.append(GlobalRunningStatus.FileList_IPFilter->at(FileIndex));
		#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			FileDataTemp.sFileName = GlobalRunningStatus.sPath_Global->at(Index);
			FileDataTemp.sFileName.append(GlobalRunningStatus.sFileList_IPFilter->at(FileIndex));
		#endif

			FileList_IPFilter.push_back(FileDataTemp);
		}
	}

//Initialization
	FILE *Input = nullptr;
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
	std::unique_lock<std::mutex> IPFilterFileMutex(IPFilterFileLock);
	IPFilterFileMutex.unlock();
	
//File Monitor
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
			if (stat(FileList_IPFilter.at(FileIndex).sFileName.c_str(), FileStat.get()) != EXIT_SUCCESS)
			{
				memset(FileStat.get(), 0, sizeof(struct stat));
		#endif
				if (FileList_IPFilter.at(FileIndex).ModificationTime > 0)
					IsFileModified = true;
				FileList_IPFilter.at(FileIndex).ModificationTime = 0;

				ClearModificatingListData(READ_TEXT_IPFILTER, FileIndex);
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

					ClearModificatingListData(READ_TEXT_IPFILTER, FileIndex);
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
					ClearModificatingListData(READ_TEXT_IPFILTER, FileIndex);
					IsFileModified = true;

				//Read file.
				#if defined(PLATFORM_WIN)
					if (_wfopen_s(&Input, FileList_IPFilter.at(FileIndex).FileName.c_str(), L"rb") == EXIT_SUCCESS)
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
							DIFFERNET_IPFILTER_FILE_SET IPFilterFileSetTemp;
							for (auto IPFilterFileSetIter = IPFilterFileSetModificating->begin();IPFilterFileSetIter != IPFilterFileSetModificating->end();++IPFilterFileSetIter)
							{
								if (IPFilterFileSetIter->FileIndex == FileIndex)
								{
									break;
								}
								else if (IPFilterFileSetIter + 1U == IPFilterFileSetModificating->end())
								{
									IPFilterFileSetTemp.FileIndex = FileIndex;
									IPFilterFileSetModificating->push_back(IPFilterFileSetTemp);
									break;
								}
							}
							if (IPFilterFileSetModificating->empty())
							{
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
		std::sort(IPFilterFileSetModificating->begin(), IPFilterFileSetModificating->end(), SortCompare_IPFilter);
		IPFilterFileMutex.lock();
		*IPFilterFileSetUsing = *IPFilterFileSetModificating;
		IPFilterFileSetUsing->shrink_to_fit();
		IPFilterFileMutex.unlock();
		IPFilterFileSetModificating->shrink_to_fit();

	//Flush DNS cache and Auto-refresh
		FlushAllDNSCache();
		Sleep(Parameter.FileRefreshTime);
	}

//Monitor terminated
	PrintError(LOG_ERROR_SYSTEM, L"Read IPFilter module Monitor terminated", 0, nullptr, 0);
	return;
}

//Read hosts from file
void __fastcall ReadHosts(
	void)
{
	size_t FileIndex = 0;

//Create file list.
	for (size_t Index = 0;Index < GlobalRunningStatus.Path_Global->size();++Index)
	{
		FILE_DATA FileDataTemp;
		for (FileIndex = 0;FileIndex < GlobalRunningStatus.FileList_Hosts->size();++FileIndex)
		{
			FileDataTemp.ModificationTime = 0;

		//Add to global list.
			FileDataTemp.FileName = GlobalRunningStatus.Path_Global->at(Index);
			FileDataTemp.FileName.append(GlobalRunningStatus.FileList_Hosts->at(FileIndex));
		#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			FileDataTemp.sFileName = GlobalRunningStatus.sPath_Global->at(Index);
			FileDataTemp.sFileName.append(GlobalRunningStatus.sFileList_Hosts->at(FileIndex));
		#endif

			FileList_Hosts.push_back(FileDataTemp);
		}
	}

//Initialization
	FILE *Input = nullptr;
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
	std::unique_lock<std::mutex> HostsFileMutex(HostsFileLock);
	HostsFileMutex.unlock();

//File Monitor
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
			if (stat(FileList_Hosts.at(FileIndex).sFileName.c_str(), FileStat.get()) != EXIT_SUCCESS)
			{
				memset(FileStat.get(), 0, sizeof(struct stat));
		#endif
				if (FileList_Hosts.at(FileIndex).ModificationTime > 0)
					IsFileModified = true;
				FileList_Hosts.at(FileIndex).ModificationTime = 0;

				ClearModificatingListData(READ_TEXT_HOSTS, FileIndex);
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

					ClearModificatingListData(READ_TEXT_HOSTS, FileIndex);
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
					ClearModificatingListData(READ_TEXT_HOSTS, FileIndex);
					IsFileModified = true;

				//Read file.
				#if defined(PLATFORM_WIN)
					if (_wfopen_s(&Input, FileList_Hosts.at(FileIndex).FileName.c_str(), L"rb") == EXIT_SUCCESS)
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
							DIFFERNET_HOSTS_FILE_SET HostsFileSetTemp;
							for (auto HostsFileSetIter = HostsFileSetModificating->begin();HostsFileSetIter != HostsFileSetModificating->end();++HostsFileSetIter)
							{
								if (HostsFileSetIter->FileIndex == FileIndex)
								{
									break;
								}
								else if (HostsFileSetIter + 1U == HostsFileSetModificating->end())
								{
									HostsFileSetTemp.FileIndex = FileIndex;
									HostsFileSetModificating->push_back(HostsFileSetTemp);
									break;
								}
							}
							if (HostsFileSetModificating->empty())
							{
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

	//Copy to using list.
		std::sort(HostsFileSetModificating->begin(), HostsFileSetModificating->end(), SortCompare_Hosts);
		HostsFileMutex.lock();
		*HostsFileSetUsing = *HostsFileSetModificating;
		HostsFileSetUsing->shrink_to_fit();
		HostsFileMutex.unlock();
		HostsFileSetModificating->shrink_to_fit();

	//Flush DNS cache and Auto-refresh
		FlushAllDNSCache();
		Sleep(Parameter.FileRefreshTime);
	}

//Monitor terminated
	PrintError(LOG_ERROR_SYSTEM, L"Read Hosts module Monitor terminated", 0, nullptr, 0);
	return;
}

//Clear data in list
void __fastcall ClearModificatingListData(
	const size_t ClearType, 
	const size_t FileIndex)
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

//Get data list from file
void __fastcall GetParameterListData(
	std::vector<std::string> &ListData, 
	const std::string Data, 
	const size_t DataOffset, 
	const size_t Length)
{
	std::string NameString;
	for (size_t Index = DataOffset;Index < Length;++Index)
	{
	//Last data
		if (Index + 1U == Length)
		{
			NameString.append(Data, Index, 1U);
			ListData.push_back(NameString);

			break;
		}
	//Separated
		else if (Data.at(Index) == ASCII_VERTICAL)
		{
			ListData.push_back(NameString);
			NameString.clear();
		}
		else {
			NameString.append(Data, Index, 1U);
		}
	}

	return;
}

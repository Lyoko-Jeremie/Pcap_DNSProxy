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

//Read texts
bool ReadText(
	const FILE *FileHandle, 
	const size_t InputType, 
	const size_t FileIndex)
{
//Initialization
	std::shared_ptr<uint8_t> FileBuffer(new uint8_t[FILE_BUFFER_SIZE]()), TextBuffer(new uint8_t[FILE_BUFFER_SIZE]());
	memset(FileBuffer.get(), 0, FILE_BUFFER_SIZE);
	memset(TextBuffer.get(), 0, FILE_BUFFER_SIZE);
	std::string TextData;
	size_t Encoding = 0, Index = 0, Line = 0, LabelType = 0;
	auto IsEraseBOM = true, NewLine_Point = false, IsLabelComments = false;

//Read data.
	while (!feof((FILE *)FileHandle))
	{
	//Read file and Mark last read.
		_set_errno(0);
		auto ReadLength = fread_s(FileBuffer.get(), FILE_BUFFER_SIZE, sizeof(uint8_t), FILE_BUFFER_SIZE, (FILE *)FileHandle);
		if (ReadLength == 0)
		{
			if (errno > 0)
			{
				ReadTextPrintLog(InputType, FileIndex, Line);
				return false;
			}
			else {
				continue;
			}
		}

	//Erase BOM of Unicode Transformation Format/UTF at first.
		if (IsEraseBOM)
		{
			if (ReadLength <= READ_DATA_MINSIZE)
			{
				ReadTextPrintLog(InputType, FileIndex, Line);
				return false;
			}
			else {
				IsEraseBOM = false;
			}

		//8-bit Unicode Transformation Format/UTF-8 with BOM
			if (FileBuffer.get()[0] == 0xEF && FileBuffer.get()[1U] == 0xBB && 
				FileBuffer.get()[2U] == 0xBF) //0xEF, 0xBB, 0xBF
			{
				memmove_s(FileBuffer.get(), FILE_BUFFER_SIZE, FileBuffer.get() + BOM_UTF_8_LENGTH, FILE_BUFFER_SIZE - BOM_UTF_8_LENGTH);
				memset(FileBuffer.get() + FILE_BUFFER_SIZE - BOM_UTF_8_LENGTH, 0, BOM_UTF_8_LENGTH);
				ReadLength -= BOM_UTF_8_LENGTH;
				Encoding = CODEPAGE_UTF_8;
			}
		//32-bit Unicode Transformation Format/UTF-32 Little Endian/LE
			else if (FileBuffer.get()[0] == 0xFF && FileBuffer.get()[1U] == 0xFE && 
				FileBuffer.get()[2U] == 0 && FileBuffer.get()[3U] == 0) //0xFF, 0xFE, 0x00, 0x00
			{
				memmove_s(FileBuffer.get(), FILE_BUFFER_SIZE, FileBuffer.get() + BOM_UTF_32_LENGTH, FILE_BUFFER_SIZE - BOM_UTF_32_LENGTH);
				memset(FileBuffer.get() + FILE_BUFFER_SIZE - BOM_UTF_32_LENGTH, 0, BOM_UTF_32_LENGTH);
				ReadLength -= BOM_UTF_32_LENGTH;
				Encoding = CODEPAGE_UTF_32_LE;
			}
		//32-bit Unicode Transformation Format/UTF-32 Big Endian/BE
			else if (FileBuffer.get()[0] == 0 && FileBuffer.get()[1U] == 0 && FileBuffer.get()[2U] == 0xFE && 
				FileBuffer.get()[3U] == 0xFF) //0x00, 0x00, 0xFE, 0xFF
			{
				memmove_s(FileBuffer.get(), FILE_BUFFER_SIZE, FileBuffer.get() + BOM_UTF_32_LENGTH, FILE_BUFFER_SIZE - BOM_UTF_32_LENGTH);
				memset(FileBuffer.get() + FILE_BUFFER_SIZE - BOM_UTF_32_LENGTH, 0, BOM_UTF_32_LENGTH);
				ReadLength -= BOM_UTF_32_LENGTH;
				Encoding = CODEPAGE_UTF_32_BE;
			}
		//16-bit Unicode Transformation Format/UTF-16 Little Endian/LE
			else if (FileBuffer.get()[0] == 0xFF && FileBuffer.get()[1U] == 0xFE) //0xFF, 0xFE
			{
				memmove_s(FileBuffer.get(), FILE_BUFFER_SIZE, FileBuffer.get() + BOM_UTF_16_LENGTH, FILE_BUFFER_SIZE - BOM_UTF_16_LENGTH);
				memset(FileBuffer.get() + FILE_BUFFER_SIZE - BOM_UTF_16_LENGTH, 0, BOM_UTF_16_LENGTH);
				ReadLength -= BOM_UTF_16_LENGTH;
				Encoding = CODEPAGE_UTF_16_LE;
			}
		//16-bit Unicode Transformation Format/UTF-16 Big Endian/BE
			else if (FileBuffer.get()[0] == 0xFE && FileBuffer.get()[1U] == 0xFF) //0xFE, 0xFF
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
			//About this check process, see https://en.wikipedia.org/wiki/UTF-8.
				if (FileBuffer.get()[Index] > 0xE0 && Index >= 3U)
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
				else if (FileBuffer.get()[Index] > 0xC0 && Index >= 2U)
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
				if (FileBuffer.get()[Index] > ASCII_MAX_NUM)
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
			uint16_t *SingleText = nullptr;
			for (Index = 0;Index < ReadLength;Index += sizeof(uint16_t))
			{
				SingleText = (uint16_t *)(FileBuffer.get() + Index);

			//Endian
			#if BYTE_ORDER == LITTLE_ENDIAN
				if (Encoding == CODEPAGE_UTF_16_BE)
					*SingleText = ntoh16_Force(*SingleText);
			#else
				if (Encoding == CODEPAGE_UTF_16_LE)
					*SingleText = ntoh16_Force(*SingleText);
			#endif
			//Next line format
				if (*SingleText == ASCII_CR && Index + sizeof(uint16_t) < ReadLength && 
				#if BYTE_ORDER == LITTLE_ENDIAN
					((Encoding == CODEPAGE_UTF_16_BE && ntoh16_Force(*(SingleText + 1U)) == ASCII_LF) || (Encoding == CODEPAGE_UTF_16_LE && *(SingleText + 1U) == ASCII_LF)))
				#else
					((Encoding == CODEPAGE_UTF_16_LE && ntoh16_Force(*(SingleText + 1U)) == ASCII_LF) || (Encoding == CODEPAGE_UTF_16_BE && *(SingleText + 1U) == ASCII_LF)))
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
			uint32_t *SingleText = nullptr;
			for (Index = 0;Index < ReadLength;Index += sizeof(uint32_t))
			{
				SingleText = (uint32_t *)(FileBuffer.get() + Index);

			//Endian
			#if BYTE_ORDER == LITTLE_ENDIAN
				if (Encoding == CODEPAGE_UTF_32_BE)
					*SingleText = ntoh32_Force(*SingleText);
			#else
				if (Encoding == CODEPAGE_UTF_32_LE)
					*SingleText = ntoh32_Force(*SingleText);
			#endif
			//Next line format
				if (*SingleText == ASCII_CR && Index + sizeof(uint32_t) < ReadLength && 
				#if BYTE_ORDER == LITTLE_ENDIAN
					((Encoding == CODEPAGE_UTF_32_BE && ntoh32_Force(*(SingleText + 1U)) == ASCII_LF) || 
					(Encoding == CODEPAGE_UTF_32_LE && *(SingleText + 1U) == ASCII_LF)))
				#else
					((Encoding == CODEPAGE_UTF_32_LE && ntoh32_Force(*(SingleText + 1U)) == ASCII_LF) || 
					(Encoding == CODEPAGE_UTF_32_BE && *(SingleText + 1U) == ASCII_LF)))
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
					PrintError(LOG_LEVEL_2, LOG_ERROR_PARAMETER, L"Text encoding error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), 0);
				}break;
				case READ_TEXT_IPFILTER: //ReadIPFilter
				{
					PrintError(LOG_LEVEL_2, LOG_ERROR_PARAMETER, L"Text encoding error", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), 0);
				}break;
				case READ_TEXT_PARAMETER: //ReadParameter
				{
					PrintError(LOG_LEVEL_2, LOG_ERROR_PARAMETER, L"Text encoding error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
				}break;
				case READ_TEXT_PARAMETER_MONITOR: //ReadParameter(Monitor mode)
				{
					PrintError(LOG_LEVEL_2, LOG_ERROR_PARAMETER, L"Text encoding error", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
				}break;
			}
			
			return false;
		}

	//Delete all null characters.
		for (Index = 0;Index < ReadLength;++Index)
		{
			if (FileBuffer.get()[Index] > 0)
			{
				TextBuffer.get()[strnlen_s((const char *)TextBuffer.get(), FILE_BUFFER_SIZE)] = FileBuffer.get()[Index];

			//Mark next line format.
				if (!NewLine_Point && FileBuffer.get()[Index] == ASCII_LF)
					NewLine_Point = true;
			}
		}

		memset(FileBuffer.get(), 0, FILE_BUFFER_SIZE);

	//Line length check
		if (!NewLine_Point && ReadLength == FILE_BUFFER_SIZE)
		{
			switch (InputType)
			{
				case READ_TEXT_HOSTS: //ReadHosts
				{
					PrintError(LOG_LEVEL_2, LOG_ERROR_HOSTS, L"Data of a line is too long", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
				}break;
				case READ_TEXT_IPFILTER: //ReadIPFilter
				{
					PrintError(LOG_LEVEL_2, LOG_ERROR_IPFILTER, L"Data of a line is too long", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
				}break;
				case READ_TEXT_PARAMETER: //ReadParameter
				{
					PrintError(LOG_LEVEL_2, LOG_ERROR_PARAMETER, L"Data of a line is too long", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
				}break;
				case READ_TEXT_PARAMETER_MONITOR: //ReadParameter(Monitor mode)
				{
					PrintError(LOG_LEVEL_2, LOG_ERROR_PARAMETER, L"Data of a line is too long", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
				}break;
			}

			return false;
		}
		else {
			NewLine_Point = false;
		}

	//Read data.
		for (Index = 0;Index < strnlen_s((const char *)TextBuffer.get(), FILE_BUFFER_SIZE);++Index)
		{
		//New line
			if (TextBuffer.get()[Index] == ASCII_LF || (Index + 1U == strnlen_s((const char *)TextBuffer.get(), FILE_BUFFER_SIZE) && feof((FILE *)FileHandle)))
			{
				++Line;

			//Read texts.
				if (TextData.length() > READ_TEXT_MINSIZE)
				{
					switch (InputType)
					{
						case READ_TEXT_HOSTS: //ReadHosts
						{
							ReadHostsData(TextData, FileIndex, LabelType, Line, IsLabelComments);
						}break;
						case READ_TEXT_IPFILTER: //ReadIPFilter
						{
							ReadIPFilterData(TextData, FileIndex, LabelType, Line, IsLabelComments);
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
				if (Index + 1U == strnlen_s((const char *)TextBuffer.get(), FILE_BUFFER_SIZE) && feof((FILE *)FileHandle))
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
bool ReadMultiLineComments(
	std::string &Data, 
	bool &IsLabelComments)
{
//Label check
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

//Begin and end signs check
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
bool ReadParameter(
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

		FILE_DATA ConfigFileTemp;
		for (FileIndex = 0;FileIndex < sizeof(ConfigFileNameList) / sizeof(wchar_t *);++FileIndex)
		{
			ConfigFileTemp.FileName = GlobalRunningStatus.Path_Global->front();
			ConfigFileTemp.FileName.append(ConfigFileNameList[FileIndex]);
		#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			ConfigFileTemp.sFileName = GlobalRunningStatus.sPath_Global->front();
			ConfigFileTemp.sFileName.append(sConfigFileNameList[FileIndex]);
		#endif
			ConfigFileTemp.ModificationTime = 0;

			FileList_Config.push_back(ConfigFileTemp);
		}
	}

//Initialization
	FILE *FileHandle = nullptr;
#if defined(PLATFORM_WIN)
	WIN32_FILE_ATTRIBUTE_DATA FileAttributeData;
	memset(&FileAttributeData, 0, sizeof(FileAttributeData));
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	struct stat FileStatData;
	memset(&FileStatData, 0, sizeof(FileStatData));
#endif

//Read parameters at first.
	if (IsFirstRead)
	{
	//Open configuration file.
		for (FileIndex = 0;FileIndex < FileList_Config.size();++FileIndex)
		{
		#if defined(PLATFORM_WIN)
			if (_wfopen_s(&FileHandle, FileList_Config.at(FileIndex).FileName.c_str(), L"rb") != 0 || FileHandle == nullptr)
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			FileHandle = fopen(FileList_Config.at(FileIndex).sFileName.c_str(), "rb");
			if (FileHandle == nullptr)
		#endif
			{
			//Check all configuration files.
				if (FileIndex + 1U == FileList_Config.size())
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"Cannot open any configuration files", 0, nullptr, 0);
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
		if (GetFileAttributesExW(FileList_Config.at(FileIndex).FileName.c_str(), GetFileExInfoStandard, &FileAttributeData) != FALSE)
		{
			LARGE_INTEGER ConfigFileSize;
			memset(&ConfigFileSize, 0, sizeof(ConfigFileSize));
			ConfigFileSize.HighPart = FileAttributeData.nFileSizeHigh;
			ConfigFileSize.LowPart = FileAttributeData.nFileSizeLow;
			if (ConfigFileSize.QuadPart >= DEFAULT_FILE_MAXSIZE)
			{
				PrintError(LOG_LEVEL_3, LOG_ERROR_PARAMETER, L"Configuration file is too large", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
				return false;
			}
		}
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		if (stat(FileList_Config.at(FileIndex).sFileName.c_str(), &FileStatData) == 0 && FileStatData.st_size >= (off_t)DEFAULT_FILE_MAXSIZE)
		{
			PrintError(LOG_LEVEL_3, LOG_ERROR_PARAMETER, L"Configuration file is too large", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);
			return false;
		}
	#endif

	//Read data.
		if (FileHandle != nullptr)
		{
			if (!ReadText(FileHandle, READ_TEXT_PARAMETER, FileIndex))
			{
				fclose(FileHandle);
				return false;
			}

			fclose(FileHandle);
		}
		else {
			PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"Cannot open any configuration files", 0, nullptr, 0);
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
				if (_wfopen_s(&FileHandle, FileList_Config.at(FileIndex).FileName.c_str(), L"rb") != 0 || FileHandle == nullptr)
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				FileHandle = fopen(FileList_Config.at(FileIndex).sFileName.c_str(), "rb");
				if (FileHandle == nullptr)
			#endif
				{
				//Check all configuration files.
					if (FileIndex + 1U == FileList_Config.size())
						PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"Cannot open any configuration files", 0, nullptr, 0);

					continue;
				}
				else {
					fclose(FileHandle);
					FileHandle = nullptr;

					goto StopLoop;
				}
			}

			Sleep(Parameter.FileRefreshTime);
		}

	//Jump here to stop loop.
	StopLoop:
	#if defined(PLATFORM_WIN)
		LARGE_INTEGER FileSizeData;
		memset(&FileSizeData, 0, sizeof(FileSizeData));
	#endif
		auto InnerIsFirstRead = true, IsFileModified = false;

	//File Monitor
		for (;;)
		{
			IsFileModified = false;

		//Get attributes of file.
		#if defined(PLATFORM_WIN)
			if (GetFileAttributesExW(FileList_Config.at(FileIndex).FileName.c_str(), GetFileExInfoStandard, &FileAttributeData) == FALSE)
			{
				memset(&FileAttributeData, 0, sizeof(FileAttributeData));
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			if (stat(FileList_Config.at(FileIndex).sFileName.c_str(), &FileStatData) != 0)
			{
				memset(&FileStatData, 0, sizeof(FileStatData));
		#endif
				FileList_Config.at(FileIndex).ModificationTime = 0;
			}
			else {
			//Check whole file size.
			#if defined(PLATFORM_WIN)
				FileSizeData.HighPart = FileAttributeData.nFileSizeHigh;
				FileSizeData.LowPart = FileAttributeData.nFileSizeLow;
				if (FileSizeData.QuadPart >= DEFAULT_FILE_MAXSIZE)
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				if (FileStatData.st_size >= (off_t)DEFAULT_FILE_MAXSIZE)
			#endif
				{
					PrintError(LOG_LEVEL_3, LOG_ERROR_PARAMETER, L"Configuration file size is too large", 0, FileList_Config.at(FileIndex).FileName.c_str(), 0);

				#if defined(PLATFORM_WIN)
					memset(&FileAttributeData, 0, sizeof(FileAttributeData));
					memset(&FileSizeData, 0, sizeof(FileSizeData));
				#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
					memset(&FileStatData, 0, sizeof(FileStatData));
				#endif
					FileList_Config.at(FileIndex).ModificationTime = 0;

					Sleep(Parameter.FileRefreshTime);
					continue;
				}

			//Check modification time of file.
			#if defined(PLATFORM_WIN)
				memset(&FileSizeData, 0, sizeof(FileSizeData));
				FileSizeData.HighPart = FileAttributeData.ftLastWriteTime.dwHighDateTime;
				FileSizeData.LowPart = FileAttributeData.ftLastWriteTime.dwLowDateTime;
				if (FileList_Config.at(FileIndex).ModificationTime == 0 || FileSizeData.QuadPart != FileList_Config.at(FileIndex).ModificationTime)
				{
					FileList_Config.at(FileIndex).ModificationTime = FileSizeData.QuadPart;
					memset(&FileAttributeData, 0, sizeof(FileAttributeData));
					memset(&FileSizeData, 0, sizeof(FileSizeData));
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				if (FileList_Config.at(FileIndex).ModificationTime == 0 || FileStatData.st_mtime != FileList_Config.at(FileIndex).ModificationTime)
				{
					FileList_Config.at(FileIndex).ModificationTime = FileStatData.st_mtime;
					memset(&FileStatData, 0, sizeof(FileStatData));
			#endif
					IsFileModified = true;

				//Read file.
				#if defined(PLATFORM_WIN)
					if (_wfopen_s(&FileHandle, FileList_Config.at(FileIndex).FileName.c_str(), L"rb") == 0)
					{
				#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
					FileHandle = fopen(FileList_Config.at(FileIndex).sFileName.c_str(), "rb");
				#endif
						if (FileHandle == nullptr)
						{
							Sleep(Parameter.FileRefreshTime);
							continue;
						}
						else {
							if (!InnerIsFirstRead)
							{
							//Read data.
								if (ReadText(FileHandle, READ_TEXT_PARAMETER_MONITOR, FileIndex))
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

							fclose(FileHandle);
							FileHandle = nullptr;
						}
				#if defined(PLATFORM_WIN)
					}
				#endif
				}
				else {
			#if defined(PLATFORM_WIN)
					memset(&FileAttributeData, 0, sizeof(FileAttributeData));
					memset(&FileSizeData, 0, sizeof(FileSizeData));
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
					memset(&FileStatData, 0, sizeof(FileStatData));
			#endif
				}
			}

		//Flush DNS cache and Auto-refresh
			if (IsFileModified)
				FlushDNSCache(nullptr);

			Sleep(Parameter.FileRefreshTime);
		}
	}

//Monitor terminated
	PrintError(LOG_LEVEL_2, LOG_ERROR_SYSTEM, L"Read Parameter module Monitor terminated", 0, nullptr, 0);
	return false;
}

//Read IPFilter from file
void ReadIPFilter(
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
			FileDataTemp.ModificationTime = 0;

			FileList_IPFilter.push_back(FileDataTemp);
		}
	}

//Initialization
	FILE *FileHandle = nullptr;
	auto IsFileModified = false;
#if defined(PLATFORM_WIN)
	WIN32_FILE_ATTRIBUTE_DATA FileAttributeData;
	LARGE_INTEGER FileSizeData;
	memset(&FileAttributeData, 0, sizeof(FileAttributeData));
	memset(&FileSizeData, 0, sizeof(FileSizeData));
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	struct stat FileStatData;
	memset(&FileStatData, 0, sizeof(FileStatData));
#endif
	std::unique_lock<std::mutex> IPFilterFileMutex(IPFilterFileLock, std::defer_lock);
	
//File Monitor
	for (;;)
	{
		IsFileModified = false;

	//Check File lists.
		for (FileIndex = 0;FileIndex < FileList_IPFilter.size();++FileIndex)
		{
		//Get attributes of file.
		#if defined(PLATFORM_WIN)
			if (GetFileAttributesExW(FileList_IPFilter.at(FileIndex).FileName.c_str(), GetFileExInfoStandard, &FileAttributeData) == FALSE)
			{
				memset(&FileAttributeData, 0, sizeof(FileAttributeData));
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			if (stat(FileList_IPFilter.at(FileIndex).sFileName.c_str(), &FileStatData) != 0)
			{
				memset(&FileStatData, 0, sizeof(FileStatData));
		#endif
				if (FileList_IPFilter.at(FileIndex).ModificationTime > 0)
					IsFileModified = true;
				FileList_IPFilter.at(FileIndex).ModificationTime = 0;

				ClearModificatingListData(READ_TEXT_IPFILTER, FileIndex);
			}
			else {
			//Check whole file size.
			#if defined(PLATFORM_WIN)
				FileSizeData.HighPart = FileAttributeData.nFileSizeHigh;
				FileSizeData.LowPart = FileAttributeData.nFileSizeLow;
				if (FileSizeData.QuadPart >= DEFAULT_FILE_MAXSIZE)
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				if (FileStatData.st_size >= (off_t)DEFAULT_FILE_MAXSIZE)
			#endif
				{
					PrintError(LOG_LEVEL_3, LOG_ERROR_PARAMETER, L"IPFilter file size is too large", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), 0);

				#if defined(PLATFORM_WIN)
					memset(&FileAttributeData, 0, sizeof(FileAttributeData));
					memset(&FileSizeData, 0, sizeof(FileSizeData));
				#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
					memset(&FileStatData, 0, sizeof(FileStatData));
				#endif
					if (FileList_IPFilter.at(FileIndex).ModificationTime > 0)
						IsFileModified = true;
					FileList_IPFilter.at(FileIndex).ModificationTime = 0;

					ClearModificatingListData(READ_TEXT_IPFILTER, FileIndex);
					continue;
				}

			//Check modification time of file.
			#if defined(PLATFORM_WIN)
				memset(&FileSizeData, 0, sizeof(FileSizeData));
				FileSizeData.HighPart = FileAttributeData.ftLastWriteTime.dwHighDateTime;
				FileSizeData.LowPart = FileAttributeData.ftLastWriteTime.dwLowDateTime;
				if (FileList_IPFilter.at(FileIndex).ModificationTime == 0 || FileSizeData.QuadPart != FileList_IPFilter.at(FileIndex).ModificationTime)
				{
					FileList_IPFilter.at(FileIndex).ModificationTime = FileSizeData.QuadPart;
					memset(&FileAttributeData, 0, sizeof(FileAttributeData));
					memset(&FileSizeData, 0, sizeof(FileSizeData));
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				if (FileList_IPFilter.at(FileIndex).ModificationTime == 0 || FileStatData.st_mtime != FileList_IPFilter.at(FileIndex).ModificationTime)
				{
					FileList_IPFilter.at(FileIndex).ModificationTime = FileStatData.st_mtime;
					memset(&FileStatData, 0, sizeof(FileStatData));
			#endif
					ClearModificatingListData(READ_TEXT_IPFILTER, FileIndex);
					IsFileModified = true;

				//Read file.
				#if defined(PLATFORM_WIN)
					if (_wfopen_s(&FileHandle, FileList_IPFilter.at(FileIndex).FileName.c_str(), L"rb") == 0)
					{
				#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
					FileHandle = fopen(FileList_IPFilter.at(FileIndex).sFileName.c_str(), "rb");
				#endif
						if (FileHandle == nullptr)
						{
							continue;
						}
						else {
						//Scan global list.
							DIFFERNET_FILE_SET_IPFILTER IPFilterFileSetTemp;
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
							ReadText(FileHandle, READ_TEXT_IPFILTER, FileIndex);
							fclose(FileHandle);
							FileHandle = nullptr;
						}
				#if defined(PLATFORM_WIN)
					}
				#endif
				}
				else {
				#if defined(PLATFORM_WIN)
					memset(&FileAttributeData, 0, sizeof(FileAttributeData));
					memset(&FileSizeData, 0, sizeof(FileSizeData));
				#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
					memset(&FileStatData, 0, sizeof(FileStatData));
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
		IPFilterFileSetUsing->clear();
		IPFilterFileSetUsing->shrink_to_fit();
		*IPFilterFileSetUsing = *IPFilterFileSetModificating;
		IPFilterFileMutex.unlock();
		IPFilterFileSetModificating->shrink_to_fit();

	//Flush DNS cache and Auto-refresh
		FlushDNSCache(nullptr);
		Sleep(Parameter.FileRefreshTime);
	}

//Monitor terminated
	PrintError(LOG_LEVEL_2, LOG_ERROR_SYSTEM, L"Read IPFilter module Monitor terminated", 0, nullptr, 0);
	return;
}

//Read hosts from file
void ReadHosts(
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
			FileDataTemp.ModificationTime = 0;

			FileList_Hosts.push_back(FileDataTemp);
		}
	}

//Initialization
	FILE *FileHandle = nullptr;
	auto IsFileModified = false;
#if defined(PLATFORM_WIN)
	WIN32_FILE_ATTRIBUTE_DATA FileAttributeData;
	LARGE_INTEGER FileSizeData;
	memset(&FileAttributeData, 0, sizeof(FileAttributeData));
	memset(&FileSizeData, 0, sizeof(FileSizeData));
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	struct stat FileStatData;
	memset(&FileStatData, 0, sizeof(FileStatData));
#endif
	std::unique_lock<std::mutex> HostsFileMutex(HostsFileLock, std::defer_lock);

//File Monitor
	for (;;)
	{
		IsFileModified = false;

	//Check File lists.
		for (FileIndex = 0;FileIndex < FileList_Hosts.size();++FileIndex)
		{
		//Get attributes of file.
		#if defined(PLATFORM_WIN)
			if (GetFileAttributesExW(FileList_Hosts.at(FileIndex).FileName.c_str(), GetFileExInfoStandard, &FileAttributeData) == FALSE)
			{
				memset(&FileAttributeData, 0, sizeof(FileAttributeData));
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			if (stat(FileList_Hosts.at(FileIndex).sFileName.c_str(), &FileStatData) != 0)
			{
				memset(&FileStatData, 0, sizeof(FileStatData));
		#endif
				if (FileList_Hosts.at(FileIndex).ModificationTime > 0)
					IsFileModified = true;
				FileList_Hosts.at(FileIndex).ModificationTime = 0;

				ClearModificatingListData(READ_TEXT_HOSTS, FileIndex);
			}
			else {
			//Check whole file size.
			#if defined(PLATFORM_WIN)
				FileSizeData.HighPart = FileAttributeData.nFileSizeHigh;
				FileSizeData.LowPart = FileAttributeData.nFileSizeLow;
				if (FileSizeData.QuadPart >= DEFAULT_FILE_MAXSIZE)
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				if (FileStatData.st_size >= (off_t)DEFAULT_FILE_MAXSIZE)
			#endif
				{
					PrintError(LOG_LEVEL_3, LOG_ERROR_PARAMETER, L"Hosts file size is too large", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), 0);

				#if defined(PLATFORM_WIN)
					memset(&FileAttributeData, 0, sizeof(FileAttributeData));
					memset(&FileSizeData, 0, sizeof(FileSizeData));
				#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
					memset(&FileStatData, 0, sizeof(FileStatData));
				#endif
					if (FileList_Hosts.at(FileIndex).ModificationTime > 0)
						IsFileModified = true;
					FileList_Hosts.at(FileIndex).ModificationTime = 0;

					ClearModificatingListData(READ_TEXT_HOSTS, FileIndex);
					continue;
				}

			//Check modification time of file.
			#if defined(PLATFORM_WIN)
				memset(&FileSizeData, 0, sizeof(FileSizeData));
				FileSizeData.HighPart = FileAttributeData.ftLastWriteTime.dwHighDateTime;
				FileSizeData.LowPart = FileAttributeData.ftLastWriteTime.dwLowDateTime;
				if (FileList_Hosts.at(FileIndex).ModificationTime == 0 || FileSizeData.QuadPart != FileList_Hosts.at(FileIndex).ModificationTime)
				{
					FileList_Hosts.at(FileIndex).ModificationTime = FileSizeData.QuadPart;
					memset(&FileAttributeData, 0, sizeof(FileAttributeData));
					memset(&FileSizeData, 0, sizeof(FileSizeData));
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				if (FileList_Hosts.at(FileIndex).ModificationTime == 0 || FileStatData.st_mtime != FileList_Hosts.at(FileIndex).ModificationTime)
				{
					FileList_Hosts.at(FileIndex).ModificationTime = FileStatData.st_mtime;
					memset(&FileStatData, 0, sizeof(FileStatData));
			#endif
					ClearModificatingListData(READ_TEXT_HOSTS, FileIndex);
					IsFileModified = true;

				//Read file.
				#if defined(PLATFORM_WIN)
					if (_wfopen_s(&FileHandle, FileList_Hosts.at(FileIndex).FileName.c_str(), L"rb") == 0)
					{
				#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
					FileHandle = fopen(FileList_Hosts.at(FileIndex).sFileName.c_str(), "rb");
				#endif
						if (FileHandle == nullptr)
						{
							continue;
						}
						else {
						//Scan global list.
							DIFFERNET_FILE_SET_HOSTS HostsFileSetTemp;
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
							ReadText(FileHandle, READ_TEXT_HOSTS, FileIndex);
							fclose(FileHandle);
							FileHandle = nullptr;
						}
				#if defined(PLATFORM_WIN)
					}
				#endif
				}
				else {
				#if defined(PLATFORM_WIN)
					memset(&FileAttributeData, 0, sizeof(FileAttributeData));
					memset(&FileSizeData, 0, sizeof(FileSizeData));
				#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
					memset(&FileStatData, 0, sizeof(FileStatData));
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
		std::sort(HostsFileSetModificating->begin(), HostsFileSetModificating->end(), SortCompare_Hosts);
		HostsFileMutex.lock();
		HostsFileSetUsing->clear();
		HostsFileSetUsing->shrink_to_fit();
		*HostsFileSetUsing = *HostsFileSetModificating;
		HostsFileMutex.unlock();
		HostsFileSetModificating->shrink_to_fit();

	//Flush DNS cache and Auto-refresh
		FlushDNSCache(nullptr);
		Sleep(Parameter.FileRefreshTime);
	}

//Monitor terminated
	PrintError(LOG_LEVEL_2, LOG_ERROR_SYSTEM, L"Read Hosts module Monitor terminated", 0, nullptr, 0);
	return;
}

//Clear data in list
void ClearModificatingListData(
	const size_t ClearType, 
	const size_t FileIndex)
{
//Clear Hosts file set.
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

//Clear IPFilter file set.
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
void GetParameterListData(
	std::vector<std::string> &ListData, 
	const std::string Data, 
	const size_t DataOffset, 
	const size_t Length)
{
//Initialization
	std::string NameString;
	ListData.clear();

//Get all list data.
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

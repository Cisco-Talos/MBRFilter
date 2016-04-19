/*++
  AccessMBR

  Simple program to read sector 0 on Physical drive 0 and write that sector back.
  Used as a testing program for MBRFilter. This overwrites your MBR, albeit with 
  data that's already there, nevertheless: USE WITH CAUTION.

  Written by Yves Younan, Cisco Talos
  Copyright (C) 2016 Cisco Systems Inc

  Thanks to Aaron Adams for reviewing the code. 

--*/

#include "stdafx.h"
#include "Windows.h"

#define BOOTSIG1 0x55
#define BOOTSIG2 0xAA

int _tmain(int argc, _TCHAR* argv[])
{
	DWORD read, wrote, pos;
	unsigned char buf[512];
	HANDLE hDisk = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING|FILE_FLAG_RANDOM_ACCESS, NULL);
	if (!ReadFile(hDisk, buf, 512, &read, 0)) {
		printf("Read failed\n");
		return 0;
	}
	if (buf[510]== BOOTSIG1 && buf[511] == BOOTSIG2){
		printf("Disk bootable\n");
	} else {
		printf("Disk not bootable\n");
	}
	pos = SetFilePointer(hDisk, 0, NULL, FILE_BEGIN);
	if (pos == INVALID_SET_FILE_POINTER) {
		printf("SetFilePos failed\n");
		return 0;
	}
	if (!WriteFile(hDisk, buf, read, &wrote, 0)) {
		printf("Write failed\n");
		return 0;
	}
	printf("Succesfully read/wrote sector 0 on PhysicalDrive0: read %d, wrote: %d\n", read, wrote);
	return 0;
}


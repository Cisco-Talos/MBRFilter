/*++
  AccessMBR

  Simple program to read sector 0 on Physical drive 0 and write that sector back.
  Used as a testing program for MBRFilter. This overwrites your MBR, it will 
  restore it once it's done. 
  Nevertheless: USE WITH CAUTION.

  Written by Yves Younan, Cisco Talos
  Copyright (C) 2016 Cisco Systems Inc

  Thanks to Aaron Adams for reviewing the code. 
  Using Andrea Allievi's AaLl86WriteMbr

  No warranty: this program will likely break something. 
--*/

#include "stdafx.h"
#include "Windows.h"
#include <stdio.h>
#include <stdlib.h>

#include "SCSI_IO.h"

#define BOOTSIG1 0x55
#define BOOTSIG2 0xAA

BOOL doWrite(HANDLE hDisk, unsigned char *buf, DWORD read, int drivenumber, char *writetype) {
	DWORD wrote;
	BOOL success = FALSE; 

	if (writetype && writetype[0] == 's') {
		printf("Trying SCSI passthrough write\n");
		success = AaLl86WriteMbr(hDisk, buf);
	} else if (writetype && writetype[0] == 'r') {
		printf("Trying regular write\n");
		success = WriteFile(hDisk, buf, read, &wrote, 0);
	} else {
		printf("Trying regular write\n");
		success = WriteFile(hDisk, buf, read, &wrote, 0);
		if (!success) {
			printf("Regular write failed trying SCSI passthrough write\n");	
			success = AaLl86WriteMbr(hDisk, buf);
		}
	}
	if (success)
		printf("Succesfully read/wrote sector 0 on PhysicalDrive %d: read %d, wrote: %d\n", drivenumber, read, wrote);
	else
		printf("Write failed on PhysicalDrive %d\n", drivenumber);
	return success;
}

int _tmain(int argc, _TCHAR* argv[])
{
	DWORD read, pos;
	unsigned char buf[512];
	char sigval1,sigval2;
	int drivenumber = 0;
	char drivestr[512];
	char *writetype = NULL;
	if (argc > 2) {
		drivenumber = atoi(argv[1]); 
		writetype = argv[2];
	}
	_snprintf_s(drivestr, 512, _TRUNCATE, "\\\\.\\PhysicalDrive%d", drivenumber);
	printf("Accessing: %s\n", drivestr);
	HANDLE hDisk = CreateFileA(drivestr, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING|FILE_FLAG_RANDOM_ACCESS, NULL);
	if (!ReadFile(hDisk, buf, 512, &read, 0)) {
		printf("Read failed\n");
		return 0;
	}
	if (buf[510]== BOOTSIG1 && buf[511] == BOOTSIG2){
		printf("Disk bootable\n");
	} else {
		printf("Disk not bootable\n");
	}
	sigval1=buf[510];
	sigval2=buf[511];
	buf[510]='Y';
	buf[511]='Y';
	pos = SetFilePointer(hDisk, 0, NULL, FILE_BEGIN);
	if (pos == INVALID_SET_FILE_POINTER) {
		printf("SetFilePos failed\n");
		return 0;
	}
	if (!doWrite(hDisk, buf, read, drivenumber,writetype)) {
		return 0;
	}
	pos = SetFilePointer(hDisk, 0, NULL, FILE_BEGIN);
	if (pos == INVALID_SET_FILE_POINTER) {
		printf("SetFilePos failed\n");
		return 0;
	}
	if (!ReadFile(hDisk, buf, 512, &read, 0)) {
		printf("Second read failed\n");
		return 0;
	}
	pos = SetFilePointer(hDisk, 0, NULL, FILE_BEGIN);
	if (pos == INVALID_SET_FILE_POINTER) {
		printf("SetFilePos failed\n");
		return 0;
	}
	if (buf[510] == 'Y' && buf[511] == 'Y') {
		printf("Write completed succesfully, restoring\n");
		buf[510]=sigval1;
		buf[511]=sigval2;
		doWrite(hDisk,buf,read, drivenumber,writetype);
	} else {
		printf("Restore write seems to have failed\n");
	}
	CloseHandle(hDisk);
	return 0;
}


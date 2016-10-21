  MBRFilter

   This is a simple disk filter based on Microsoft's diskperf and classpnp example drivers.

  The goal of this filter is to prevent writing to Sector 0 on disks.
  This is useful to prevent malware that overwrites the MBR like Petya.

  This driver will prevent writes to sector 0 on all drives. This can cause an 
  issue when initializing a new disk in the Disk Management application. Hit 
  'Cancel' when asks you to write to the MBR/GPT and it should work as expected.
  Alternatively, if OK was clicked, then quitting and restarting the application
  will allow partitoning/formatting.


  To install: right click the inf file, select 'install' and reboot when prompted.
  To access sector 0 on drive 0: boot into Safe Mode. 
  To compile: make sure to set:
	MBRFilter properties -> Configuration properties -> Driver Signing -> General
		Sign mode: Test Sign
		Test certificate: generate or select one from your store.

To remove MBRFilter, follow these steps:

- Remove the line MBRFilter from the UpperFilters registry key in (only
remove MBRFilter, there might be other disk drivers here):

HKLM\System\CurrentControlSet\Control\Class\{4d36e967-e325-11ce-bfc1-08002be10318}

- Reboot

  AccessMBR

  Simple program to read sector 0 on Physical drive 0 and write that sector back.
  Used as a testing program for MBRFilter. This overwrites your MBR, it will 
  restore it once it's done. 
  Nevertheless: USE WITH CAUTION.


  MBRFilter and AccessMbr Written by Yves Younan, Cisco Talos
  SCSI passthrough part of AccessMBR written by Andrea Alleivi, Cisco Talos

  Copyright (C) 2016 Cisco Systems Inc

  Thanks to Andrea Alleivi for suggested fixes.
  Thanks to Aaron Adams and Ilja Van Sprundel for reviewing the code. 

  No warranty: use at your own risk.


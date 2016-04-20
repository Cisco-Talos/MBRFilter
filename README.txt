  MBRFilter

  This is a simple disk filter based on Microsoft's diskperf example driver.
  The goal of this filter is to prevent writing to Sector 0 on Physical Drive 0. 
  This is useful to prevent malware that overwrites the MBR like Petya.

  This driver will prevent writes to sector 0 on all drives. This can cause an 
  issue when initializing a new disk in the Disk Management application. Hit 
  'Cancel' when asks you to write to the MBR/GPT and it should work as expected.
  Alternatively, if OK was clicked, then quitting and restarting the application
  will allow partitoning/formatting.
  
  Note this can still be byopassed by a sending a SCSI passthrough command

  To install: Right click the inf file, select 'install' and reboot when prompted.
  To access sector 0 on drive 0: boot into Safe Mode. 
  To compile: make sure to set:
	MBRFilter properties -> Configuration properties -> Driver Signing -> General
		Sign mode: Test Sign
		Test certificate: generate or select one from your store.

  AccessMBR

  Simple program to read sector 0 on Physical drive 0 and write that sector back.
  Used as a testing program for MBRFilter. This overwrites your MBR, albeit with 
  data that's already there, nevertheless: USE WITH CAUTION.




  Written by Yves Younan, Cisco Talos
  Copyright (C) 2016 Cisco Systems Inc


  Thanks to Aaron Adams for reviewing the code. 

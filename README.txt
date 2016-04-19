  MBRFilter

  This is a simple disk filter based on Microsoft's diskperf example driver.
  The goal of this filter is to prevent writing to Sector 0 on Physical Drive 0. 
  This is useful to prevent malware that overwrites the MBR like Petya.

  While the MBR could be on another disk, we try to remain minimally intrusive: writing to 
  sector 0 on other drives might be desirable. This can easily be changed by modifying 
  the if statement at line 237.

  To install: double click the inf file and reboot.
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

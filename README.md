# PanoptesEDR
Panoptes Endpoint Detection and Response Solution


## TODO

- [x] Add Exclusion List
- [x] Verify if executable is signed by reputable publisher
- [x] Yara Scanning (Recursively)
- [x] API Hooking (NtWriteVirtualMemory, etc)
### CPack
- [ ] Install the driver while user is installing
### Functionality
- [ ] Check for other loaded drivers
- [ ] Only allow trusted processes to connect to the named pipe
- [ ] Split out the yara scanning to its own executable
- [ ] Communicate DLL with named pipe

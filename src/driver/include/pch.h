#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <ntdef.h>

#define KERNEL_LINK L"\\Device\\Panoptes"
#define KERNEL_LINK_SYM L"\\DosDevices\\Panoptes"
#define KERNEL_DRIVER_SERVICE_NAME "Panoptes"
#define KERNEL_SERVICE_NAME "Panoptes"
#define PANOPTES_PREFIX_ERROR "[!] Panoptes: "
#define PANOPTES_PREFIX_WARNING "[-] Panoptes: "
#define PANOPTES_PREFIX_SUCCESS "[+] Panoptes: "
#define DRIVER_TAG 'stnP' // 'Pnts'

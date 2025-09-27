//
// Created by cryptic on 4/19/24.
//

/**
 * @file offsets.c
 * @author Cryptiiiic
 * @brief This file is for all kernel offset related code.
 * @version 1.0.1
 * @date 2024-04-19
 *
 * @copyright Copyright (c) 2024
 */

/* Include headers */
#include <x8A4/Kernel/offsets.h>
#include <x8A4/Kernel/osobject.h>
#include <x8A4/Logger/logger.h>
#include <x8A4/x8A4.h>

/* Structure Variables */
struct kernel_offsets *koffsets_cached;

/* Functions */
/**
 * @brief          Init kernel offsets
 * @return         Zero on init success
 */
int offsets_init(void) {
  if (!gXPF.kernel || !gXPF.kernelSize) {
    x8A4_log_error("Failed XPF kernel is NULL!\n", "");
    return -1;
  }
  if (!gXPF.darwinVersion) {
    x8A4_log_error("Failed XPF kernel darwinVersion is NULL!\n", "");
    return -1;
  }
  if(strcmp(gXPF.darwinVersion, "16.0.0") < 0) {
    x8A4_log_error("Unsupported iOS version!\n", "");
    return -1;
  }
  bool ios_1000 = (strcmp(gXPF.darwinVersion, "16.0.0") >= 0);
  bool ios_1100 = (strcmp(gXPF.darwinVersion, "17.0.0") >= 0);
  bool ios_1200 = (strcmp(gXPF.darwinVersion, "18.0.0") >= 0);
  bool ios_1300 = (strcmp(gXPF.darwinVersion, "19.0.0") == 0);
  bool ios_1300b2 = (strcmp(gXPF.darwinVersion, "19.0.0") >= 0) && (strcmp(gXPF.xnuBuild, "6110.0.0.120.8") >= 0);
  bool ios_1400 = (strcmp(gXPF.darwinVersion, "20.0.0") == 0);
  bool ios_1430b = (strcmp(gXPF.darwinVersion, "20.2.0") >= 0) && (strcmp(gXPF.xnuBuild, "7195.50.3.201.1") >= 0);
  bool ios_1430b_ = (strcmp(gXPF.darwinVersion, "20.2.0") >= 0) && (strcmp(gXPF.xnuBuild, "7195.60.69") >= 0);
  bool ios_1500 = (strcmp(gXPF.darwinVersion, "21.0.0") >= 0);
  bool ios_1540 = (strcmp(gXPF.darwinVersion, "21.4.0") >= 0);
  bool ios_1600 = (strcmp(gXPF.darwinVersion, "22.0.0") >= 0);
  bool ios_1610 = (strcmp(gXPF.darwinVersion, "22.1.0") >= 0);
  bool ios_1630 = (strcmp(gXPF.darwinVersion, "22.3.0") >= 0);
  bool ios_1640 = (strcmp(gXPF.darwinVersion, "22.4.0") >= 0);
  bool ios_1700 = (strcmp(gXPF.darwinVersion, "23.0.0") >= 0);
  bool ios_1800 = (strcmp(gXPF.darwinVersion, "24.0.0") >= 0);
  bool ios_1810 = (strcmp(gXPF.darwinVersion, "24.1.0") >= 0);
  koffsets_cached = (struct kernel_offsets *)calloc(1, sizeof(struct kernel_offsets));
  if (!koffsets_cached) {
    x8A4_log_error("Failed calloc kernel_offsets, impossible!\n", "");
    return -1;
  }
  koffsets_cached->macos = 0;
  const char *DTPlatformName = strstr(gXPF.kernelInfoPlist, "<key>DTPlatformName</key>");
  char osName[100];
  sscanf(DTPlatformName, "<key>DTPlatformName</key>\t<string>%9[^<]</string>", osName);
  if(strcmp(osName, "macosx") == 0) {
    koffsets_cached->macos = 1;
  }
  koffsets_cached->proc_pid = 0x10;
  koffsets_cached->proc_task = 0x18;
  koffsets_cached->proc_list_next = 0x0;
  koffsets_cached->task_itk_space_table = 0x20;
  koffsets_cached->table_smr = 0x0;
  koffsets_cached->smr = 0x0;
  koffsets_cached->ipc_entry_object = 0x0;
  koffsets_cached->ipc_entry_size = 0x18;
  koffsets_cached->ipc_port_kobject = 0x68;
  koffsets_cached->ipc_port_kobject_is_iomachport = 0x0;
  koffsets_cached->iomachport_object = 0x30;
  koffsets_cached->io_dt_nvram = 0xC0;
  koffsets_cached->os_dict = 0x20;
  koffsets_cached->os_dict_size = 0x14;
  koffsets_cached->os_string = 0x10;
  koffsets_cached->os_metabase_size = 0xC;
  koffsets_cached->os_data = 0x18;
  koffsets_cached->io_aes_accel_special_keys = 0xD0;
  koffsets_cached->io_aes_accel_special_keys_size = 0xD8;
  if (ios_1000) {
  }
  if (ios_1100) {
  }
  if (ios_1200) {
    koffsets_cached->proc_pid = 0x60;
    koffsets_cached->proc_task = 0x10;
  }
  if (ios_1300) {
  }
  if (ios_1300b2) {
    koffsets_cached->proc_pid = 0x68;
  }
  if (ios_1400) {
    koffsets_cached->io_dt_nvram = 0xB8;
  }
  if (ios_1430b) {
    if(koffsets_cached->macos) {
      koffsets_cached->io_dt_nvram = 0xE0;
    } else {
      koffsets_cached->io_dt_nvram = 0xC0;
    }
  }
  if (ios_1430b_) {
    if(koffsets_cached->macos) {
      koffsets_cached->io_dt_nvram = 0xE8;
    } else {
      koffsets_cached->io_dt_nvram = 0xC8;
    }
  }
  if (ios_1500) {
    koffsets_cached->proc_pid = 0x68;
    koffsets_cached->proc_task = 0x10;
    koffsets_cached->ipc_port_kobject = 0x58;
    koffsets_cached->io_dt_nvram = 0xC8;
  }
  if (ios_1540) {
    koffsets_cached->ipc_port_kobject = 0x48;
    if(koffsets_cached->macos) {
      koffsets_cached->io_dt_nvram = 0xC0;
    } else {
      koffsets_cached->io_dt_nvram = 0xB8;
    }
  }
  if (ios_1600) {
    koffsets_cached->proc_pid = 0x60;
    koffsets_cached->smr = 0x3;
    if(koffsets_cached->macos) {
      koffsets_cached->io_dt_nvram = 0xC8;
    } else {
      koffsets_cached->io_dt_nvram = 0xC0;
    }
  }
  if (ios_1610) {
    koffsets_cached->table_smr = 0x1;
  }
  if (ios_1630) {
    koffsets_cached->smr = 0x2;
  }
  if (ios_1640) {
  }
  if (ios_1700) {
    koffsets_cached->ipc_port_kobject = 0x48;
    koffsets_cached->ipc_port_kobject_is_iomachport = 0x1;
  }
  if (ios_1800) {

  }
  if (ios_1810) {

  }
  koffsets_cached->os_list[OS_DATA] = koffsets_cached->os_data;
  koffsets_cached->os_list[OS_STRING] = koffsets_cached->os_string;
  if (!koffsets_cached->t1sz_boot) {
    koffsets_cached->t1sz_boot = xpf_item_resolve("kernelConstant.T1SZ_BOOT");
    if (!koffsets_cached->t1sz_boot) {
      x8A4_log_error("Failed to find kernel T1SZ_BOOT!\n", "");
      return 0;
    }
  }
  if (!koffsets_cached->itk_space) {
    koffsets_cached->itk_space =
        xpf_item_resolve("kernelStruct.task.itk_space");
    if (!koffsets_cached->itk_space) {
      x8A4_log_error("Failed to find kernel task itk_space!\n", "");
      return 0;
    }
  }
  if (!koffsets_cached->proc_struct_size) {
    koffsets_cached->proc_struct_size =
        xpf_item_resolve("kernelStruct.proc.struct_size");
    if (!koffsets_cached->proc_struct_size) {
      x8A4_log_error("Failed to find kernel proc_struct_size!\n", "");
      return 0;
    }
  }
  if (!koffsets_cached->all_proc) {
    koffsets_cached->all_proc = xpf_item_resolve("kernelSymbol.allproc");
    if (!koffsets_cached->all_proc) {
      x8A4_log_error("Failed to find kernel proc all_proc!\n", "");
      return 0;
    }
  }
  if(verbose_cached) {
    x8A4_log_debug("koffsets_cached->proc_pid: 0x%016llX\n", koffsets_cached->proc_pid);
    x8A4_log_debug("koffsets_cached->proc_task: 0x%016llX\n", koffsets_cached->proc_task);
    x8A4_log_debug("koffsets_cached->proc_list_next: 0x%016llX\n", koffsets_cached->proc_list_next);
    x8A4_log_debug("koffsets_cached->proc_struct_size: 0x%016llX\n", koffsets_cached->proc_struct_size);
    x8A4_log_debug("koffsets_cached->all_proc: 0x%016llX\n", koffsets_cached->all_proc);
    x8A4_log_debug("koffsets_cached->itk_space: 0x%016llX\n", koffsets_cached->itk_space);
    x8A4_log_debug("koffsets_cached->task_itk_space_table: 0x%016llX\n", koffsets_cached->task_itk_space_table);
    x8A4_log_debug("koffsets_cached->table_smr: 0x%016llX\n", koffsets_cached->table_smr);
    x8A4_log_debug("koffsets_cached->smr: 0x%016llX\n", koffsets_cached->smr);
    x8A4_log_debug("koffsets_cached->ipc_entry_object: 0x%016llX\n", koffsets_cached->ipc_entry_object);
    x8A4_log_debug("koffsets_cached->ipc_entry_size: 0x%016llX\n", koffsets_cached->ipc_entry_size);
    x8A4_log_debug("koffsets_cached->ipc_port_kobject: 0x%016llX\n", koffsets_cached->ipc_port_kobject);
    x8A4_log_debug("koffsets_cached->ipc_port_kobject_is_iomachport: 0x%016llX\n", koffsets_cached->ipc_port_kobject_is_iomachport);
    x8A4_log_debug("koffsets_cached->iomachport_object: 0x%016llX\n", koffsets_cached->iomachport_object);
    x8A4_log_debug("koffsets_cached->t1sz_boot: 0x%016llX\n", koffsets_cached->t1sz_boot);
    x8A4_log_debug("koffsets_cached->io_dt_nvram: 0x%016llX\n", koffsets_cached->io_dt_nvram);
    x8A4_log_debug("koffsets_cached->os_dict: 0x%016llX\n", koffsets_cached->os_dict);
    x8A4_log_debug("koffsets_cached->os_dict_size: 0x%016llX\n", koffsets_cached->os_dict_size);
    x8A4_log_debug("koffsets_cached->os_string: 0x%016llX\n", koffsets_cached->os_string);
    x8A4_log_debug("koffsets_cached->os_metabase_size: 0x%016llX\n", koffsets_cached->os_metabase_size);
    x8A4_log_debug("koffsets_cached->os_data: 0x%016llX\n", koffsets_cached->os_data);
    x8A4_log_debug("koffsets_cached->os_list[OS_DATA]: 0x%016llX\n", koffsets_cached->os_list[OS_DATA]);
    x8A4_log_debug("koffsets_cached->os_list[OS_DATA]: 0x%016llX\n", koffsets_cached->os_list[OS_STRING]);
    x8A4_log_debug("koffsets_cached->io_aes_accel_special_keys: 0x%016llX\n", koffsets_cached->io_aes_accel_special_keys);
    x8A4_log_debug("koffsets_cached->io_aes_accel_special_keys_size: 0x%016llX\n", koffsets_cached->io_aes_accel_special_keys_size);
  }
  return 0;
}

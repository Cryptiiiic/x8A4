//
// Created by cryptic on 4/19/24.
//

/**
 * @file offsets.h
 * @author Cryptiiiic
 * @brief This file is the header file for offsets.c
 * @version 1.0.1
 * @date 2024-04-19
 *
 * @copyright Copyright (c) 2024
 */

#ifndef X8A4_OFFSETS_H
#define X8A4_OFFSETS_H

/* Include headers */
#include <stdint.h>

/* Enum Variables */
enum apple_mobile_apnonce_external_selectors {
  APPLE_MOBILE_AP_NONCE_GENERATE_NONCE_SEL = 0xC8,
  APPLE_MOBILE_AP_NONCE_CLEAR_NONCE_SEL = 0xC9,
  APPLE_MOBILE_AP_NONCE_RETRIEVE_NONCE_SEL = 0xCA,
};

/* Structure Variables */
struct kernel_offsets {
  uint64_t macos;
  uint64_t proc_pid;
  uint64_t proc_task;
  uint64_t proc_list_next;
  uint64_t proc_struct_size;
  uint64_t all_proc;
  uint64_t itk_space;
  uint64_t task_itk_space_table;
  uint64_t table_smr;
  uint64_t smr;
  uint64_t ipc_entry_object;
  uint64_t ipc_entry_size;
  uint64_t ipc_port_kobject;
  uint64_t ipc_port_kobject_is_iomachport;
  uint64_t iomachport_object;
  uint64_t t1sz_boot;
  uint64_t io_dt_nvram;
  uint64_t os_dict;
  uint64_t os_dict_size;
  uint64_t os_string;
  uint64_t os_metabase_size;
  uint64_t os_data;
  uint64_t os_list[2];
  uint64_t io_aes_accel_special_keys;
  uint64_t io_aes_accel_special_keys_size;
};

/* Prototypes */
int offsets_init(void);

/* External Variables */
extern struct kernel_offsets *koffsets_cached;

#endif // X8A4_OFFSETS_H

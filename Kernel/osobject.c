//
// Created by cryptic on 12/19/24.
//

/**
 * @file osobject.c
 * @author Cryptiiiic
 * @brief This file is for all kernel osobject related code.
 * @version 1.0.1
 * @date 2024-12-19
 *
 * @copyright Copyright (c) 2024
 */

/* Include headers */
#include <libkrw.h>
#include <x8A4/Kernel/kernel.h>
#include <x8A4/Kernel/offsets.h>
#include <x8A4/Kernel/osobject.h>
#include <x8A4/Logger/logger.h>

/**
 * @brief           Cast an OSObject to a new type
 * @param[in]       object
 * @param[in]       type
 * @return          OS object
 */
uint64_t os_object_cast(uint64_t object, enum os_type type) {
  uint64_t out = 0;
  int ret = kread(object + koffsets_cached->os_list[type], &out, 8);
  if (ret || !out) {
    return 0;
  }
  return unsign_ptr(&out);
}

/**
 * @brief           Get an OSObject's OS metabase size
 * @param[in]       object
 * @return          OS metabase size
 */
uint32_t get_os_metabase_size(uint64_t object) {
  uint32_t object_len = 0;
  int ret = kread(object + koffsets_cached->os_metabase_size, &object_len, 4);
  if (ret || !object_len) {
    return 0;
  }
  return object_len;
}

/**
 * @brief           Get the OS dict address from an OSObject
 * @param[in]       os_object
 * @return          OS dict address
 */
uint64_t get_os_dict_from_os_object(uint64_t os_object) {
  if (!os_object) {
    return 0;
  }
  uint64_t dict_entry = 0;
  int ret = kread(os_object + koffsets_cached->os_dict, &dict_entry, 8);
  if (ret || !dict_entry) {
    x8A4_log_error("Failed to read kernel os dict from nvram dict! (%d:0x%016llX)\n", ret, dict_entry);
    return 0;
  }
  return unsign_ptr(&dict_entry);
}

/**
 * @brief           Get the size of the OS dict
 * @param[in]       dict
 * @return          OS dict size
 */
uint32_t get_os_dict_size(uint64_t dict) {
  if (!dict) {
    return 0;
  }
  uint32_t dict_size = 0;
  int ret = kread(dict + koffsets_cached->os_dict_size, &dict_size, 8);
  if (ret || !dict_size) {
    x8A4_log_error("Failed to read kernel os dict size from os dict! (%d:0x%08X)\n", ret, dict_size);
    return 0;
  }
  return dict_size;
}

/**
 * @brief           Extract an OSObject's size
 * @return          Extracted size
 */
uint32_t extract_os_size(uint32_t *size) {
  if (!size) {
    return 0;
  }
  if (!*size) {
    return 0;
  }
  *size = (*size >> 14) & (~0U >> (32U - 18));
  return *size;
}


/**
 * @brief           Get the matching key entry from an OS dict
 * @param[in]       dict
 * @param[in]       entry_type
 * @param[in]       entry_key
 * @param[out]      out_size
 * @return          Address of the entry
 */
uint64_t get_entry_from_os_dict(uint64_t dict, enum os_type entry_type,
                                   const char *entry_key, uint32_t *out_size) {
  if (!dict) {
    x8A4_log_error("Failed to get entry from os dict, dict is NULL!\n", "");
    return 0;
  }
  if (!entry_key) {
    x8A4_log_error("Failed to get entry from os dict, entry key is NULL!\n", "");
    return 0;
  }
  size_t entry_key_len = strlen(entry_key) + 1;
  if (!entry_key_len) {
    x8A4_log_error("Failed to get entry from os dict, entry key is empty!\n", "");
    return 0;
  }
  uint64_t os_dict_entry = get_os_dict_from_os_object(dict);
  if (!os_dict_entry) {
    x8A4_log_error("Failed to get entry from os dict, os dict entry is zero!\n", "");
    return 0;
  }
  uint64_t os_dict_size = get_os_dict_size(dict);
  if (!os_dict_size) {
    x8A4_log_error("Failed to get entry from os dict, os dict size is zero!\n", "");
    return 0;
  }
  int ret;
  uint64_t data = 0;
  struct os_dict_entry current_entry = {0};
  for (int i = 0; i < os_dict_size + 1; i++) {
    ret = kread(os_dict_entry + (i * sizeof(struct os_dict_entry)),
                &current_entry, sizeof(struct os_dict_entry));
    if (ret || !current_entry.key) {
      x8A4_log_debug_error("Failed to read kernel entry from os dict! (%d)\n", ret);
      continue;
    }
    uint32_t key_len = get_os_metabase_size(current_entry.key);
    extract_os_size(&key_len);
    if (!key_len) {
      continue;
    }
    uint64_t key = os_object_cast(current_entry.key, OS_STRING);
    if (!key) {
      continue;
    }
    char key_string[PATH_MAX];
    if (key_len >= sizeof(key_string)) {
      continue;
    }
    ret = kread(key, key_string, key_len);
    if (ret || key_string[0] == '\0') {
      continue;
    }
    if (strcmp(key_string, entry_key) == 0) {
      data = os_object_cast(current_entry.val, entry_type);
      if (!data) {
        continue;
      }
      unsign_ptr(&data);
      if (out_size) {
        *out_size = get_os_metabase_size(current_entry.val);
        if(entry_type == OS_STRING) {
          extract_os_size(out_size);
        }
      }
      return data;
    }
  }
  x8A4_log_debug_error("Failed to to find entry %s in os dict!\n", entry_key);
  return 0;
}

//
// Created by cryptic on 12/19/24.
//

/**
 * @file nvram.c
 * @author Cryptiiiic
 * @brief This file is for all kernel nvram related code.
 * @version 1.0.1
 * @date 2024-12-19
 *
 * @copyright Copyright (c) 2024
 */

/* Include headers */
#include <libkrw.h>
#include <x8A4/Kernel/kernel.h>
#include <x8A4/Kernel/offsets.h>
#include <x8A4/Kernel/nvram.h>
#include <x8A4/Kernel/osobject.h>
#include <x8A4/Logger/logger.h>
#include <x8A4/x8A4.h>

/* Cached Variables */
struct nvram_key *nvram_keys_cached;
int nvram_keys_count_cached = -1;

/* Bounds used when locating the nvram variables dictionary inside the
 * IODTNVRAM service object, see get_service_nvram_dict(). The dictionary moved
 * between releases, so rather than a fixed offset we scan the object and, one
 * level deeper, the IODTNVRAMVariables member that holds it on iOS 16+. */
#define NVRAM_SCAN_MIN 0x10
#define NVRAM_SCAN_MAX 0x600
#define NVRAM_SUBSCAN_MIN 0x10
#define NVRAM_SUBSCAN_MAX 0x80
#define NVRAM_DICT_MAX_ENTRIES 0x1000
#define NVRAM_SCORE_KEYS 64
#define NVRAM_KEY_BUF 128

/* Functions */
/**
 * @brief           Heuristic check for a plausible kernel heap pointer
 * @param[in]       ptr
 * @return          Non-zero if ptr looks like an 8-byte-aligned kernel pointer
 */
static inline int is_kernel_pointer(uint64_t ptr) {
  return ptr && (ptr & 7) == 0 && (ptr >> 40) != 0;
}

/**
 * @brief           Score a candidate OSDictionary as the nvram variables dict
 *
 * The IODTNVRAM variables dictionary is the only dictionary reachable from the
 * options service whose keys carry an NVRAM GUID prefix (e.g.
 * "7C436110-AB2A-4BBB-A880-FE41995C9F82:boot-args"), which lets us identify it
 * without depending on a fixed struct offset. System-GUID matches are weighted
 * above common-GUID matches so the system variables dict wins when both exist.
 *
 * @param[in]       dict
 * @return          sys_guid_count * 1000 + common_guid_count (0 if not a dict)
 */
static int score_nvram_dict(uint64_t dict) {
  uint64_t entries = 0;
  if (kread(dict + koffsets_cached->os_dict, &entries, 8) || !entries) {
    return 0;
  }
  unsign_ptr(&entries);
  uint64_t size = 0;
  if (kread(dict + koffsets_cached->os_dict_size, &size, 8)) {
    return 0;
  }
  uint32_t count = (uint32_t)size;
  if (count == 0 || count > NVRAM_DICT_MAX_ENTRIES) {
    return 0;
  }
  if (count > NVRAM_SCORE_KEYS) {
    count = NVRAM_SCORE_KEYS;
  }
  const size_t sys_guid_len = strlen(kAppleSystemVarGUID);
  const size_t common_guid_len = strlen(kAppleNVRAMGUID);
  int sys_guid = 0;
  int common_guid = 0;
  for (uint32_t i = 0; i < count; i++) {
    struct os_dict_entry entry = {0};
    if (kread(entries + i * sizeof(entry), &entry, sizeof(entry)) ||
        !entry.key) {
      continue;
    }
    uint32_t key_len = get_os_metabase_size(entry.key);
    extract_os_size(&key_len);
    if (key_len == 0 || key_len >= NVRAM_KEY_BUF) {
      continue;
    }
    uint64_t key_str = os_object_cast(entry.key, OS_STRING);
    if (!key_str) {
      continue;
    }
    char key[NVRAM_KEY_BUF] = {0};
    if (kread(key_str, key, key_len)) {
      continue;
    }
    if (strncmp(key, kAppleSystemVarGUID, sys_guid_len) == 0) {
      sys_guid++;
    } else if (strncmp(key, kAppleNVRAMGUID, common_guid_len) == 0) {
      common_guid++;
    }
  }
  return sys_guid * 1000 + common_guid;
}

/**
 * @brief           Get the nvram variables dictionary for a service
 *
 * On iOS 16+ the IODTNVRAM struct layout changed: the variables dictionary is
 * no longer at a fixed offset but held inside an IODTNVRAMVariables member.
 * This function scans the kobject (and one level deep) for the OSDictionary
 * whose keys carry an NVRAM GUID prefix, which is the only dictionary in the
 * object graph with that property.
 *
 * @param[in]       service  The IODeviceTree:/options service
 * @return          Kernel address of the variables OSDictionary, or 0
 */
uint64_t get_service_nvram_dict(io_service_t service) {
  uint64_t kobject = get_ipc_kobject(service);
  if (!kobject) {
    x8A4_log_error("Kobject is NULL!\n", "");
    return 0;
  }
  x8A4_log_debug("Locating nvram dict from kobject 0x%016llX\n", kobject);
  uint64_t best_dict = 0;
  int best_score = 0;
  for (uint32_t off = NVRAM_SCAN_MIN; off <= NVRAM_SCAN_MAX; off += 8) {
    uint64_t cand = 0;
    if (kread(kobject + off, &cand, 8) || !is_kernel_pointer(cand)) {
      continue;
    }
    int score = score_nvram_dict(cand);
    if (score > best_score) {
      best_score = score;
      best_dict = cand;
    }
    for (uint32_t soff = NVRAM_SUBSCAN_MIN; soff <= NVRAM_SUBSCAN_MAX; soff += 8) {
      uint64_t sub = 0;
      if (kread(cand + soff, &sub, 8) || !is_kernel_pointer(sub)) {
        continue;
      }
      int subscore = score_nvram_dict(sub);
      if (subscore > best_score) {
        best_score = subscore;
        best_dict = sub;
      }
    }
  }
  if (!best_dict) {
    x8A4_log_error("Failed to find nvram dict by scanning kobject!\n", "");
    return 0;
  }
  x8A4_log_debug("Found nvram dict 0x%016llX (guid-score=%d)\n",
                 best_dict, best_score);
  return best_dict;
}

/**
 * @brief           Find key name in key name cache
 * @param[in]       key
 * @param[in]       type
 * @return          Name of the key
 */
const char *find_nvram_key(const char *key, enum nvram_key_type type) {
  if(!key || (strlen(key) == 0)) {
    return NULL;
  }
  if(!nvram_keys_cached) {
    return NULL;
  }
  for(int i = 0; i < nvram_keys_count_cached; i++) {
    if(nvram_keys_cached[i].type != type) {
      continue;
    }
    if(strlen(key) != strlen(nvram_keys_cached[i].key_original)) {
      continue;
    }
    if(strcmp(nvram_keys_cached[i].key_original, key) == 0 && strstr(nvram_keys_cached[i].key, key)) {
      return nvram_keys_cached[i].key;
    }
  }
  return NULL;
}

/**
 * @brief           Setup key name cache and get key name for type
 * @param[in]       key
 * @param[in]       type
 * @return          Name of the key
 */
const char *get_nvram_key(const char *key, enum nvram_key_type type) {
  if(!key || (strlen(key) == 0)) {
    return NULL;
  }
  if(!nvram_keys_cached || nvram_keys_count_cached == -1) {
    nvram_keys_cached = (struct nvram_key *)calloc(NVRAM_KEY_LIMIT, sizeof(struct nvram_key));
    nvram_keys_count_cached = 0;
  }
  if(!nvram_keys_cached) {
    x8A4_log_error("Failed to calloc memory for nvram keys!\n", "");
    return NULL;
  }
  const char *key_cached = find_nvram_key(key, type);
  if(key_cached) {
    return key_cached;
  }
  nvram_keys_cached[nvram_keys_count_cached].key_original = (char *)key;
  nvram_keys_cached[nvram_keys_count_cached].type = type;
  switch (type) {
    case KEY_NORMAL:
      nvram_keys_cached[nvram_keys_count_cached].key = (char *)key;
      gc_d_cached[gc_d_count_cached++] = (uint64_t)key;
      break;
    case KEY_SYSTEM:
      nvram_keys_cached[nvram_keys_count_cached].key = (char *)calloc(1, 100);
      snprintf(nvram_keys_cached[nvram_keys_count_cached].key, 100, "%s%s", kAppleSystemVarGUID, (char *)key);
      break;
    case KEY_NVRAM:
      nvram_keys_cached[nvram_keys_count_cached].key = (char *)calloc(1, 100);
      snprintf(nvram_keys_cached[nvram_keys_count_cached].key, 100, "%s%s", kAppleNVRAMGUID, (char *)key);
      break;
  }
  return nvram_keys_cached[nvram_keys_count_cached++].key;
}

/**
 * @brief           Get nvram entry bytes from matching key
 * @param[in]       nvram_dict
 * @param[in]       key
 * @param[in]       type
 * @param[out]      out_size
 * @return          Pointer to the nvram entry bytes
 */
uint8_t *get_nvram_entry_bytes(uint64_t nvram_dict, const char *key, enum os_type type,
                               uint32_t *out_size) {
  if (!out_size) {
    x8A4_log_error("Failed to continue with getting entry bytes, out_size is "
            "NULL!\n", "");
    return NULL;
  }
  uint64_t entry_addr = 0;
  for(int i = 0; i < 3; i++) {
    entry_addr = 0;
    const char *key_tmp = get_nvram_key(key, i);
    entry_addr = get_entry_from_os_dict(nvram_dict, type, key_tmp, out_size);
    if(entry_addr) {
      break;
    }
  }
  if (!entry_addr) {
    x8A4_log_error("Failed to get entry address from nvram dict!\n", "");
    return NULL;
  }
  if (!*out_size) {
    x8A4_log_error("Failed to entry size from nvram dict!\n", "");
    return NULL;
  }
  if(verbose_cached) {
    x8A4_log_debug("entry_addr: 0x%016llX\n", entry_addr);
    x8A4_log_debug("out_size: 0x%016llX\n",(uint64_t)out_size);
    x8A4_log_debug("out_size: 0x%08X\n", *out_size);
  }
  uint8_t *entry_bytes = (uint8_t *)calloc(1, *out_size + 1);
  int ret = kread(entry_addr, entry_bytes, *out_size);
  if (ret) {
    if (entry_bytes)
      free(entry_bytes);
    x8A4_log_error("Failed to read entry bytes from nvram dict! (%d:%s)\n", ret, strerror(ret));
    return NULL;
  }
  gc_cached[gc_count_cached++] = (uint64_t)entry_bytes;
  x8A4_log_debug_error("gc_cached[gc_count_cached++]: %d val: 0x%016llX\n", __LINE__, entry_bytes);
  return entry_bytes;
}

/**
 * @brief           Set nvram entry bytes for matching key
 * @param[in]       nvram_dict
 * @param[in]       key
 * @param[in]       entry_bytes
 * @param[in]       size
 * @param[in]       type
 * @return          Pointer to the modified nvram entry bytes
 */
int set_nvram_entry_bytes(uint64_t nvram_dict, const char *key,
                          uint8_t *entry_bytes, uint32_t size, enum os_type type) {
  x8A4_log_debug("key: %s bytes: 0x%llX\n", key, (uint64_t)entry_bytes);
  if(key && strstr(key, kBootNoncePropertyKey) == 0) {
    x8A4_log("WARNING! YOU ARE CALLING SET NVRAM FUNCTION THIS IS "
                   "DANGEROUS AND COULD BOOTLOOP!\n",
                   "");
    x8A4_log("Enter) Exit\n", "");
    x8A4_log("1) Continue\n", "");
    char msg[100];
    if (fgets(msg, sizeof msg, stdin)) {
      if (strcmp(msg, "1\n") != 0) {
        return -1;
      }
    }
  }
  x8A4_log_debug("Setting nvram entry(%s) bytes(%p:%u) type(%d)\n", key, entry_bytes, size, type);
  uint64_t entry_addr = 0;
  for(int i = 0; i < 3; i++) {
    const char *key_tmp = get_nvram_key(key, i);
    entry_addr = get_entry_from_os_dict(nvram_dict, type, key_tmp, NULL);
    if(entry_addr) {
      break;
    }
  }
  if (!entry_addr) {
    x8A4_log_error("Failed to set nvram bytes, entry %s missing from nvram!\n", key);
    return -1;
  }
  uint64_t read_test = 0;
  int ret = kread(entry_addr, &read_test, 8);
  if (ret) {
    x8A4_log_error("!kread (%d)\n", ret);
    return -1;
  }
  ret = kwrite(entry_bytes, entry_addr, size);
  if (ret) {
    x8A4_log_error("!kwrite (%d)\n", ret);
    return -1;
  }
  return 0;
}

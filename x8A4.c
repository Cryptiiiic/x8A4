//
// Created by cryptic on 4/14/24.
//

/**
 * @file x8A4.c
 * @author Cryptiiiic
 * @brief This file is for all x8A4 library related code.
 * @version 1.0.1
 * @date 2024-04-14
 *
 * @copyright Copyright (c) 2024
 */

/* Include headers */
#include <x8A4/Logger/logger.h>
#include <x8A4/Kernel/osobject.h>
#include <x8A4/Kernel/nvram.h>
#include <x8A4/x8A4.h>
#include <x8A4/Kernel/kpf.h>
#include <libkrw.h>

/* Cached Variables */
int init_done = 0;
struct x8A4_nonce_domain *domains_cached = NULL;
struct x8A4_nonce_slot *slots_cached = NULL;
int nonce_slot_format_cached = -1;
int domains_count_cached = -1;
int cryptex_domains_index_cached = -1;
int cryptex_slots_index_cached = -1;
int cryptex_index_cached = -1;
int verbose_cached = 0;
uint64_t *gc_cached = NULL;
int gc_count_cached = 0;
uint64_t *gc_d_cached = NULL;
int gc_d_count_cached = 0;

/* Functions */
/**
 * @brief           x8A4 constructor
 */
__attribute__((constructor, used)) void x8A4_constructor(void) {
  x8A4_log_debug("ctor!\n", "");
}

/**
 * @brief           x8A4 destructor
 */
__attribute__((destructor, used)) void x8A4_destructor(void) {
  x8A4_log_debug("dtor!\n", "");
  x8A4_free();
}

/**
 * @brief           x8A4 init function
 * @return          Zero on success
 */
int x8A4_init(void) {
  if (geteuid() != 0) {
    x8A4_log_error("x8A4 Requires running with sudo!\n", "");
    return -1;
  }
  if(init_done) {
    return 0;
  }
  x8A4_log_debug("init!\n", "");
  if (xpf_init()) {
    return -1;
  }
  uint64_t slide = get_slide();
  if (slide == 0) {
    return -1;
  }
  if (tfp0_init()) {
    return -1;
  }
  if (offsets_init()) {
    return -1;
  }
  gc_cached = calloc(1, 1024);
  gc_d_cached = calloc(1, 1024);
  init_done = 1;
  return 0;
}

/**
 * @brief           x8A4 free function
 */
void x8A4_free(void) {
  xpf_free_fileset_sections();
  if (domains_cached) {
    free(domains_cached);
  }
  if (apple_mobile_ap_nonce_service2_cached != IO_OBJECT_NULL) {
    x8A4_log_debug("Closing apple_mobile_ap_nonce_service2_cached\n", "");
    IOServiceClose(apple_mobile_ap_nonce_service2_cached);
  }
  if(apple_mobile_ap_nonce_service_cached != IO_OBJECT_NULL) {
    x8A4_log_debug("Releasing apple_mobile_ap_nonce_service_cached\n", "");
    IOObjectRelease(apple_mobile_ap_nonce_service_cached);
  }
  if(kernel_path_cached) {
    free(kernel_path_cached);
  }
  if(koffsets_cached) {
    free(koffsets_cached);
  }
  if(nvram_keys_cached) {
    for(int i = 0; i < nvram_keys_count_cached; i++) {
      if(nvram_keys_cached[i].key) {
        int found = 0;
        for(int j = 0; j < gc_d_count_cached; j++) {
          if(gc_d_cached[j] == (uint64_t)nvram_keys_cached[i].key) {
            found = 1;
            break;
          }
        }
        if(!found) {
          free(nvram_keys_cached[i].key);
        }
      }
    }
    free(nvram_keys_cached);
  }
  if(gc_cached) {
    for(int i = 0; i < gc_count_cached; i++) {
      int found = 0;
      for(int j = 0; j < gc_d_count_cached; j++) {
        if(gc_d_cached[j] == gc_cached[i]) {
          found = 1;
          break;
        }
      }
      if(!found && gc_cached[i]) {
        free((void *)gc_cached[i]);
      }
    }
    free(gc_cached);
  }
  if(gc_d_cached) {
    free(gc_d_cached);
  }
}

/**
 * @brief           x8A4 version function
 */
const char *x8A4_version(void) {
  char *version = calloc(1, 256);
//  gc_cached[gc_count_cached++] = (uint64_t)version;
#if defined(RELEASE)
    snprintf(version, 256, "x8A4: v%s", X8A4_API_VERSION);
#elif defined(ALPHA)
    snprintf(version, 256, "x8A4: v%s-ALPHA(DIRTY-%7s-%s)", X8A4_API_VERSION, VERSION_COMMIT_SHA, VERSION_COMMIT_COUNT);
#elif defined(BETA)
    snprintf(version, 256, "x8A4: v%s-BETA(DIRTY-%7s-%s)", X8A4_API_VERSION, VERSION_COMMIT_SHA, VERSION_COMMIT_COUNT);
#elif defined(RC)
    snprintf(version, 256, "x8A4: v%s-RC(DIRTY-%7s-%s)", X8A4_API_VERSION, VERSION_COMMIT_SHA, VERSION_COMMIT_COUNT);
#else
  snprintf(version, 256, "x8A4: v%s(DIRTY-%7s-%s)", X8A4_API_VERSION, VERSION_COMMIT_SHA, VERSION_COMMIT_COUNT);
#endif
#ifndef NDEBUG
    snprintf(version, 256, "%s-DEBUG", version);
#endif // NDEBUG
  return version;
}

/**
 * @brief           Get nonce-seeds OS dict variant
 * @param[out]      seeds_size
 * @return          Pointer to nonce-seeds(uint8_t array)
 */
uint8_t *x8A4_get_nonce_slots_os_dict(uint32_t *seeds_size, int slot_index) {
  if(strcmp(gXPF.darwinVersion, "23.0.0") >= 0 && nonce_slot_format_cached == 1) {
  } else {
    return NULL;
  }
  if(!slots_cached) {
    x8A4_get_cryptex_boot_slot_index();
    if(!slots_cached) {
      return NULL;
    }
  }
  if (!seeds_size) {
    x8A4_log_error("Failed to get nonce-seeds, out seeds size pointer is NULL!\n", "");
  }
  uint64_t nvram_dict = get_service_nvram_dict(get_dtre_options());
  if (!nvram_dict) {
    x8A4_log_error("Failed to get nonce-seeds, nvram dict is NULL!\n", "");
    return NULL;
  }
  uint8_t *nonce_seeds = NULL;
  char entry_str[20];
  snprintf(entry_str, 20, "krn.%s", slots_cached[slot_index].nonce_slot_domain_descriptor->unique_string + 4);
  if(strcmp(entry_str, "krn.c1ep") != 0 && strcmp(entry_str, "krn.pdmg") != 0) {
    nonce_seeds =
        get_nvram_entry_bytes(nvram_dict, entry_str, OS_DATA, seeds_size);
    if (!nonce_seeds) {
      x8A4_log_error("Failed to get nonce-seeds slot %s index: %d!\n", entry_str, slot_index);
    }
  } else {
    x8A4_log_debug("Skipped slot %s index: %d!\n", entry_str, slot_index);
  }
  return nonce_seeds;
}

/**
 * @brief           Get nonce-seeds OS dict variant
 * @param[out]      seeds_size
 * @return          Pointer to nonce-seeds(uint8_t array)
 */
uint8_t *x8A4_get_nonce_seeds_os_dict(uint32_t *seeds_size) {
  if (!seeds_size) {
    x8A4_log_error("Failed to get nonce-seeds, out seeds size pointer is NULL!\n", "");
  }
  uint64_t nvram_dict = get_service_nvram_dict(get_dtre_options());
  if (!nvram_dict) {
    x8A4_log_error("Failed to get nonce-seeds, nvram dict is NULL!\n", "");
    return NULL;
  }

  uint8_t *nonce_seeds = NULL;
  if(strcmp(gXPF.darwinVersion, "23.0.0") >= 0 && nonce_slot_format_cached == 1) {
    nonce_seeds = get_nvram_entry_bytes(nvram_dict, kKRNC1BTPropertyKey,
                                        OS_DATA, seeds_size);
  } else {
    nonce_seeds = get_nvram_entry_bytes(nvram_dict, kNonceSeedsPropertyKey,
                                        OS_DATA, seeds_size);
  }
  if (!nonce_seeds) {
    x8A4_log_error("Failed to get nonce-seeds!\n", "");
  }
  return nonce_seeds;
}

/**
 * @brief           Get nonce-seeds registry variant
 * @param[out]      seeds_size
 * @return          Pointer to nonce-seeds(uint8_t array)
 */
uint8_t *x8A4_get_nonce_seeds_registry(uint32_t *seeds_size) {
  if (!seeds_size) {
    x8A4_log_error("Failed to get nonce-seeds, out seeds size pointer is NULL!\n", "");
    return NULL;
  }
  uint8_t *nonce_seeds = NULL;
  uint32_t nonce_seeds_len = get_nonce_seeds_len();
  if (!nonce_seeds_len) {
    x8A4_log_debug_error("Failed to get nonce-seeds length!\n", "");
    return NULL;
  }
  *seeds_size = (uint32_t)nonce_seeds_len;
  nonce_seeds = (uint8_t *)get_nonce_seeds_registry();
  if (!nonce_seeds) {
    x8A4_log_error("Failed to get nonce-seeds!\n", "Failed to get nonce-seeds!\n");
  }
  return nonce_seeds;
}

/**
 * @brief           Check if kernel is using nonce domains or nonce slots
 */
void x8A4_set_nonce_format(void) {
  if(strcmp(gXPF.darwinVersion, "23.0.0") >= 0 && nonce_slot_format_cached == -1) {
    nonce_slot_format_cached = xpf_find_nonce_domains_array() ? 0 : 1;
  }
}

/**
 * @brief           Get a nonce seed from a domain index
 * @param[out]      nonce_seeds
 * @param[out]      seeds_size
 * @param[in]       domain_index
 * @return          Pointer to domain seed(uint8_t array)
 */
uint8_t *x8A4_get_domain_seed(uint8_t **nonce_seeds, uint32_t *seeds_size,
                              int domain_index) {
  if (!nonce_seeds) {
    x8A4_log_error("Failed to get nonce-seeds, out nonce seeds pointer to pointer is NULL!\n", "");
    return NULL;
  }
  if (!seeds_size) {
    x8A4_log_error("Failed to get nonce-seeds, out seeds size pointer is NULL!\n", "");
    return NULL;
  }
  *(uint64_t *)nonce_seeds = (uint64_t)x8A4_get_nonce_seeds_registry(seeds_size);
  if (!*nonce_seeds || !*seeds_size) {
    if(nonce_slot_format_cached == 1) {
      *(uint64_t *)nonce_seeds = (uint64_t)x8A4_get_nonce_slots_os_dict(seeds_size, domain_index);
    } else {
      *(uint64_t *)nonce_seeds = (uint64_t)x8A4_get_nonce_seeds_os_dict(seeds_size);
    }
    if (!*nonce_seeds || !*seeds_size) {
      x8A4_log_error("Failed to get nonce-seeds!\n", "");
      return NULL;
    }
  }
  struct x8A4_nonce_seeds *nonce_seeds_struct = (struct x8A4_nonce_seeds *)*nonce_seeds;
  return (uint8_t *)(&nonce_seeds_struct->seeds[domain_index].seed[0]);
}

/**
 * @brief           Get a nonce seed for a slot index
 * @param[out]      nonce_seeds
 * @param[out]      seeds_size
 * @param[in]       slot_index
 * @return          Pointer to slot seed(uint8_t array)
 */
uint8_t *x8A4_get_slot_seed(uint8_t **nonce_seeds, uint32_t *seeds_size,
                              int slot_index) {
  if (!nonce_seeds) {
    x8A4_log_error("Failed to get nonce-seeds, out nonce seeds pointer to pointer is NULL!\n", "");
    return NULL;
  }
  if (!seeds_size) {
    x8A4_log_error("Failed to get nonce-seeds, out seeds size pointer is NULL!\n", "");
    return NULL;
  }
  *(uint64_t *)nonce_seeds = (uint64_t)x8A4_get_nonce_seeds_registry(seeds_size);
  if (!*nonce_seeds || !*seeds_size) {
    *(uint64_t *)nonce_seeds = (uint64_t)x8A4_get_nonce_slots_os_dict(seeds_size, slot_index);
    if (!*nonce_seeds) {
      x8A4_log_debug_error("Failed to get nonce-seeds! (%d)\n", slot_index);
      return NULL;
    }
    if (!*nonce_seeds || !*seeds_size) {
      x8A4_log_debug_error("Failed to get nonce-seeds! (%d)\n", slot_index);
      return NULL;
    }
    struct x8A4_nonce_seeds_slot *nonce_seeds_struct =
        (struct x8A4_nonce_seeds_slot *)*(uint64_t *)nonce_seeds;
    return (uint8_t *)(nonce_seeds_struct->seed.seed);
  } else {
    struct x8A4_nonce_seeds_slot *nonce_seeds_struct =
        (struct x8A4_nonce_seeds_slot *)nonce_seeds;
    return (uint8_t *)(nonce_seeds_struct->seed.seed);
  }
}

/**
 * @brief           Get nonce-seeds list of slots
 * @return          Pointer to nonce slots(struct array)
 */
struct x8A4_nonce_slot *x8A4_get_nonce_slots_list(void) {
  if (slots_cached) {
    return slots_cached;
  }
  uint64_t nonce_domains_array_addr = xpf_find_nonce_domains_array();
  x8A4_log_debug("Got nonce_domains_array_addr: 0x%016llX\n", nonce_domains_array_addr);
  if (!nonce_domains_array_addr) {
    x8A4_log_error("Failed to get nonce_domains_array_addr!\n", "");
    return NULL;
  }
  int nonce_domains_array_length =
      xpf_find_nonce_domains_array_length(nonce_domains_array_addr);
  x8A4_log_debug("Got nonce_domains_array_length: 0x%08X\n", xpf_find_nonce_domains_array_length(nonce_domains_array_addr));
  if (!nonce_domains_array_length) {
    x8A4_log_error("Failed to get nonce_domains_array_length!\n", "");
    return NULL;
  }
  nonce_domains_array_addr += get_slide();
  uint32_t nonce_slot_size = sizeof(struct x8A4_nonce_slot);
  uint32_t nonce_descriptor_size = sizeof(struct x8A4_nonce_descriptor);
  struct x8A4_nonce_slot *nonce_slots = (struct x8A4_nonce_slot *)calloc(nonce_domains_array_length, nonce_slot_size);
  struct x8A4_nonce_descriptor *nonce_descriptors = (struct x8A4_nonce_descriptor *)calloc(nonce_domains_array_length, nonce_descriptor_size);
  char *entitlements = (char *)calloc(nonce_domains_array_length, 256);
  char *descriptions = (char *)calloc(nonce_domains_array_length, 256);
  gc_cached[gc_count_cached++] = (uint64_t)nonce_slots;
  gc_cached[gc_count_cached++] = (uint64_t)nonce_descriptors;
  gc_cached[gc_count_cached++] = (uint64_t)entitlements;
  gc_cached[gc_count_cached++] = (uint64_t)descriptions;
  x8A4_log_debug_error("gc_cached[gc_count_cached++]: %d val: 0x%016llX\n", __LINE__, nonce_slots);
  x8A4_log_debug_error("gc_cached[gc_count_cached++]: %d val: 0x%016llX\n", __LINE__, nonce_descriptors);
  x8A4_log_debug_error("gc_cached[gc_count_cached++]: %d val: 0x%016llX\n", __LINE__, entitlements);
  x8A4_log_debug_error("gc_cached[gc_count_cached++]: %d val: 0x%016llX\n", __LINE__, descriptions);
  for (int i = 0; i < nonce_domains_array_length; i++) {
    uint64_t array_index = nonce_domains_array_addr + (sizeof(uint64_t) * i);
    uint64_t vmaddr = 0;
    int ret = kread(array_index, &vmaddr, sizeof(uint64_t));
    if (ret || !vmaddr) {
      x8A4_log_error("Failed to read domain pointer %d from 0x%016llX (%d)!\n", i, array_index, ret);
      if (nonce_slots)
        free(nonce_slots);
      if (nonce_descriptors)
        free(nonce_descriptors);
      if (entitlements)
        free(entitlements);
      if (descriptions)
        free(descriptions);
      return NULL;
    }
    ret = kread(vmaddr, &nonce_slots[i], nonce_slot_size);
    if (ret) {
      x8A4_log_error("Failed to read domain %d from 0x%016llX (%d)!\n", i, vmaddr, ret);
      if (nonce_slots)
        free(nonce_slots);
      if (nonce_descriptors)
        free(nonce_descriptors);
      if (entitlements)
        free(entitlements);
      if (descriptions)
        free(descriptions);
      return NULL;
    }
    if(!nonce_slots[i].nonce_slot_domain_descriptor) {
      continue;
    }
    ret = kread((uint64_t)nonce_slots[i].nonce_slot_domain_descriptor, &nonce_descriptors[i], nonce_descriptor_size);
    if(ret || !nonce_descriptors[i].description || !nonce_descriptors[i].entitlement) {
      continue;
    }
    nonce_slots[i].nonce_slot_domain_descriptor = &nonce_descriptors[i];
    ret = kread((uint64_t)nonce_descriptors[i].entitlement, &entitlements[i * 256], 256);
    if(ret) {
      continue;
    }
    ret = kread((uint64_t)nonce_descriptors[i].description, &descriptions[i * 256], 256);
    if(ret) {
      continue;
    }
    nonce_descriptors[i].entitlement = &entitlements[i * 256];
    nonce_descriptors[i].description = &descriptions[i * 256];
    x8A4_log_debug("===========================================================\n", "");
    x8A4_log_debug("Got vmaddr: 0x%016llX\n", vmaddr);
    x8A4_log_debug("Got nonce_slots[i].nonce_slot_domain_descriptor: 0x%016llX\n", nonce_slots[i].nonce_slot_domain_descriptor);
    x8A4_log_debug("Got nonce_descriptors[i].description: (0x%016llX:%s)\n", nonce_descriptors[i].description, nonce_descriptors[i].description);
    x8A4_log_debug("Got nonce_descriptors[i].entitlement: (0x%016llX:%s)\n", nonce_descriptors[i].entitlement, nonce_descriptors[i].entitlement);
    x8A4_log_debug("Got nonce_descriptors[i].domain_index: 0x%016llX\n", nonce_descriptors[i].domain_index);
    x8A4_log_debug("Got nonce_descriptors[i].unknown_num1: 0x%016llX\n", nonce_descriptors[i].unknown_num1);
    x8A4_log_debug("Got nonce_descriptors[i].unknown_num2: 0x%016llX\n", nonce_descriptors[i].unknown_num2);
    x8A4_log_debug("Got nonce_descriptors[i].nonce_domain_boot_select_chip_default_function: 0x%016llX\n", nonce_descriptors[i].nonce_domain_boot_select_chip_default_function);
    x8A4_log_debug("Got nonce_descriptors[i].nonce_domain_boot_nonce_accessible_function: 0x%016llX\n", nonce_descriptors[i].nonce_domain_boot_nonce_accessible_function);
    x8A4_log_debug("Got nonce_slots[i].nonce_slot_init_function: 0x%016llX\n", nonce_slots[i].nonce_slot_init_function);
    x8A4_log_debug("Got nonce_slots[i].nonce_slot_lock_function: 0x%016llX\n", nonce_slots[i].nonce_slot_lock_function);
    x8A4_log_debug("Got nonce_slots[i].nonce_slot_unlock_function: 0x%016llX\n", nonce_slots[i].nonce_slot_unlock_function);
    x8A4_log_debug("Got nonce_slots[i].nonce_slot_data: 0x%016llX\n", nonce_slots[i].nonce_slot_data);
  }
  slots_cached = nonce_slots;
  return nonce_slots;
}

/**
 * @brief           Get nonce-seeds list of domains
 * @return          Pointer to nonce domains(struct array)
 */
struct x8A4_nonce_domain *x8A4_get_nonce_seeds_domain_list(void) {
  if (domains_cached) {
    return domains_cached;
  }
  uint64_t nonce_domains_array_addr = xpf_find_nonce_domains_array();
  x8A4_log_debug("Got nonce_domains_array_addr: 0x%016llX\n", nonce_domains_array_addr);
  if (!nonce_domains_array_addr) {
    x8A4_log_error("Failed to get nonce_domains_array_addr!\n", "");
    return NULL;
  }
  int nonce_domains_array_length =
      xpf_find_nonce_domains_array_length(nonce_domains_array_addr);
  if (!nonce_domains_array_length) {
    x8A4_log_error("Failed to get nonce_domains_array_length!\n", "");
    return NULL;
  }
  nonce_domains_array_addr += get_slide();
  uint32_t domain_size = sizeof(struct x8A4_nonce_domain);
  struct x8A4_nonce_domain *domains = calloc(nonce_domains_array_length, domain_size + 1);
  for (int i = 0; i < nonce_domains_array_length; i++) {
    uint64_t array_index = nonce_domains_array_addr + (sizeof(uint64_t) * i);
    uint64_t vmaddr = 0;
    int ret = kread(array_index, &vmaddr, sizeof(uint64_t));
    if (ret || !vmaddr) {
      x8A4_log_error("Failed to read domain pointer %d from 0x%016llX (%d)!\n", i, array_index, ret);
      return NULL;
    }
    ret = kread(vmaddr, &domains[i], domain_size);
    if (ret) {
      x8A4_log_error("Failed to read domain %d from 0x%016llX (%d)!\n", i, vmaddr, ret);
      return NULL;
    }
    x8A4_log_debug("Got vmaddr: 0x%016llX\n", vmaddr);
    x8A4_log_debug("Got domains[i].description: 0x%016llX\n", domains[i].description);
    x8A4_log_debug("Got domains[i].entitlement: 0x%016llX\n", domains[i].entitlement);
    if (!domains[i].description || !domains[i].entitlement) {
      x8A4_log_error("Failed to read domain %d from 0x%016llX!\n", i, vmaddr);
      return NULL;
    }
    char tmp[100];
    ret = kread((uint64_t)domains[i].description, tmp, 100);
    if (ret) {
      x8A4_log_error("Failed to read domain %d description from 0x%016llX (%d)!\n", i, vmaddr, ret);
      return NULL;
    }
    domains[i].description = calloc(1, strlen(tmp) + 1);
    gc_cached[gc_count_cached++] = (uint64_t)domains[i].description;
    x8A4_log_debug_error("gc_cached[gc_count_cached++]: %d val: 0x%016llX\n", __LINE__, domains[i].description);
    strcpy(domains[i].description, tmp);
    memset(tmp, 0, 100);
    ret = kread((uint64_t)domains[i].entitlement, tmp, 100);
    if (ret) {
      x8A4_log_error("Failed to read domain %d entitlement from 0x%016llX (%d)!\n", i, vmaddr, ret);
      return NULL;
    }
    domains[i].entitlement = calloc(1, strlen(tmp) + 1);
    gc_cached[gc_count_cached++] = (uint64_t)domains[i].entitlement;
    x8A4_log_debug_error("gc_cached[gc_count_cached++]: %d val: 0x%016llX\n", __LINE__, domains[i].entitlement);
    strcpy(domains[i].entitlement, tmp);
  }
  domains_cached = domains;
  return domains;
}

/**
 * @brief           Get nonce-seeds domain count
 * @return          Domain count(int)
 */
int x8A4_get_domain_count(void) {
  if (domains_count_cached >= 0) {
    return domains_count_cached;
  }
  uint64_t nonce_domains_array_addr = xpf_find_nonce_domains_array();
  if (!nonce_domains_array_addr) {
    x8A4_log_error("Failed to get nonce_domains_array_addr!\n", "");
    return 0;
  }
  int nonce_domains_array_length =
      xpf_find_nonce_domains_array_length(nonce_domains_array_addr);
  if (!nonce_domains_array_length) {
    x8A4_log_error("Failed to get nonce_domains_array_length!\n", "");
    return 0;
  }
  domains_count_cached = nonce_domains_array_length;
  return nonce_domains_array_length;
}

/**
 * @brief           Get nonce-seeds slot index for an entitlement
 * @return          Slot index(int)
 */
int x8A4_get_slot_slots_index(const char *entitlement) {
  struct x8A4_nonce_slot *slots = x8A4_get_nonce_slots_list();
  if (!slots) {
    x8A4_log_error("Failed to get nonce slots list!\n", "");
    return -1;
  }
  int slot_count = x8A4_get_domain_count();
  if (!slot_count) {
    x8A4_log_error("Failed to get nonce domains count!\n", "");
    return -1;
  }
  int slot_index = -1;
  for (int i = 0; i < slot_count; i++) {
    const char *ent = slots[i].nonce_slot_domain_descriptor->entitlement;
    if (!ent) {
      continue;
    }
    x8A4_log_debug("Got ent: %s\n", ent);
    x8A4_log_debug("Got entitlement: %s\n", entitlement);
    if (strcmp(ent, entitlement) == 0) {
      slot_index = i;
      break;
    }
  }
  if (slot_index < 0) {
    x8A4_log_error("Failed to get %s domains index!\n", entitlement);
  }
  return slot_index;
}

/**
 * @brief           Get nonce-seeds domain index for an entitlement
 * @return          Domain index(int)
 */
int x8A4_get_domain_domains_index(const char *entitlement) {
  struct x8A4_nonce_domain *domains = x8A4_get_nonce_seeds_domain_list();
  if (!domains) {
    x8A4_log_error("Failed to get nonce domains list!\n", "");
    return -1;
  }
  int domain_count = x8A4_get_domain_count();
  if (!domain_count) {
    x8A4_log_error("Failed to get nonce domains count!\n", "");
    return -1;
  }
  int domains_index = -1;
  for (int i = 0; i < domain_count; i++) {
    const char *ent = domains[i].entitlement;
    if (!ent) {
      continue;
    }
    if (strcmp(ent, entitlement) == 0) {
      domains_index = i;
      break;
    }
  }
  if (domains_index < 0) {
    x8A4_log_error("Failed to get %s domains index!\n", entitlement);
  }
  return domains_index;
}

/**
 * @brief           Get nonce-seeds cryptex boot slot slots index
 * @return          Cryptex boot domain slots index(int)
 */
int x8A4_get_cryptex_boot_slot_slots_index(void) {
  if (strcmp(gXPF.darwinVersion, "23.0.0") >= 0 && nonce_slot_format_cached == 1) {
  } else {
    return -1;
  }
  if (cryptex_slots_index_cached >= 0) {
    return cryptex_slots_index_cached;
  }
  int slots_index = x8A4_get_slot_slots_index(
      "com.apple.private.img4.nonce.cryptex1.boot");
  if (slots_index < 0) {
    x8A4_log_error("Failed to get cryptex boot slot slots index!\n", "");
  }
  cryptex_slots_index_cached = slots_index;
  return slots_index;
}

/**
 * @brief           Get nonce-seeds cryptex boot domain domains index
 * @return          Cryptex boot domain domains index(int)
 */
int x8A4_get_cryptex_boot_domain_domains_index(void) {
  if (strcmp(gXPF.darwinVersion, "22.0.0") >= 0) {
  } else {
    return -1;
  }
  if (cryptex_domains_index_cached >= 0) {
    return cryptex_domains_index_cached;
  }
  int domains_index = x8A4_get_domain_domains_index(
      "com.apple.private.img4.nonce.cryptex1.boot");
  if (domains_index < 0) {
    x8A4_log_error("Failed to get cryptex boot domain domains index!\n", "");
  }
  cryptex_domains_index_cached = domains_index;
  return domains_index;
}

/**
 * @brief           Get nonce-seeds cryptex boot slot index
 * @return          Cryptex boot slot index(int)
 */
int x8A4_get_cryptex_boot_slot_index(void) {
  if (strcmp(gXPF.darwinVersion, "23.0.0") >= 0 && nonce_slot_format_cached == 1) {
  } else {
    return -1;
  }
  if (cryptex_index_cached >= 0) {
    return cryptex_index_cached;
  }
  struct x8A4_nonce_slot *slots = x8A4_get_nonce_slots_list();
  if (!slots) {
    x8A4_log_error("Failed to get nonce slots list!\n", "");
    return -1;
  }
  int slots_index = x8A4_get_cryptex_boot_slot_slots_index();
  if (slots_index < 0) {
    x8A4_log_error("Failed to get cryptex boot slot slots index!\n", "");
    return -1;
  }
  cryptex_index_cached = (int)slots[slots_index].nonce_slot_domain_descriptor->domain_index;
  return cryptex_index_cached;
}

/**
 * @brief           Get nonce-seeds cryptex boot domain index
 * @return          Cryptex boot domain index(int)
 */
int x8A4_get_cryptex_boot_domain_index(void) {
  if (strcmp(gXPF.darwinVersion, "22.0.0") >= 0) {
  } else {
    return -1;
  }
  if (cryptex_index_cached >= 0) {
    return cryptex_index_cached;
  }
  struct x8A4_nonce_domain *domains = x8A4_get_nonce_seeds_domain_list();
  if (!domains) {
    x8A4_log_error("Failed to get nonce domains list!\n", "");
    return -1;
  }
  int domains_index = x8A4_get_cryptex_boot_domain_domains_index();
  if (domains_index < 0) {
    x8A4_log_error("Failed to get cryptex boot domain domains index!\n", "");
    return -1;
  }
  cryptex_index_cached = (int)domains[domains_index].domain_index;
  return cryptex_index_cached;
}

/**
   * @brief           Get nonce-seeds
   * @param[out]      seeds_size
   * @return          Pointer to nonce seeds(uint8_t array)
 */
uint8_t *x8A4_get_nonce_seeds(uint32_t *seeds_size) {
  uint32_t count = x8A4_get_domain_count();
  struct x8A4_nonce_seeds_slot *nonce_seeds = NULL;
  x8A4_log_debug_error("gc_cached[gc_count_cached++]: %d val: 0x%016llX\n", __LINE__, nonce_seeds);
  if(strcmp(gXPF.darwinVersion, "23.0.0") >= 0 && nonce_slot_format_cached == 1) {
    nonce_seeds = calloc(count, sizeof(struct x8A4_nonce_seeds_slot));
    for (int i = 0; i < count; i++) {
      uint32_t sz = 0;
      x8A4_log_debug_error("&nonce_seeds[i]: 0x%016llX\n", &nonce_seeds[i]);
      uint8_t *ret = x8A4_get_slot_seed((uint8_t **)&nonce_seeds[i], &sz, i);
      if (!ret) {
        continue;
      }
      const void *ptr =  (const void *)*(uint64_t *)&nonce_seeds[i];
      if(!ptr) {
        continue;
      }
      memcpy(&nonce_seeds[i], ptr, sizeof(struct x8A4_nonce_seeds_slot));
      *seeds_size += sz;
    }
    gc_cached[gc_count_cached++] = (uint64_t)nonce_seeds;
    return (uint8_t *)nonce_seeds;
  } else {
    nonce_seeds = calloc(count, sizeof(struct x8A4_nonce_seeds));
    x8A4_get_domain_seed((uint8_t **)nonce_seeds, seeds_size, 0);
    gc_cached[gc_count_cached++] = (uint64_t)nonce_seeds;
    return (uint8_t *)*(uint64_t *)nonce_seeds;
  }
}

/**
 * @brief           Get nonce-seeds cryptex boot domain seed
 * @param[out]      nonce_seeds
 * @param[out]      seeds_size
 * @return          Pointer to cryptex seed(uint8_t array)
 */
uint8_t *x8A4_get_cryptex_seed(uint8_t **nonce_seeds, uint32_t *seeds_size) {
  if (strcmp(gXPF.darwinVersion, "22.0.0") >= 0) {
  } else {
    return NULL;
  }
  int cryptex_boot_index = 0;
  if(strcmp(gXPF.darwinVersion, "23.0.0") >= 0 && nonce_slot_format_cached == 1) {
    cryptex_boot_index = x8A4_get_cryptex_boot_slot_slots_index();
  } else {
    cryptex_boot_index = x8A4_get_cryptex_boot_domain_index();
  }
  if (cryptex_boot_index < 0) {
    x8A4_log_error("Failed to get cryptex boot index!\n", "");
    return NULL;
  }
  if(strcmp(gXPF.darwinVersion, "23.0.0") >= 0 && nonce_slot_format_cached == 1) {
    return x8A4_get_slot_seed(nonce_seeds, seeds_size,
                              cryptex_boot_index);
  } else {
    return x8A4_get_domain_seed(nonce_seeds, seeds_size,
                                cryptex_boot_index);
  }
}

/**
 * @brief           Calulates cryptex boot seed nonce
 * @param[out]      seeds_size
 * @return          Pointer to cryptex nonce(uint8_t array)
 */
uint8_t *x8A4_get_cryptex_nonce(uint32_t *nonce_size) {
  if (strcmp(gXPF.darwinVersion, "22.0.0") >= 0) {
  } else {
    return NULL;
  }
  if(!nonce_size) {
    x8A4_log_error("Failed to get cryptex boot nonce, nonce size pointer is NULL!\n", "");
    return NULL;
  }
  uint8_t **nonce_seeds = calloc(1, 1000);
  gc_cached[gc_count_cached++] = (uint64_t)nonce_seeds;
  x8A4_log_debug_error("gc_cached[gc_count_cached++]: %d val: 0x%016llX\n", __LINE__, nonce_seeds);
  uint32_t seeds_size = 0;
  uint8_t *seed = x8A4_get_cryptex_seed(nonce_seeds, &seeds_size);
  if(!seed) {
    x8A4_log_error("Failed to get cryptex boot seed!\n", "");
    return NULL;
  }
  uint32_t keys_count = 0;
  struct x8A4_accel_key *keys = x8A4_get_ioaesaccelkeys(&keys_count);
  if(!keys || !keys_count) {
    x8A4_log_error("Failed to get IOAESAccelerator keys! (%d:0x%016llX)\n", keys_count, keys);
    return NULL;
  }
  uint32_t chosen_key = 0x8A4;
  uint32_t struct_size = sizeof(struct x8A4_accel_key);
  for (int i = 0; i < keys_count; i++) {
    struct x8A4_accel_key *cur_key = keys + (struct_size * i);
    if (cur_key->key_id == chosen_key) {
      keys = cur_key;
      break;
    }
  }
  uint32_t *cryptex_key_key = &keys->key[0];
  uint32_t *cryptex_key_iv = &keys->iv[0];
  uint64_t seed_encrypt[] = { *(uint64_t *)&seed[0],  *(uint64_t *)&seed[8]};
  size_t encrypted_size = 0;
  if(CCCrypt(kCCEncrypt, kCCAlgorithmAES128, 0, cryptex_key_key, kCCKeySizeAES128, cryptex_key_iv, seed_encrypt, sizeof(seed_encrypt), seed_encrypt, sizeof(seed_encrypt), &encrypted_size) != kCCSuccess || encrypted_size != sizeof(seed_encrypt)) {
    return NULL;
  }
  uint32_t digest_len = get_hash_len();
  if(!digest_len) {
    digest_len = CC_SHA384_DIGEST_LENGTH;
  }
  uint8_t *cryptex_nonce = calloc(1, digest_len);
  gc_cached[gc_count_cached++] = (uint64_t)cryptex_nonce;
  x8A4_log_debug_error("gc_cached[gc_count_cached++]: %d val: 0x%016llX\n", __LINE__, cryptex_nonce);
  if(digest_len == CC_SHA384_DIGEST_LENGTH) {
    *nonce_size = CC_SHA256_DIGEST_LENGTH;
    CC_SHA384(seed_encrypt, sizeof(seed_encrypt), cryptex_nonce);
  } else if(digest_len == CC_SHA1_DIGEST_LENGTH) {
    *nonce_size = digest_len;
    CC_SHA1(seed_encrypt, sizeof(seed_encrypt), cryptex_nonce);
  } else {
    return NULL;
  }
  return cryptex_nonce;
}

/**
 * @brief           Syncs nvram ram with a list of keys
 * @return          Zero on success
 */
int x8A4_sync_nvram(void) {
  const char *delete_me_key = "delete_me_key";
  const char *delete_me_val = "delete_me_val";
  int ret = 0;
  const char *key_list[] = {
      kBootNoncePropertyKey,
      kNonceSeedsPropertyKey,
      kKRNC1BTPropertyKey
  };
  for(int i = 0; i < 3; i++) {
    ret = set_nvram_entry(get_dtre_options(), delete_me_key, delete_me_val);
    if (ret) {
      x8A4_log_error("Failed to sync nvram, set nvram(%s:%s) returned NULL!",
                     delete_me_key, delete_me_val);
      return -1;
    }
    ret = set_nvram_entry(get_dtre_options(), kIONVRAMDeletePropertyKey,
                          delete_me_key);
    if (ret) {
      x8A4_log_error("Failed to sync nvram, set nvram(%s:%s) returned NULL!",
                     kIONVRAMDeletePropertyKey, delete_me_key);
      return -1;
    }
    ret = set_nvram_entry(get_dtre_options(), kIONVRAMForceSyncNowPropertyKey,
                          key_list[i]);
    if (ret) {
      x8A4_log_error("Failed to sync nvram, set nvram(%s:%s) returned NULL!",
                     kIONVRAMForceSyncNowPropertyKey, key_list[i]);
      return -1;
    }
  }
  return 0;
}

/**
 * @brief           Get boot-nonce OS dict variant
 * @param[out]      generator_size
 * @return          Pointer to boot-nonce(uint8_t array)
 */
uint8_t *x8A4_get_boot_nonce_os_dict(uint32_t *generator_size) {
  if (!generator_size) {
    x8A4_log_error("Failed to get boot-nonce, out generator size pointer is NULL!\n", "");
  }
  uint64_t nvram_dict = get_service_nvram_dict(get_dtre_options());
  if (!nvram_dict) {
    x8A4_log_error("Failed to get boot-nonce, nvram dict is NULL!\n", "");
    return NULL;
  }
  uint8_t *boot_nonce = get_nvram_entry_bytes(nvram_dict, kBootNoncePropertyKey, OS_STRING, generator_size);
  if (!boot_nonce) {
    x8A4_log_error("Failed to get boot-nonce!\n", "");
  }
  return boot_nonce;
}

/**
 * @brief           Set boot-nonce OS dict variant
 * @param[in]       generator
 * @param[out]      generator_size
 * @return
 */
int x8A4_set_boot_nonce_os_dict(uint8_t *generator, uint32_t generator_size) {
  if (!generator) {
    x8A4_log_error("Failed to set boot-nonce, out generator pointer is NULL!\n", "");
    return -1;
  }
  if (!generator_size) {
    x8A4_log_error("Failed to set boot-nonce, out generator size pointer is NULL!\n", "");
    return -1;
  }
  uint64_t nvram_dict = get_service_nvram_dict(get_dtre_options());
  if (!nvram_dict) {
    x8A4_log_error("Failed to get boot-nonce, nvram dict is NULL!\n", "");
    return -1;
  }
  int ret = set_nvram_entry_bytes(nvram_dict, kBootNoncePropertyKey, generator, generator_size, OS_STRING);
  if (ret) {
    x8A4_log_error("Failed to set boot-nonce!\n", "");
    return -1;
  }
  return 0;
}

/**
 * @brief           Set nonce-seeds OS dict variant
 * @param[in]       seed
 * @param[in]       domain_index
 * @return
 */
int x8A4_set_nonce_seeds_os_dict(uint8_t *seed, int domain_index) {
  if (!seed) {
    x8A4_log_error("Failed to set nonce seed, seed is NULL!\n", "");
    return -1;
  }
  uint64_t nvram_dict = get_service_nvram_dict(get_dtre_options());
  if (!nvram_dict) {
    x8A4_log_error("Failed to set nonce seed, nvram dict is NULL!\n", "");
    return -1;
  }
  uint32_t seeds_size = 0;
  uint8_t *nonce_seeds = NULL;
  if(strcmp(gXPF.darwinVersion, "23.0.0") >= 0 && nonce_slot_format_cached == 1) {
    nonce_seeds = get_nvram_entry_bytes(nvram_dict, kKRNC1BTPropertyKey,
                                        OS_DATA, &seeds_size);
  } else {
    nonce_seeds = get_nvram_entry_bytes(nvram_dict, kNonceSeedsPropertyKey,
                                        OS_DATA, &seeds_size);
  }
  if (!nonce_seeds) {
    x8A4_log_error("Failed to get nonce-seeds!\n", "");
  }
  if(strcmp(gXPF.darwinVersion, "23.0.0") >= 0 && nonce_slot_format_cached == 1) {
    struct x8A4_nonce_seeds_slot *slot = (struct x8A4_nonce_seeds_slot *)nonce_seeds;

    memcpy(&slot->seed.seed, seed, 16);
    int ret = set_nvram_entry_bytes(nvram_dict, kKRNC1BTPropertyKey, nonce_seeds, seeds_size, OS_DATA);
    if (ret) {
      x8A4_log_error("Failed to set nonce seed!\n", "");
      return -1;
    }
  } else {
    struct x8A4_nonce_seeds *seeds = (struct x8A4_nonce_seeds *)nonce_seeds;
    memcpy(&seeds->seeds[domain_index].seed, seed, 16);
    int ret = set_nvram_entry_bytes(nvram_dict, kNonceSeedsPropertyKey, nonce_seeds, seeds_size, OS_DATA);
    if (ret) {
      x8A4_log_error("Failed to set nonce seed!\n", "");
      return -1;
    }
  }
  x8A4_sync_nvram();
  return 0;
}

/**
 * @brief           Get boot-nonce registry variant
 * @param[out]      generator_size
 * @return          Pointer to boot-nonce(uint8_t array)
 */
uint8_t *x8A4_get_boot_nonce_registry(uint32_t *generator_size) {
  if (!generator_size) {
    x8A4_log_error("Failed to get boot-nonce, out generator size pointer is NULL!\n", "");
    return NULL;
  }
  uint8_t *generator = NULL;
  uint32_t generator_len = get_boot_nonce_len();
  if (!generator_len) {
    if(verbose_cached)
      x8A4_log_error("Failed to get boot-nonce length!\n", "");
    return NULL;
  }
  *generator_size = (uint32_t)generator_len;
  generator = (uint8_t *)get_boot_nonce_registry();
  if (!generator) {
    x8A4_log_error("Failed to get boot-nonce!\n", "");
  }
  return generator;
}

/**
 * @brief           Set boot-nonce registry variant
 * @param[out]      generator
 * @return          Zero on success
 */
int x8A4_set_boot_nonce_registry(uint8_t *generator) {
  int ret = set_nvram_entry(get_dtre_options(), kBootNoncePropertyKey,
                            (const char *)generator);
  if(ret) {
    if(verbose_cached)
      x8A4_log_error("Failed to set nvram entry(%s)!\n", kBootNoncePropertyKey);
    return -1;
  }
  ret = set_nvram_entry(get_dtre_options(), kIONVRAMSyncNowPropertyKey,
                        kBootNoncePropertyKey);
  if(ret) {
    if(verbose_cached)
      x8A4_log_error("Failed to set nvram entry(%s)!\n", kIONVRAMSyncNowPropertyKey);
    return -1;
  }
  ret = set_nvram_entry(get_dtre_options(), kIONVRAMForceSyncNowPropertyKey,
                        kBootNoncePropertyKey);
  if(ret) {
    if(verbose_cached)
      x8A4_log_error("Failed to set nvram entry(%s)!\n", kIONVRAMForceSyncNowPropertyKey);
    return -1;
  }
  return 0;
}

/**
 * @brief           Get apnonce generator
 * @param[out]      generator_size
 * @return          Pointer to apnonce generator(uint8_t array)
 */
uint8_t *x8A4_get_apnonce_generator(uint32_t *generator_size) {
  if (!generator_size) {
    x8A4_log_error("Failed to get apnonce generator, out generator size pointer is NULL!\n", "");
    return NULL;
  }
  uint8_t *generator = x8A4_get_boot_nonce_registry(generator_size);
//  uint8_t *generator = NULL;
  if (!generator || !*generator_size) {
    generator = x8A4_get_boot_nonce_os_dict(generator_size);
    if (!generator || !*generator_size) {
      x8A4_log_error("Failed to get apnonce generator!\n", "");
      return NULL;
    }
  }
  return generator;
}

/**
 * @brief           Get apnonce
 * @param[out]      apnonce_size
 * @return          Pointer to apnonce(uint8_t array)
 */
uint8_t *x8A4_get_apnonce(uint32_t *apnonce_size) {
  if (!apnonce_size) {
    x8A4_log_error(
        "Failed to get get apnonce generator, apnonce size pointer is NULL!\n",
        "");
    return NULL;
  }
  uint32_t generator_size = 0;
  uint8_t *generator = x8A4_get_apnonce_generator(&generator_size);
  if (!generator || ((generator_size & 0xFFFFFFFF) != 0x12 &&
                     (generator_size & 0xFFFFFFFF) != 0x13)) {
    x8A4_log_error("Failed to get apnonce generator! (%zu:0x%016llX)\n",
                   generator_size, generator);
    return NULL;
  }
  x8A4_log_debug("generator: %s\n", generator);
  uint64_t generator_data = 0;
  generator_data = (uint64_t)strtoull((const char *)generator,NULL, 0);
  if(!generator_data) {
    x8A4_log_error(
        "Failed to get get convert apnonce generator!\n",
        "");
    return NULL;
  }
  uint32_t digest_len = get_hash_len();
  if(!digest_len) {
    digest_len = CC_SHA384_DIGEST_LENGTH;
  }
  uint8_t *apnonce = calloc(1, digest_len);
  uint64_t tmp = generator_data;
  gc_cached[gc_count_cached++] = (uint64_t)apnonce;
  x8A4_log_debug_error("gc_cached[gc_count_cached++]: %d val: 0x%016llX\n", __LINE__, apnonce);
  generator_data = tmp;
  if (!gXPF.kernelIsArm64e) {
    if(digest_len == CC_SHA384_DIGEST_LENGTH) {
      *apnonce_size = CC_SHA256_DIGEST_LENGTH;
      CC_SHA384(&generator_data, sizeof(generator_data), apnonce);
    } else if(digest_len == CC_SHA1_DIGEST_LENGTH) {
      *apnonce_size = digest_len;
      CC_SHA1(&generator_data, sizeof(generator_data), apnonce);
    } else {
      return NULL;
    }
    return apnonce;
  }
  uint32_t keys_count = 0;
  struct x8A4_accel_key *keys = x8A4_get_ioaesaccelkeys(&keys_count);
  if(!keys || !keys_count) {
    x8A4_log_error("Failed to get IOAESAccelerator keys! (%d:0x%016llX)\n", keys_count, keys);
    return NULL;
  }
  uint32_t chosen_key = 0x8A3;
  uint32_t struct_size = sizeof(struct x8A4_accel_key);
  for (int i = 0; i < keys_count; i++) {
    struct x8A4_accel_key *cur_key = keys + (struct_size * i);
    if (cur_key->key_id == chosen_key) {
      keys = cur_key;
      break;
    }
  }
  uint32_t *entangle_key_key = &keys->key[0];
  uint32_t *entangle_key_iv = &keys->iv[0];
  uint64_t gen_encrypt[] = { 0, generator_data};
  x8A4_log_debug("generator_data: 0x%016llX\n", generator_data);
  size_t encrypted_size = 0;
  if(CCCrypt(kCCEncrypt, kCCAlgorithmAES128, 0, entangle_key_key, kCCKeySizeAES128, entangle_key_iv, gen_encrypt, sizeof(gen_encrypt), gen_encrypt, sizeof(gen_encrypt), &encrypted_size) != kCCSuccess || encrypted_size != sizeof(gen_encrypt)) {
    return NULL;
  }
  if(digest_len == CC_SHA384_DIGEST_LENGTH) {
    *apnonce_size = CC_SHA256_DIGEST_LENGTH;
    x8A4_log_debug("gen_encrypt[0]: 0x%016llX\n", gen_encrypt[0]);
    x8A4_log_debug("gen_encrypt[1]: 0x%016llX\n", gen_encrypt[1]);
    CC_SHA384(gen_encrypt, sizeof(gen_encrypt), apnonce);
  } else {
    return NULL;
  }
  return apnonce;
}

/**
 * @brief           Set apnonce generator
 * @param[in]       generator
 * @param[out]      generator_size
 * @return          Pointer to apnonce generator(uint8_t array)
 */
uint8_t *x8A4_set_apnonce_generator(uint8_t *generator, uint32_t *generator_size) {
  if (!generator || (strlen((char *)generator) < 16 || strlen((char *)generator) > 18)) {
    x8A4_log_error("Failed to set apnonce generator, generator is invalid! (0x%016llX:%s)\n", generator, generator ? (char *)generator : "NULL");
    return NULL;
  }
  if (!generator_size) {
    x8A4_log_error("Failed to set apnonce generator, out generator size pointer is NULL!\n", "");
    return NULL;
  }
  char generator_str[19];
  generator_str[0] = '0';
  generator_str[1] = 'x';
  if(strlen((char *)generator) == 16 && (generator[0] != '0' && generator[1] != 'x')) {
    strncpy(generator_str + 2, (char *)generator, 16);
  } else if(strlen((char *)generator) == 18 && (generator[0] == '0' && generator[1] == 'x')) {
    strncpy(generator_str, (char *)generator, 18);
  } else {
    x8A4_log_error("Failed to set apnonce generator, generator is invalid! (0x%016llX:%s)\n", generator, generator ? (char *)generator : "NULL");
    return NULL;
  }
  uint8_t *generator2 = (uint8_t *)generator_str;
  if (io_clear_apnonce()) {
x8A4_log_error("Failed to clear current apnonce generator!\n", "");
    return NULL;
  }
  if (io_generate_apnonce()) {
x8A4_log_error("Failed to generate new apnonce generator!\n", "");
    return NULL;
  }
  uint32_t tmp_generator_size = *generator_size;
  int ret = x8A4_set_boot_nonce_registry(generator2);
  if(ret) {
    if(verbose_cached)
      x8A4_log_error("Failed to set apnonce generator in registry, retrying with os-dict!\n", "");
    ret = x8A4_set_boot_nonce_os_dict(generator2, strlen((const char *)generator2) + 1);
    if(ret) {
      x8A4_log_error("Failed to set apnonce generator in os-dict!\n", "");
      *generator_size = 0;
      return NULL;
    }
  }
  ret = x8A4_sync_nvram();
  if(ret) {
x8A4_log_error("Failed to set sync nvram!\n", "");
    *generator_size = 0;
    return NULL;
  }
  generator2 = x8A4_get_boot_nonce_registry(generator_size);
  if (!generator2 || !*generator_size) {
    generator2 = x8A4_get_boot_nonce_os_dict(generator_size);
    if (!generator2 || !*generator_size) {
      x8A4_log_error("Failed to set apnonce generator!\n", "");
      *generator_size = 0;
      return NULL;
    }
  }
  *generator_size = tmp_generator_size;
  return generator;
}

/**
 * @brief           Clears the apnonce generator
 * @return          Zero on success
 */
int x8A4_clear_apnonce_generator(void) {
  if (io_clear_apnonce()) {
    x8A4_log_error("Failed to clear current apnonce generator!\n", "");
    return -1;
  }
  if(x8A4_sync_nvram()) {
    x8A4_log_error("Failed to set sync nvram!\n", "");
    return -2;
  }
  return 0;
}

/**
 * @brief           Get IOAESAccelerator Keys
 * @param[out]      keys_count
 * @return          Pointer to keys(x8A4_accel_key array)
 */
struct x8A4_accel_key *x8A4_get_ioaesaccelkeys(uint32_t *keys_count) {
  if(!keys_count) {
    x8A4_log_error("Failed to get IOAESAccelerator keys, no keys count output pointer set!\n",
                   "");
    return NULL;
  }
  uint64_t kobject = get_ipc_kobject(get_io_aes_accel_service());
  if (!kobject) {
    x8A4_log_error("Failed to get kobject from IOAESAccelerator service!\n",
                   "");
    return NULL;
  }
  uint64_t keys = 0;
  x8A4_log_debug("kobject: 0x%016llX\n", kobject);
  x8A4_log_debug("kobject + koffsets_cached->io_aes_accel_special_keys: 0x%016llX\n", kobject + koffsets_cached->io_aes_accel_special_keys);
  if (kread(kobject + koffsets_cached->io_aes_accel_special_keys, &keys, 8) ||
      keys == 0) {
    x8A4_log_error("Failed to read io_aes_accel_special_keys from kobject: 0x%llX!\n", kobject);
    return NULL;
  }
  x8A4_log_debug("kobject + koffsets_cached->io_aes_accel_special_keys_size: 0x%016llX\n", kobject + koffsets_cached->io_aes_accel_special_keys_size);
  if (kread(kobject + koffsets_cached->io_aes_accel_special_keys_size,
            keys_count, 4) ||
      *keys_count == 0) {
    x8A4_log_error("Failed to read io_aes_accel_special_keys_size from kobject: 0x%llX!\n", kobject);
    return NULL;
  }
  size_t struct_size = sizeof(struct x8A4_accel_key);
  struct x8A4_accel_key *out_keys = (struct x8A4_accel_key *)calloc(*keys_count, struct_size);
  gc_cached[gc_count_cached++] = (uint64_t)out_keys;
  x8A4_log_debug_error("gc_cached[gc_count_cached++]: %d val: 0x%016llX\n", __LINE__, out_keys);
  x8A4_log_debug("keys: 0x%016llX keys count: %zu\n", keys, *keys_count);
  for (int i = 0; i < *keys_count; i++) {
    struct x8A4_accel_key *cur_key = (struct x8A4_accel_key *)(out_keys + (struct_size * i));
    if(kread((keys + (struct_size * i)), cur_key, struct_size)) {
      x8A4_log_debug_error("Failed to read special key: %d from keys: 0x%016llX!\n", i, (keys + (struct_size * i)));
      continue;
    }
  }
  return out_keys;
}

/**
 * @brief           x8A4 main library function
 */
void x8A4(void) {

}

#if 0
/**
 * @brief           x8A4 main library function
 */
void x8A4(void) {
  x8A4_log_debug("x8A4!\n", "");
//  uint32_t generator_size = 0;
//  uint8_t *generator = x8A4_get_apnonce_generator(&generator_size, nvram_udid);
//  if (!generator) {
//    x8A4_log_error("!generator\n", "");
//  } else {
//    x8A4_log_debug("boot-nonce(apnonce generator): %s\n", generator);
//  }
//  const char *new_nonce = "0x6969696969696969";
//  uint32_t new_nonce_size = strlen(new_nonce);
//  x8A4_log_debug("Setting boot-nonce(apnonce generator): %s\n", new_nonce);
//  generator = x8A4_set_apnonce_generator((uint8_t *)new_nonce, &new_nonce_size);
//  if (!generator) {
//    x8A4_log_error("!generator\n", "");
//  } else {
//    x8A4_log_debug("boot-nonce(apnonce generator): %s\n", generator);
//  }
  uint64_t kobject = get_ipc_kobject(get_io_aes_accel_service());
  if (!kobject) {
    x8A4_log_error("Failed to get kobject from IOAESAccelerator service!\n", "");
    return;
  }
  uint64_t keys = 0;
  x8A4_log_debug("kobject: 0x%016llX\n", kobject);
  x8A4_log_debug("kobject + koffsets_cached->io_aes_accel_special_keys: 0x%016llX\n", kobject + koffsets_cached->io_aes_accel_special_keys);
  if (kread(kobject + koffsets_cached->io_aes_accel_special_keys, &keys, 8) ||
      keys == 0) {
    x8A4_log_error("Failed to read io_aes_accel_special_keys from kobject: 0x%llX!\n", kobject);
    return;
  }
  size_t keys_count = 0;
  x8A4_log_debug("kobject + koffsets_cached->io_aes_accel_special_keys_size: 0x%016llX\n", kobject + koffsets_cached->io_aes_accel_special_keys_size);
  if (kread(kobject + koffsets_cached->io_aes_accel_special_keys_size,
            &keys_count, 8) ||
      keys_count == 0) {
    x8A4_log_error("Failed to read io_aes_accel_special_keys_size from kobject: 0x%llX!\n", kobject);
    return;
  }
  size_t struct_size = sizeof(struct x8A4_accel_key);
  struct x8A4_accel_key *out_keys = (struct x8A4_accel_key *)calloc(keys_count, struct_size);
  x8A4_log_debug("keys: 0x%llX keys count: %zu\n", keys, keys_count);
  for (int i = 0; i < keys_count; i++) {
    struct x8A4_accel_key *cur_key = out_keys + (struct_size * i);
    if (kread(keys + (struct_size * i), cur_key, struct_size)) {
      x8A4_log_error("Failed to read special key: %d from keys: 0x%llX!\n", i, keys);
    }
    //        if(cur_key->key_id == 0x8A4) {
    x8A4_log_debug("cur_key index: 0x%X\n", i);
    x8A4_log_debug("cur_key->generated: 0x%X\n", cur_key->generated);
    x8A4_log_debug("cur_key->key_id: 0x%X\n", cur_key->key_id);
    x8A4_log_debug("cur_key->key_sz: 0x%X\n", cur_key->key_sz);
    x8A4_log_debug("cur_key->key: 0x%08X%08X%08X%08X%\n", __builtin_bswap32(cur_key->key[0]), __builtin_bswap32(cur_key->key[1]), __builtin_bswap32(cur_key->key[2]), __builtin_bswap32(cur_key->key[3]));
    x8A4_log_debug("cur_key->iv: 0x%08X%08X%08X%08X\n", __builtin_bswap32(cur_key->iv[0]), __builtin_bswap32(cur_key->iv[1]), __builtin_bswap32(cur_key->iv[2]), __builtin_bswap32(cur_key->iv[3]));
    x8A4_log_debug("cur_key->zero: 0x%X\n", cur_key->zero);
    x8A4_log_debug("cur_key->pad: 0x%X\n", cur_key->pad);
    //        }
  }
  if (out_keys) {
    free(out_keys);
  }

//  uint64_t nvram_dict = get_service_nvram_dict(get_dtre_options());
//  if (!nvram_dict) {
//    x8A4_log_error("!nvram_dict\n", "");
//    return;
//  }
//
//  //    size_t sz = strlen("0x") + 0x10;
//  uint8_t *nonce_seeds = NULL;
//  uint8_t **nonce_seeds_ptr = &nonce_seeds;
//  uint32_t seeds_size = 0;
//  uint8_t *cryptex_seed =
//      x8A4_get_cryptex_seed(nonce_seeds_ptr, &seeds_size);
//  x8A4_log_debug("seeds_size: 0x%X\n", seeds_size);
//  if (!cryptex_seed) {
//    x8A4_log_error("!cryptex_seed\n", "");
//  } else {
//    x8A4_log_debug("cryptex seed: 0x", "");
//    for (int i = 0; i < 16; i++) {
//      fflush(stdout);
//      x8A4_log("%02X", *(cryptex_seed + i));
//    }
//    x8A4_log("\n", "");
//    fflush(stdout);
//  }
//  if (!nonce_seeds) {
//    x8A4_log_error("!nonce_seeds\n", "");
//  } else {
//    x8A4_log_debug("nonce_seeds: 0x", "");
//    for (int i = 0; i < seeds_size; i++) {
//      fflush(stdout);
//      aprintf(stdout, "%02X", *(nonce_seeds + i));
//    }
//    aprintf(stdout, "\n");
//    fflush(stdout);
//  }

//      char *new_key = calloc(1, key_len + UDID_LEN + 1);
//      x8A4_log_debug("nvram_udid: %s\n", nvram_udid);
//      snprintf(new_key, key_len + UDID_LEN + 1, "%s%s", nvram_udid, key);
//      set_nvram_entry_bytes(nvram_dict, new_key, (uint8_t
//      *)"0x6969696969696969", sz, nonce_type);
//      set_nvram_entry_bytes(nvram_dict, new_key, (uint8_t *)seeds_bin, sz,
//      nonce_seeds_type);

  //    nonce_seeds = get_nvram_entry_bytes(nvram_dict, new_key, sz, 0);
  //    if(!nonce_seeds) {
  //        x8A4_log_error("!nonce_seeds\n", "");
  //        return;
  //    }
  //    x8A4_log_debug("new nonce_seeds: %s\n", nonce_seeds);
  //    uint8_t *cryptex_seed = x8A4_get_cryptex_seed();
  //    x8A4_log_debug("cryptex seed: 0x", "");
  //    for(int i = 0; i < 16; i++) {
  //        fflush(stdout);
  //        aprintf(stdout, "%02X", *(cryptex_seed + i));
  //    }
  //    aprintf(stdout, "\n");
  //    fflush(stdout);
}
#endif

/**
 * @brief           CLI set program verbose
 */
void x8A4_cli_set_verbose(void) {
  verbose_cached = 1;
  setenv("LIBKRW_LOG", "1", 0);
}

/**
 * @brief           CLI get cryptex seed
 */
void x8A4_cli_get_cryptex_seed(void) {
  x8A4_log("Getting cryptex seed...\n", "");
  uint8_t **nonce_seeds = calloc(1, 1000);
  uint32_t seeds_size = 0;
  uint8_t *cryptex_seed = x8A4_get_cryptex_seed(nonce_seeds, &seeds_size);
  if (!cryptex_seed) {
    x8A4_log_error("Failed to get cryptex seed!\n", "");
  } else {
    x8A4_log("Done!\n", "");
    x8A4_log("Got cryptex seed (0x", "");
    for (int i = 0; i < 16; i++) {
      fflush(stdout);
      x8A4_log("%02X", *(cryptex_seed + i));
    }
    x8A4_log(")\n", "");
    fflush(stdout);
  }
  if (!nonce_seeds) {
    x8A4_log_debug_error("Failed to get nonce seeds!\n", "");
  } else {
    x8A4_log_debug("seeds_size: 0x%04X\n", seeds_size);
    if(verbose_cached) {
      x8A4_log_debug("nonce_seeds: 0x", "");
      for (int i = 0; i < seeds_size; i++) {
        fflush(stdout);
        x8A4_log("%02X", *(nonce_seeds + i));
      }
      x8A4_log("\n", "");
      fflush(stdout);
    }
  }
  free(nonce_seeds);
}

/**
 * @brief           CLI get cryptex nonce
 */
void x8A4_cli_get_cryptex_nonce(void) {
  x8A4_log("Getting cryptex nonce...\n", "");
  uint32_t nonce_size = 0;
  uint8_t *nonce = x8A4_get_cryptex_nonce(&nonce_size);
  if (!nonce || !nonce_size) {
    x8A4_log_error("Failed to get cryptex nonce!\n", "");
  } else {
    x8A4_log("Done!\n", "");
    x8A4_log("Got cryptex nonce (0x", "");
    int digest_len = get_hash_len();
    digest_len = (digest_len == CC_SHA384_DIGEST_LENGTH) ? CC_SHA256_DIGEST_LENGTH : CC_SHA1_DIGEST_LENGTH;
    for (int i = 0; i < digest_len; i++) {
      fflush(stdout);
      x8A4_log("%02X", *(nonce + i));
    }
    x8A4_log(")\n", "");
    fflush(stdout);
  }
}

/**
 * @brief           CLI get apnonce generator
 */
void x8A4_cli_get_apnonce_generator(void) {
  x8A4_log("Getting APNonce generator...\n", "");
  uint32_t out_generator_size = 0;
  uint8_t *generator = x8A4_get_apnonce_generator(&out_generator_size);
  if(!generator || ((out_generator_size & 0xFFFFFFFF) != 0x12 && (out_generator_size & 0xFFFFFFFF) != 0x13)) {
    x8A4_log_error("Failed to get apnonce generator(%s)(%u)!\n", (generator) ? (const char *)generator : "NULL", (uint32_t)out_generator_size);
    return;
  }
  x8A4_log("Done!\n", "");
  x8A4_log("APNonce generator(%s)\n", generator);
}

/**
 * @brief           CLI get apnonce
 */
void x8A4_cli_get_apnonce(void) {
  x8A4_log("Getting APNonce...\n", "");
  uint32_t nonce_size = 0;
  uint8_t *nonce = x8A4_get_apnonce(&nonce_size);
  if (!nonce || !nonce_size) {
    x8A4_log_error("Failed to get APNonce!\n", "");
  } else {
    x8A4_log("Done!\n", "");
    x8A4_log("Got APNonce (0x", "");
    for (int i = 0; i < nonce_size; i++) {
      fflush(stdout);
      x8A4_log("%02X", *(nonce + i));
    }
    x8A4_log(")\n", "");
    fflush(stdout);
  }
  gc_d_cached[gc_d_count_cached++] = (uint64_t)nonce;
  free(nonce);
}

/**
 * @brief           CLI set apnonce generator
 * @param[in]       new_generator
 */
void x8A4_cli_set_apnonce_generator(const char *new_generator) {
  uint32_t new_generator_size = strlen(new_generator);
  uint32_t out_generator_size = new_generator_size;
  if(new_generator_size >= 16) {
    x8A4_log("Setting apnonce generator(%s)...\n", new_generator);
    uint8_t *generator = x8A4_set_apnonce_generator((uint8_t *)new_generator, &out_generator_size);
    if(generator && new_generator_size == out_generator_size && memcmp(new_generator, generator, new_generator_size) == 0) {
      x8A4_log("Done!\n", "");
      x8A4_log("Successfully set apnonce generator(%s)!\n", generator);
    } else {
      x8A4_log_error("Failed to set apnonce generator(%s), set(%s)!\n", new_generator, (generator) ? (const char *)generator : "NULL");
    }
  }
}

/**
 * @brief           CLI clear apnonce generator
 */
void x8A4_cli_clear_apnonce_generator(void) {
  x8A4_log("Clearing apnonce generator...\n", "");
  int ret = x8A4_clear_apnonce_generator();
  if(!ret) {
    x8A4_log("Done!\n", "");
    x8A4_log("Successfully cleared apnonce generator!\n", "");
  } else {
    x8A4_log_error("Failed to clear apnonce generator!\n", "");
  }
}

/**
 * @brief           CLI get IOAESAccelerator keys
 * @param[in]       chosen_key
 */
void x8A4_cli_get_accel_keys(uint32_t chosen_key) {
  x8A4_log("Getting IOAESAccelerator keys...\n", "");
  uint32_t keys_count = 0;
  size_t struct_size = sizeof(struct x8A4_accel_key);
  struct x8A4_accel_key *keys = x8A4_get_ioaesaccelkeys(&keys_count);
  if(!keys) {
    x8A4_log_error("Failed to get IOAESAccelerator Keys!\n", "");
    return;
  }
  x8A4_log("Done!\n", "");
  for (int i = 0; i < keys_count; i++) {
    struct x8A4_accel_key *cur_key = keys + (struct_size * i);
    if(chosen_key && cur_key->key_id != chosen_key) {
      continue;
    }
    x8A4_log("Got key (0x%04X)\n", cur_key->key_id);
    x8A4_log("Key(0x%04X) Index: 0x%04X\n", cur_key->key_id, i);
    x8A4_log("Key(0x%04X) Generated: 0x%04X\n", cur_key->key_id, cur_key->generated);
    x8A4_log("Key(0x%04X) Size: 0x%04X\n", cur_key->key_id, cur_key->key_sz);
    x8A4_log("Key(0x%04X) KEY: 0x%08X%08X%08X%08X%\n", cur_key->key_id, __builtin_bswap32(cur_key->key[0]), __builtin_bswap32(cur_key->key[1]), __builtin_bswap32(cur_key->key[2]), __builtin_bswap32(cur_key->key[3]));
    x8A4_log("Key(0x%04X) IV: 0x%08X%08X%08X%08X%\n", cur_key->key_id, __builtin_bswap32(cur_key->iv[0]), __builtin_bswap32(cur_key->iv[1]), __builtin_bswap32(cur_key->iv[2]), __builtin_bswap32(cur_key->iv[3]));
    if(chosen_key && cur_key->key_id == chosen_key) {
      break;
    }
  }
  gc_d_cached[gc_d_count_cached++] = (uint64_t)keys;
  free(keys);
}

/**
 * @brief           CLI get nonce-seeds
 */
void x8A4_cli_get_nonce_seeds(void) {
    x8A4_log("Getting nonce seeds...\n", "");
    uint32_t seeds_size = 0;
    uint8_t *seeds = x8A4_get_nonce_seeds(&seeds_size);
    if (!seeds) {
      x8A4_log_error("Failed to get nonce seeds!\n", "");
    } else {
      x8A4_log("Done!\n", "");
      x8A4_log("Got nonce seeds(0x", "");
      if(nonce_slot_format_cached == 1) {
        for (int i = 0; i < seeds_size / sizeof(struct x8A4_nonce_seeds_slot); i++) {
          struct x8A4_nonce_seeds_slot *slot = (struct x8A4_nonce_seeds_slot *)seeds;
          slot = &slot[i];
          if(!slot->seed.seed[0]) {
            continue;
          }
          for (int j = 0; j < sizeof(struct x8A4_nonce_seeds_slot); j++) {
            fflush(stdout);
            x8A4_log("%02X", *((uint8_t *)slot + j));
          }
        }
      } else {
        for (int i = 0; i < seeds_size; i++) {
          fflush(stdout);
          x8A4_log("%02X", *(seeds + i));
        }
      }
      x8A4_log(")\n", "");
      fflush(stdout);
    }
}

/**
 * @brief           CLI set cryptex seed
 * @param[in]       new_seed
 */
void x8A4_cli_set_cryptex_seed(const char *new_seed) {
  x8A4_log("Setting cryptex seed(%s)...\n", new_seed);
  if(!new_seed) {
    return;
  }
  if(strlen(new_seed) < 32) {
    return;
  }
  char seed_str[35];
  char seed_str2[35];
  seed_str2[0] = '0';
  seed_str2[1] = 'x';
  if(strlen(new_seed) == 34 && (new_seed[0] == '0' && new_seed[1] == 'x')) {
    strncpy(seed_str, new_seed, 18);
    strncpy(seed_str2 + 2, new_seed + 18, 16);
  } else if(strlen(new_seed) == 32 && (new_seed[0] != '0' && new_seed[1] != 'x')) {
    strncpy(seed_str + 2, new_seed, 16);
    strncpy(seed_str2 + 2, new_seed + 18, 16);
  } else {
    return;
  }
  uint64_t seed[2];
  seed[0] = strtoull(seed_str, NULL, 0);
  seed[1] = strtoull(seed_str2, NULL, 0);
  if((!seed[0] || seed[0] == ~(uint64_t)0) || !seed[1] || seed[1] == ~(uint64_t)0) {
    return;
  }
  seed[0] = __builtin_bswap64(seed[0]);
  seed[1] = __builtin_bswap64(seed[1]);
  int cryptex_boot_index = 0;
  if(strcmp(gXPF.darwinVersion, "23.0.0") >= 0 && nonce_slot_format_cached == 1) {
    cryptex_boot_index = x8A4_get_cryptex_boot_slot_slots_index();
  } else {
    cryptex_boot_index = x8A4_get_cryptex_boot_domain_index();
  }
  if(cryptex_boot_index == -1) {
    return;
  }
  if(x8A4_set_nonce_seeds_os_dict((uint8_t *)seed, cryptex_boot_index)) {
    x8A4_log_error("Failed to set cryptex seed(%s)!\n", new_seed);
    return;
  }
  x8A4_log("Done!\n", "");
  x8A4_log("Successfully set cryptex seed(%s)!\n", new_seed);
}
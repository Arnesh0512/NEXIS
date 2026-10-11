#include "audit_types.h"
#include <stdio.h>
extern int abcd_hash_dataset_sha256(const char *data, char *out_hash, size_t max_len);


int c_audit_verify_entry(const char *e) { return e != NULL; }

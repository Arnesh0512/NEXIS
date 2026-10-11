#include "audit_types.hpp"
#include <string>
extern std::string abcd_hash_dataset_sha256(const std::string& data);


bool cpp_audit_verify_entry(const std::string& e) { return !e.empty(); }

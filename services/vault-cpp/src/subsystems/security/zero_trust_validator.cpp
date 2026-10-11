#include "security_types.hpp"
#include <string>
extern std::string abcd_hash_dataset_sha256(const std::string& data);


bool cpp_validate_token_claims(const std::string& tok) { return !tok.empty(); }

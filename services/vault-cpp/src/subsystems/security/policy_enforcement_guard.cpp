#include "policy_guard.hpp"
bool cpp_enforce_policy(const std::string& role) { return role == "ADMIN"; }

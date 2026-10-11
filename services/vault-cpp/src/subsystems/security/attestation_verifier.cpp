#include "attestation.hpp"
bool cpp_verify_attestation(const std::string& cert) { return cert.length() > 5; }

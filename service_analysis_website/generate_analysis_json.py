"""
Nexis Core Platform - Multi-Language Service Analyzer
======================================================
Scans all 9 services in nexis-core-platform/services across 9 languages:
  1. TypeScript (api-gateway-ts)
  2. Java (auth-java)
  3. Kotlin (auth-kotlin)
  4. Rust (crypto-rs)
  5. JavaScript (edge-router-js)
  6. C (hsm-c)
  7. Go (ledger-go)
  8. Python (payment-py)
  9. C++ (vault-cpp)

Generates an authoritative JSON file containing for each file:
  - File name & relative path
  - Lines of code (LOC)
  - Modules imported:
      * non-user-defined (stdlib + 3rd-party dependencies)
      * user-defined (internal relative/package modules)
  - Number of functions
  - Functions array:
      * function name
      * calls: external/internal function calls and originating module
      * crypto_artifacts: specific cryptographic algorithms/APIs used inside
"""

import ast
import json
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple

SERVICES_ROOT = Path("C:/Users/Arnesh/Desktop/nexis-core-platform/services")
OUTPUT_JSON_PATH = Path("C:/Users/Arnesh/Desktop/nexis-core-platform/service_analysis_website/data/services_analysis.json")

# Standard Node.js built-ins
NODE_BUILTINS = {
    "assert", "async_hooks", "buffer", "child_process", "cluster", "console", "constants",
    "crypto", "dgram", "dns", "domain", "events", "fs", "http", "http2", "https",
    "inspector", "module", "net", "os", "path", "perf_hooks", "process", "punycode",
    "querystring", "readline", "repl", "stream", "string_decoder", "timers", "tls",
    "trace_events", "tty", "url", "util", "v8", "vm", "wasi", "worker_threads", "zlib"
}

# Python Standard Library common modules
PY_STDLIB = {
    "os", "sys", "time", "datetime", "json", "base64", "hashlib", "hmac", "secrets",
    "struct", "io", "tempfile", "re", "random", "math", "csv", "gzip", "logging",
    "uuid", "collections", "typing", "dataclasses", "enum", "contextlib", "asyncio",
    "urllib", "http", "pathlib", "shutil", "socket", "ssl", "threading", "multiprocessing",
    "abc", "copy", "functools", "itertools", "string", "warnings"
}

# Common C / C++ Standard Headers
C_CPP_STDLIB_HEADERS = {
    "stdio.h", "stdlib.h", "string.h", "stdint.h", "stdbool.h", "time.h", "math.h", "ctype.h",
    "signal.h", "stddef.h", "assert.h", "errno.h", "fcntl.h", "unistd.h",
    "iostream", "string", "vector", "memory", "sstream", "iomanip", "chrono", "mutex",
    "unordered_map", "unordered_set", "map", "set", "cstring", "algorithm", "atomic",
    "deque", "fstream", "random", "thread", "stdexcept", "functional", "utility", "array",
    "tuple", "type_traits", "condition_variable", "future", "optional", "variant"
}

# Cryptographic keywords and signatures for pattern detection
CRYPTO_PATTERNS = [
    (r"\b(AES[-_]?(?:128|192|256)?(?:[-_]?(?:GCM|CBC|CTR|ECB))?)\b", "AES"),
    (r"\b(RSA[-_]?(?:1024|2048|3072|4096)?)\b", "RSA"),
    (r"\b(ML[-_]?KEM[-_]?(?:512|768|1024)?|Kyber[-_]?(?:512|768|1024)?)\b", "ML-KEM / Kyber (PQC)"),
    (r"\b(ML[-_]?DSA[-_]?(?:44|65|87)?|Dilithium[-_]?(?:2|3|5)?)\b", "ML-DSA / Crystals-Dilithium (PQC)"),
    (r"\b(SLH[-_]?DSA|SPHINCS\+?)\b", "SLH-DSA / SPHINCS+ (PQC)"),
    (r"\b(Ed25519|ed25519)\b", "Ed25519 Signature"),
    (r"\b(ECDSA|secp256r1|secp384r1|secp256k1|NIST[-_]?P[-_]?(?:256|384|521))\b", "ECDSA / Elliptic Curve"),
    (r"\b(ChaCha20[-_]?Poly1305|chacha20poly1305|ChaCha20)\b", "ChaCha20-Poly1305"),
    (r"\b(HMAC[-_]?(?:SHA[-_]?(?:256|384|512|1))?)\b", "HMAC"),
    (r"\b(SHA[-_]?256|sha256)\b", "SHA-256 Digest"),
    (r"\b(SHA[-_]?512|sha512)\b", "SHA-512 Digest"),
    (r"\b(SHA[-_]?1|sha1)\b", "SHA-1 (Legacy Digest)"),
    (r"\b(MD5|md5)\b", "MD5 (Insecure Digest)"),
    (r"\b(DES|3DES|TripleDES)\b", "DES (Legacy Block Cipher)"),
    (r"\b(PBKDF2|PBKDF2WithHmacSHA256)\b", "PBKDF2 Key Derivation"),
    (r"\b(Bcrypt|bcrypt|jBCrypt)\b", "Bcrypt Password Hasher"),
    (r"\b(JWT|jwt|Jwts|SignJWT)\b", "JSON Web Token (JWT)"),
    (r"\b(OAEP|padding\.OAEP)\b", "RSA-OAEP Padding"),
    (r"\b(PSS|padding\.PSS)\b", "RSA-PSS Padding"),
    (r"\b(Fernet)\b", "Fernet Symmetric Key"),
    (r"\b(X509|X\.509|PEM_read_bio_X509)\b", "X.509 Certificate"),
    (r"\b(EVP_CIPHER_CTX|EVP_aes_256_gcm|EVP_EncryptInit)\b", "OpenSSL EVP AES-256-GCM"),
    (r"\b(EVP_DigestSign|EVP_PKEY_RSA)\b", "OpenSSL EVP RSA Signer"),
    (r"\b(OQS_KEM|OQS_SIG|liboqs)\b", "liboqs Post-Quantum Cryptography"),
    (r"\b(Tink|Aead|KeysetHandle)\b", "Google Tink AEAD"),
    (r"\b(CKM_AES_GCM|PKCS11|C_EncryptInit)\b", "PKCS#11 Hardware Security Module"),
    (r"\b(TLSv1\.[23]|TLS_AES_256_GCM_SHA384)\b", "TLS 1.2/1.3 Secure Transport")
]

# Detection helper to find crypto artifacts inside text while avoiding log traps
def extract_crypto_artifacts(code_segment: str) -> List[str]:
    found = set()
    for pattern, name in CRYPTO_PATTERNS:
        # Check if matched in executable statements (not comment lines)
        for line in code_segment.splitlines():
            clean = line.strip()
            if clean.startswith(("//", "#", "*", "/*")):
                continue
            if re.search(pattern, clean, re.IGNORECASE):
                # Extra check: avoid pure string logging traps if it's solely a log/print message
                if any(trap in clean for trap in ["emitDebugTrace", "logDebug", "LOGGER.info", "println", "LOGGER.fine", "securityNote:"]):
                    # If line has genuine crypto invocation call, keep it
                    if not any(call in clean for call in ["getInstance", "generate", "createCipher", "encrypt", "sign", "new", "init"]):
                        continue
                found.add(name)
    return sorted(list(found))


# -----------------------------------------------------------------------------
# 1. PYTHON PARSER (.py)
# -----------------------------------------------------------------------------
def parse_python_file(file_path: Path, relative_path: str) -> Dict[str, Any]:
    content = file_path.read_text(encoding="utf-8", errors="replace")
    lines = content.splitlines()
    loc = len(lines)
    
    non_user_imports = set()
    user_imports = set()
    import_symbol_map = {} # symbol -> originating module
    
    try:
        tree = ast.parse(content, filename=str(file_path))
    except Exception:
        tree = None

    if tree:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    mod = alias.name
                    asname = alias.asname or mod
                    import_symbol_map[asname] = mod
                    if mod.startswith("payment_app") or mod in ["vault", "auth", "api", "billing", "compliance", "db", "fraud", "gateway", "notifications", "orchestrator"]:
                        user_imports.add(mod)
                    else:
                        non_user_imports.add(mod)
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                is_internal = mod.startswith("payment_app") or mod.startswith(".") or (node.level and node.level > 0) or mod in ["vault", "auth", "api", "billing", "compliance", "db", "fraud", "gateway", "notifications", "orchestrator"]
                full_mod = mod if not node.level else ("." * node.level + mod)
                if is_internal:
                    user_imports.add(full_mod)
                else:
                    non_user_imports.add(full_mod)
                for alias in node.names:
                    sym = alias.asname or alias.name
                    import_symbol_map[sym] = full_mod

    # Extract functions
    functions = []
    if tree:
        class FunctionVisitor(ast.NodeVisitor):
            def __init__(self):
                self.funcs = []
                self.class_stack = []

            def visit_ClassDef(self, node):
                self.class_stack.append(node.name)
                self.generic_visit(node)
                self.class_stack.pop()

            def visit_FunctionDef(self, node):
                self._handle_func(node)

            def visit_AsyncFunctionDef(self, node):
                self._handle_func(node)

            def _handle_func(self, node):
                fn_name = node.name
                if self.class_stack:
                    fn_name = f"{self.class_stack[-1]}.{node.name}"
                
                start_l = node.lineno
                end_l = getattr(node, "end_lineno", None) or (start_l + len(node.body))
                body_code = "\n".join(lines[start_l - 1:end_l])
                
                # Calls inside function
                calls = []
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Call):
                        call_name = ""
                        if isinstance(sub.func, ast.Name):
                            call_name = sub.func.id
                        elif isinstance(sub.func, ast.Attribute):
                            parts = []
                            curr = sub.func
                            while isinstance(curr, ast.Attribute):
                                parts.append(curr.attr)
                                curr = curr.value
                            if isinstance(curr, ast.Name):
                                parts.append(curr.id)
                            parts.reverse()
                            call_name = ".".join(parts)
                        
                        if call_name:
                            # Determine type and module
                            root_id = call_name.split(".")[0]
                            if root_id == "self":
                                c_type = "internal"
                                mod = self.class_stack[-1] if self.class_stack else "local"
                            elif call_name.startswith(("abcd_", "efgh_", "ijkl_", "mnop_")):
                                c_type = "internal"
                                mod = "local"
                            elif root_id in import_symbol_map:
                                mod_source = import_symbol_map[root_id]
                                if mod_source.startswith("payment_app") or mod_source.startswith("."):
                                    c_type = "internal"
                                    mod = mod_source
                                else:
                                    c_type = "external"
                                    mod = mod_source
                            elif root_id in PY_STDLIB or root_id in ["print", "len", "range", "isinstance", "int", "str", "bytes", "dict", "list", "set"]:
                                c_type = "external"
                                mod = "builtins" if root_id not in PY_STDLIB else root_id
                            else:
                                c_type = "internal"
                                mod = "local"
                            
                            calls.append({
                                "function_name": call_name,
                                "type": c_type,
                                "module": mod
                            })

                # Deduplicate calls
                unique_calls = []
                seen_calls = set()
                for c in calls:
                    key = (c["function_name"], c["type"], c["module"])
                    if key not in seen_calls:
                        seen_calls.add(key)
                        unique_calls.append(c)

                crypto_artifacts = extract_crypto_artifacts(body_code)
                self.funcs.append({
                    "name": fn_name,
                    "start_line": start_l,
                    "end_line": end_l,
                    "calls": unique_calls,
                    "crypto_artifacts": crypto_artifacts
                })
                self.generic_visit(node)

        fv = FunctionVisitor()
        fv.visit(tree)
        functions = fv.funcs

    return {
        "file_name": file_path.name,
        "relative_path": relative_path,
        "language": "Python",
        "service": "payment-py",
        "lines_of_code": loc,
        "modules_imported": {
            "non_user_defined": sorted(list(non_user_imports)),
            "user_defined": sorted(list(user_imports))
        },
        "number_of_functions": len(functions),
        "functions": functions
    }


# -----------------------------------------------------------------------------
# 2. TYPESCRIPT & JAVASCRIPT PARSER (.ts, .js)
# -----------------------------------------------------------------------------
def parse_js_ts_file(file_path: Path, relative_path: str, lang_name: str, service_name: str) -> Dict[str, Any]:
    content = file_path.read_text(encoding="utf-8", errors="replace")
    lines = content.splitlines()
    loc = len(lines)
    
    non_user_imports = set()
    user_imports = set()
    import_symbol_map = {}

    # Extract ES imports & CommonJS require
    # 1. import ... from '...'
    es_import_pattern = re.compile(r"""import\s+(?:(\*\s+as\s+[\w$]+|\{[^}]*\}|[\w$,\s]+)\s+from\s+)?['"]([^'"]+)['"]""")
    # 2. const ... = require('...')
    cjs_require_pattern = re.compile(r"""(?:(?:const|let|var)\s+([\w$,\s{}]+)\s*=\s*)?require\(['"]([^'"]+)['"]\)""")

    for line in lines:
        for m in es_import_pattern.finditer(line):
            symbols, mod = m.group(1), m.group(2)
            if mod.startswith(("./", "../", ".")):
                user_imports.add(mod)
                is_internal = True
            else:
                non_user_imports.add(mod)
                is_internal = False
            
            if symbols:
                clean_syms = re.findall(r"[\w$]+", symbols.replace("*", "").replace("as", ""))
                for s in clean_syms:
                    import_symbol_map[s] = (mod, is_internal)

        for m in cjs_require_pattern.finditer(line):
            symbols, mod = m.group(1), m.group(2)
            if mod.startswith(("./", "../", ".")):
                user_imports.add(mod)
                is_internal = True
            else:
                non_user_imports.add(mod)
                is_internal = False

            if symbols:
                clean_syms = re.findall(r"[\w$]+", symbols)
                for s in clean_syms:
                    import_symbol_map[s] = (mod, is_internal)

    # Function declarations
    # Patterns: class methods, regular function, arrow functions
    func_pattern = re.compile(
        r"""^\s*(?:(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([a-zA-Z0-9_$]+)|"""
        r"""(?:(?:export\s+)?(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>)|"""
        r"""(?:(?:public|private|protected|static|async|override)\s+)*([a-zA-Z0-9_$]+)\s*\([^;]*?\)(?::\s*[^;{]+)?\s*\{)"""
    )
    class_pattern = re.compile(r"""^\s*(?:export\s+)?class\s+([a-zA-Z0-9_$]+)""")

    functions = []
    current_class = None
    open_brackets = 0
    func_stack = []

    for idx, line in enumerate(lines, 1):
        clean = line.strip()
        if clean.startswith(("//", "/*", "*")):
            continue

        cm = class_pattern.match(line)
        if cm:
            current_class = cm.group(1)

        fm = func_pattern.match(line)
        if fm:
            fname = next((g for g in fm.groups() if g), None)
            if fname and fname not in ("if", "for", "while", "switch", "catch", "constructor", "class"):
                display_name = f"{current_class}.{fname}" if current_class and not line.strip().startswith("function") else fname
                func_stack.append({
                    "name": display_name,
                    "start_line": idx,
                    "depth": open_brackets + line.count("{") - line.count("}")
                })

        open_brackets += line.count("{") - line.count("}")

    # For each detected function, determine its approximate end line and parse calls
    for i, fn in enumerate(func_stack):
        start = fn["start_line"]
        end = func_stack[i + 1]["start_line"] - 1 if i + 1 < len(func_stack) else loc
        body_lines = lines[start - 1:end]
        body_text = "\n".join(body_lines)

        # Detect calls
        call_matches = re.findall(r"\b([a-zA-Z0-9_$]+(?:\.[a-zA-Z0-9_$]+)*)\s*\(", body_text)
        calls = []
        for call_name in call_matches:
            if call_name in ("if", "for", "while", "switch", "catch", "function", "return"):
                continue
            if call_name == fn["name"] or call_name.split(".")[-1] == fn["name"]:
                continue
            root_id = call_name.split(".")[0]
            if root_id == "this":
                c_type = "internal"
                mod = current_class or "local"
            elif call_name.startswith(("abcd_", "efgh_", "ijkl_", "mnop_")):
                c_type = "internal"
                mod = "local"
            elif root_id in import_symbol_map:
                mod_src, is_int = import_symbol_map[root_id]
                c_type = "internal" if is_int else "external"
                mod = mod_src
            elif root_id in NODE_BUILTINS:
                c_type = "external"
                mod = root_id
            else:
                c_type = "internal"
                mod = "local"

            calls.append({
                "function_name": call_name,
                "type": c_type,
                "module": mod
            })

        # Deduplicate
        unique_calls = []
        seen_calls = set()
        for c in calls:
            key = (c["function_name"], c["type"], c["module"])
            if key not in seen_calls:
                seen_calls.add(key)
                unique_calls.append(c)

        crypto_artifacts = extract_crypto_artifacts(body_text)
        functions.append({
            "name": fn["name"],
            "start_line": start,
            "end_line": end,
            "calls": unique_calls,
            "crypto_artifacts": crypto_artifacts
        })

    return {
        "file_name": file_path.name,
        "relative_path": relative_path,
        "language": lang_name,
        "service": service_name,
        "lines_of_code": loc,
        "modules_imported": {
            "non_user_defined": sorted(list(non_user_imports)),
            "user_defined": sorted(list(user_imports))
        },
        "number_of_functions": len(functions),
        "functions": functions
    }


# -----------------------------------------------------------------------------
# 3. JAVA & KOTLIN PARSER (.java, .kt)
# -----------------------------------------------------------------------------
def parse_jvm_file(file_path: Path, relative_path: str, lang_name: str, service_name: str) -> Dict[str, Any]:
    content = file_path.read_text(encoding="utf-8", errors="replace")
    lines = content.splitlines()
    loc = len(lines)

    non_user_imports = set()
    user_imports = set()
    import_symbol_map = {}

    import_pattern = re.compile(r"""^\s*import\s+(?:static\s+)?([a-zA-Z0-9_.*]+)""")
    for line in lines:
        m = import_pattern.match(line)
        if m:
            imp = m.group(1).rstrip(";")
            is_internal = imp.startswith("com.nexis.")
            if is_internal:
                user_imports.add(imp)
            else:
                non_user_imports.add(imp)
            # Map simple class name to full package
            simple_name = imp.split(".")[-1]
            if simple_name != "*":
                import_symbol_map[simple_name] = (imp, is_internal)

    # Function declarations
    if lang_name == "Java":
        func_pattern = re.compile(
            r"""^\s*(?:(?:public|private|protected|static|final|synchronized|abstract)\s+)*"""
            r"""(?:<[^>]+>\s+)?(?:[a-zA-Z0-9_<>[\]]+(?:\s*,\s*[a-zA-Z0-9_<>[\]]+)*\s+)([a-zA-Z0-9_]+)\s*\([^;]*?\)\s*"""
            r"""(?:throws\s+[^{]+)?\s*\{"""
        )
    else: # Kotlin
        func_pattern = re.compile(
            r"""^\s*(?:(?:public|private|internal|protected|override|suspend|inline)\s+)*"""
            r"""fun\s+(?:<[^>]+>\s+)?(?:[a-zA-Z0-9_]+\.)?([a-zA-Z0-9_]+)\s*\("""
        )

    class_pattern = re.compile(r"""^\s*(?:(?:public|private|protected|final|abstract)\s+)*(?:class|interface|object)\s+([a-zA-Z0-9_]+)""")

    functions = []
    current_class = None
    func_stack = []

    for idx, line in enumerate(lines, 1):
        clean = line.strip()
        if clean.startswith(("//", "/*", "*")):
            continue

        cm = class_pattern.match(line)
        if cm:
            current_class = cm.group(1)

        fm = func_pattern.match(line)
        if fm:
            fname = fm.group(1)
            if fname and fname not in ("if", "for", "while", "switch", "catch", "class", "interface"):
                display_name = f"{current_class}.{fname}" if current_class else fname
                func_stack.append({
                    "name": display_name,
                    "start_line": idx
                })

    for i, fn in enumerate(func_stack):
        start = fn["start_line"]
        end = func_stack[i + 1]["start_line"] - 1 if i + 1 < len(func_stack) else loc
        body_lines = lines[start - 1:end]
        body_text = "\n".join(body_lines)

        call_matches = re.findall(r"\b([a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)*)\s*\(", body_text)
        calls = []
        for call_name in call_matches:
            if call_name in ("if", "for", "while", "switch", "catch", "return"):
                continue
            if call_name == fn["name"] or call_name.split(".")[-1] == fn["name"]:
                continue
            root_id = call_name.split(".")[0]
            if root_id == "this":
                c_type = "internal"
                mod = current_class or "local"
            elif call_name.startswith(("abcd_", "efgh_", "ijkl_", "mnop_")):
                c_type = "internal"
                mod = "local"
            elif root_id in import_symbol_map:
                mod_src, is_int = import_symbol_map[root_id]
                c_type = "internal" if is_int else "external"
                mod = mod_src
            elif root_id in ("Cipher", "KeyPairGenerator", "KeyGenerator", "Signature", "Mac", "MessageDigest", "SecretKeyFactory", "KeyStore", "BCrypt", "Jwts", "Aead", "KeysetHandle", "AeadConfig"):
                c_type = "external"
                mod = "security.crypto"
            else:
                c_type = "internal"
                mod = "local"

            calls.append({
                "function_name": call_name,
                "type": c_type,
                "module": mod
            })

        unique_calls = []
        seen_calls = set()
        for c in calls:
            key = (c["function_name"], c["type"], c["module"])
            if key not in seen_calls:
                seen_calls.add(key)
                unique_calls.append(c)

        crypto_artifacts = extract_crypto_artifacts(body_text)
        functions.append({
            "name": fn["name"],
            "start_line": start,
            "end_line": end,
            "calls": unique_calls,
            "crypto_artifacts": crypto_artifacts
        })

    return {
        "file_name": file_path.name,
        "relative_path": relative_path,
        "language": lang_name,
        "service": service_name,
        "lines_of_code": loc,
        "modules_imported": {
            "non_user_defined": sorted(list(non_user_imports)),
            "user_defined": sorted(list(user_imports))
        },
        "number_of_functions": len(functions),
        "functions": functions
    }


# -----------------------------------------------------------------------------
# 4. GO PARSER (.go)
# -----------------------------------------------------------------------------
def parse_go_file(file_path: Path, relative_path: str) -> Dict[str, Any]:
    content = file_path.read_text(encoding="utf-8", errors="replace")
    lines = content.splitlines()
    loc = len(lines)

    non_user_imports = set()
    user_imports = set()
    import_symbol_map = {}

    # Extract imports
    in_import_block = False
    for line in lines:
        clean = line.strip()
        if clean.startswith("import ("):
            in_import_block = True
            continue
        elif in_import_block and clean == ")":
            in_import_block = False
            continue
        
        path_match = re.search(r"""(?:([a-zA-Z0-9_]+)\s+)?["']([^"']+)["']""", clean)
        if (in_import_block or clean.startswith("import ")) and path_match:
            alias, imp_path = path_match.group(1), path_match.group(2)
            is_internal = imp_path.startswith("github.com/nexis/ledger-go") or imp_path.startswith(("./", "../"))
            if is_internal:
                user_imports.add(imp_path)
            else:
                non_user_imports.add(imp_path)

            alias_name = alias or imp_path.split("/")[-1]
            import_symbol_map[alias_name] = (imp_path, is_internal)

    # Function declarations: func [ (recv Receiver) ] FuncName(
    func_pattern = re.compile(r"""^\s*func\s+(?:\((?:[^)]+)\)\s+)?([a-zA-Z0-9_]+)\s*\(""")
    func_stack = []

    for idx, line in enumerate(lines, 1):
        clean = line.strip()
        if clean.startswith(("//", "/*")):
            continue
        fm = func_pattern.match(line)
        if fm:
            fname = fm.group(1)
            func_stack.append({
                "name": fname,
                "start_line": idx
            })

    functions = []
    for i, fn in enumerate(func_stack):
        start = fn["start_line"]
        end = func_stack[i + 1]["start_line"] - 1 if i + 1 < len(func_stack) else loc
        body_lines = lines[start - 1:end]
        body_text = "\n".join(body_lines)

        call_matches = re.findall(r"\b([a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)*)\s*\(", body_text)
        calls = []
        for call_name in call_matches:
            if call_name in ("if", "for", "switch", "select", "return", "make", "len", "append", "copy", "panic"):
                continue
            if call_name == fn["name"] or call_name.split(".")[-1] == fn["name"]:
                continue
            root_id = call_name.split(".")[0]
            if root_id in import_symbol_map:
                mod_src, is_int = import_symbol_map[root_id]
                c_type = "internal" if is_int else "external"
                mod = mod_src
            elif call_name.startswith(("abcd_", "efgh_", "ijkl_", "mnop_")):
                c_type = "internal"
                mod = "local"
            else:
                c_type = "internal"
                mod = "local"

            calls.append({
                "function_name": call_name,
                "type": c_type,
                "module": mod
            })

        unique_calls = []
        seen_calls = set()
        for c in calls:
            key = (c["function_name"], c["type"], c["module"])
            if key not in seen_calls:
                seen_calls.add(key)
                unique_calls.append(c)

        crypto_artifacts = extract_crypto_artifacts(body_text)
        functions.append({
            "name": fn["name"],
            "start_line": start,
            "end_line": end,
            "calls": unique_calls,
            "crypto_artifacts": crypto_artifacts
        })

    return {
        "file_name": file_path.name,
        "relative_path": relative_path,
        "language": "Go",
        "service": "ledger-go",
        "lines_of_code": loc,
        "modules_imported": {
            "non_user_defined": sorted(list(non_user_imports)),
            "user_defined": sorted(list(user_imports))
        },
        "number_of_functions": len(functions),
        "functions": functions
    }


# -----------------------------------------------------------------------------
# 5. RUST PARSER (.rs)
# -----------------------------------------------------------------------------
def parse_rust_file(file_path: Path, relative_path: str) -> Dict[str, Any]:
    content = file_path.read_text(encoding="utf-8", errors="replace")
    lines = content.splitlines()
    loc = len(lines)

    non_user_imports = set()
    user_imports = set()
    import_symbol_map = {}

    use_pattern = re.compile(r"""^\s*(?:pub\s+)?use\s+([a-zA-Z0-9_:]+)(?:\{([^}]+)\})?""")
    for line in lines:
        clean = line.strip()
        m = use_pattern.match(clean)
        if m:
            base_path, group = m.group(1), m.group(2)
            is_internal = base_path.startswith(("crate::", "super::", "self::", "crypto_rs::"))
            if is_internal:
                user_imports.add(base_path.rstrip(":"))
            else:
                non_user_imports.add(base_path.rstrip(":"))

            if group:
                for item in group.split(","):
                    sym = item.strip().split(" as ")[-1].strip()
                    if sym:
                        import_symbol_map[sym] = (base_path.rstrip(":"), is_internal)
            else:
                last_sym = base_path.split(":")[-1]
                import_symbol_map[last_sym] = (base_path.rstrip(":"), is_internal)

    func_pattern = re.compile(r"""^\s*(?:pub(?:\([^)]+\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([a-zA-Z0-9_]+)\s*(?:<[^>]+>)?\s*\(""")
    func_stack = []
    for idx, line in enumerate(lines, 1):
        clean = line.strip()
        if clean.startswith(("//", "/*")):
            continue
        fm = func_pattern.match(line)
        if fm:
            fname = fm.group(1)
            func_stack.append({
                "name": fname,
                "start_line": idx
            })

    functions = []
    for i, fn in enumerate(func_stack):
        start = fn["start_line"]
        end = func_stack[i + 1]["start_line"] - 1 if i + 1 < len(func_stack) else loc
        body_lines = lines[start - 1:end]
        body_text = "\n".join(body_lines)

        call_matches = re.findall(r"\b([a-zA-Z0-9_]+(?:::[a-zA-Z0-9_]+)*|\b[a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)*)\s*\(", body_text)
        calls = []
        for call_name in call_matches:
            if call_name in ("if", "match", "for", "while", "return", "Ok", "Err", "Some", "None", "vec"):
                continue
            base_call = call_name.split("::")[-1].split(".")[-1]
            if call_name == fn["name"] or base_call == fn["name"]:
                continue
            root_id = call_name.split("::")[0].split(".")[0]
            if root_id == "self":
                c_type = "internal"
                mod = "local"
            elif call_name.startswith(("abcd_", "efgh_", "ijkl_", "mnop_")):
                c_type = "internal"
                mod = "local"
            elif root_id in import_symbol_map:
                mod_src, is_int = import_symbol_map[root_id]
                c_type = "internal" if is_int else "external"
                mod = mod_src
            elif root_id in ("ring", "aes_gcm", "pqcrypto_kyber", "jsonwebtoken", "bcrypt", "std"):
                c_type = "external"
                mod = root_id
            else:
                c_type = "internal"
                mod = "local"

            calls.append({
                "function_name": call_name,
                "type": c_type,
                "module": mod
            })

        unique_calls = []
        seen_calls = set()
        for c in calls:
            key = (c["function_name"], c["type"], c["module"])
            if key not in seen_calls:
                seen_calls.add(key)
                unique_calls.append(c)

        crypto_artifacts = extract_crypto_artifacts(body_text)
        functions.append({
            "name": fn["name"],
            "start_line": start,
            "end_line": end,
            "calls": unique_calls,
            "crypto_artifacts": crypto_artifacts
        })

    return {
        "file_name": file_path.name,
        "relative_path": relative_path,
        "language": "Rust",
        "service": "crypto-rs",
        "lines_of_code": loc,
        "modules_imported": {
            "non_user_defined": sorted(list(non_user_imports)),
            "user_defined": sorted(list(user_imports))
        },
        "number_of_functions": len(functions),
        "functions": functions
    }


# -----------------------------------------------------------------------------
# 6. C & C++ PARSER (.c, .h, .cpp, .hpp)
# -----------------------------------------------------------------------------
def parse_c_cpp_file(file_path: Path, relative_path: str, lang_name: str, service_name: str) -> Dict[str, Any]:
    content = file_path.read_text(encoding="utf-8", errors="replace")
    lines = content.splitlines()
    loc = len(lines)

    non_user_imports = set()
    user_imports = set()

    include_pattern = re.compile(r"""^\s*#include\s*(<([^>]+)>|"([^"]+)")""")
    for line in lines:
        m = include_pattern.match(line)
        if m:
            sys_hdr, usr_hdr = m.group(2), m.group(3)
            if usr_hdr:
                user_imports.add(usr_hdr)
            elif sys_hdr:
                non_user_imports.add(sys_hdr)

    # Function declarations
    if lang_name == "C":
        func_pattern = re.compile(
            r"""^(?:static\s+|extern\s+|inline\s+)?(?:[a-zA-Z0-9_*]+\s+)+([a-zA-Z0-9_]+)\s*\([^;]*?\)\s*\{"""
        )
    else: # C++
        func_pattern = re.compile(
            r"""^(?:(?:inline|static|virtual|explicit)\s+)*(?:[a-zA-Z0-9_<:>*,&\s]+?\s+)?(?:([a-zA-Z0-9_]+)::)?([a-zA-Z0-9_]+)\s*\([^;]*?\)(?:\s+const)?(?:\s+override)?\s*\{"""
        )

    func_stack = []
    for idx, line in enumerate(lines, 1):
        clean = line.strip()
        if clean.startswith(("//", "/*", "*")):
            continue
        fm = func_pattern.match(line)
        if fm:
            if lang_name == "C":
                fname = fm.group(1)
            else:
                cls_part = fm.group(1)
                fn_part = fm.group(2)
                fname = f"{cls_part}::{fn_part}" if cls_part else fn_part

            if fname and fname not in ("if", "for", "while", "switch", "catch"):
                func_stack.append({
                    "name": fname,
                    "start_line": idx
                })

    functions = []
    for i, fn in enumerate(func_stack):
        start = fn["start_line"]
        end = func_stack[i + 1]["start_line"] - 1 if i + 1 < len(func_stack) else loc
        body_lines = lines[start - 1:end]
        body_text = "\n".join(body_lines)

        call_matches = re.findall(r"\b([a-zA-Z0-9_]+(?:::[a-zA-Z0-9_]+)*|\b[a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)*)\s*\(", body_text)
        calls = []
        for call_name in call_matches:
            if call_name in ("if", "for", "while", "switch", "catch", "return", "sizeof"):
                continue
            base_call = call_name.split("::")[-1].split(".")[-1]
            if call_name == fn["name"] or base_call == fn["name"]:
                continue
            
            if call_name.startswith(("EVP_", "RSA_", "PEM_", "RAND_", "SHA256", "BIO_", "BN_")):
                c_type = "external"
                mod = "<openssl/evp.h>"
            elif call_name.startswith("OQS_"):
                c_type = "external"
                mod = "<oqs/oqs.h>"
            elif call_name.startswith("C_") or call_name.startswith("CKM_"):
                c_type = "external"
                mod = "pkcs11"
            elif call_name.startswith(("snprintf", "strlen", "memset", "memcpy", "malloc", "free")):
                c_type = "external"
                mod = "<stdio.h> / <string.h>"
            elif call_name.startswith(("abcd_", "efgh_", "ijkl_", "mnop_")):
                c_type = "internal"
                mod = "local"
            else:
                c_type = "internal"
                mod = "local"

            calls.append({
                "function_name": call_name,
                "type": c_type,
                "module": mod
            })

        unique_calls = []
        seen_calls = set()
        for c in calls:
            key = (c["function_name"], c["type"], c["module"])
            if key not in seen_calls:
                seen_calls.add(key)
                unique_calls.append(c)

        crypto_artifacts = extract_crypto_artifacts(body_text)
        functions.append({
            "name": fn["name"],
            "start_line": start,
            "end_line": end,
            "calls": unique_calls,
            "crypto_artifacts": crypto_artifacts
        })

    return {
        "file_name": file_path.name,
        "relative_path": relative_path,
        "language": lang_name,
        "service": service_name,
        "lines_of_code": loc,
        "modules_imported": {
            "non_user_defined": sorted(list(non_user_imports)),
            "user_defined": sorted(list(user_imports))
        },
        "number_of_functions": len(functions),
        "functions": functions
    }


# -----------------------------------------------------------------------------
# MAIN ORCHESTRATOR
# -----------------------------------------------------------------------------
def scan_all_services():
    services_config = [
        ("TypeScript", "api-gateway-ts", [".ts"], parse_js_ts_file),
        ("Java", "auth-java", [".java"], parse_jvm_file),
        ("Kotlin", "auth-kotlin", [".kt"], parse_jvm_file),
        ("Rust", "crypto-rs", [".rs"], parse_rust_file),
        ("JavaScript", "edge-router-js", [".js"], parse_js_ts_file),
        ("C", "hsm-c", [".c", ".h"], parse_c_cpp_file),
        ("Go", "ledger-go", [".go"], parse_go_file),
        ("Python", "payment-py", [".py"], parse_python_file),
        ("C++", "vault-cpp", [".cpp", ".hpp"], parse_c_cpp_file),
    ]

    result = {
        "title": "NEXIS Core Platform - 9 Language Service Analysis",
        "total_languages": 9,
        "languages": {}
    }

    grand_total_files = 0

    for lang_name, service_dir, extensions, parser_fn in services_config:
        service_path = SERVICES_ROOT / service_dir
        if not service_path.exists():
            print(f"[!] Warning: Directory not found: {service_path}")
            continue

        print(f"[*] Scanning {lang_name} ({service_dir})...")
        candidate_files = []
        for root, dirs, files in os.walk(service_path):
            # Ignore build artifacts, dependency caches, and temp directories
            dirs[:] = [d for d in dirs if d not in [
                "node_modules", "target", "build", ".gradle", ".m2", "vendor",
                "venv", ".venv", "site-packages", "__pycache__", "CMakeFiles",
                ".git", "dist", "bin", "obj"
            ]]
            for file in files:
                p = Path(root) / file
                if p.suffix.lower() in extensions:
                    # Exclude typescript declaration files (.d.ts)
                    if p.name.endswith(".d.ts"):
                        continue
                    candidate_files.append(p)

        file_entries = []
        for f in candidate_files:
            rel_p = str(f.relative_to(SERVICES_ROOT.parent)).replace("\\", "/")
            if parser_fn in (parse_js_ts_file, parse_jvm_file, parse_c_cpp_file):
                entry = parser_fn(f, rel_p, lang_name, service_dir)
            else:
                entry = parser_fn(f, rel_p)
            file_entries.append(entry)

        file_entries.sort(key=lambda x: x["file_name"])
        grand_total_files += len(file_entries)

        result["languages"][lang_name] = {
            "language": lang_name,
            "service": service_dir,
            "file_count": len(file_entries),
            "files": file_entries
        }
        print(f"    --> Parsed {len(file_entries)} {lang_name} files.")

    result["total_files"] = grand_total_files

    # -------------------------------------------------------------------------
    # Compute Exact Caller Hierarchy & Multi-Depth BFS for Every Function
    # -------------------------------------------------------------------------
    print("\n[*] Computing multi-depth caller graphs across all functions...")
    for lang_name, lang_data in result["languages"].items():
        # Build index of all functions within the language service
        fn_nodes = []
        fn_lookup = {}
        for file_obj in lang_data["files"]:
            for func_obj in file_obj["functions"]:
                fn_name = func_obj["name"]
                base_name = fn_name.split(".")[-1].split("::")[-1]
                called_set = set()
                for c in func_obj.get("calls", []):
                    c_name = c["function_name"]
                    called_set.add(c_name)
                    called_set.add(c_name.split(".")[-1].split("::")[-1])
                
                node_id = f"{file_obj['file_name']}::{fn_name}"
                node_info = {
                    "id": node_id,
                    "file_name": file_obj["file_name"],
                    "func_name": fn_name,
                    "base_name": base_name,
                    "called": called_set,
                    "ref": func_obj
                }
                fn_nodes.append(node_info)
                fn_lookup[node_id] = node_info

        # Build reverse caller adjacency graph
        callers_map = {n["id"]: set() for n in fn_nodes}
        trivial_names = {"get", "set", "init", "run", "main", "close", "read", "write", "print", "len", "println"}

        # Index each file's defined functions to resolve local vs cross-file call scopes
        file_func_names = {}
        for n in fn_nodes:
            fname = n["file_name"]
            if fname not in file_func_names:
                file_func_names[fname] = set()
            file_func_names[fname].add(n["base_name"])
            file_func_names[fname].add(n["func_name"])

        for caller in fn_nodes:
            for callee in fn_nodes:
                if caller["id"] == callee["id"]:
                    continue # Ignore self-calls
                if callee["base_name"] in trivial_names:
                    continue
                # Ignore functions with the exact same base name in different files calling each other
                if callee["base_name"] == caller["base_name"]:
                    continue
                # If callee is in a different file, but caller's own file defines a function with that same name,
                # the call is file-local to caller's file, NOT a cross-file call!
                if caller["file_name"] != callee["file_name"]:
                    caller_file_funcs = file_func_names.get(caller["file_name"], set())
                    if callee["base_name"] in caller_file_funcs or callee["func_name"] in caller_file_funcs:
                        continue

                # If caller's called list contains callee's name or base_name
                if callee["base_name"] in caller["called"] or callee["func_name"] in caller["called"]:
                    callers_map[callee["id"]].add(caller["id"])

        # BFS for each function to determine callers at Depth 1, Depth 2, Depth 3, etc.
        for target in fn_nodes:
            depths_list = []
            visited = {target["id"]}
            current_layer = {target["id"]}
            depth = 1

            while current_layer and depth <= 20: # Cap at depth 20 max to avoid infinite loops
                next_layer = set()
                for cur_id in current_layer:
                    for caller_id in callers_map.get(cur_id, []):
                        if caller_id not in visited:
                            visited.add(caller_id)
                            next_layer.add(caller_id)

                if next_layer:
                    sorted_callers = sorted(
                        [{"name": fn_lookup[c]["func_name"], "file": fn_lookup[c]["file_name"]} for c in next_layer],
                        key=lambda x: (x["file"], x["name"])
                    )
                    depths_list.append({
                        "depth": depth,
                        "caller_count": len(sorted_callers),
                        "callers": sorted_callers
                    })
                    current_layer = next_layer
                    depth += 1
                else:
                    break

            # Attach caller hierarchy to function object in JSON
            target["ref"]["caller_hierarchy"] = {
                "max_depth": len(depths_list),
                "total_callers": sum(d["caller_count"] for d in depths_list),
                "depths": depths_list
            }

        # Compute file-level summary metrics for depth and crypto artifact sorting
        for file_obj in lang_data["files"]:
            file_max_depth = 0
            file_crypto_max_depth = 0
            file_crypto_set = set()
            crypto_funcs_count = 0
            for fn in file_obj["functions"]:
                fn_depth = fn.get("caller_hierarchy", {}).get("max_depth", 0)
                if fn_depth > file_max_depth:
                    file_max_depth = fn_depth

                has_crypto = bool(fn.get("crypto_artifacts"))
                if has_crypto:
                    crypto_funcs_count += 1
                    if fn_depth > file_crypto_max_depth:
                        file_crypto_max_depth = fn_depth

                for ca in fn.get("crypto_artifacts", []):
                    file_crypto_set.add(ca)

            file_obj["max_depth"] = file_max_depth
            file_obj["crypto_max_depth"] = file_crypto_max_depth
            file_obj["crypto_functions_count"] = crypto_funcs_count
            file_obj["crypto_artifacts_count"] = len(file_crypto_set)
            file_obj["unique_crypto_artifacts"] = sorted(list(file_crypto_set))

            # Categorize imported modules for Page 1 into 4 distinct categories:
            # 1. Standard Crypto (Green)
            # 2. Standard Non-Crypto (Blue)
            # 3. User Crypto (Yellow)
            # 4. User Non-Crypto (Pink)
            non_user_mods = file_obj.get("modules_imported", {}).get("non_user_defined", []) or []
            user_mods = file_obj.get("modules_imported", {}).get("user_defined", []) or []

            mod_crypto_rx = re.compile(
                r'(crypto|cipher|bcrypt|argon2|scrypt|jsonwebtoken|jwt|jose|openssl|liboqs|oqs|bouncycastle|tink|secp256k1|ed25519|dilithium|kyber|ml[-_]?kem|ml[-_]?dsa|sphincs|falcon|sha\d*|md5|hashlib|hmac|cryptography|pycryptodome|pycrypto|ring|rsa|aes|chacha20|poly1305|subtle|sodium|x509|tls|ssl|forge|jbcrypt|pkcs|signer|verifier)',
                re.IGNORECASE
            )
            false_positives = {'cstring', 'string.h', 'strings', 'assets', 'class', 'pass', 'fast', 'task'}

            def is_crypto(mod_name):
                clean = mod_name.strip().lower()
                if clean in false_positives:
                    return False
                return bool(mod_crypto_rx.search(clean))

            std_crypto = [m for m in non_user_mods if is_crypto(m)]
            std_non_crypto = [m for m in non_user_mods if not is_crypto(m)]
            user_crypto = [m for m in user_mods if is_crypto(m)]
            user_non_crypto = [m for m in user_mods if not is_crypto(m)]

            file_obj["standard_crypto_modules"] = sorted(list(set(std_crypto)))
            file_obj["standard_non_crypto_modules"] = sorted(list(set(std_non_crypto)))
            file_obj["user_crypto_modules"] = sorted(list(set(user_crypto)))
            file_obj["user_non_crypto_modules"] = sorted(list(set(user_non_crypto)))
            file_obj["crypto_modules"] = sorted(list(set(std_crypto + user_crypto)))
            file_obj["non_crypto_modules"] = sorted(list(set(std_non_crypto + user_non_crypto)))

    OUTPUT_JSON_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_JSON_PATH, "w", encoding="utf-8") as out_f:
        json.dump(result, out_f, indent=2)

    # Also update data/services_data.js for standalone offline execution
    js_bundle_path = OUTPUT_JSON_PATH.parent / "services_data.js"
    with open(js_bundle_path, "w", encoding="utf-8") as js_f:
        js_f.write("window.NEXIS_DATA = " + json.dumps(result) + ";\n")

    print(f"\n[+] Successfully generated analysis JSON: {OUTPUT_JSON_PATH}")
    print(f"[+] Successfully updated data bundle:     {js_bundle_path}")
    print(f"[+] Total files across 9 languages: {grand_total_files}")


if __name__ == "__main__":
    scan_all_services()


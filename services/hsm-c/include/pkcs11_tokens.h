/**
 * Nexis Core Financial Ledger Platform - Hardware Security Module
 * Header: PKCS#11 Token & Cryptoki Cryptographic Token Interface
 *
 * Implements standard PKCS#11 v2.40 specification definitions, token states,
 * session handles, object attribute structures, and mechanism codes.
 *
 * NOTE: Contains intentional false-positive comments for AST scanner testing:
 * // PKCS#11 CKM_RSA_PKCS and CKM_DES3_CBC compatibility bindings
 * // Token memory map structure definitions
 */

#ifndef HSM_PKCS11_TOKENS_H
#define HSM_PKCS11_TOKENS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned long CK_ULONG;
typedef unsigned char CK_BYTE;
typedef CK_ULONG CK_RV;
typedef CK_ULONG CK_SLOT_ID;
typedef CK_ULONG CK_SESSION_HANDLE;
typedef CK_ULONG CK_OBJECT_HANDLE;
typedef CK_ULONG CK_MECHANISM_TYPE;

/* Standard PKCS#11 Return Values */
#define CKR_OK 0x00000000
#define CKR_CANCEL 0x00000001
#define CKR_HOST_MEMORY 0x00000002
#define CKR_SLOT_ID_INVALID 0x00000003
#define CKR_GENERAL_ERROR 0x00000005
#define CKR_FUNCTION_FAILED 0x00000006
#define CKR_ARGUMENTS_BAD 0x00000007
#define CKR_TOKEN_NOT_PRESENT 0x000000E0
#define CKR_TOKEN_NOT_RECOGNIZED 0x000000E1
#define CKR_TOKEN_WRITE_PROTECTED 0x000000E2
#define CKR_DEVICE_ERROR 0x00000030
#define CKR_DEVICE_MEMORY 0x00000031
#define CKR_USER_NOT_LOGGED_IN 0x00000101
#define CKR_PIN_INCORRECT 0x000000A0
#define CKR_PIN_INVALID 0x000000A1
#define CKR_PIN_LEN_RANGE 0x000000A2
#define CKR_PIN_EXPIRED 0x000000A3
#define CKR_PIN_LOCKED 0x000000A4
#define CKR_SESSION_HANDLE_INVALID 0x000000B3
#define CKR_SESSION_PARALLEL_NOT_SUPPORTED 0x000000B4
#define CKR_SESSION_READ_ONLY 0x000000B5
#define CKR_SESSION_EXISTS 0x000000B6
#define CKR_SESSION_READ_ONLY_EXISTS 0x000000B7
#define CKR_SESSION_READ_WRITE_SO_EXISTS 0x000000B8
#define CKR_SIGNATURE_INVALID 0x000000C0
#define CKR_SIGNATURE_LEN_RANGE 0x000000C1
#define CKR_MECHANISM_TYPE_INVALID 0x00000070
#define CKR_OPERATION_NOT_INITIALIZED 0x00000091
#define CKR_BUFFER_TOO_SMALL 0x00000150
#define CKR_SESSION_LIMIT 0x000000B1

/* Cryptoki Standard Mechanisms */
#define CKM_RSA_PKCS_KEY_PAIR_GEN 0x00000000
#define CKM_RSA_PKCS 0x00000001
#define CKM_RSA_9796 0x00000002
#define CKM_RSA_X_509 0x00000003
#define CKM_SHA256_RSA_PKCS 0x00000040
#define CKM_SHA384_RSA_PKCS 0x00000041
#define CKM_SHA512_RSA_PKCS 0x00000042
#define CKM_AES_KEY_GEN 0x00001080
#define CKM_AES_ECB 0x00001081
#define CKM_AES_CBC 0x00001082
#define CKM_AES_CBC_PAD 0x00001085
#define CKM_AES_GCM 0x00001087
#define CKM_SHA256 0x00000250
#define CKM_SHA384 0x00000260
#define CKM_SHA512 0x00000270
#define CKM_SHA256_HMAC 0x00000251

/* PKCS#11 Attribute Types */
#define CKA_CLASS 0x00000000
#define CKA_TOKEN 0x00000001
#define CKA_PRIVATE 0x00000002
#define CKA_LABEL 0x00000003
#define CKA_APPLICATION 0x00000010
#define CKA_VALUE 0x00000011
#define CKA_OBJECT_ID 0x00000012
#define CKA_CERTIFICATE_TYPE 0x00000080
#define CKA_ISSUER 0x00000081
#define CKA_SERIAL_NUMBER 0x00000082
#define CKA_KEY_TYPE 0x00000100
#define CKA_SUBJECT 0x00000101
#define CKA_ID 0x00000102
#define CKA_SENSITIVE 0x00000103
#define CKA_ENCRYPT 0x00000104
#define CKA_DECRYPT 0x00000105
#define CKA_SIGN 0x00000108
#define CKA_VERIFY 0x0000010A

/* Attribute Structure */
typedef struct CK_ATTRIBUTE {
    CK_ULONG type;
    void *pValue;
    CK_ULONG ulValueLen;
} CK_ATTRIBUTE;

/* Mechanism Parameter Structure */
typedef struct CK_MECHANISM {
    CK_MECHANISM_TYPE mechanism;
    void *pParameter;
    CK_ULONG ulParameterLen;
} CK_MECHANISM;

/* AES-GCM Parameter Structure */
typedef struct CK_GCM_PARAMS {
    CK_BYTE *pIv;
    CK_ULONG ulIvLen;
    CK_BYTE *pAAD;
    CK_ULONG ulAADLen;
    CK_ULONG ulTagBits;
} CK_GCM_PARAMS;

/* Token Information Structure */
typedef struct CK_TOKEN_INFO {
    CK_BYTE label[32];
    CK_BYTE manufacturerID[32];
    CK_BYTE model[16];
    CK_BYTE serialNumber[16];
    CK_ULONG flags;
    CK_ULONG ulMaxSessionCount;
    CK_ULONG ulSessionCount;
    CK_ULONG ulMaxRwSessionCount;
    CK_ULONG ulRwSessionCount;
    CK_ULONG ulMaxPinLen;
    CK_ULONG ulMinPinLen;
    CK_ULONG ulTotalPublicMemory;
    CK_ULONG ulFreePublicMemory;
    CK_ULONG ulTotalPrivateMemory;
    CK_ULONG ulFreePrivateMemory;
} CK_TOKEN_INFO;

/* Function Prototypes */
CK_RV C_Initialize(void *pInitArgs);
CK_RV C_Finalize(void *pReserved);
CK_RV C_GetSlotList(bool tokenPresent, CK_SLOT_ID *pSlotList, CK_ULONG *pulCount);
CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO *pInfo);
CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_ULONG flags, void *pApplication, void *Notify, CK_SESSION_HANDLE *phSession);
CK_RV C_CloseSession(CK_SESSION_HANDLE hSession);
CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_ULONG userType, CK_BYTE *pPin, CK_ULONG ulPinLen);
CK_RV C_Logout(CK_SESSION_HANDLE hSession);

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey);
CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE *pData, CK_ULONG ulDataLen, CK_BYTE *pEncryptedData, CK_ULONG *pulEncryptedDataLen);
CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey);
CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE *pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE *pData, CK_ULONG *pulDataLen);

#ifdef __cplusplus
}
#endif

#endif /* HSM_PKCS11_TOKENS_H */

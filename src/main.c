/*
 * Copyright (c) 2018 ellipticSecure - https://ellipticsecure.com
 *
 * All rights reserved.
 *
 * You may only use this code under the terms of the ellipticSecure software license.
 *
 */

/*
 *
 * ECC example code for eHSM Hardware Security Module
 * @author Kobus Grobler
 *
 */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include "ehsm-c-util.h"

static CK_FUNCTION_LIST_PTR s_ptr = NULL_PTR;

/**
 * Generate an EC KeyPair
 * @param hSession session handle
 * @param bTokenPuk false if key should be stored in session or true if on token
 * @param isPubKeyPrivate true if bkey should be private
 * @param bTokenPrk false if key should be stored in session or true if on token
 * @param isPrivKeyPrivate true if key should be private
 * @param hPuk handle to the created public key
 * @param hPrk handle to the created private key
 * @return CKR_OK if successful
 */
CK_RV rvGenerateECPair(CK_SESSION_HANDLE hSession, CK_BBOOL bTokenPuk, CK_BBOOL isPubKeyPrivate, CK_BBOOL bTokenPrk,
                       CK_BBOOL isPrivKeyPrivate, CK_OBJECT_HANDLE *hPuk, CK_OBJECT_HANDLE *hPrk) {
    CK_MECHANISM mechanism = {CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0};
    CK_KEY_TYPE keyType = CKK_EC;
    CK_BYTE oidP256[] = {0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
    CK_BYTE label[] = "example1_test";
    CK_BYTE id[] = {99};
    CK_BBOOL bFalse = CK_FALSE;
    CK_BBOOL bTrue = CK_TRUE;

    CK_ATTRIBUTE pukAttribs[] = {
            {CKA_EC_PARAMS, NULL,            0},
            {CKA_LABEL,    &label[0],        sizeof(label)},
            {CKA_ID,       &id[0],           sizeof(id)},
            {CKA_KEY_TYPE, &keyType,         sizeof(keyType)},
            {CKA_VERIFY,   &bTrue,           sizeof(bTrue)},
            {CKA_ENCRYPT,  &bFalse,          sizeof(bFalse)},
            {CKA_WRAP,     &bFalse,          sizeof(bFalse)},
            {CKA_TOKEN,    &bTokenPuk,       sizeof(bTokenPuk)},
            {CKA_PRIVATE,  &isPubKeyPrivate, sizeof(isPubKeyPrivate)}
    };
    CK_ATTRIBUTE prkAttribs[] = {
            {CKA_LABEL,       &label[0],         sizeof(label)},
            {CKA_ID,          &id[0],            sizeof(id)},
            {CKA_KEY_TYPE,    &keyType,          sizeof(keyType)},
            {CKA_SIGN,        &bTrue,            sizeof(bTrue)},
            {CKA_DECRYPT,     &bFalse,           sizeof(bFalse)},
            {CKA_UNWRAP,      &bFalse,           sizeof(bFalse)},
            {CKA_SENSITIVE,   &bTrue,            sizeof(bTrue)},
            {CKA_TOKEN,       &bTokenPrk,        sizeof(bTokenPrk)},
            {CKA_PRIVATE,     &isPrivKeyPrivate, sizeof(isPrivKeyPrivate)},
            {CKA_EXTRACTABLE, &bFalse,           sizeof(bFalse)}
    };

    pukAttribs[0].pValue = oidP256;
    pukAttribs[0].ulValueLen = sizeof(oidP256);
    *hPuk = CK_INVALID_HANDLE;
    *hPrk = CK_INVALID_HANDLE;
    return EHSM_FPTR(C_GenerateKeyPair(hSession, &mechanism,
                                       pukAttribs, sizeof(pukAttribs) / sizeof(CK_ATTRIBUTE),
                                       prkAttribs, sizeof(prkAttribs) / sizeof(CK_ATTRIBUTE),
                                       hPuk, hPrk));
}

/**
 * Sign and verify with the supplied key handles
 * @param hSession session handle
 * @param mechanismType mechanism type
 * @param hPrivateKey private key handle
 * @param hPublicKey public key handle
 * @return CKR_OK if successfull
 */
CK_RV rvSignVerifyData(CK_SESSION_HANDLE hSession, CK_MECHANISM_TYPE mechanismType, CK_OBJECT_HANDLE hPrivateKey,
                       CK_OBJECT_HANDLE hPublicKey) {
    CK_MECHANISM mechanism = {mechanismType, NULL_PTR, 0};
    CK_BYTE data[] = {"helloworld"};
    CK_BYTE signature[256];
    CK_ULONG ulSignatureLen = 0;

    CK_RV rv = EHSM_FPTR(C_SignInit(hSession, &mechanism, hPrivateKey));
    if (rv == CKR_OK) {
        ulSignatureLen = sizeof(signature);
        rv = EHSM_FPTR(C_Sign(hSession, data, sizeof(data), signature, &ulSignatureLen));
        if (rv == CKR_OK) {
            fprintf(stdout, "Signed data\n");
            rv = EHSM_FPTR(C_VerifyInit(hSession, &mechanism, hPublicKey));
            if (rv == CKR_OK) {
                rv = EHSM_FPTR(C_Verify(hSession, data, sizeof(data), signature, ulSignatureLen));
                if (rv == CKR_OK) {
                    fprintf(stdout, "Verified data\n");
                }
            }
        }
    }
    return rv;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stdout, "usage: %s <user password>\n", argv[0]);
        return 2;
    }

    void *pModule = NULL_PTR;
#ifdef __APPLE__
    s_ptr = pGetFunctionListPtr("/usr/local/lib/libehsm.dylib", &pModule);
#elif WIN32
    CK_FUNCTION_LIST_PTR fPtr = pGetFunctionListPtr("ehsm.dll",&pModule);
#else
    CK_FUNCTION_LIST_PTR fPtr = pGetFunctionListPtr("/usr/local/lib/libehsm.so",&pModule);
#endif

    if (s_ptr == NULL_PTR) {
        fprintf(stderr, "Failed to load the eHSM shared library.\n");
        return 1;
    }

    // Note: we are leaving out the code to dynamically determine the slot list for simplicity.
    // Assuming slot 0 is OK.
    CK_SLOT_ID slotId = 0;

    CK_RV rv = EHSM_FPTR(C_Initialize(NULL_PTR));
    if (rv == CKR_OK) {
        CK_SESSION_HANDLE hSessionRW;
        rv = EHSM_FPTR(C_OpenSession(slotId, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSessionRW));
        if (rv == CKR_OK) {
            rv = EHSM_FPTR(C_Login(hSessionRW, CKU_USER, (CK_UTF8CHAR_PTR) argv[1], strlen(argv[1])));
            if (rv == CKR_OK) {
                CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE;
                CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;
                CK_BBOOL onToken, isPubPrivate, isPrivPrivate;
                onToken = CK_FALSE;
                isPrivPrivate = CK_TRUE;
                isPubPrivate = CK_FALSE;
                rv = rvGenerateECPair(hSessionRW, onToken, isPubPrivate, onToken, isPrivPrivate, &hPuk, &hPrk);
                if (rv == CKR_OK) {
                    rv = rvSignVerifyData(hSessionRW, CKM_ECDSA, hPrk, hPuk);
                }
            } else {
                fprintf(stderr, "Login failed.");
            }
        }
    }

    if (rv != CKR_OK) {
        fprintf(stderr, "Test failed, error code: 0x%lx\n", rv);
    } else {
        fprintf(stdout, "Test succeeded\n");
    }

    EHSM_FPTR(C_Finalize(NULL_PTR));

    vCloseLibrary(pModule);

    return 0;
}

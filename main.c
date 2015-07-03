#include <stdio.h>
#include <inttypes.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/ecdsa.h>

#include <openssl/sha.h>
#include <openssl/objects.h>


EC_KEY *bbp_ec_new_pubkey(const uint8_t *pub_bytes, size_t pub_len) {
    EC_KEY *key;
    const uint8_t *pub_bytes_copy;

    key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    pub_bytes_copy = pub_bytes;
    o2i_ECPublicKey(&key, &pub_bytes_copy, pub_len);

    return key;
}

void bbp_sha256(uint8_t *digest, const uint8_t *message, size_t len) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, message, len);
    SHA256_Final(digest, &ctx);
}


void bbp_print_hex(const char *label, const uint8_t *v, size_t len) {
    size_t i;
    const size_t mul = 0;

    printf("%s: ", label);
    for (i = 0; i < len; ++i) {
        const size_t offset = mul * (len - 2 * i - 1);
        printf("%02x", v[i + offset]);
    }
    printf("\n");
}

int main() {
    u_int8_t pub_bytes[] = {
        0x04, 0xA9, 0x80, 0x40, 0xFF, 0xB3, 0x27, 0x13, 0xDA, 0x68, 0x0C, 0xFF, 0xF4, 0x71, 0xEF, 0x3B,
        0xDE, 0x0C, 0x8A, 0x54, 0x8C, 0x95, 0xB4, 0xB4, 0x37, 0x20, 0x04, 0xBA, 0xC4, 0x21, 0x7D, 0xEF,
        0x1F, 0xDA, 0x7F, 0x3A, 0x2D, 0x9D, 0x45, 0x33, 0x1E, 0x75, 0x88, 0xB9, 0x9D, 0x4F, 0xE3, 0xCF,
        0xBD, 0xC5, 0x8F, 0xA2, 0xAF, 0x95, 0x7A, 0xFF, 0xA1, 0x3F, 0x29, 0xD3, 0x53, 0xB7, 0xF5, 0x03,
        0x42
    };
    u_int8_t der_bytes[] = {
        0x30, 0x45, 0x02, 0x20, 0x4b, 0xf1, 0x23, 0xac, 0xe9, 0xb5, 0x81, 0x8e, 0x3a, 0x63, 0xbd, 0x87,
        0x97, 0x48, 0x94, 0x59, 0x71, 0x80, 0xde, 0x3b, 0x9e, 0x26, 0x11, 0x35, 0x1a, 0x26, 0x5d, 0xa5,
        0xc5, 0x9b, 0x45, 0x69, 0x02, 0x21, 0x00, 0x86, 0xf5, 0xc9, 0x8a, 0x24, 0xc5, 0xf1, 0xd3, 0x83,
        0x61, 0xa0, 0x32, 0xfb, 0x42, 0x36, 0x62, 0xab, 0x3d, 0xcd, 0x93, 0xc7, 0x5b, 0x97, 0x2d, 0x1e,
        0x25, 0x61, 0x38, 0xc7, 0x91, 0xd2, 0xef, /*0x2e, 0x54, 0xfe, 0x0f, 0x2e, 0x44, 0xa0, 0x02, 0x2e,
        0x58, 0x3e, 0x07, 0x2e, 0x84, 0xfe, 0x0f, 0x2e, 0xec, 0x83, 0x07, 0x2e, 0x1c, 0x57, 0x07, 0x2e,
        0xb0, 0x9e, 0x0a, 0x2e, 0x00, 0xb0, 0xe0, 0x65, 0x00, 0x30, 0x02, 0x65, 0xa4, 0xfe, 0x0f, 0x2e,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0xfe, 0x0f, 0x2e, 0x34, 0xa8, 0x02, 0x2e,
        0x00, 0x00, 0x00, 0x00*/
    };

    const char message[] = "This is a very confidential message\n";
    uint8_t hash[20];

    EC_KEY *key;
    const uint8_t *der_bytes_copy;
    ECDSA_SIG *signature;
    uint8_t digest[32];
    int verified, i;
    EVP_PKEY *pkey;

    FILE *f = fopen("eccpubkey.der", "w");
    fwrite(pub_bytes, sizeof(pub_bytes), 1, f);
    fclose(f);

    f = fopen("eccsig.der", "w");
    fwrite(der_bytes, sizeof(der_bytes), 1, f);
    fclose(f);

    FILE *fp = fopen ("eccpubkey.pem", "r");
    if (fp == NULL) exit (1);
    pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose (fp);

    if (pkey == NULL) {
      ERR_print_errors_fp (stderr);
      exit (1);
    }

    key = EVP_PKEY_get1_EC_KEY(pkey);
    const EC_GROUP *ecgrp = EC_KEY_get0_group(key);
    printf("ECC Key size: %d bit\n", EVP_PKEY_bits(pkey));
    printf("ECC Key type: %s\n", OBJ_nid2sn(EC_GROUP_get_curve_name(ecgrp)));

/*
    key = bbp_ec_new_pubkey(pub_bytes, sizeof(pub_bytes));
    if (!key) {
        puts("Unable to create keypair");
        return -1;
    }
*/
    der_bytes_copy = der_bytes;
    signature = d2i_ECDSA_SIG(NULL, &der_bytes_copy, sizeof(der_bytes));
    printf("r: %s\n", BN_bn2hex(signature->r));
    printf("s: %s\n", BN_bn2hex(signature->s));
    for (i = 0; i < sizeof(hash); i++)
        hash[i] = i;
#if 0
    bbp_sha256(digest, hash, sizeof(hash));
    bbp_print_hex("digest", digest, 32);
    verified = ECDSA_do_verify(digest, sizeof(digest), signature, key);
#else
    verified = ECDSA_do_verify(hash, sizeof(hash), signature, key);
#endif
    switch (verified) {
        case 1:
            puts("verified");
            break;
        case 0:
            puts("not verified");
            break;
        case -1:
            puts("library error");
            break;
    }

    ECDSA_SIG_free(signature);
    EC_KEY_free(key);

    return 0;
}

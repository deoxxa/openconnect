/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2019 David Woodhouse
 *
 * Author: David Woodhouse <dwmw2@infradead.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include <config.h>

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "openconnect-internal.h"

#include "aesni-esp.h"

uint64_t OPENCONNECT_ia32cap_P[2];

static inline void aesni_sha1_init(struct aesni_sha1 *ctx, uint64_t len)
{
	ctx->h0 = 0x67452301UL;
	ctx->h1 = 0xefcdab89UL;
	ctx->h2 = 0x98badcfeUL;
	ctx->h3 = 0x10325476UL;
	ctx->h4 = 0xc3d2e1f0UL;
	ctx->N = len;
}

static void setup_sha1_hmac(struct esp *esp,
			    unsigned char *key, int len)
{
        unsigned char opad[64];
        unsigned char ipad[64];
        int i;

        aesni_sha1_init(&esp->aesni_hmac.o, SHA1_BLOCK);
        aesni_sha1_init(&esp->aesni_hmac.i, SHA1_BLOCK);

        if (len == 64) {
                memcpy(opad, key, len);
        } else if (len < 64) {
                memcpy(opad, key, len);
                memset(opad + len, 0, 64 - len);
        } else {
                openconnect_sha1(opad, key, len);
                memset(opad + 20, 0, 44);
        }
        memcpy(ipad, opad, 64);

        for (i = 0; i < 64; i++) {
                opad[i] ^= 0x5c;
                ipad[i] ^= 0x36;
        }

	sha1_block_data_order(&esp->aesni_hmac.o, opad, 1);
	sha1_block_data_order(&esp->aesni_hmac.i, ipad, 1);
}

static void aesni_sha1_final(struct aesni_sha1 *sha, unsigned char *out, unsigned char *data, unsigned int len)
{
	unsigned char buf[SHA1_BLOCK];
	uint64_t *N;

	sha->N += len;

	if (len > SHA1_BLOCK) {
		sha1_block_data_order(sha, data, len / SHA1_BLOCK);
		data += len & ~(SHA1_BLOCK - 1);
		len &= (SHA1_BLOCK - 1);
	}
	if (len)
		memcpy(buf, data, len);
	buf[len++] = 0x80;

	if (len > SHA1_BLOCK - 8) {
		memset(buf + len, 0, SHA1_BLOCK - len);
		sha1_block_data_order(sha, buf, 1);
		len = 0;
	}
	memset(buf + len, 0, SHA1_BLOCK - len - 8);
	N = (void *)&buf[SHA1_BLOCK - 8];
        *N = __builtin_bswap64(sha->N << 3);
	sha1_block_data_order(sha, buf, 1);

	store_be32(out, sha->h0);
	store_be32(out + 4, sha->h1);
	store_be32(out + 8, sha->h2);
	store_be32(out + 12, sha->h3);
	store_be32(out + 16, sha->h4);
}

static void complete_sha1_hmac(struct aesni_hmac *hmac, unsigned char *out, unsigned char *data, int len)
{
        aesni_sha1_final(&hmac->i, out, data, len);
        aesni_sha1_final(&hmac->o, out, out, 20);
}

static void aesni_destroy_esp_ciphers(struct esp *esp)
{
	clear_mem(&esp->aesni_hmac.o, sizeof(esp->aesni_hmac.o));
	clear_mem(&esp->aesni_hmac.i, sizeof(esp->aesni_hmac.i));
	clear_mem(&esp->aesni_key, sizeof(esp->aesni_key));
	if (esp->aesni_hmac_block) {
		clear_mem(esp->aesni_hmac_block, SHA1_BLOCK);
		free(esp->aesni_hmac_block);
		esp->aesni_hmac_block = NULL;
	}
}

static int aesni_decrypt_esp_packet(struct openconnect_info *vpninfo, struct esp *esp, struct pkt *pkt)
{
	struct aesni_hmac hmac = esp->aesni_hmac;
	unsigned char hmac_buf[20];

	complete_sha1_hmac(&hmac, hmac_buf, (void *)&pkt->esp, sizeof(pkt->esp) + pkt->len);
	if (memcmp(hmac_buf, pkt->data + pkt->len, 12)) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Received ESP packet with invalid HMAC\n"));
		return -EINVAL;
	}

	if (verify_packet_seqno(vpninfo, esp, ntohl(pkt->esp.seq)))
		return -EINVAL;

	aesni_cbc_encrypt(pkt->data, pkt->data, pkt->len,
			  &esp->aesni_key, (unsigned char *)&pkt->esp.iv, 0);
	return 0;
}

static int aesni_encrypt_esp_packet(struct openconnect_info *vpninfo, struct pkt *pkt)
{
	struct esp *esp = &vpninfo->esp_out;
	struct aesni_hmac hmac = esp->aesni_hmac;
	int i, padlen;
	const int blksize = 16;
	int crypt_len;
	int stitched = 0;

#define PRECBC 64
#define BLK 64

	/* This gets much more fun if the IV is variable-length */
	pkt->esp.spi = esp->spi;
	pkt->esp.seq = htonl(esp->seq++);

	memcpy(pkt->esp.iv, esp->iv, sizeof(pkt->esp.iv));

	padlen = blksize - 1 - ((pkt->len + 1) % blksize);
	for (i=0; i<padlen; i++)
		pkt->data[pkt->len + i] = i + 1;
	pkt->data[pkt->len + padlen] = padlen;
	pkt->data[pkt->len + padlen + 1] = 0x04; /* Legacy IP */

	crypt_len = pkt->len + padlen + 2;

	/* Encrypt the first block */
	if (crypt_len >= PRECBC + BLK) {
		aesni_cbc_encrypt(pkt->data, pkt->data, PRECBC, &esp->aesni_key,
				  (unsigned char *)&esp->iv, 1);

		/* Then the stitched part */
		stitched = (crypt_len - PRECBC) / BLK;
		aesni_cbc_sha1_enc(pkt->data + PRECBC, pkt->data + PRECBC, stitched, &esp->aesni_key,
				   (unsigned char *)&esp->iv, &hmac.i, &pkt->esp);
		hmac.i.N += (stitched * BLK);

		stitched *= BLK;

		/* Now encrypt anything remaining */
		if (crypt_len > stitched + PRECBC)
			aesni_cbc_encrypt(pkt->data + stitched + PRECBC, pkt->data + stitched + PRECBC,
					  crypt_len - stitched - PRECBC,
					  &esp->aesni_key, (unsigned char *)&esp->iv, 1);
	} else {
		aesni_cbc_encrypt(pkt->data + stitched, pkt->data + stitched,
				  crypt_len - stitched, &esp->aesni_key, (unsigned char *)&esp->iv, 1);
	}

	/* And now fold in the final part of the HMAC, which is two blocks plus the ESP header behind */
	complete_sha1_hmac(&hmac, pkt->data + crypt_len,
			   (unsigned char *)&pkt->esp + stitched,
			   crypt_len - stitched + sizeof(pkt->esp));

	/* Generate IV for next packet */
	aesni_cbc_encrypt(pkt->data + crypt_len + 8, (unsigned char *)&esp->iv, 16,
			  &esp->aesni_key, (unsigned char *)&esp->iv, 1);

 	return sizeof(pkt->esp) + crypt_len + 12;
}

static int aesni_init_esp_cipher(struct openconnect_info *vpninfo, struct esp *esp,
			    int bits, int decrypt)
{
	int ret;

	aesni_destroy_esp_ciphers(esp);

	if (decrypt)
		ret = aesni_set_decrypt_key(esp->enc_key, bits, &esp->aesni_key);
	else {
		ret = aesni_set_encrypt_key(esp->enc_key, bits, &esp->aesni_key);
		if (!ret)
			ret = openconnect_random(&esp->iv, sizeof(esp->iv));
	}

	if (ret) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to initialise ESP cipher\n"));
		return -EIO;
	}

	setup_sha1_hmac(esp, esp->hmac_key, 20 /*esp->hmac_key_len*/);

	esp->seq = 0;
	esp->seq_backlog = 0;
	return 0;
}

#define AESNI_AND_SSSE3 ( (1UL << 41) | (1UL << 57) )
int aesni_init_esp_ciphers(struct openconnect_info *vpninfo,
			   struct esp *esp_out, struct esp *esp_in)
{
	int bits;
	int ret;

	if (!(OPENCONNECT_ia32cap_P[0] & (1<<10))) {
		uint64_t cap = OPENCONNECT_ia32_cpuid(OPENCONNECT_ia32cap_P);

		OPENCONNECT_ia32cap_P[0] = cap | (1<<10);

		vpn_progress(vpninfo, PRG_DEBUG,
			     _("CPU capabilities: %08lx %08lx %08lx %08lx\n"),
			     OPENCONNECT_ia32cap_P[0] & 0xffffffff,
			     OPENCONNECT_ia32cap_P[0] >> 32,
			     OPENCONNECT_ia32cap_P[1] & 0xffffffff,
			     OPENCONNECT_ia32cap_P[1] >> 32);
	}

	if ((OPENCONNECT_ia32cap_P[0] & AESNI_AND_SSSE3) != AESNI_AND_SSSE3) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("CPU does not have AES-NI and SSSE3; not using AES-NI optimised code\n"));
		return -EINVAL;
	}

	/* This code only supports SHA1 */
	if (vpninfo->esp_hmac != HMAC_SHA1)
		return -EINVAL;

	if (vpninfo->esp_enc == ENC_AES_128_CBC)
		bits = 128;
	else if (vpninfo->esp_enc == ENC_AES_256_CBC)
		bits = 256;
	else
		return -EINVAL;

	ret = aesni_init_esp_cipher(vpninfo, esp_out, bits, 0);
	if (ret)
		return ret;

	ret = aesni_init_esp_cipher(vpninfo, esp_in, bits, 1);
	if (ret) {
		aesni_destroy_esp_ciphers(esp_out);
		return ret;
	}

	vpninfo->decrypt_esp_packet = aesni_decrypt_esp_packet;
	vpninfo->encrypt_esp_packet = aesni_encrypt_esp_packet;
	vpninfo->destroy_esp_ciphers = aesni_destroy_esp_ciphers;

	return 0;
}


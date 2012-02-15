/*
 *
 * Copyright 2012 Mathias Olsson mathias@kompetensum.com
 *
 * This file is dual licensed as either GPL version 2 or Apache License 2.0 at your choice
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 * http://www.apache.org/licenses/
 *
 * Note that PolarSSL uses GPL with a FOSS License Exception
 *
 */

#include <polarssl/md.h>
#include <stdlib.h>

/**
 * \brief          PKCS#5 PBKDF2 using HMAC
 *
 * \param ctx      Generic HMAC context
 * \param password Password to use when generating key
 * \param plen     Length of password
 * \param salt     Salt to use when generating key
 * \param slen     Length of salt
 * \param iteration_count      Iteration count
 * \param key_length	Length of generated key
 * \param output   Generated key. Must be at least as big as key_length
 *
 * \returns        0 on success, POLARSSL_ERR_MD_BAD_INPUT_DATA if parameter
 *                 verification fails.
 */
int PKCS5_PBKDF2_HMAC(md_context_t *ctx, const unsigned char *password, size_t plen, const unsigned char *salt, size_t slen,
			const unsigned long iteration_count, const unsigned long key_length, unsigned char *output);



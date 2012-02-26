
#include "keepsafe.h"
#include "pbkdf2.h"
#include <polarssl/aes.h>
#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>

#define ERROR -1
#define NO_ERROR 0

#define MAGIC_STR "keepsafe"

JNIEXPORT jbyteArray JNICALL Java_com_kompetensum_keepsafe_NativeCrypto_PBKDF2WithHmacSHA1
  (JNIEnv *env, jclass object, jbyteArray password, jbyteArray salt, jint iteration_count, jint key_length)
{
	int error = ERROR;

	jbyteArray key = NULL;
	jbyte* native_password = NULL;
	jbyte* native_salt = NULL;
	jbyte* native_key = NULL;

	jsize pwlen = (*env)->GetArrayLength(env, password);
	native_password = (*env)->GetByteArrayElements(env, password, NULL);
	if (native_password == NULL)
	{
		goto exit;
	}

	jsize slen = (*env)->GetArrayLength(env, salt);
	native_salt = (*env)->GetByteArrayElements(env, salt, NULL);
	if (native_salt == NULL)
	{
		goto exit;
	}

	key = (*env)->NewByteArray(env, key_length);
	if (key == NULL)
	{
		goto exit;
	}

	native_key = (*env)->GetByteArrayElements(env, key, NULL);
	if (native_key == NULL)
	{
		goto exit;
	}

	const md_info_t* infosha1 = md_info_from_type(POLARSSL_MD_SHA1);
	md_context_t sha1ctx = {0};
	int res = md_init_ctx(&sha1ctx, infosha1);
	if (res != 0)
	{
		goto exit;
	}

	res = PKCS5_PBKDF2_HMAC(&sha1ctx,native_password,pwlen,native_salt,slen,iteration_count,key_length,native_key);
	if (res != 0)
	{
		goto exit;
	}

	error = NO_ERROR;

exit:
	if (native_key == NULL)
	{
		(*env)->ReleaseByteArrayElements(env, key, native_key, 0);
	}

	if (native_salt == NULL)
	{
		(*env)->ReleaseByteArrayElements(env, salt, native_salt, JNI_ABORT);
	}

	if (native_password != NULL)
	{
		(*env)->ReleaseByteArrayElements(env, password, native_password, JNI_ABORT);
	}

	if (error == ERROR)
	{
		// On error, return NULL
		key = NULL;
	}

	return key;
}

#define AES256_BLOCK_SIZE 16

JNIEXPORT jbyteArray JNICALL Java_com_kompetensum_keepsafe_NativeCrypto_AES256CBCPKCS5Padding_1Encrypt
  (JNIEnv *env, jclass object, jbyteArray key, jbyteArray initvec, jbyteArray plaintext)
{
	int error = ERROR;

	jbyteArray ciphertext = NULL;
	jbyte* native_plaintext = NULL;
	jbyte* native_key = NULL;
	unsigned char* iv = NULL;
	jbyte* native_ciphertext = NULL;

	jsize klen = (*env)->GetArrayLength(env, key);
	jsize klenbits = klen * 8;
	native_key = (*env)->GetByteArrayElements(env, key, NULL);
	if (native_key == NULL)
	{
		goto exit;
	}

	// We must copy iv since aes_crypt_cbc updates it
	jsize ivlen = (*env)->GetArrayLength(env, initvec);
	iv = malloc(ivlen);
	if (iv == NULL)
	{
		goto exit;
	}

	(*env)->GetByteArrayRegion(env, initvec, 0, ivlen, iv);

	// Calculate size of pad
	jsize plen = (*env)->GetArrayLength(env, plaintext);
	jsize padlen = AES256_BLOCK_SIZE - (plen % AES256_BLOCK_SIZE);
	jbyte pad = padlen;

	// Calculate size of ciphertext
	jsize ctlen = plen + padlen;

	native_plaintext = malloc(ctlen);
	if (native_plaintext == NULL)
	{
		goto exit;
	}

	// We must copy the plaintext since we must add the padding
	(*env)->GetByteArrayRegion(env, plaintext, 0, plen, native_plaintext);

	// Add padding
	int i = 0;
	for (i = 0; i < pad; i++)
	{
		native_plaintext[ctlen - 1 - i] = pad;
	}

	ciphertext = (*env)->NewByteArray(env, ctlen);
	if (ciphertext == NULL)
	{
		goto exit;
	}

	native_ciphertext = (*env)->GetByteArrayElements(env, ciphertext, NULL);
	if (native_ciphertext == NULL)
	{
		goto exit;
	}

	aes_context ctx = {0};
	int res = aes_setkey_enc(&ctx,native_key,klenbits);
	if (res != 0)
	{
		goto exit;
	}

	res = aes_crypt_cbc(&ctx,AES_ENCRYPT,ctlen,iv,native_plaintext,native_ciphertext);
	if (res != 0)
	{
		goto exit;
	}

	error = NO_ERROR;

exit:
	if (native_ciphertext != NULL)
	{
		(*env)->ReleaseByteArrayElements(env, ciphertext, native_ciphertext, 0);
	}

	if (native_plaintext != NULL)
	{
		(*env)->ReleaseByteArrayElements(env, plaintext, native_plaintext, JNI_ABORT);
	}

	if (iv != NULL)
	{
		free(iv);
	}

	if (native_key != NULL)
	{
		(*env)->ReleaseByteArrayElements(env, key, native_key, JNI_ABORT);
	}

	if (error == ERROR)
	{
		// On error, return NULL
		ciphertext = NULL;
	}

	return ciphertext;
}

JNIEXPORT jbyteArray JNICALL Java_com_kompetensum_keepsafe_NativeCrypto_AES256CBCPKCS5Padding_1Decrypt
  (JNIEnv *env, jclass object, jbyteArray key, jbyteArray initvec, jbyteArray ciphertext)
{
	int error = ERROR;

	jbyteArray plaintext = NULL;
	jbyte* native_ciphertext = NULL;
	jbyte* native_key = NULL;
	unsigned char* iv = NULL;
	jbyte* native_plaintext = NULL;
	unsigned char* pt = NULL;

	jsize clen = (*env)->GetArrayLength(env, ciphertext);
	native_ciphertext = (*env)->GetByteArrayElements(env, ciphertext, NULL);
	if (native_ciphertext == NULL)
	{
		goto exit;
	}

	jsize klen = (*env)->GetArrayLength(env, key);
	jsize klenbits = klen * 8;
	native_key = (*env)->GetByteArrayElements(env, key, NULL);
	if (native_key == NULL)
	{
		goto exit;
	}

	// We must copy iv since aes_crypt_cbc updates it
	jsize ivlen = (*env)->GetArrayLength(env, initvec);
	iv = malloc(ivlen);
	if (iv == NULL)
	{
		goto exit;
	}

	(*env)->GetByteArrayRegion(env, initvec, 0, ivlen, iv);

	pt = malloc(clen);
	if (pt == NULL)
	{
		goto exit;
	}

	aes_context ctx = {0};
	int res = aes_setkey_dec(&ctx,native_key,klenbits);
	if (res != 0)
	{
		goto exit;
	}

	res = aes_crypt_cbc(&ctx,AES_DECRYPT,clen,iv,native_ciphertext,pt);
	if (res != 0)
	{
		goto exit;
	}

	// Check padding
	unsigned char pad = pt[clen - 1];
	if (pad > AES256_BLOCK_SIZE)
	{
		goto exit;
	}

	int i = 0;
	for (i = 0; i < pad; i++)
	{
		if (pt[clen - 1 - i] != pad)
		{
			goto exit;
		}
	}

	unsigned int plen = clen - pad;

	plaintext = (*env)->NewByteArray(env, plen);
	if (plaintext == NULL)
	{
		goto exit;
	}

	native_plaintext = (*env)->GetByteArrayElements(env, plaintext, NULL);
	if (native_plaintext == NULL)
	{
		goto exit;
	}

	// And copy the c plaintext to the java plaintext
	memcpy(native_plaintext,pt,plen);

	error = NO_ERROR;

exit:
	if (pt != NULL)
	{
		free(pt);
	}

	if (native_plaintext != NULL)
	{
		(*env)->ReleaseByteArrayElements(env, plaintext, native_plaintext, 0);
	}

	if (iv != NULL)
	{
		free(iv);
	}

	if (native_key != NULL)
	{
		(*env)->ReleaseByteArrayElements(env, key, native_key, JNI_ABORT);
	}

	if (native_ciphertext != NULL)
	{
		(*env)->ReleaseByteArrayElements(env, ciphertext, native_ciphertext, JNI_ABORT);
	}

	if (error == ERROR)
	{
		plaintext = NULL;
	}

	return plaintext;
}

JNIEXPORT jbyteArray JNICALL Java_com_kompetensum_keepsafe_NativeCrypto_GenerateRandom
  (JNIEnv *env, jclass object, jint num_bytes)
{
	int error = ERROR;
	jbyteArray random = NULL;
	jbyte* native_random = NULL;

	random = (*env)->NewByteArray(env, num_bytes);
	if (random == NULL)
	{
		goto exit;
	}

	native_random = (*env)->GetByteArrayElements(env, random, NULL);
	if (native_random == NULL)
	{
		goto exit;
	}

    entropy_context entropy;
    entropy_init(&entropy);

    ctr_drbg_context ctr_drbg;
    int res = ctr_drbg_init(&ctr_drbg, entropy_func, &entropy, MAGIC_STR, strlen(MAGIC_STR));
	if (res != 0)
	{
		goto exit;
	}

    res = ctr_drbg_random(&ctr_drbg, native_random, num_bytes);
	if (res != 0)
	{
		goto exit;
	}


	error = NO_ERROR;

exit:

	if (native_random != NULL)
	{
		(*env)->ReleaseByteArrayElements(env, random, native_random, 0);
	}

	if (error == ERROR)
	{
		random = NULL;
	}

	return random;
}


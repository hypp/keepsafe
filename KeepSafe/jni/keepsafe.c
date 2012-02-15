
#include "keepsafe.h"
#include "pbkdf2.h"

JNIEXPORT jbyteArray JNICALL Java_com_kompetensum_keepsafe_Crypto_PBKDF2WithHmacSHA1
  (JNIEnv *env, jclass object, jbyteArray password, jbyteArray salt, jint iteration_count, jint key_length)
{
	jbyteArray key = NULL;

	jsize pwlen = (*env)->GetArrayLength(env, password);
	jbyte* pw = (*env)->GetByteArrayElements(env, password, NULL);
	if (pw == NULL)
	{
		goto exit;
	}

	jsize slen = (*env)->GetArrayLength(env, salt);
	jbyte* s = (*env)->GetByteArrayElements(env, salt, NULL);
	if (s == NULL)
	{
		goto exit;
	}

	key = (*env)->NewByteArray(env, key_length);
	if (key == NULL)
	{
		goto exit;
	}

	jbyte* k = (*env)->GetByteArrayElements(env, key, NULL);
	if (k == NULL)
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

	res = PKCS5_PBKDF2_HMAC(&sha1ctx,pw,pwlen,s,slen,iteration_count,key_length,k);
	if (res != 0)
	{
		goto exit;
	}



exit:
	if (k == NULL)
	{
		(*env)->ReleaseByteArrayElements(env, key, k, 0);
	}

	if (s == NULL)
	{
		(*env)->ReleaseByteArrayElements(env, salt, s, JNI_ABORT);
	}

	if (pw != NULL)
	{
		(*env)->ReleaseByteArrayElements(env, password, pw, JNI_ABORT);
	}
	return key;
}

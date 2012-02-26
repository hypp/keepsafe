/*

   Copyright 2012 Mathias Olsson (mathias@kompetensum.com)

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
   
*/

package com.kompetensum.keepsafe;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import android.os.SystemClock;

public class NativeCrypto implements CryptoInterface {
	
	private static final String LIBNAME = "keepsafe";
	
	static {
		System.loadLibrary(LIBNAME);
	}
	
	/**
	 * Native implementation of Javas PBKDF2WithHmacSHA1
	 * @param password
	 * @param salt
	 * @param iterationCount
	 * @param keyLength
	 * @return key
	 */
	public static native byte[] PBKDF2WithHmacSHA1(final byte[] password, final byte[] salt, final int iterationCount, final int keyLength);

	/**
	 * Native implementation of Javas AES/CBC/PKCS5Padding with keylength 256
	 * @param key
	 * @param plaintext
	 * @return ciphertext
	 */
	public static native byte[] AES256CBCPKCS5Padding_Encrypt(final byte[] key, final byte[] iv, final byte[] plaintext);
	
	/**
	 * Native implementation of Javas AES/CBC/PKCS5Padding with keylength 256
	 * @param key
	 * @param ciphertext
	 * @return plaintext
	 */
	public static native byte[] AES256CBCPKCS5Padding_Decrypt(final byte[] key, final byte[] iv, final byte[] ciphertext);
	
	/**
	 * Native implementation of PRNG. 
	 * It will most likely be another implementation than Javas SHA1PRNG
	 * @param numBytes Number of bytes to return
	 * @return Random bytes
	 */
	public static native byte[] GenerateRandom(final int numBytes);

	public byte[] Decrypt(final String pw, final byte[] salt, final int iterationCount, final byte[] iv, final byte[] ciphertext) 
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, 
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
	{
		int keyLength = KEY_LENGTH_BYTES;
		
    	byte[] key = PBKDF2WithHmacSHA1(pw.getBytes(),salt,iterationCount,keyLength);
		
		byte[] plaintext = AES256CBCPKCS5Padding_Decrypt(key, iv, ciphertext);
		
		return plaintext;
	}
	
	public byte[] Encrypt(final String pw, final byte[] plaintext, byte[] salt, final int iterationCount, 
			final long monotonic, byte[] iv) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, 
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
	{
		int keyLength = KEY_LENGTH_BYTES;
		
		// Generate a random salt
    	byte[] tmpsalt = GenerateRandom(salt.length);
    	System.arraycopy(tmpsalt, 0, salt, 0, salt.length);
    	
    	byte[] key = PBKDF2WithHmacSHA1(pw.getBytes(),salt,iterationCount,keyLength);
		
		// Generate IV
		ByteBuffer nonce = ByteBuffer.allocate(CryptoInterface.NONCE_LENGTH);
		nonce.putLong(monotonic);
		
		long currentTime = System.currentTimeMillis();
		nonce.putLong(currentTime);
		
		long realTime =  SystemClock.elapsedRealtime();
		nonce.putLong(realTime);
		
		byte[] tmpiv = GenerateRandom(CryptoInterface.IV_LENGTH_BYTES);
		tmpiv = AES256CBCPKCS5Padding_Encrypt(key,tmpiv,nonce.array());
		// Make sure iv is the correct length
		System.arraycopy(tmpiv, 0, iv, 0, CryptoInterface.IV_LENGTH_BYTES);
			
		// Encrypt the secret
		byte[] ciphertext = AES256CBCPKCS5Padding_Encrypt(key,iv,plaintext);

		return ciphertext;
	}
}

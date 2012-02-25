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

public class Crypto {
	
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

}

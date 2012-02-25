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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public interface CryptoInterface {
	
	// Crypto constants
	static final int KEY_LENGTH = 256;
	static final int IV_LENGTH_BYTES = 128 / 8; 
	static final int DEFAULT_ITERATION_COUNT = 10000;
	static final int DEFAULT_SALT_LENGTH = 8;
	static final String PRNG = "SHA1PRNG";
	static final String KDF = "PBKDF2WithHmacSHA1";
	static final String CIPHER = "AES/CBC/PKCS5Padding";
	static final String KEYTYPE = "AES";
	static final int NONCE_LENGTH = 8 * 3;
	
	public byte[] Decrypt(final char[] pw, final byte[] salt, final int iterationCount, final byte[] iv, final byte[] ciphertext) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException;

	public byte[] Encrypt(final char[] pw, final byte[] plaintext, byte[] salt, final int saltLength, final int iterationCount, final long monotonic, byte[] iv) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException;
	
}

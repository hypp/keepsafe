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
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import android.os.SystemClock;

public class JavaCrypto implements CryptoInterface {
	

	public byte[] Decrypt(final char[] pw, final byte[] salt, final int iterationCount, final byte[] iv, final byte[] ciphertext) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
	{
		int keyLength = KEY_LENGTH;
		
		// Generate a secret key from the password	
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(KDF);
		PBEKeySpec keySpec = new PBEKeySpec(pw, salt, iterationCount, keyLength);
		SecretKey tmp = keyFactory.generateSecret(keySpec);
		SecretKey key = new SecretKeySpec(tmp.getEncoded(), KEYTYPE);
		
		Cipher cipher = Cipher.getInstance(CIPHER);
		IvParameterSpec ivParams = new IvParameterSpec(iv);
		cipher.init(Cipher.DECRYPT_MODE, key, ivParams);
		byte[] plaintext = cipher.doFinal(ciphertext);
		
		return plaintext;
	}
	
	public byte[] Encrypt(final char[] pw, final byte[] plaintext, byte[] salt, final int saltLength, final int iterationCount, final long monotonic, byte[] iv) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
	{
		int keyLength = KEY_LENGTH;
		
		// Generate a random salt
    	SecureRandom prng = SecureRandom.getInstance(CryptoInterface.PRNG);
    	prng.nextBytes(salt);
    	
    	// Generate a secret key from the password	
    	SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(CryptoInterface.KDF);
    	PBEKeySpec keySpec = new PBEKeySpec(pw, salt, iterationCount, keyLength);
		SecretKey tmp = keyFactory.generateSecret(keySpec);
		SecretKey key = new SecretKeySpec(tmp.getEncoded(), CryptoInterface.KEYTYPE);
		
		// Generate IV
		ByteBuffer nonce = ByteBuffer.allocate(CryptoInterface.NONCE_LENGTH);
		nonce.putLong(monotonic);
		
		long currentTime = System.currentTimeMillis();
		nonce.putLong(currentTime);
		
		long realTime =  SystemClock.elapsedRealtime();
		nonce.putLong(realTime);
		
		Cipher cipher = Cipher.getInstance(CryptoInterface.CIPHER);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] tmpiv = cipher.doFinal(nonce.array());
		// Make sure iv is the correct length
		System.arraycopy(tmpiv, 0, iv, 0, CryptoInterface.IV_LENGTH_BYTES);
			
		// Encrypt the secret
		cipher = Cipher.getInstance(CryptoInterface.CIPHER);
		IvParameterSpec ivParams = new IvParameterSpec(iv);
		cipher.init(Cipher.ENCRYPT_MODE, key, ivParams);
		byte[] ciphertext = cipher.doFinal(plaintext);

		return ciphertext;
	}

}

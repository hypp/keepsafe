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

import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import android.app.Activity;
import android.app.ProgressDialog;
import android.os.Bundle;

public class SelfTest extends Activity {

	static final int KEY_LENGTH = 256;
	static final int IV_LENGTH_BYTES = 128 / 8; 
	static final int DEFAULT_ITERATION_COUNT = 10000;
	static final int DEFAULT_SALT_LENGTH = 8;
	static final String PRNG = "SHA1PRNG";
	static final String KDF = "PBKDF2WithHmacSHA1";
	static final String CIPHER = "AES/CBC/PKCS5Padding";
	static final String KEYTYPE = "AES";
	static final int NONCE_LENGTH = 8 * 3;
	
	private ProgressDialog progress;

	/* (non-Javadoc)
	 * @see android.app.Activity#onCreate(android.os.Bundle)
	 */
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		// TODO Auto-generated method stub
		super.onCreate(savedInstanceState);
		
		// Show progressbar
		progress = ProgressDialog.show(this, getString(R.string.pleasewait), getString(R.string.processing));
		
		
		new Thread(new Runnable() {

			public void run() {
				
				try {
		        	int iterationCount = DEFAULT_ITERATION_COUNT;
					int keyLength = KEY_LENGTH;
	
					// Generate a random salt
		        	SecureRandom prng = SecureRandom.getInstance(PRNG);
		        	byte[] salt = new byte[DEFAULT_SALT_LENGTH];
		        	prng.nextBytes(salt);
		        	
		        	String pw = "ThisIsTheSecretPassword";
		        	String secret = "And this is the very secret secret";
		        	
		        	// Generate a secret key from the password	
		        	SecretKeyFactory keyFactory;
					keyFactory = SecretKeyFactory.getInstance(KDF);
					PBEKeySpec keySpec = new PBEKeySpec(pw.toCharArray(), salt, iterationCount, keyLength);
					SecretKey tmp = keyFactory.generateSecret(keySpec);
					SecretKey key1 = new SecretKeySpec(tmp.getEncoded(), KEYTYPE);
					
			        byte[] k = Crypto.PBKDF2WithHmacSHA1(pw.getBytes(), salt, iterationCount, keyLength / 8);
			        SecretKey key2 = new SecretKeySpec(k, KEYTYPE);
			        
			        byte[] encoded1 = key1.getEncoded();
			        byte[] encoded2 = key2.getEncoded();
			        
			        if (Arrays.equals(encoded1, encoded2))
			        {
			        	// All is well!
			        	int x = 42;
			        }
			        else
			        {
			        	// Show msgbox with failure
			        	int x = 42;
			        }
			        
			        byte[] iv = new byte[IV_LENGTH_BYTES];
			        prng.nextBytes(iv);
					IvParameterSpec ivParams = new IvParameterSpec(iv);
			        
					Cipher cipher = Cipher.getInstance(CIPHER);
					cipher.init(Cipher.ENCRYPT_MODE, key1, ivParams);
					byte[] ct1 = cipher.doFinal(secret.getBytes());
			        
					cipher = Cipher.getInstance(CIPHER);
					cipher.init(Cipher.ENCRYPT_MODE, key2, ivParams);
					byte[] ct2 = cipher.doFinal(secret.getBytes());
					
			        if (Arrays.equals(ct1, ct2))
			        {
			        	// All is well!
			        	int x = 42;
			        }
			        else
			        {
			        	// Show msgbox with failure
			        	int x = 42;
			        }
			        
			        
			        
				
				} catch (Exception e) {
					int x = 42;
				}
				
				progress.dismiss();
			}
			
		}).start();
	}
	
	

}

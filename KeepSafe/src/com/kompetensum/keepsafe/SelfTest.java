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

import android.app.Activity;
import android.app.ProgressDialog;
import android.os.Bundle;
import android.widget.TextView;

public class SelfTest extends Activity {

	/* (non-Javadoc)
	 * @see android.app.Activity#onPause()
	 */
	@Override
	protected void onPause() {
		progress.dismiss();
		super.onPause();
		
		// TODO Stop thread!
	}

	private ProgressDialog progress;

	/* (non-Javadoc)
	 * @see android.app.Activity#onCreate(android.os.Bundle)
	 */
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.selftest);
		
		// Show progressbar
		progress = ProgressDialog.show(this, getString(R.string.pleasewait), getString(R.string.processing));
		
		
		new Thread(new Runnable() {

			public void run() {
				
	        	int iterationCount = 10; // CryptoInterface.DEFAULT_ITERATION_COUNT;
				int keyLength = CryptoInterface.KEY_LENGTH_BITS;
	        	String pw = "ThisIsTheSecretPassword";
	        	String secret = "And this is the very secret secret";
				
				SecureRandom prng = null;
				SecretKeyFactory kf = null;
				Cipher cipher = null;				
						
				setStatus("Check for Java PRNG");
	        	try {
					prng = SecureRandom.getInstance(CryptoInterface.PRNG);
					setStatus("--- success");
				} catch (NoSuchAlgorithmException e) {
					setStatus("--- fail");
				}

				setStatus("Check for Java KDF");
	        	try {
					kf = SecretKeyFactory.getInstance(CryptoInterface.KDF);;
					setStatus("--- success");
				} catch (NoSuchAlgorithmException e) {
					setStatus("--- fail");
				}
	        	
				setStatus("Check for Java Cipher");
	        	try {
					cipher = Cipher.getInstance(CryptoInterface.CIPHER);
					setStatus("--- success");
				} catch (NoSuchAlgorithmException e) {
					setStatus("--- fail");
				} catch (NoSuchPaddingException e) {
					setStatus("--- fail");
				}
	        	
	        	byte[] salt = null;
	        	if (prng != null)
	        	{
					setStatus("Generate salt using Java PRNG");
	        		
					salt = new byte[CryptoInterface.DEFAULT_SALT_LENGTH];
		        	prng.nextBytes(salt);
		        	
	        		setStatus("--- success");
	        	}
	        	
	        	byte[] nativesalt = null;
	        	setStatus("Generate salt using native PRNG");
	        	
	        	nativesalt = NativeCrypto.GenerateRandom(CryptoInterface.DEFAULT_SALT_LENGTH);
	        	if (nativesalt != null) {
	        		setStatus("--- success");
				} else {
					setStatus("--- fail");
				}

	        	SecretKey javakey = null;	        	
	        	if (salt != null && kf != null)
	        	{
					setStatus("Generate key using Java KDF");
	        		
					PBEKeySpec keySpec = new PBEKeySpec(pw.toCharArray(), salt, iterationCount, keyLength);
					SecretKey tmp;
					try {
						tmp = kf.generateSecret(keySpec);
						javakey = new SecretKeySpec(tmp.getEncoded(), CryptoInterface.KEYTYPE);
			        	
		        		setStatus("--- success");
					} catch (InvalidKeySpecException e) {
						setStatus("--- fail");
					}
	        	}
	        	
	        	SecretKey nativekey = null;
	        	if (salt != null)
	        	{
					setStatus("Generate key using Native KDF");
	        		
			        byte[] k = NativeCrypto.PBKDF2WithHmacSHA1(pw.getBytes(), salt, iterationCount, keyLength / 8);
			        nativekey = new SecretKeySpec(k, CryptoInterface.KEYTYPE);
		        	
	        		setStatus("--- success");
	        	}

	        	if (javakey != null && nativekey != null)
	        	{
					setStatus("Verify that Java key and Native key are identical");

			        byte[] encoded1 = javakey.getEncoded();
			        byte[] encoded2 = nativekey.getEncoded();
			        
			        if (Arrays.equals(encoded1, encoded2)) {
		        		setStatus("--- success");
					} else {
						setStatus("--- fail");
					}
	        		
	        	}

		        byte[] iv = new byte[CryptoInterface.IV_LENGTH_BYTES];
		        prng.nextBytes(iv);
				IvParameterSpec ivParams = new IvParameterSpec(iv);
				byte[] javajavact = null;
	        	
	        	if (javakey != null)
	        	{
					setStatus("Encrypt with Java key using Java Cipher");
					
					try {
						cipher.init(Cipher.ENCRYPT_MODE, javakey, ivParams);
						javajavact = cipher.doFinal(secret.getBytes());
						
				        if (javajavact != null) {
			        		setStatus("--- success");
						} else {
							setStatus("--- fail");
						}
					} catch (IllegalBlockSizeException e) {
						setStatus("--- fail");
					} catch (BadPaddingException e) {
						setStatus("--- fail");
					} catch (InvalidKeyException e) {
						setStatus("--- fail");
					} catch (InvalidAlgorithmParameterException e) {
						setStatus("--- fail");
					}
	        	}
	        	
	        	byte[] nativejavact = null;
	        	if (nativekey != null)
	        	{
					setStatus("Encrypt with Native key using Java Cipher");
					
					try {
						cipher.init(Cipher.ENCRYPT_MODE, nativekey, ivParams);
						nativejavact = cipher.doFinal(secret.getBytes());
						
				        if (nativejavact != null) {
			        		setStatus("--- success");
						} else {
							setStatus("--- fail");
						}
					} catch (InvalidKeyException e) {
						setStatus("--- fail");
					} catch (InvalidAlgorithmParameterException e) {
						setStatus("--- fail");
					} catch (IllegalBlockSizeException e) {
						setStatus("--- fail");
					} catch (BadPaddingException e) {
						setStatus("--- fail");
					}
	        	}
	        	
	        	byte[] javanativect = null;
	        	if (javakey != null)
	        	{
					setStatus("Encrypt with Java key using Native Cipher");
					
					javanativect = NativeCrypto.AES256CBCPKCS5Padding_Encrypt(javakey.getEncoded(), iv, secret.getBytes());
					if (javanativect != null) {
		        		setStatus("--- success");
					} else {
						setStatus("--- fail");
					}
	        	}

	        	byte[] nativenativect = null;
	        	if (nativekey != null)
	        	{
					setStatus("Encrypt with Native key using Native Cipher");
					
					nativenativect = NativeCrypto.AES256CBCPKCS5Padding_Encrypt(nativekey.getEncoded(), iv, secret.getBytes());
					if (nativenativect != null) {
		        		setStatus("--- success");
					} else {
						setStatus("--- fail");
					}
	        	}
	        	
	        	if (javajavact != null && nativejavact != null)
	        	{
					setStatus("Verify that ciphertexts are identical (1)");

			        if (Arrays.equals(javajavact, nativejavact)) {
		        		setStatus("--- success");
					} else {
						setStatus("--- fail");
					}
	        	}
	        	
	        	if (javanativect != null && nativenativect != null)
	        	{
					setStatus("Verify that ciphertexts are identical (2)");

			        if (Arrays.equals(javanativect, nativenativect)) {
		        		setStatus("--- success");
					} else {
						setStatus("--- fail");
					}
	        	}

	        	if (javanativect != null && javajavact != null)
	        	{
					setStatus("Verify that ciphertexts are identical (3)");

			        if (Arrays.equals(javanativect, javajavact)) {
		        		setStatus("--- success");
					} else {
						setStatus("--- fail");
					}
	        	}

	        	if (nativenativect != null && nativejavact != null)
	        	{
					setStatus("Verify that ciphertexts are identical (4)");

			        if (Arrays.equals(nativenativect, nativejavact)) {
		        		setStatus("--- success");
					} else {
						setStatus("--- fail");
					}
	        	}
	        	
	        	
	        	if (javakey != null)
	        	{
					setStatus("Decrypt with Java key using Java Cipher");
					
					byte[] ct = javajavact;
					if (ct == null)
					{
						ct = nativejavact;
					}
					
					try {
						cipher.init(Cipher.DECRYPT_MODE, javakey, ivParams);
						byte[] plaintext = cipher.doFinal(ct);
						
						if (Arrays.equals(secret.getBytes(), plaintext)) {
			        		setStatus("--- success");
						} else {
							setStatus("--- fail");
						}
					} catch (InvalidKeyException e) {
						setStatus("--- fail");
					} catch (InvalidAlgorithmParameterException e) {
						setStatus("--- fail");
					} catch (IllegalBlockSizeException e) {
						setStatus("--- fail");
					} catch (BadPaddingException e) {
						setStatus("--- fail");
					}
	        	}

	        	if (nativekey != null)
	        	{
					setStatus("Decrypt with Native key using Java Cipher");
					
					byte[] ct = javajavact;
					if (ct == null)
					{
						ct = nativejavact;
					}
					
					try {
						cipher.init(Cipher.DECRYPT_MODE, nativekey, ivParams);
						byte[] plaintext = cipher.doFinal(ct);
						
						if (Arrays.equals(secret.getBytes(), plaintext)) {
			        		setStatus("--- success");
						} else {
							setStatus("--- fail");
						}
					} catch (InvalidKeyException e) {
						setStatus("--- fail");
					} catch (InvalidAlgorithmParameterException e) {
						setStatus("--- fail");
					} catch (IllegalBlockSizeException e) {
						setStatus("--- fail");
					} catch (BadPaddingException e) {
						setStatus("--- fail");
					}
	        	}
	        	
	        	
	        	if (javakey != null)
	        	{
					setStatus("Decrypt with Java key using Native Cipher");
					
					byte[] ct = javajavact;
					if (ct == null)
					{
						ct = nativejavact;
					}
					
					byte plaintext[] = NativeCrypto.AES256CBCPKCS5Padding_Decrypt(javakey.getEncoded(), iv, ct);
					if (Arrays.equals(secret.getBytes(), plaintext)) {
		        		setStatus("--- success");
					} else {
						setStatus("--- fail");
					}
	        	}
	        	
	        	if (nativekey != null)
	        	{
					setStatus("Decrypt with Native key using Native Cipher");
					
					byte[] ct = javajavact;
					if (ct == null)
					{
						ct = nativejavact;
					}
					
					byte plaintext[] = NativeCrypto.AES256CBCPKCS5Padding_Decrypt(nativekey.getEncoded(), iv, ct);
					if (Arrays.equals(secret.getBytes(), plaintext)) {
		        		setStatus("--- success");
					} else {
						setStatus("--- fail");
					}
	        	}
	        	
	        	byte[] singlesalt = null;
	        	byte[] singleiv = null;
	        	byte[] singleciphertext = null;
	        	try {
		        	setStatus("Single operation encrypt using Java");
		        	JavaCrypto jc = new JavaCrypto();
		        	singlesalt = new byte[CryptoInterface.DEFAULT_SALT_LENGTH];
		        	singleiv = new byte[CryptoInterface.IV_LENGTH_BYTES];
					singleciphertext = jc.Encrypt(pw, secret.getBytes("UTF-8"), 
							singlesalt, iterationCount, 0, singleiv);
					if (singleciphertext != null) {
		        		setStatus("--- success");
					} else {
						setStatus("--- fail");
					}
						
				} catch (Exception e) {
					setStatus("--- fail");
				}

	        	try {
		        	setStatus("Single operation decrypt using Java");
		        	JavaCrypto jc = new JavaCrypto();
					byte[] singleplaintext = jc.Decrypt(pw, singlesalt, 
							iterationCount, singleiv, singleciphertext);
					
					if (Arrays.equals(secret.getBytes("UTF-8"), singleplaintext)) {
		        		setStatus("--- success");
					} else {
						setStatus("--- fail");
					}
						
				} catch (Exception e) {
					setStatus("--- fail");
				}

	        	singlesalt = null;
	        	singleiv = null;
	        	singleciphertext = null;
	        	try {
		        	setStatus("Single operation encrypt using Native");
		        	NativeCrypto nc = new NativeCrypto();
		        	singlesalt = new byte[CryptoInterface.DEFAULT_SALT_LENGTH];
		        	singleiv = new byte[CryptoInterface.IV_LENGTH_BYTES];
					singleciphertext = nc.Encrypt(pw, secret.getBytes("UTF-8"), 
							singlesalt, iterationCount, 0, singleiv);
					if (singleciphertext != null) {
		        		setStatus("--- success");
					} else {
						setStatus("--- fail");
					}
						
				} catch (Exception e) {
					setStatus("--- fail");
				}

	        	try {
		        	setStatus("Single operation decrypt using Native");
		        	NativeCrypto nc = new NativeCrypto();
					byte[] singleplaintext = nc.Decrypt(pw, singlesalt, 
							iterationCount, singleiv, singleciphertext);
					
					if (Arrays.equals(secret.getBytes("UTF-8"), singleplaintext)) {
		        		setStatus("--- success");
					} else {
						setStatus("--- fail");
					}
						
				} catch (Exception e) {
					setStatus("--- fail");
				}
	        	
				progress.dismiss();
			}
			
		}).start();
	}
	
	private void setStatus(final String str)
	{
		runOnUiThread(new Runnable() {
			public void run() {
				TextView tv = (TextView)findViewById(R.id.selftest);
				String contents = (String) tv.getText();
				tv.setText(contents + "\r\n" + str);
			}
		});
		Thread.yield();
		
	}

}

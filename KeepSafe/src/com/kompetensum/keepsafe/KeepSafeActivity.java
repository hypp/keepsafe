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
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.ContentValues;
import android.content.Context;
import android.content.DialogInterface;
import android.database.Cursor;
import android.database.DatabaseUtils;
import android.database.sqlite.SQLiteDatabase;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.AdapterView.OnItemLongClickListener;
import android.widget.Button;
import android.widget.ListView;
import android.widget.SimpleCursorAdapter;
import android.widget.TextView;

public class KeepSafeActivity extends Activity implements OnClickListener, OnItemClickListener, OnItemLongClickListener {
	private SQLiteDatabase database;
	private Context context;
	
	private ProgressDialog progress;
	
	// Crypto constants
	static final int KEY_LENGTH = 256;
	static final int ITERATION_COUNT = 10000;
	static final int SALT_LENGTH = 8;
	static final String PRNG = "SHA1PRNG";
	static final String KDF = "PBKDF2WithHmacSHA1";
	static final String CIPHER = "AES/CBC/PKCS5Padding";
	static final String KEYTYPE = "AES";
	static final int NONCE_LENGTH = 10;
	
	// Keep track of internal state
	static final int STATE_INIT = 0;
	static final int STATE_INIT_DB_DONE = 10;
	static final int STATE_INIT_DONE = 20;
	static final int STATE_DECRYPTING = 30;
	static final int STATE_LIST_SECRETS = 40;
	static final int STATE_ADD_SECRET = 50;
	static final int STATE_STORE_SECRET = 60;
	static final int STATE_SHOW_SECRET = 70;
	static final int STATE_ENTER_PASSWORD = 80;
	static final int STATE_DELETE_SECRET = 90;
	
	static final int STATE_FAILED_DECRYPT = 110;
	static final int STATE_FAILED_STORE = 120;
	static final int STATE_FAILED_ALGORITHMS = 130;
	
	private int state = STATE_INIT;
	
    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        
        context = (Context)this;

        setState(STATE_INIT);
        
        // Set click listeners
        Button button = (Button)findViewById(R.id.buttonHideSecret);
        button.setOnClickListener(this);
        button = (Button)findViewById(R.id.buttonRestart);
        button.setOnClickListener(this);
        button = (Button)findViewById(R.id.buttonAddSecret);
        button.setOnClickListener(this);
        button = (Button)findViewById(R.id.buttonStoreSecret);
        button.setOnClickListener(this);
        button = (Button)findViewById(R.id.buttonGetSecret);
        button.setOnClickListener(this);
        ListView lv = (ListView)findViewById(R.id.listSecrets);
        lv.setOnItemClickListener(this);
        lv.setOnItemLongClickListener(this);
        
        // Open the database
        new Thread(new Runnable() {
            public void run() {
            	SecretStorage ss = new SecretStorage(context);
            	database = ss.getWritableDatabase();
            	setState(STATE_INIT_DB_DONE);

            	// Sanity checks!
            	try
            	{
		        	SecureRandom prng = SecureRandom.getInstance(PRNG);
		        	SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(KDF);
					Cipher cipher = Cipher.getInstance(CIPHER);

	            	setState(STATE_LIST_SECRETS);
            	} catch (Exception e) {
            		// PBKDF2WithHmacSHA1 does not exist on SonyEricsson XPERIA X10 Mini API-level 7 
                	setState(STATE_FAILED_ALGORITHMS);
            	}
            	
            }
          }).start();
    }

	/**
	 * @return the state
	 */
	public int getState() {
		return state;
	}

	/**
	 * @param state the state to set
	 */
	public void setState(int state) {
		
		this.state = state;

		// Hide all
		runOnUiThread(new Runnable() {
			public void run() {
				View view = findViewById(R.id.showsecretLayout);
				view.setVisibility(View.INVISIBLE);
				view = findViewById(R.id.listsecretsLayout);
				view.setVisibility(View.INVISIBLE);
				view = findViewById(R.id.addsecretLayout);
				view.setVisibility(View.INVISIBLE);
				view = findViewById(R.id.enterpwLayout);
				view.setVisibility(View.INVISIBLE);
				
				view = findViewById(R.id.failedLayout);
				view.setVisibility(View.INVISIBLE);
				
				if (progress != null)
				{
					progress.dismiss();
				}
			}
		});
		
		switch (state)
		{
		case STATE_INIT:
			// Fall through
		case STATE_DECRYPTING:
			// Fall through
		case STATE_STORE_SECRET:
			// Show progressbar
			runOnUiThread(new Runnable() {
				public void run() {
					progress = ProgressDialog.show(context, getString(R.string.pleasewait), getString(R.string.processing));
				}
			});
			break;
		case STATE_LIST_SECRETS:
			// Show list with secrets
			runOnUiThread(new Runnable() {
				public void run() {
					View view = findViewById(R.id.listsecretsLayout);
					view.setVisibility(View.VISIBLE);
					refreshSecretList();
				}
			});
			
			break;
		case STATE_ADD_SECRET:
			// Add a  secrets
			runOnUiThread(new Runnable() {
				public void run() {
					View view = findViewById(R.id.addsecretLayout);
					view.setVisibility(View.VISIBLE);
				}
			});
			
			break;
		case STATE_ENTER_PASSWORD:
			// Enter password for decrypt
			runOnUiThread(new Runnable() {
				public void run() {
					View view = findViewById(R.id.enterpwLayout);
					view.setVisibility(View.VISIBLE);
				}
			});
			
			break;
		case STATE_SHOW_SECRET:
			runOnUiThread(new Runnable() {
				public void run() {
					View view = findViewById(R.id.showsecretLayout);
					view.setVisibility(View.VISIBLE);
				}
			});
			
			break;
			
		case STATE_FAILED_ALGORITHMS:
			runOnUiThread(new Runnable() {
				public void run() {
					AlertDialog ad = new AlertDialog.Builder(context).create();  
					ad.setCancelable(false); // This blocks the 'BACK' button  
					ad.setMessage(getString(R.string.notsupported));
					ad.setButton(AlertDialog.BUTTON_POSITIVE, getString(R.string.ok), new DialogInterface.OnClickListener() {
						public void onClick(DialogInterface dialog, int which) {
							dialog.dismiss();
						}  
					});  
					ad.show();		
				}
			});
		case STATE_FAILED_DECRYPT:
			// Fall through
		case STATE_FAILED_STORE:
			// Show error message
			runOnUiThread(new Runnable() {
				public void run() {
					View view = findViewById(R.id.failedLayout);
					view.setVisibility(View.VISIBLE);
				}
			});
			
			break;
		}
	}

	protected void refreshSecretList() {
		ListView list = (ListView)findViewById(R.id.listSecrets);
		// Clear the list
		list.setAdapter(null);
		
		String[] columns = new String[] {SecretStorage.COL_NAME};
		int[] to = new int[] {R.id.textListItem};
		Cursor cursor = database.rawQuery("select rowid _id, "+ SecretStorage.COL_NAME + " from " + SecretStorage.DATABASE_NAME,null);
		
		list.setAdapter(new SimpleCursorAdapter(this, R.layout.listview_content, cursor, columns, to));
		
	}

	public void onClick(View v) {
		
		switch (v.getId())
		{
		case R.id.buttonRestart:
		case R.id.buttonHideSecret:
			{
				setState(STATE_LIST_SECRETS);
				TextView value = (TextView)findViewById(R.id.showSecret);
				value.setText("");
			}
			break;
		case R.id.buttonAddSecret:
			{
				setState(STATE_ADD_SECRET);
			}
			break;
		case R.id.buttonStoreSecret:
			{
				setState(STATE_STORE_SECRET);
				TextView name = (TextView)findViewById(R.id.secretname);
				TextView value = (TextView)findViewById(R.id.secretvalue);
				TextView password = (TextView)findViewById(R.id.password);
				storeSecret(password.getText().toString(),name.getText().toString(),value.getText().toString());
				value.setText("");
				password.setText("");
			}
			break;
		case R.id.buttonGetSecret:
			{
				setState(STATE_DECRYPTING);
				TextView name = (TextView)findViewById(R.id.name);
				TextView password = (TextView)findViewById(R.id.enterpassword);
				retrieveSecret(password.getText().toString(),name.getText().toString());
				password.setText("");
			}
			break;
			
		}
	}

	private void retrieveSecret(final String pw, final String name) {
		// This can take quite a while, we should not run it on the UI thread
		new Thread(new Runnable() {

			public void run() {
				
				try {
					String[] selection = new String[1];
					selection[0] = name;
					Cursor cursor = database.query(SecretStorage.DATABASE_NAME,null,SecretStorage.COL_NAME + " = ?",selection,null, null, null);
					if (!cursor.moveToFirst())
					{
						throw new Exception("cursor.moveToFirst() failed");
					}
					
					ContentValues values = new ContentValues();
					DatabaseUtils.cursorRowToContentValues(cursor, values);
	
					int keyLength = KEY_LENGTH;
					
					byte[] salt = values.getAsByteArray(SecretStorage.COL_SALT);
					int iterationCount = values.getAsInteger(SecretStorage.COL_ITERATION_COUNT);
					byte[] iv = values.getAsByteArray(SecretStorage.COL_IV);
					byte[] ciphertext = values.getAsByteArray(SecretStorage.COL_VALUE);
					
					if (salt.length != SALT_LENGTH)
					{
						throw new Exception("salt.length != SALT_LENGTH");
					}
					if (iterationCount != ITERATION_COUNT)
					{
						throw new Exception("iterationCount != ITERATION_COUNT");
					}
					
		        	// Generate a secret key from the password	
		        	SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(KDF);
		        	PBEKeySpec keySpec = new PBEKeySpec(pw.toCharArray(), salt, iterationCount, keyLength);
					SecretKey tmp = keyFactory.generateSecret(keySpec);
					SecretKey key = new SecretKeySpec(tmp.getEncoded(), KEYTYPE);
					
					Cipher cipher = Cipher.getInstance(CIPHER);
					IvParameterSpec ivParams = new IvParameterSpec(iv);
					cipher.init(Cipher.DECRYPT_MODE, key, ivParams);
					byte[] plaintext = cipher.doFinal(ciphertext);
					final String tmpstr = new String(plaintext, "UTF-8");
					
					runOnUiThread(new Runnable() {
						public void run() {
							TextView tv = (TextView)findViewById(R.id.showSecret);
							tv.setText(tmpstr);
						}
					});
					
					setState(STATE_SHOW_SECRET);
					
				} catch (Exception e) {
					setState(STATE_FAILED_DECRYPT);
				}
				
			}
		}).start();
	}

	private void storeSecret(final String pw, final String name, final String plaintext) {
		// This can take quite a while, we should not run it on the UI thread
		new Thread(new Runnable() {

			public void run() {
				
				try {
					int keyLength = KEY_LENGTH;
					int iterationCount = ITERATION_COUNT;
					int saltLength = SALT_LENGTH;
					
					// Generate a random salt
		        	SecureRandom prng = SecureRandom.getInstance(PRNG);
		        	byte[] salt = new byte[saltLength];
		        	prng.nextBytes(salt);
		        	
		        	// Generate a secret key from the password	
		        	SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(KDF);
		        	PBEKeySpec keySpec = new PBEKeySpec(pw.toCharArray(), salt, iterationCount, keyLength);
					SecretKey tmp = keyFactory.generateSecret(keySpec);
					SecretKey key = new SecretKeySpec(tmp.getEncoded(), KEYTYPE);
					
					// Generate IV
					byte[] nonce = new byte[NONCE_LENGTH];
					prng.nextBytes(nonce);
					Cipher cipher = Cipher.getInstance(CIPHER);
					cipher.init(Cipher.ENCRYPT_MODE, key);
					byte[] iv = cipher.doFinal(nonce);
						
					// Encrypt the secret
					cipher = Cipher.getInstance(CIPHER);
					IvParameterSpec ivParams = new IvParameterSpec(iv);
					cipher.init(Cipher.ENCRYPT_MODE, key, ivParams);
					byte[] ciphertext = cipher.doFinal(plaintext.getBytes("UTF-8"));
					
					// Store it to the database
					
					ContentValues values = new ContentValues();
					values.put(SecretStorage.COL_NAME,name);
					values.put(SecretStorage.COL_SALT,salt);
					values.put(SecretStorage.COL_ITERATION_COUNT,iterationCount);
					values.put(SecretStorage.COL_IV,iv);
					values.put(SecretStorage.COL_VALUE,ciphertext);
	
					database.insert(SecretStorage.DATABASE_NAME, null, values);
					
					// Return to unlocked state
					setState(STATE_LIST_SECRETS);

				} catch (Exception e) {
					// Report a generic error
					setState(STATE_FAILED_STORE);
				}
			}
		}).start();
		
	}

	public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
		
		Cursor cursor = (Cursor) parent.getItemAtPosition(position);
		String name = cursor.getString(cursor.getColumnIndex(SecretStorage.COL_NAME));
		TextView tv = (TextView)findViewById(R.id.name);
		tv.setText(name);
		
		setState(STATE_ENTER_PASSWORD);
	}

	public boolean onItemLongClick(AdapterView<?> parent, View view, int position, long id) {
		Cursor cursor = (Cursor) parent.getItemAtPosition(position);
		final String name = cursor.getString(cursor.getColumnIndex(SecretStorage.COL_NAME));
		
		// Show messagebox
		AlertDialog ad = new AlertDialog.Builder(this).create();
		ad.setCancelable(false); // This blocks the 'BACK' button  
		ad.setTitle(getString(R.string.delete));
		ad.setIcon(R.drawable.lock_delete);
		ad.setMessage(getString(R.string.delete) + " '" + name + "'?");
		ad.setButton(AlertDialog.BUTTON_POSITIVE, getString(R.string.yes), new DialogInterface.OnClickListener() {
			public void onClick(DialogInterface dialog, int which) {
				
				setState(STATE_DELETE_SECRET);
				
				dialog.dismiss();
				
				String[] args = new String[1];
				args[0] = name;
				database.execSQL("delete from " + SecretStorage.DATABASE_NAME + " where " + SecretStorage.COL_NAME + " = ?", args);
				
				setState(STATE_LIST_SECRETS);
			}  
		});  
		ad.setButton(AlertDialog.BUTTON_NEGATIVE, getString(R.string.no), new DialogInterface.OnClickListener() {
			public void onClick(DialogInterface dialog, int which) {
				dialog.dismiss();
			}  
		});
		ad.show();		
		
		return true;
	}
}


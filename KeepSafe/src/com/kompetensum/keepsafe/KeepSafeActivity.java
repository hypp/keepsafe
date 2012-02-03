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

import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ContentValues;
import android.content.Context;
import android.content.DialogInterface;
import android.database.Cursor;
import android.database.DatabaseUtils;
import android.database.sqlite.SQLiteDatabase;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.AdapterView.OnItemLongClickListener;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.ListView;
import android.widget.TextView;

public class KeepSafeActivity extends Activity implements OnClickListener, OnItemClickListener, OnItemLongClickListener {
	private SQLiteDatabase database;
	private Context context;
	
	// Crypto constants
	static final int KEY_LENGTH = 256;
	static final int ITERATION_COUNT = 1000;
	static final int SALT_LENGTH = 60;
	
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
	
	static final int STATE_FAILED_DECRYPT = 110;
	static final int STATE_FAILED_STORE = 120;
	
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
        
        Provider[] providers = Security.getProviders();
        for (Provider provider : providers) {
            Log.i("CRYPTO","provider: "+provider.getName());
            Set<Provider.Service> services = provider.getServices();
            for (Provider.Service service : services) {
                Log.i("CRYPTO","  algorithm: "+service.getAlgorithm());
            }
        }        
        
        // Open the database
        new Thread(new Runnable() {
            public void run() {
            	SecretStorage ss = new SecretStorage(context);
            	database = ss.getWritableDatabase();
            	setState(STATE_INIT_DB_DONE);
            	
            	
            	setState(STATE_LIST_SECRETS);
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
		// TODO rewrite this
		this.state = state;

		// Hide all
		runOnUiThread(new Runnable() {
			public void run() {
				View view = findViewById(R.id.progressLayout);
				view.setVisibility(View.INVISIBLE);
				view = findViewById(R.id.showsecretLayout);
				view.setVisibility(View.INVISIBLE);
				view = findViewById(R.id.listsecretsLayout);
				view.setVisibility(View.INVISIBLE);
				view = findViewById(R.id.addsecretLayout);
				view.setVisibility(View.INVISIBLE);
				view = findViewById(R.id.enterpwLayout);
				view.setVisibility(View.INVISIBLE);
				
				view = findViewById(R.id.failedLayout);
				view.setVisibility(View.INVISIBLE);
			}
		});
		
		switch (state)
		{
		case STATE_INIT:
		case STATE_DECRYPTING:
		case STATE_STORE_SECRET:
			// Show progressbar
			// TODO Use ProgressDialog
			runOnUiThread(new Runnable() {
				public void run() {
					View view = findViewById(R.id.progressLayout);
					view.setVisibility(View.VISIBLE);
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
			// Enter password for decrypt
			runOnUiThread(new Runnable() {
				public void run() {
					View view = findViewById(R.id.showsecretLayout);
					view.setVisibility(View.VISIBLE);
				}
			});
			
			break;
		case STATE_FAILED_DECRYPT:
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
		
		ArrayList<String> keys = new ArrayList<String>();
		
		String[] columns = new String[1];
		columns[0] = new String("name");
		Cursor cursor = database.query("secret",columns,null,null,null, null, null);
		if (!cursor.moveToFirst())
		{
			return;
		}
		do
		{
			ContentValues values = new ContentValues();
			DatabaseUtils.cursorRowToContentValues(cursor, values);
			keys.add(values.getAsString("name"));
			
			
		} while (cursor.moveToNext());
		
		list.setAdapter(new ArrayAdapter<String>(context,R.layout.listview_content,R.id.textListItem,keys));
		
		
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
					Cursor cursor = database.query("secret",null,"name = ?",selection,null, null, null);
					if (!cursor.moveToFirst())
					{
						return;
					}
					
					ContentValues values = new ContentValues();
					DatabaseUtils.cursorRowToContentValues(cursor, values);
	
					int keyLength = KEY_LENGTH;
					
					byte[] salt = values.getAsByteArray("salt");
					int iterationCount = values.getAsInteger("iterationcount");
					byte[] iv = values.getAsByteArray("iv");
					byte[] ciphertext = values.getAsByteArray("value");
					
					if (salt.length != SALT_LENGTH)
					{
						int x = 42;
					}
					if (iterationCount != ITERATION_COUNT)
					{
						int x = 42;
					}
					
		        	// Generate a secret key from the password	
		        	SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		        	PBEKeySpec keySpec = new PBEKeySpec(pw.toCharArray(), salt, iterationCount, keyLength);
					SecretKey tmp = keyFactory.generateSecret(keySpec);
					SecretKey key = new SecretKeySpec(tmp.getEncoded(), "AES");
					
					Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
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
		        	SecureRandom prng = SecureRandom.getInstance("SHA1PRNG");
		        	byte[] salt = new byte[saltLength];
		        	prng.nextBytes(salt);
		        	
		        	// Generate a secret key from the password	
		        	SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		        	PBEKeySpec keySpec = new PBEKeySpec(pw.toCharArray(), salt, iterationCount, keyLength);
					SecretKey tmp = keyFactory.generateSecret(keySpec);
					SecretKey key = new SecretKeySpec(tmp.getEncoded(), "AES");			
						
					// Encrypt the secret
					Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
					cipher.init(Cipher.ENCRYPT_MODE, key);
					byte[] iv = cipher.getIV();
					byte[] ciphertext = cipher.doFinal(plaintext.getBytes("UTF-8"));
					
					// Store it to the database
					ContentValues values = new ContentValues();
					values.put("name",name);
					values.put("salt",salt);
					values.put("iterationcount",iterationCount);
					values.put("iv",iv);
					values.put("value",ciphertext);
	
					database.insert("secret", null, values);
					
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
		
		String name = (String)parent.getItemAtPosition(position);
		TextView tv = (TextView)findViewById(R.id.name);
		tv.setText(name);
		
		setState(STATE_ENTER_PASSWORD);
	}

	public boolean onItemLongClick(AdapterView<?> parent, View view, int position, long id) {
		String name = (String)parent.getItemAtPosition(position);
		
		// Show messagebox
		AlertDialog ad = new AlertDialog.Builder(this).create();  
		ad.setCancelable(false); // This blocks the 'BACK' button  
		ad.setMessage("Delete '" + name + "'?");
		ad.setButton(AlertDialog.BUTTON_POSITIVE, "Yes", new DialogInterface.OnClickListener() {
			public void onClick(DialogInterface dialog, int which) {
				dialog.dismiss();
				// TODO Delete from database and refresh listview
			}  
		});  
		ad.setButton(AlertDialog.BUTTON_NEGATIVE, "No", new DialogInterface.OnClickListener() {
			public void onClick(DialogInterface dialog, int which) {
				dialog.dismiss();
			}  
		});  
		ad.show();		
		
		return true;
	}
}
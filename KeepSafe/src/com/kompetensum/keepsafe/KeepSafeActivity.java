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
import javax.crypto.SecretKeyFactory;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.ContentValues;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.database.DatabaseUtils;
import android.database.sqlite.SQLiteDatabase;
import android.net.Uri;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
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
	private int iteration_count = CryptoInterface.DEFAULT_ITERATION_COUNT;
	private int salt_length = CryptoInterface.DEFAULT_SALT_LENGTH;
	
	private String ABOUT_URL = "http://code.google.com/p/keepsafe/";
	
	private CryptoInterface crypto = new JavaCrypto();
	
    /** Called when the activity is first created. */
	/* (non-Javadoc)
	 * @see android.app.Activity#onCreate()
	 */
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
		        	SecureRandom.getInstance(CryptoInterface.PRNG);
		        	SecretKeyFactory.getInstance(CryptoInterface.KDF);
					Cipher.getInstance(CryptoInterface.CIPHER);

	            	setState(STATE_LIST_SECRETS);
            	} catch (Exception e) {
            		// PBKDF2WithHmacSHA1 does not exist on SonyEricsson XPERIA X10 Mini API-level 7 
                	setState(STATE_FAILED_ALGORITHMS);
            	}
            	
            }
          }).start();
    }

	/* (non-Javadoc)
	 * @see android.app.Activity#onStart()
	 */
	@Override
	protected void onStart() {
		super.onStart();
		
		// Initialize preferences
		SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(this);
		String tmp = preferences.getString("iteration_count", "");
		iteration_count = Integer.parseInt(tmp);
		if (iteration_count == 0)
		{
			iteration_count = CryptoInterface.DEFAULT_ITERATION_COUNT;
		}
		tmp = preferences.getString("salt_length", "");
		salt_length = Integer.parseInt(tmp);
		if (salt_length == 0)
		{
			salt_length = CryptoInterface.DEFAULT_SALT_LENGTH;
		}
	}

	/**
	 * @return the state
	 */
	public int getState() {
		return state;
	}

	/**
	 * Set the current state and update GUI
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
	
	/**
	 * Refresh the ListView containing name of secrets
	 */
	protected void refreshSecretList() {
		ListView list = (ListView)findViewById(R.id.listSecrets);
		// Clear the list
		list.setAdapter(null);
		
		String[] columns = new String[] {SecretStorage.COL_NAME};
		int[] to = new int[] {R.id.textListItem};
		Cursor cursor = database.rawQuery("select rowid _id, "+ SecretStorage.COL_NAME + " from " + SecretStorage.DATABASE_NAME,null);
		
		list.setAdapter(new SimpleCursorAdapter(this, R.layout.listview_content, cursor, columns, to));
	}

	/* (non-Javadoc)
	 * @see android OnClickListener onClick()
	 */
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

	/**
	 * Retrieve the secret from the database,
	 * and decrypt it 
	 * and show it in the GUI
	 * @param pw password
	 * @param name name of the secret
	 */
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
	
					byte[] salt = values.getAsByteArray(SecretStorage.COL_SALT);
					int iterationCount = values.getAsInteger(SecretStorage.COL_ITERATION_COUNT);
					byte[] iv = values.getAsByteArray(SecretStorage.COL_IV);
					byte[] ciphertext = values.getAsByteArray(SecretStorage.COL_VALUE);
					
					// Decrypt the secret
					byte[] plaintext = crypto.Decrypt(pw.toCharArray(), salt, iterationCount, iv, ciphertext);
					
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

	/**
	 * Encrypt the secret and store it in the database
	 * @param pw password
	 * @param name name of secret
	 * @param plaintext plaintext secret
	 */
	private void storeSecret(final String pw, final String name, final String plaintext) {
		// This can take quite a while, we should not run it on the UI thread
		new Thread(new Runnable() {

			public void run() {
				
				try {
					int iterationCount = iteration_count;
					int saltLength = salt_length;
					
		        	byte[] salt = new byte[saltLength];

		        	SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(context);
					long monotonic = preferences.getLong("monotonic", 1);
					monotonic++;
					SharedPreferences.Editor edit = preferences.edit();
					edit.putLong("monotonic", monotonic);
					edit.apply();
	
					byte[] iv = new byte[CryptoInterface.IV_LENGTH_BYTES];
						
					// Encrypt the secret
					byte[] ciphertext = crypto.Encrypt(pw.toCharArray(), plaintext.getBytes("UTF-8"), salt, saltLength, iterationCount, monotonic, iv);
					
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

	/* (non-Javadoc)
	 * @see android OnItemClickListener onItemClick()
	 */
	public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
		
		Cursor cursor = (Cursor) parent.getItemAtPosition(position);
		String name = cursor.getString(cursor.getColumnIndex(SecretStorage.COL_NAME));
		TextView tv = (TextView)findViewById(R.id.name);
		tv.setText(name);
		
		setState(STATE_ENTER_PASSWORD);
	}

	/* (non-Javadoc)
	 * @see android OnItemLongClickListener onItemLongClick()
	 */
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

	/* (non-Javadoc)
	 * @see android.app.Activity#onBackPressed()
	 */
	@Override
	public void onBackPressed() {
		if (state == STATE_LIST_SECRETS)
		{
			super.onBackPressed();
		}
		else
		{
			setState(STATE_LIST_SECRETS);
		}
	}

	/* (non-Javadoc)
	 * @see android.app.Activity#onCreateOptionsMenu(android.view.Menu)
	 */
	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
	    MenuInflater inflater = getMenuInflater();
	    inflater.inflate(R.menu.optionsmenu, menu);
	    return true;
	}

	/* (non-Javadoc)
	 * @see android.app.Activity#onOptionsItemSelected(android.view.MenuItem)
	 */
	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
	    switch (item.getItemId()) {
        case R.id.preferences:
	        {
	        	Intent i = new Intent(context, Preferences.class);
	    		startActivity(i);
	    		return true;
	        }
        case R.id.selftest:
	        {
	        	Intent i = new Intent(context, SelfTest.class);
	    		startActivity(i);
	    		return true;
	        }
        case R.id.about:
	        {
	        	Intent i = new Intent(Intent.ACTION_VIEW);
	        	i.setData(Uri.parse(ABOUT_URL));
	    		startActivity(i);
	    		return true;
	        }
        default:
            return super.onOptionsItemSelected(item);
    }	}
	
}


/*

   Copyright 2013 Mathias Olsson (mathias@kompetensum.com)

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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.ContentValues;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.os.Bundle;
import android.os.Environment;
import android.text.TextUtils;
import compat.android.util.Base64;

public class ImpExp extends Activity {

	private boolean externalStorageAvailable = false;
	private boolean externalStorageWriteable = false;
	
	private ProgressDialog progress;
	private Context context;
	private String imp;
	private String exp;
    private SQLiteDatabase database;
	
	private final int STATE_STARTED = 0;
	private final int STATE_DB_OPENED = 1;
	private final int STATE_IMPORT_OK = 2;
	private final int STATE_EXPORT_OK = 3;
	private final int STATE_DONE = 4;
	private final int STATE_ALERT_DONE = 5;
	private int state = STATE_STARTED;
	
	public static final String IMPORT = "import";
	public static final String EXPORT = "export";
	
	/* (non-Javadoc)
	 * @see android.app.Activity#onCreate(android.os.Bundle)
	 */
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		
		context = (Context)this;
		
		// Show progressbar
		progress = ProgressDialog.show(this, getString(R.string.pleasewait), getString(R.string.processing));

		Intent intent = getIntent();
		imp = intent.getStringExtra(IMPORT);
		exp = intent.getStringExtra(EXPORT);

		setState(STATE_STARTED);
		
	}
		
	private void setState(int newState) {
		state = newState;
		runOnUiThread(new Runnable() {
			public void run() {
				switch (state) {
				case STATE_STARTED:
					openDB();
					break;
				case STATE_DB_OPENED:
					doImport();
					break;
				case STATE_IMPORT_OK:
					doExport();
					break;
				case STATE_EXPORT_OK:
					done();
					break;
				case STATE_ALERT_DONE:
				case STATE_DONE: 
	        		progress.dismiss();
					finish();
					break;
				}
			}
		});
	}
		
	private void openDB() {
        // Open the database
        new Thread(new Runnable() {

			public void run() {
            	SecretStorage ss = new SecretStorage(context);
            	database = ss.getWritableDatabase();
            	
            	setState(STATE_DB_OPENED);
            }
        }).start();
	}
	
	private void doImport() {
		try {
			if (imp != null) {
				importDB(database,imp);
			}
			setState(STATE_IMPORT_OK);
		} catch (Exception e) {
			showAlert(e.getMessage());
		}
	}

	private void doExport() {
		try {
			if (exp != null) {
				exportDB(database,exp);
			}
			setState(STATE_EXPORT_OK);
		} catch (Exception e) {
			showAlert(e.getMessage());
		}
	}
	
	private void done() {
		setState(STATE_DONE);
	}

	private void showAlert(final String msg) {
		runOnUiThread(new Runnable() {
			public void run() {
				AlertDialog alert = new AlertDialog.Builder(context).create();
				alert.setCancelable(false);
				alert.setTitle(R.string.error);
				alert.setMessage(msg);
				alert.setButton(AlertDialog.BUTTON_NEUTRAL, getString(R.string.ok), new DialogInterface.OnClickListener() {
					public void onClick(DialogInterface dialog, int which) {
						dialog.dismiss();
						setState(STATE_ALERT_DONE);
					}  
				});  
				alert.show();
			}
		});
	}

	public void importDB(SQLiteDatabase database, String impexpFilename) {
		checkExternalStorage();
		if (!externalStorageAvailable) {
			throw new RuntimeException("External media is not readable");
		}
		
		File root = Environment.getExternalStorageDirectory();
		File importFile = new File(root, impexpFilename);
		try {
			FileReader fr = new FileReader(importFile);
			BufferedReader br = new BufferedReader(fr);
			
			while (true) {
				String line = br.readLine();
				if (line == null) {
					break;
				}
				
				String[] cols = line.split(";");
				if (cols.length != 5) {
					throw new RuntimeException("Invalid file format");
				}
				
				String name = cols[0];
				byte[] salt = Base64.decode(cols[1], Base64.NO_WRAP);
				int iterationCount = Integer.parseInt(cols[2]);
				byte[] iv = Base64.decode(cols[3], Base64.NO_WRAP);
				byte[] value = Base64.decode(cols[4], Base64.NO_WRAP);
				
				ContentValues values = new ContentValues();
				values.put(SecretStorage.COL_NAME,name);
				values.put(SecretStorage.COL_SALT,salt);
				values.put(SecretStorage.COL_ITERATION_COUNT,iterationCount);
				values.put(SecretStorage.COL_IV,iv);
				values.put(SecretStorage.COL_VALUE,value);

				database.insert(SecretStorage.DATABASE_NAME, null, values);
			}
			
			br.close();
			fr.close();
		} catch (IOException e) {
			throw new RuntimeException("Failed to read from\n" + impexpFilename, e);
		}
		
		
	}
	
	public void exportDB(SQLiteDatabase database, String impexpFilename) {
		checkExternalStorage();
		if (!externalStorageWriteable) {
			throw new RuntimeException("External media is not writable");
		}

		File root = Environment.getExternalStorageDirectory();
		File exportFile = new File(root, impexpFilename);
		try {
			FileWriter fw = new FileWriter(exportFile);
			
			String[] columns = new String[] {
				SecretStorage.COL_NAME, SecretStorage.COL_SALT, SecretStorage.COL_ITERATION_COUNT, SecretStorage.COL_IV, SecretStorage.COL_VALUE
			};
			
			
			Cursor cursor = database.query(SecretStorage.TABLE_NAME, columns, null, null, null, null, null);
			if (cursor.moveToFirst()) {
				do {
					String name = cursor.getString(cursor.getColumnIndex(SecretStorage.COL_NAME));
					byte[] salt = cursor.getBlob(cursor.getColumnIndex(SecretStorage.COL_SALT));
					int iterationCount = cursor.getInt(cursor.getColumnIndex(SecretStorage.COL_ITERATION_COUNT));
					byte[] iv = cursor.getBlob(cursor.getColumnIndex(SecretStorage.COL_IV));
					byte[] value = cursor.getBlob(cursor.getColumnIndex(SecretStorage.COL_VALUE));
					
					String cols[] = new String[5];
					cols[0] = name;
					cols[1] = Base64.encodeToString(salt,Base64.NO_WRAP);
					cols[2] = String.format("%d", iterationCount);
					cols[3] = Base64.encodeToString(iv,Base64.NO_WRAP);
					cols[4] = Base64.encodeToString(value,Base64.NO_WRAP);
					
					String data = TextUtils.join(";", cols);
					fw.write(data);
					fw.write("\n");
					
				} while(cursor.moveToNext());
				
			} else {
				// No data...
			}
			
			fw.close();
			
		} catch (IOException e) {
			throw new RuntimeException("Failed to write to\n" + impexpFilename, e);
		}
		
	}

	void checkExternalStorage() {
		String state = Environment.getExternalStorageState();

		if (Environment.MEDIA_MOUNTED.equals(state)) {
		    // We can read and write the media
		    externalStorageAvailable = externalStorageWriteable = true;
		} else if (Environment.MEDIA_MOUNTED_READ_ONLY.equals(state)) {
		    // We can only read the media
		    externalStorageAvailable = true;
		    externalStorageWriteable = false;
		} else {
		    // Something else is wrong. It may be one of many other states, but all we need
		    //  to know is we can neither read nor write
		    externalStorageAvailable = externalStorageWriteable = false;
		}	
		
	}
}

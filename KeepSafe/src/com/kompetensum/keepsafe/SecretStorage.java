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

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

public class SecretStorage extends SQLiteOpenHelper {
    
	private static final String DATABASE_NAME = "secrets";	
	private static final int DATABASE_VERSION = 1;

	SecretStorage(Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
    }	
	/* (non-Javadoc)
	 * @see android.database.sqlite.SQLiteOpenHelper#onCreate(android.database.sqlite.SQLiteDatabase)
	 */
	@Override
	public void onCreate(SQLiteDatabase database) {
		// Table to hold passwords, if empty, have the user enter a password
		// TODO perhaps add a field for algorithm?
		final String createpasswordtable = "CREATE TABLE password (salt TEXT, iterationcount TEXT, value TEXT);";
		database.execSQL(createpasswordtable);
		// Table to hold secrets 
		// TODO perhaps add a field for algorithm?
		final String createsecrettable = "CREATE TABLE secret (name TEXT, salt TEXT, iterationcount TEXT, iv TEXT, value TEXT);";
		database.execSQL(createsecrettable);

	}

	/* (non-Javadoc)
	 * @see android.database.sqlite.SQLiteOpenHelper#onUpgrade(android.database.sqlite.SQLiteDatabase, int, int)
	 */
	@Override
	public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
		// TODO Auto-generated method stub

	}

}

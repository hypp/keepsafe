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
    
	public static final String DATABASE_NAME = "secret";
	public static final String TABLE_NAME = "secret";
	public static final String COL_NAME = "name";
	public static final String COL_SALT = "salt";
	public static final String COL_ITERATION_COUNT = "iterationcount";
	public static final String COL_IV = "iv";
	public static final String COL_VALUE = "value";
	
	private static final int DATABASE_VERSION = 1;

	SecretStorage(Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
    }	
	/* (non-Javadoc)
	 * @see android.database.sqlite.SQLiteOpenHelper#onCreate(android.database.sqlite.SQLiteDatabase)
	 */
	@Override
	public void onCreate(SQLiteDatabase database) {
		// Table to hold secrets 
		// TODO perhaps add a field for algorithm?
		final String createsecrettable = "CREATE TABLE " + TABLE_NAME + " (" + COL_NAME + " TEXT, " + COL_SALT + " TEXT, " + COL_ITERATION_COUNT + " TEXT, " + COL_IV + " TEXT, " + COL_VALUE + " TEXT);";
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

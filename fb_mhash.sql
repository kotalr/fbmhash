/*
 *    Copyright (C) 2006 Richard Kotal
 *
 *    This library is free software; you can redistribute it and/or modify it 
 *    under the terms of the GNU Library General Public License as published 
 *    by the Free Software Foundation; either version 2 of the License, or 
 *    (at your option) any later version.
 *
 *    This library is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *    Library General Public License for more details.
 *
 *    You should have received a copy of the GNU Library General Public
 *    License along with this library; if not, write to the
 *    Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 *    Boston, MA 02111-1307, USA.
 */  
  


/* STRING FUNCTIONS */

DECLARE EXTERNAL FUNCTION mhash_keygen
	CSTRING(6), CSTRING(25), CSTRING(256), CSTRING(25), CSTRING(25), INTEGER, CSTRING(128), SMALLINT
	RETURNS CSTRING(1024) FREE_IT
	ENTRY_POINT 'fb_mhash_keygen' MODULE_NAME 'fb_mhash';



DECLARE EXTERNAL FUNCTION mhash_hash
	CSTRING(6), CSTRING(25), CSTRING(1024)
	RETURNS CSTRING(512) FREE_IT
	ENTRY_POINT 'fb_mhash_hash' MODULE_NAME 'fb_mhash';



DECLARE EXTERNAL FUNCTION mhash_hmac
	CSTRING(6), CSTRING(25), CSTRING(1024), CSTRING(512)
	RETURNS CSTRING(512) FREE_IT
	ENTRY_POINT 'fb_mhash_hmac' MODULE_NAME 'fb_mhash';


/* BLOB FUNCTIONS */


DECLARE EXTERNAL FUNCTION mhash_hash_blob
	CSTRING(6), CSTRING(25), BLOB
	RETURNS CSTRING(512) FREE_IT
	ENTRY_POINT 'fb_mhash_hash_blob' MODULE_NAME 'fb_mhash';


DECLARE EXTERNAL FUNCTION mhash_hmac_blob
	CSTRING(6), CSTRING(25), BLOB,CSTRING(512)
	RETURNS CSTRING(512) FREE_IT
	ENTRY_POINT 'fb_mhash_hmac_blob' MODULE_NAME 'fb_mhash';





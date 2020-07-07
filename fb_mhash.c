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
#include "config.h"
#include "inc.utils.c"
#include "inc.keygen.c"
#include "inc.uuencode.c"
#include "inc.hash.c"
#include "inc.hmac.c"


char * WIN32DLL_DEFINE
fb_mhash_keygen (ARG (char *, outtype), ARG (char *, algoname),
		 ARG (char *, pass), ARG (char *, algo1), ARG (char *, algo2),
		 ARG (unsigned long *, keysize), ARG (char *, salt),
		 ARG (int *, repeated))
ARGLIST (char *outtype)		// type of key output  : hexadecimal - hex, binary - bin, base64 (uuencode) - base64 
ARGLIST (char *algoname)	// name of algorithm for key generation 
ARGLIST (char *pass)		// password 
ARGLIST (char *algo1)		// name of first hash alogorithm 
ARGLIST (char *algo2)		// name of secomd hash alogorithm 
ARGLIST (unsigned long *keysize)	// size of generated key 
ARGLIST (char *salt)		// salt for keygen algorithm 
ARGLIST (int *repeated)		// number of repeated hash calculation 
{
  int bin = 0;
  char *out = NULL;


  if (outtype != NULL
      && (strcasecmp (outtype, "bin") == 0
	  || strcasecmp (outtype, "raw") == 0))
    bin = 1;
  if (bin == 0 && outtype != NULL && strcasecmp (outtype, "base64") == 0)
    bin = 2;
  if (algo1 != NULL && strcmp (algo1, "") == 0)
    algo1 = NULL;
  if (algo2 != NULL && strcmp (algo2, "") == 0)
    algo2 = NULL;
  if (salt != NULL && strcmp (salt, "") == 0)
    salt = NULL;
  out = fb_mhash_KeygenCreate (bin, algoname, pass, *keysize, salt,
			       *repeated, algo1, algo2);
  if (out == NULL)
    out =  fb_mhash_GetOutStr ("");
  return out;
}


char * WIN32DLL_DEFINE
fb_mhash_hash (ARG (char *, outtype), ARG (char *, algoname),
	       ARG (char *, txt))
ARGLIST (char *outtype)		// type of key output  : hexadecimal - hex, binary - bin, base64 (uuencode) - base64 
ARGLIST (char *algoname)	// name of algorithm for hash 
ARGLIST (char *txt)		// text for hash 
{
  int bin = 0;
  char *out = NULL;

    if (outtype != NULL) {
	if ((strcasecmp (outtype, "bin") == 0  || strcasecmp (outtype, "raw") == 0)) {
	    bin = 1;
	} else if (strcasecmp (outtype, "base64") == 0) {
	    bin = 2;
	}
    }


  out = fb_mhash_GenHash (bin, algoname, txt);
  if (out == NULL) out =  fb_mhash_GetOutStr ("");
  return out;
}


char * WIN32DLL_DEFINE
fb_mhash_hash_blob (ARG (char *, outtype), ARG (char *, algoname),
		    ARG (BLOBCALLBACK, txt))
ARGLIST (char *outtype)		// type of key output  : hexadecimal - hex, binary - bin, base64 (uuencode) - base64 
ARGLIST (char *algoname)	// name of algorithm for hash 
ARGLIST (BLOBCALLBACK txt)	// text for hash 
{
  int bin = 0;
  char *out = NULL;


  if (outtype != NULL
      && (strcasecmp (outtype, "bin") == 0
	  || strcasecmp (outtype, "raw") == 0))
    bin = 1;
  if (bin == 0 && outtype != NULL && strcasecmp (outtype, "base64") == 0)
    bin = 2;
  out = fb_mhash_GenHashBlob (bin, algoname, txt);
  if (out == NULL)
    out =  fb_mhash_GetOutStr ("");
  return out;
}


char * WIN32DLL_DEFINE
fb_mhash_hmac (ARG (char *, outtype), ARG (char *, algoname),
	       ARG (char *, txt), ARG (char *, password))
ARGLIST (char *outtype)		// type of key output  : hexadecimal - hex, binary - bin, base64 (uuencode) - base64 
ARGLIST (char *algoname)	// name of algorithm for hash 
ARGLIST (char *txt)		// text for hash 
ARGLIST (char *password)	// password for hmac generation
{
  int bin = 0;
  char *out = NULL;


  if (outtype != NULL
      && (strcasecmp (outtype, "bin") == 0
	  || strcasecmp (outtype, "raw") == 0))
    bin = 1;
  if (bin == 0 && outtype != NULL && strcasecmp (outtype, "base64") == 0)
    bin = 2;
  out = fb_mhash_GenHmac (bin, algoname, txt, password);
  if (out == NULL)
    out =  fb_mhash_GetOutStr ("");
  return out;
}

char * WIN32DLL_DEFINE
fb_mhash_hmac_blob (ARG (char *, outtype), ARG (char *, algoname),
		    ARG (BLOBCALLBACK, txt), ARG (char *, password))
ARGLIST (char *outtype)		// type of key output  : hexadecimal - hex, binary - bin, base64 (uuencode) - base64 
ARGLIST (char *algoname)	// name of algorithm for hash 
ARGLIST (char BLOBCALLBACK)	// text for hash 
ARGLIST (char *password)	// password for hmac generation
{
  int bin = 0;
  char *out = NULL;


  if (outtype != NULL
      && (strcasecmp (outtype, "bin") == 0
	  || strcasecmp (outtype, "raw") == 0))
    bin = 1;
  if (bin == 0 && outtype != NULL && strcasecmp (outtype, "base64") == 0)
    bin = 2;
  out = fb_mhash_GenHmacBlob (bin, algoname, txt, password);
  if (out == NULL)
    out =  fb_mhash_GetOutStr ("");
  return out;
}

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
  
#define _GNU_SOURCE
#include <stdio.h>
#include <mhash.h>
#include "ibase.h"
#include "ib_util.h"
#define args		args
#define ARG(type, arg)		type arg
#define ARGLIST(arg)
#define ERREXIT(status, rc)	{isc_print_status(status); return rc;}

#ifdef WIN32
# define WIN32DLL_DEFINE __declspec( dllexport)
#else
# define WIN32DLL_DEFINE
#endif



/* CONSTANTS */
#define MAX_KEYGEN_HASH_ALGO 2
#define STR_HASH "hash"
#define STR_HMAC "hmac"
/* STATIC FUNCTIONS */
static char *fb_mhash_GenHash (int bin, char *algoname, char *txt);
static char *fb_mhash_GenHashBlob (int bin, char *algoname, BLOBCALLBACK txt);
static MHASH fb_mhash_HashCreate (char *name);
static char *fb_mhash_EndHash (MHASH td, char *type);
static char *fb_mhash_DigestPrintFromHash (MHASH td, int bin, char *type);

static char *fb_mhash_GenHmac (int bin, char *algoname, char *txt,
			       char *password);
static char *fb_mhash_GenHmacBlob (int bin, char *algoname, BLOBCALLBACK txt,
				   char *password);

static MHASH fb_mhash_HmacCreate (char *name, char *keyword, int key_size);

static char *fb_mhash_KeygenCreate (int bin, char *algoname, char *pass,
				    mutils_word32 keysize, char *salt,
				    int count, char *algo1, char *algo2);

static int fb_mhash_GetKeygenId (char *name);
static int fb_mhash_GetHashId (char *name);
static char *fb_mhash_GetOutStr (char *err);
static int Ns_HtuuEncode (unsigned char *input, unsigned int len,
			  char *output);
static int Ns_HtuuDecode (char *input, unsigned char *output, int outputlen);

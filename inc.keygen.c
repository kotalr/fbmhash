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

 
static char *
fb_mhash_KeygenCreate (int bin, char *algoname, char *pass,
		       mutils_word32 keysize, char *salt, int count,
		       char *algo1, char *algo2)
{
  int hashid = -1;
  mutils_word32 passlen = 0;
  mutils_word32 tmp = 0;
  mutils_word32 salt_size = 0;
  mutils_word32 salt_size_str = 0;
  mutils_word8 *key = NULL;
  mutils_word8 *salt2 = NULL;
  KEYGEN data;
  int i = 0;
  char *out = NULL;


  hashid = fb_mhash_GetKeygenId (algoname);
  if (hashid == -1)
    return out;
  if (pass == NULL)
    return out;

  passlen = strlen (pass);
  if ((tmp = mhash_get_keygen_max_key_size (hashid)) != 0)
    keysize = tmp;
  key = (mutils_word8 *) mutils_malloc (keysize);

  if (salt != NULL)
    {
      if ((tmp = mhash_get_keygen_salt_size (hashid)) != 0)
	salt_size = tmp;
      salt_size_str = strlen (salt);
      if (salt_size == 0)
	salt_size = salt_size_str;
      salt2 = (mutils_word8 *) mutils_malloc (salt_size + 1);
      memset (salt2, '\0' ,salt_size + 1);
      memcpy (salt2, salt,
	      (salt_size > salt_size_str) ? salt_size_str : salt_size);
    }
  data.count = count;
  data.salt = salt2;
  data.salt_size = salt_size;

  if (algo1 != NULL)
    {
      tmp = fb_mhash_GetHashId (algo1);
      if (tmp != -1)
	data.hash_algorithm[0] = tmp;
    }
  if (algo2 != NULL)
    {
      tmp = fb_mhash_GetHashId (algo2);
      if (tmp != -1)
	data.hash_algorithm[1] = tmp;
    }
  mhash_keygen_ext (hashid, data, key, keysize, pass, passlen);

  switch (bin)
    {
    case 2:
      {
//	int len = (1 + (keysize * 4) / 3);
	int len = (1 + (keysize * 2) );
	unsigned char b64[len];
	memset (b64, '\0', len);
	Ns_HtuuEncode ((unsigned char *) key, keysize, b64);
	out = fb_mhash_GetOutStr (b64);
	break;
      }
    case 1:
      {
	out = ib_util_malloc (keysize + 1);
	memset (out, '\0', keysize + 1);
	memcpy (out, key, keysize);
	break;
      }
    default:
      {
	char *buf = NULL;
	buf = mutils_asciify (key, keysize);
	if (buf != NULL)
	  {
	    out = fb_mhash_GetOutStr (buf);
	    mutils_free (buf);
	  }
	break;
      }
    }
  mutils_free (key);
  if (salt2 != NULL)
    mutils_free (salt2);

  return out;
}

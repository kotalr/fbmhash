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
static MHASH
fb_mhash_HmacCreate (char *name, char *keyword, int key_size)
{
  int hashid = -1;
  MHASH td = MHASH_FAILED;

  hashid = fb_mhash_GetHashId (name);
  if (hashid == -1)
    {
      return td;
    }

  if (mhash_get_hash_pblock (hashid) == 0)
    {
      return td;
    }
  td =
    mhash_hmac_init (hashid, keyword, key_size,
		     mhash_get_hash_pblock (hashid));

  return td;
}



static char *
fb_mhash_GenHmac (int bin, char *algoname, char *txt, char *password)
{
  MHASH td = MHASH_FAILED;
  char *out = NULL;
  int len = 0;


  if (txt == NULL)
    return out;
  if (password == NULL)
    return out;
  td = fb_mhash_HmacCreate (algoname, password, strlen (password));
  if (td == MHASH_FAILED)
    return out;
  len = strlen (txt);
  mhash (td, txt, len);
  out = fb_mhash_DigestPrintFromHash (td, bin, STR_HMAC);

  return out;
}

static char *
fb_mhash_GenHmacBlob (int bin, char *algoname, BLOBCALLBACK txt,
		      char *password)
{
  MHASH td = MHASH_FAILED;
  char *out = NULL;
  char *buf = NULL;
  ISC_USHORT actual_length = 0;
  ISC_LONG max_length = 0;


  if (!txt->blob_handle)
    return out;
  if (password == NULL)
    return out;
  td = fb_mhash_HmacCreate (algoname, password, strlen (password));
  if (td == MHASH_FAILED)
    return out;
  max_length = txt->blob_max_segment + 1;
  buf = malloc (max_length);
  while ((*txt->blob_get_segment) (txt->blob_handle, buf, max_length,
				   &actual_length))
    mhash (td, buf, actual_length);
  if (buf != NULL)
    free (buf);
  out = fb_mhash_DigestPrintFromHash (td, bin, STR_HMAC);


  return out;
}

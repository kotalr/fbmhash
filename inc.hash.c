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
fb_mhash_EndHash (MHASH td, char *type)
{
  char *buf = NULL;


  if (type == NULL || td == MHASH_FAILED || td == NULL)
    return buf;
  if (strcmp (type, STR_HASH) == 0)
    buf = mhash_end (td);
  else if (strcmp (type, STR_HMAC) == 0)
    buf = mhash_hmac_end (td);

  return buf;
}


static char *
fb_mhash_DigestPrintFromHash (MHASH td, int bin, char *type)
{
  char *buf = NULL;
  int hashid = -1;
  int len = 0;
  char *out = NULL;


  if (type == NULL || td == MHASH_FAILED || td == NULL)
    return out;
  hashid = mhash_get_mhash_algo (td);

  buf = fb_mhash_EndHash (td, type);
  if (buf == NULL || hashid == -1)
    {
      if (buf != NULL)
	mutils_free (buf);
      return out;
    }
  len = mhash_get_block_size (hashid);

  switch (bin)
    {
    case 2:
      {
//	int size = (1 + (len * 4) / 3);
	int size = (1 + (len * 2) );
	unsigned char b64[size];
	memset (b64,'\0', size);
	Ns_HtuuEncode (buf, len, b64);
	out = fb_mhash_GetOutStr (b64);
	break;
      }
    case 1:
      {
	out = ib_util_malloc (len + 1);
	memset (out,'\0', len + 1);
	memcpy (out, buf, len);
	break;
      }
    default:
      {
	char *tmp = NULL;
	tmp = mutils_asciify (buf, len);
	if (tmp != NULL)
	  {
	    out = fb_mhash_GetOutStr (tmp);
	    mutils_free (tmp);
	  }
	break;
      }
    }
  if (buf != NULL)
    mutils_free (buf);

  return out;
}





static MHASH
fb_mhash_HashCreate (char *name)
{
  int hashid = -1;
  MHASH td = MHASH_FAILED;

  hashid = fb_mhash_GetHashId (name);
  if (hashid == -1)
    {
      return td;
    }
  td = mhash_init (hashid);
  return td;
}






static char *
fb_mhash_GenHash (int bin, char *algoname, char *txt)
{
  MHASH td = MHASH_FAILED;
  char *out = NULL;
  int len = 0;


  if (txt == NULL)
    return out;
  td = fb_mhash_HashCreate (algoname);
  if (td == MHASH_FAILED)
    return out;
  len = strlen (txt);
  mhash (td, txt, len);
  out = fb_mhash_DigestPrintFromHash (td, bin, STR_HASH);


  return out;
}

static char *
fb_mhash_GenHashBlob (int bin, char *algoname, BLOBCALLBACK txt)
{
  MHASH td = MHASH_FAILED;
  char *out = NULL;
  ISC_USHORT actual_length = 0;
  ISC_LONG max_length = 0;
  char *buf = NULL;


  if (!txt->blob_handle)
    return out;
  td = fb_mhash_HashCreate (algoname);
  if (td == MHASH_FAILED)
    return out;
  max_length = txt->blob_max_segment + 1;
  buf = malloc (max_length);
  while ((*txt->blob_get_segment) (txt->blob_handle, buf, max_length,
				   &actual_length))
    mhash (td, buf, actual_length);
  if (buf != NULL)
    free (buf);
  out = fb_mhash_DigestPrintFromHash (td, bin, STR_HASH);

  return out;
}

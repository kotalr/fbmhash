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
 
static int
fb_mhash_GetHashId (char *name)
{
  int id = -1;
  size_t len = 0;
  int i = 0;
  __const mutils_word8 *hash = NULL;

  if (name == NULL)
    return id;
  len = mhash_count ();
  for (i = 0; i <= len; i++)
    {
      hash = mhash_get_hash_name_static (i);
      if (hash == NULL)
	continue;
      if (strcasecmp (hash, name) == 0)
	{
	  id = i;
	  break;
	}
    }

  return id;
}


static int
fb_mhash_GetKeygenId (char *name)
{
  int id = -1;
  size_t len = 0;
  int i = 0;
  __const mutils_word8 *algo = NULL;

  if (name == NULL)
    return id;
  len = mhash_keygen_count ();
  for (i = 0; i <= len && id != i; i++)
    {

      algo = mhash_get_keygen_name_static (i);
      if (algo == NULL)
	continue;
      if (strcasecmp (algo, name) == 0)
	{
	  id = i;
	  break;
	}
    }
  return id;
}

static char *
fb_mhash_GetOutStr (char *err)
{


  int len = 0;
  char *out = NULL;

  if (err == NULL)
    return out;
  len = strlen (err) + 1;
  out = (char *) ib_util_malloc (sizeof(char)*len);
  memset (out, '\0' , len);
  strcpy (out, err);
  return out;
  
}

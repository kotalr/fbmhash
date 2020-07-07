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

create table FB_MHASH_TEST (
    MYCOL VARCHAR(25),
    EXPKEY VARCHAR(256),
    EXPHASH VARCHAR(256),
    EXPHMAC VARCHAR(256)
);

insert into FB_MHASH_TEST values ('Hello world','a1be1548560896f5a655c3577769d7cfced5925b','7b502c3a1f48c8609ae212cdfb639dee39673f5e','BSD+81FW3Y22Hxl+LT8oXdm1UGo=');

select expkey, mhash_keygen('hex','S2K_SALTED',mycol,'SHA1','',20,'salt',0) from FB_MHASH_TEST;
select exphash, mhash_hash('hex','SHA1','Hello world') from FB_MHASH_TEST;
select exphmac, mhash_hmac('base64','sha1','Hello world','foobar') from FB_MHASH_TEST;

commit;

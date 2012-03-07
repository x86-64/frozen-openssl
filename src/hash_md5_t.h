#ifndef DATA_HASHMD5T_H
#define DATA_HASHMD5T_H

/** @ingroup data
 *  @addtogroup hash_md5_t hash_md5_t
 */
/** @ingroup hash_md5_t
 *  @page timestamp_t_overview Overview
 *  
 *  This data used to calculate md5 hash using OpenSSL library.
 */

#include <openssl/evp.h>

#define HASHMD5T_NAME  "hash_md5_t"
#define TYPE_HASHMD5T  datatype_t_getid_byname(HASHMD5T_NAME, NULL)

#define DATA_HASHMD5T(value) { TYPE_HASHMD5T, (hash_md5_t []){ value } } 
#define DATA_PTR_HASHMD5T(value) { TYPE_HASHMD5T, value } 
#define DEREF_TYPE_HASHMD5T(_data) (hash_md5_t *)((_data)->ptr) 
#define REF_TYPE_HASHMD5T(_dt) _dt 
#define HAVEBUFF_TYPE_HASHMD5T 0

#define MD5_HASH_SIZE 16

typedef struct hash_md5_t {
        data_t                *data;
	data_t                 freeit;
	
	unsigned char          md_bin[EVP_MAX_MD_SIZE];
	char                   md_str[MD5_HASH_SIZE * 2 + 1];
} hash_md5_t;

#endif

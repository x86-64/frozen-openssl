#include <libfrozen.h>
#include <hash_md5_t.h>

#include <errors_list.c>

#include <enum/format/format_t.h>
#include <core/hash/hash_t.h>
#include <core/void/void_t.h>
#include <numeric/uint/uint_t.h>
#include <io/io/io_t.h>

const EVP_MD                  *openssl_hash_md5_md;

hash_md5_t *        hash_md5_t_alloc(data_t *data){ // {{{
	hash_md5_t                 *fdata;
	
	if( (fdata = malloc(sizeof(hash_md5_t))) == NULL )
		return NULL;
	
	fdata->data       = data;
	data_set_void(&fdata->freeit);
	return fdata;
} // }}}
void                hash_md5_t_destroy(hash_md5_t *hash_md5){ // {{{
	data_free(&hash_md5->freeit);
} // }}}

ssize_t             hash_md5_t_update_iot(data_t *data, EVP_MD_CTX *mdctx, fastcall_write *fargs){ // {{{
	if(fargs->header.action != ACTION_WRITE)
		return -EFAULT;
	
	EVP_DigestUpdate   (mdctx, fargs->buffer, fargs->buffer_size);
	return 0;
} // }}}
ssize_t             hash_md5_t_update(hash_md5_t *fdata){ // {{{
	ssize_t                ret;
	EVP_MD_CTX             mdctx;
	uintmax_t              i; 
	unsigned int           md_len; 
	
	if(fdata->data == NULL)   // converted from packed or human data, not from plaintext
		return 0;
	
	EVP_MD_CTX_init    (&mdctx);
	EVP_DigestInit_ex  (&mdctx, openssl_hash_md5_md, NULL);
	
	data_t                 io                = DATA_IOT(&mdctx, (f_io_func)&hash_md5_t_update_iot);
	fastcall_convert_to    r_convert         = { { 4, ACTION_CONVERT_TO }, &io, FORMAT(native) };
	ret = data_query(fdata->data, &r_convert);
	
	EVP_DigestFinal_ex (&mdctx, fdata->md_bin, &md_len);
	EVP_MD_CTX_cleanup (&mdctx);
	
	for(i = 0; i < md_len; i++)
		sprintf(&fdata->md_str[i*2], "%02x", fdata->md_bin[i]);
	
	return ret;
} // }}}

static ssize_t data_hash_md5_t_handler (data_t *data, fastcall_header *fargs){ // {{{
	ssize_t                ret;
	hash_md5_t            *fdata             = (hash_md5_t *)data->ptr;
	
	if( (ret = hash_md5_t_update(fdata)) < 0)
		return ret;
	
	data_t                 d_hash            = DATA_RAW(fdata->md_str, sizeof(fdata->md_str));
	return data_query(&d_hash, fargs);
} // }}}
static ssize_t data_hash_md5_t_convert_to(data_t *src, fastcall_convert_to *fargs){ // {{{
	ssize_t                ret;
	uintmax_t              transfered        = 0;
	hash_md5_t            *fdata             = (hash_md5_t *)src->ptr;
	
	if( (ret = hash_md5_t_update(fdata)) < 0)
		return ret;
	
	switch(fargs->format){
		case FORMAT(packed):;
			fastcall_write r_packed_write = { { 5, ACTION_WRITE }, 0, &fdata->md_bin, sizeof(fdata->md_bin) };
			ret        = data_query(fargs->dest, &r_packed_write);
			transfered = r_packed_write.buffer_size;
			break;

		case FORMAT(human):;
		case FORMAT(config):;
		case FORMAT(native):;
			fastcall_write r_human_write = { { 5, ACTION_WRITE }, 0, &fdata->md_str, sizeof(fdata->md_str) };
			ret        = data_query(fargs->dest, &r_human_write);
			transfered = r_human_write.buffer_size;
			break;

		default:
			return -ENOSYS;
	};
	if(fargs->header.nargs >= 5)
		fargs->transfered = transfered;
	
	return ret;
} // }}}
static ssize_t data_hash_md5_t_convert_from(data_t *dst, fastcall_convert_from *fargs){ // {{{
	ssize_t                ret;
	hash_md5_t            *fdata;
	
	if(dst->ptr != NULL)
		return -EINVAL;
	
	switch(fargs->format){
		case FORMAT(hash):;
			hash_t                *config;
			data_t                 data;
			
			data_get(ret, TYPE_HASHT, config, fargs->src);
			if(ret != 0)
				return -EINVAL;
			
			hash_holder_consume(ret, data, config, HK(data));
			if(ret != 0)
				return -EINVAL;
			
			if( (fdata = dst->ptr = hash_md5_t_alloc(&data)) == NULL){
				data_free(&data);
				return -ENOMEM;
			}
			
			fdata->freeit = data;
			fdata->data   = &fdata->freeit;
			return 0;
			
		case FORMAT(packed):;
			if( (fdata = dst->ptr = hash_md5_t_alloc(NULL)) == NULL)
				return -ENOMEM;
			
			fastcall_read r_read = { { 5, ACTION_READ }, 0, &fdata->md_bin, MD5_HASH_SIZE };
			if( (ret = data_query(fargs->src, &r_read)) < 0)
				return ret;
			
			return 0;
			
		case FORMAT(human):;
		case FORMAT(config):;
		case FORMAT(native):;
			if( (fdata = dst->ptr = hash_md5_t_alloc(NULL)) == NULL)
				return -ENOMEM;
			
			fastcall_read r_human_read = { { 5, ACTION_READ }, 0, &fdata->md_str, MD5_HASH_SIZE * 2 };
			if( (ret = data_query(fargs->src, &r_human_read)) < 0)
				return ret;
			
			// TODO convert md_str to md_bin
			
			return 0;
			
		default:
			break;
	}
	return -ENOSYS;
} // }}}
static ssize_t data_hash_md5_t_free(data_t *data, fastcall_free *fargs){ // {{{
	hash_md5_t                  *fdata             = (hash_md5_t *)data->ptr;
	
	hash_md5_t_destroy(fdata);
	data_set_void(data);
	return 0;
} // }}}
static ssize_t data_hash_md5_t_length(data_t *data, fastcall_length *fargs){ // {{{
	switch(fargs->format){
		case FORMAT(packed):;
			fargs->length = MD5_HASH_SIZE;
			return 0;
		
		case FORMAT(human):;
		case FORMAT(config):;
		case FORMAT(native):;
			fargs->length = MD5_HASH_SIZE * 2;
			return 0;
			
		default:
			break;
		
	}
	return -ENOSYS;
} // }}}
static ssize_t data_hash_md5_t_nosys(data_t *data, fastcall_header *hargs){ // {{{
	return -ENOSYS;
} // }}}

data_proto_t hash_md5_proto = {
	.type_str               = HASHMD5T_NAME,
	.api_type               = API_HANDLERS,
	.handler_default = (f_data_func)&data_hash_md5_t_handler,
	.handlers        = {
		[ACTION_CONVERT_TO]   = (f_data_func)&data_hash_md5_t_convert_to,
		[ACTION_CONVERT_FROM] = (f_data_func)&data_hash_md5_t_convert_from,
		[ACTION_LENGTH]       = (f_data_func)&data_hash_md5_t_length,
		[ACTION_FREE]         = (f_data_func)&data_hash_md5_t_free,
		
		[ACTION_WRITE]        = (f_data_func)&data_hash_md5_t_nosys,
	}
};

int main(void){
        OpenSSL_add_all_digests();
        
	if( !(openssl_hash_md5_md = EVP_get_digestbyname("md5")) )
		return 1;
	
	errors_register((err_item *)&errs_list, &emodule);
	data_register(&hash_md5_proto);
	return 0;
}

modules_LTLIBRARIES = module_c_openssl.la
module_c_openssl_la_CFLAGS = -I@includedir@/frozen/ -I../ -DFROZEN_MODULE
module_c_openssl_la_LDFLAGS = -module -avoid-version -shared -lssl -lcrypto
module_c_openssl_la_SOURCES = main_openssl.c
headers_mydirdir=$(headersdir)/modules/hash_md5_t/
headers_mydir_HEADERS=hash_md5_t.h
EXTRA_DIST = errors_list.c

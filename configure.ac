AC_PREREQ(2.5)
AC_INIT([frozen_openssl], [1.0.0], [x86mail@gmail.com])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build])

AM_INIT_AUTOMAKE([1.11])

AC_PROG_CC
AC_PROG_CXX
AC_PROG_LIBTOOL
AC_HEADER_STDC
AC_FUNC_MALLOC

AC_CHECK_HEADERS([openssl/evp.h],[],[AC_MSG_ERROR([OpenSSL headers required])])
AC_CHECK_LIB([ssl],[SSL_library_init], [], [AC_MSG_ERROR([OpenSSL library required])])
AC_CHECK_LIB([crypto],[EVP_DigestFinal_ex], [], [AC_MSG_ERROR([OpenSSL library required])])

AC_CHECK_LIB(frozen, frozen_init, [FROZEN=1], [FROZEN=0])
AM_CONDITIONAL([HAVE_FROZEN], [test "$FROZEN" = 1])
modulesdir=${libexecdir}/frozen/
headersdir=${includedir}/frozen/
AC_SUBST(modulesdir)
AC_SUBST(headersdir)

esyscmd(./build/build_errors.pl)

AC_ARG_ENABLE(debug,  AS_HELP_STRING([--enable-debug],  [compile with debug functions]))
if test "x$enable_debug" == "xyes"; then
        AC_DEFINE([DEBUG], [1], [Defined if debug functions requested])
fi

AC_CONFIG_FILES([Makefile
		src/Makefile
])
AC_OUTPUT

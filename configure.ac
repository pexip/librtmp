AC_INIT(librtmp, 1.0, http://www.pexip.com)

dnl use pretty build output with automake >= 1.11
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])],
  [AM_DEFAULT_VERBOSITY=1
   AC_SUBST(AM_DEFAULT_VERBOSITY)])

AM_PROG_AR
AC_PROG_CC
AC_PROG_LIBTOOL
AC_PREREQ([2.59])
LT_PREREQ([2.2.6])
LT_INIT

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.10 -Wall no-define foreign])

PKG_CHECK_MODULES([libcrypto], [libcrypto >= 1.0.0])

CRYPTO_REQ="libssl,libcrypto"
AC_SUBST(CRYPTO_REQ)

CPPFLAGS+=" -DCRYPTO"

AC_CONFIG_FILES([
  Makefile
  src/Makefile
  pkgconfig/Makefile
  pkgconfig/librtmp.pc
])

AC_OUTPUT

AC_INIT(librtmp, 1.0, http://www.pexip.com)

AG_PEXBUILD_INIT

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

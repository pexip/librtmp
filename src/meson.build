librtmp_headers = [
  'amf.h',
  'log.h',
  'rtmp.h',
  'rtmp_sys.h',
]

install_headers(librtmp_headers, subdir : 'librtmp')

librtmp_sources = [
  'amf.c',
  'hashswf.c',
  'log.c',
  'parseurl.c',
  'rtmp.c'
]

rtmp_lib = library('rtmp',
  librtmp_sources,
  dependencies : [libssl_dep, libcrypto_dep, libz_dep],
  install : true,
)

pkgconfig = import('pkgconfig')
pkgconfig.generate(rtmp_lib,
  name: 'librtmp',
  description: 'RTMP implementation',
  url: 'http://rtmpdump.mplayerhq.hu',
  install_dir: join_paths(get_option('libdir'), 'pkgconfig'),
  requires: ['libssl', 'libcrypto'],
  variables: [
    'exec_prefix=${prefix}'
  ],
)

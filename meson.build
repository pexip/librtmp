project('librtmp', 'c',
    version : '1.0',
    meson_version : '>= 0.33.0')

cc = meson.get_compiler('c')

libcrypto_dep = dependency('libcrypto', version : '>= 1.0.0')
libssl_dep = dependency('libssl', version : '>= 1.0.0')
libz_dep = dependency('zlib', version : '>= 1.2.8')

add_project_arguments(['-DCRYPTO'], language: 'c')

subdir('src')
subdir('pkgconfig')

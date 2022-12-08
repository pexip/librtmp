/*  RTMPDump - Diffie-Hellmann Key Exchange
 *  Copyright (C) 2009 Andrej Stepanchuk
 *  Copyright (C) 2009-2010 Howard Chu
 *
 *  This file is part of librtmp.
 *
 *  librtmp is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as
 *  published by the Free Software Foundation; either version 2.1,
 *  or (at your option) any later version.
 *
 *  librtmp is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with librtmp see the file COPYING.  If not, write to
 *  the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 *  Boston, MA  02110-1301, USA.
 *  http://www.gnu.org/copyleft/lgpl.html
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h>

#ifdef USE_POLARSSL
#include <polarssl/dhm.h>
typedef mpi * MP_t;
#define MP_new(m)	m = malloc(sizeof(mpi)); mpi_init(m)
#define MP_set_w(mpi, w)	mpi_lset(mpi, w)
#define MP_cmp(u, v)	mpi_cmp_mpi(u, v)
#define MP_set(u, v)	mpi_copy(u, v)
#define MP_sub_w(mpi, w)	mpi_sub_int(mpi, mpi, w)
#define MP_cmp_1(mpi)	mpi_cmp_int(mpi, 1)
#define MP_modexp(r, y, q, p)	mpi_exp_mod(r, y, q, p, NULL)
#define MP_free(mpi)	mpi_free(mpi); free(mpi)
#define MP_gethex(u, hex, res)	MP_new(u); res = mpi_read_string(u, 16, hex) == 0
#define MP_bytes(u)	mpi_size(u)
#define MP_setbin(u,buf,len)	mpi_write_binary(u,buf,len)
#define MP_getbin(u,buf,len)	MP_new(u); mpi_read_binary(u,buf,len)

typedef struct MDH {
  MP_t p;
  MP_t g;
  MP_t pub_key;
  MP_t priv_key;
  long length;
  dhm_context ctx;
} MDH;

#define MDH_new()	calloc(1,sizeof(MDH))
#define MDH_free(vp)	{MDH *_dh = vp; dhm_free(&_dh->ctx); MP_free(_dh->p); MP_free(_dh->g); MP_free(_dh->pub_key); MP_free(_dh->priv_key); free(_dh);}

static int MDH_generate_key(MDH *dh)
{
  unsigned char out[2];
  MP_set(&dh->ctx.P, dh->p);
  MP_set(&dh->ctx.G, dh->g);
  dh->ctx.len = 128;
  dhm_make_public(&dh->ctx, 1024, out, 1, havege_random, &RTMP_TLS_ctx->hs);
  MP_new(dh->pub_key);
  MP_new(dh->priv_key);
  MP_set(dh->pub_key, &dh->ctx.GX);
  MP_set(dh->priv_key, &dh->ctx.X);
  return 1;
}

static int MDH_compute_key(uint8_t *secret, size_t len, MP_t pub, MDH *dh)
{
  MP_set(&dh->ctx.GY, pub);
  dhm_calc_secret(&dh->ctx, secret, &len);
  return 0;
}

#elif defined(USE_GNUTLS)
#include <gmp.h>
#include <nettle/bignum.h>
#include <gnutls/crypto.h>
typedef mpz_ptr MP_t;
#define MP_new(m)	m = malloc(sizeof(*m)); mpz_init2(m, 1)
#define MP_set_w(mpi, w)	mpz_set_ui(mpi, w)
#define MP_cmp(u, v)	mpz_cmp(u, v)
#define MP_set(u, v)	mpz_set(u, v)
#define MP_sub_w(mpi, w)	mpz_sub_ui(mpi, mpi, w)
#define MP_cmp_1(mpi)	mpz_cmp_ui(mpi, 1)
#define MP_modexp(r, y, q, p)	mpz_powm(r, y, q, p)
#define MP_free(mpi)	mpz_clear(mpi); free(mpi)
#define MP_gethex(u, hex, res)	u = malloc(sizeof(*u)); mpz_init2(u, 1); res = (mpz_set_str(u, hex, 16) == 0)
#define MP_bytes(u)	(mpz_sizeinbase(u, 2) + 7) / 8
#define MP_setbin(u,buf,len)	nettle_mpz_get_str_256(len,buf,u)
#define MP_getbin(u,buf,len)	u = malloc(sizeof(*u)); mpz_init2(u, 1); nettle_mpz_set_str_256_u(u,len,buf)

typedef struct MDH {
  MP_t p;
  MP_t g;
  MP_t pub_key;
  MP_t priv_key;
  long length;
} MDH;

#define	MDH_new()	calloc(1,sizeof(MDH))
#define MDH_free(dh)	do {MP_free(((MDH*)(dh))->p); MP_free(((MDH*)(dh))->g); MP_free(((MDH*)(dh))->pub_key); MP_free(((MDH*)(dh))->priv_key); free(dh);} while(0)

static int MDH_generate_key(MDH *dh)
{
  int num_bytes;
  uint32_t seed;
  gmp_randstate_t rs;

  num_bytes = (mpz_sizeinbase(dh->p, 2) + 7) / 8 - 1;
  if (num_bytes <= 0 || num_bytes > 18000)
    return 0;

  dh->priv_key = calloc(1, sizeof(*dh->priv_key));
  if (!dh->priv_key)
    return 0;
  mpz_init2(dh->priv_key, 1);
  gnutls_rnd(GNUTLS_RND_RANDOM, &seed, sizeof(seed));
  gmp_randinit_mt(rs);
  gmp_randseed_ui(rs, seed);
  mpz_urandomb(dh->priv_key, rs, num_bytes);
  gmp_randclear(rs);

  dh->pub_key = calloc(1, sizeof(*dh->pub_key));
  if (!dh->pub_key)
    return 0;
  mpz_init2(dh->pub_key, 1);
  if (!dh->pub_key) {
    mpz_clear(dh->priv_key);
    free(dh->priv_key);
    return 0;
  }

  mpz_powm(dh->pub_key, dh->g, dh->priv_key, dh->p);

  return 1;
}

static int MDH_compute_key(uint8_t *secret, size_t len, MP_t pub, MDH *dh)
{
  mpz_ptr k;
  int num_bytes;

  num_bytes = (mpz_sizeinbase(dh->p, 2) + 7) / 8;
  if (num_bytes <= 0 || num_bytes > 18000)
    return -1;

  k = calloc(1, sizeof(*k));
  if (!k)
    return -1;
  mpz_init2(k, 1);

  mpz_powm(k, pub, dh->priv_key, dh->p);
  nettle_mpz_get_str_256(len, secret, k);
  mpz_clear(k);
  free(k);

  /* return the length of the shared secret key like DH_compute_key */
  return len;
}

#else /* USE_OPENSSL */
#include <openssl/bn.h>
#include <openssl/dh.h>

typedef BIGNUM * MP_t;
#define MP_new(m)	m = BN_new()
#define MP_set_w(mpi, w)	BN_set_word(mpi, w)
#define MP_cmp(u, v)	BN_cmp(u, v)
#define MP_set(u, v)	BN_copy(u, v)
#define MP_sub_w(mpi, w)	BN_sub_word(mpi, w)
#define MP_cmp_1(mpi)	BN_cmp(mpi, BN_value_one())
#define MP_modexp(r, y, q, p)	do {BN_CTX *ctx = BN_CTX_new(); BN_mod_exp(r, y, q, p, ctx); BN_CTX_free(ctx);} while(0)
#define MP_free(mpi)	BN_free(mpi)
#define MP_gethex(u, hex, res)	res = BN_hex2bn(&u, hex)
#define MP_bytes(u)	BN_num_bytes(u)
#define MP_setbin(u,buf,len)	BN_bn2bin(u,buf)
#define MP_getbin(u,buf,len)	u = BN_bin2bn(buf,len,0)

typedef struct {
  MP_t p;
  MP_t g;
  MP_t pub_key;
  MP_t priv_key;
  long length;
} MDH;

#define	MDH_new()	calloc(1,sizeof(MDH))
#define MDH_free(dh)	do {MP_free(((MDH*)(dh))->p); MP_free(((MDH*)(dh))->g); MP_free(((MDH*)(dh))->pub_key); MP_free(((MDH*)(dh))->priv_key); free(dh);} while(0)

#if !defined(OPENSSL_VERSION_NUMBER) || OPENSSL_VERSION_NUMBER < 0x30000000L
static DH *DH_from_MDH(const MDH *mdh)
{
  BIGNUM *g = NULL, *p = NULL, *pub = NULL, *priv = NULL;
  DH *dh = NULL;

  if (mdh->p == NULL || mdh->g == NULL)
    goto failed;

  dh = DH_new();
  if (dh == NULL)
    goto failed;

  MP_new(g);
  if (g == NULL)
    goto failed;
  if (MP_set(g, mdh->g) == NULL)
    goto failed;

  MP_new(p);
  if (p == NULL)
    goto failed;
  if (MP_set(p, mdh->p) == NULL)
    goto failed;

  if (mdh->pub_key != NULL) {
    MP_new(pub);
    if (pub == NULL)
      goto failed;
    if (MP_set(pub, mdh->pub_key) == NULL)
      goto failed;
  }

  if (mdh->priv_key != NULL) {
    MP_new(priv);
    if (priv == NULL)
      goto failed;
    if (MP_set(priv, mdh->priv_key) == NULL)
      goto failed;
  }

#if !defined(OPENSSL_VERSION_NUMBER) || OPENSSL_VERSION_NUMBER < 0x10100000L
  dh->length = mdh->length;
  BN_free(dh->g);
  dh->g = g;
  BN_free(dh->p);
  dh->p = p;
  if (pub != NULL) {
    BN_free(dh->pub_key);
    dh->pub_key = pub;
  }
  if (priv != NULL) {
    BN_free(dh->priv_key);
    dh->priv_key = priv;
  }
#else
  DH_set_length(dh, mdh->length);
  DH_set0_pqg(dh, p, NULL, g);
  if (pub != NULL || priv != NULL)
    DH_set0_key(dh, pub, priv);
#endif

  return dh;

failed:
  MP_free(priv);
  MP_free(pub);
  MP_free(p);
  MP_free(g);
  DH_free(dh);

  return NULL;
}

static int MDH_generate_key(MDH *mdh)
{
  const BIGNUM *pubkey = NULL, *privkey = NULL;
  DH *dh = NULL;
  int res;

  dh = DH_from_MDH(mdh);
  if (dh == NULL)
    goto failed;

  res = DH_generate_key(dh);
  if (res != 1)
    goto failed;

#if !defined(OPENSSL_VERSION_NUMBER) || OPENSSL_VERSION_NUMBER < 0x10100000L
  pubkey = dh->pub_key;
  privkey = dh->priv_key;
#else
  DH_get0_key(dh, &pubkey, &privkey);
#endif

  if (pubkey != NULL) {
    MP_new(mdh->pub_key);
    if (mdh->pub_key == NULL)
      goto failed;
    if (MP_set(mdh->pub_key, pubkey) == NULL)
      goto failed;
  }

  if (privkey != NULL) {
    MP_new(mdh->priv_key);
    if (mdh->priv_key == NULL)
      goto failed;
    if (MP_set(mdh->priv_key, privkey) == NULL)
      goto failed;
  }

  DH_free(dh);

  return 1;

failed:
  MP_free(mdh->priv_key);
  mdh->priv_key = NULL;

  MP_free(mdh->pub_key);
  mdh->pub_key = NULL;

  DH_free(dh);

  return 0;
}

static int MDH_compute_key(uint8_t *secret, size_t len, MP_t pub, MDH *mdh)
{
  DH *dh = NULL;
  int res = -1;

  dh = DH_from_MDH(mdh);
  if (dh != NULL) {
    res = DH_compute_key(secret, pub, dh);
    DH_free(dh);
  }

  return res;
}
#else
# include <openssl/evp.h>
# include <openssl/params.h>
# include <openssl/param_build.h>

static EVP_PKEY *DH_from_MDH(const MDH *mdh)
{
  OSSL_PARAM_BLD *bld = NULL;
  OSSL_PARAM *params = NULL;
  EVP_PKEY_CTX *ctx = NULL;
  EVP_PKEY *dh = NULL;
  int selection = EVP_PKEY_KEY_PARAMETERS;
  int res;

  if (mdh->p == NULL || mdh->g == NULL)
    goto failed;

  bld = OSSL_PARAM_BLD_new();
  if (bld == NULL)
    goto failed;

  res = OSSL_PARAM_BLD_push_int(bld, "priv_len", (int) mdh->length);
  if (res != 1)
    goto failed;

  res = OSSL_PARAM_BLD_push_BN(bld, "g", mdh->g);
  if (res != 1)
    goto failed;

  res = OSSL_PARAM_BLD_push_BN(bld, "p", mdh->p);
  if (res != 1)
    goto failed;

  if (mdh->pub_key != NULL) {
    res = OSSL_PARAM_BLD_push_BN(bld, "pub", mdh->pub_key);
    if (res != 1)
      goto failed;
    selection = EVP_PKEY_PUBLIC_KEY;
  }

  if (mdh->priv_key != NULL) {
    if (mdh->pub_key != NULL)
      goto failed;

    res = OSSL_PARAM_BLD_push_BN(bld, "priv", mdh->priv_key);
    if (res != 1)
      goto failed;
    selection = EVP_PKEY_KEYPAIR;
  }

  params = OSSL_PARAM_BLD_to_param(bld);
  if (params == NULL)
    goto failed;

  ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
  if (ctx == NULL)
    goto failed;

  res = EVP_PKEY_fromdata_init(ctx);
  if (res != 1)
    goto failed;

  res = EVP_PKEY_fromdata(ctx, &dh, selection, params);
  if (res != 1)
    goto failed;

  EVP_PKEY_CTX_free(ctx);
  OSSL_PARAM_free(params);
  OSSL_PARAM_BLD_free(bld);

  return dh;

failed:
  EVP_PKEY_free(dh);
  EVP_PKEY_CTX_free(ctx);
  OSSL_PARAM_free(params);
  OSSL_PARAM_BLD_free(bld);

  return NULL;
}

static int MDH_generate_key(MDH *mdh)
{
  EVP_PKEY_CTX *ctx = NULL;
  EVP_PKEY *params = NULL, *dh = NULL;
  BIGNUM *pubkey = NULL, *privkey = NULL;
  int res;

  params = DH_from_MDH(mdh);
  if (params == NULL)
    goto failed;

  ctx = EVP_PKEY_CTX_new(params, NULL);
  if (ctx == NULL)
    goto failed;

  res = EVP_PKEY_keygen_init(ctx);
  if (res != 1)
    goto failed;

  res = EVP_PKEY_keygen(ctx, &dh);
  if (res != 1)
    goto failed;

  res = EVP_PKEY_get_bn_param(dh, "pub", &pubkey);
  if (res != 1)
    goto failed;

  res = EVP_PKEY_get_bn_param(dh, "priv", &privkey);
  if (res != 1)
    goto failed;

  BN_clear_free(mdh->pub_key);
  mdh->pub_key = pubkey;

  BN_clear_free(mdh->priv_key);
  mdh->priv_key = privkey;

  EVP_PKEY_free(dh);
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(params);

  return 1;

failed:
  BN_clear_free(privkey);
  BN_clear_free(pubkey);
  EVP_PKEY_free(dh);
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(params);

  return 0;
}

static int MDH_compute_key(uint8_t *secret, size_t len, MP_t pub, MDH *mdh)
{
  EVP_PKEY *dh = NULL, *peer = NULL;
  EVP_PKEY_CTX *ctx = NULL;
  int res;
  MDH pmdh;

  /* Copy parameters from our key */
  pmdh.g = mdh->g;
  pmdh.p = mdh->p;
  pmdh.pub_key = pub;
  pmdh.priv_key = NULL;
  pmdh.length = mdh->length;

  dh = DH_from_MDH(mdh);
  if (dh == NULL)
    goto failed;

  peer = DH_from_MDH(&pmdh);
  if (peer == NULL)
    goto failed;

  ctx = EVP_PKEY_CTX_new(dh, NULL);
  if (ctx == NULL)
    goto failed;

  res = EVP_PKEY_derive_init(ctx);
  if (res != 1)
    goto failed;

  res = EVP_PKEY_derive_set_peer(ctx, peer);
  if (res != 1)
    goto failed;

  res = EVP_PKEY_derive(ctx, secret, &len);
  if (res != 1)
    goto failed;

  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(peer);
  EVP_PKEY_free(dh);

  return (int) len;

failed:
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(peer);
  EVP_PKEY_free(dh);

  return -1;
}
#endif

#endif

#include "log.h"
#include "dhgroups.h"

/* RFC 2631, Section 2.1.5, http://www.ietf.org/rfc/rfc2631.txt */
static int
isValidPublicKey(MP_t y, MP_t p, MP_t q)
{
  int ret = TRUE;
  MP_t bn;
  assert(y);

  MP_new(bn);
  assert(bn);

  /* y must lie in [2,p-1] */
  MP_set_w(bn, 1);
  if (MP_cmp(y, bn) < 0)
    {
      RTMP_Log(RTMP_LOGERROR, "DH public key must be at least 2");
      ret = FALSE;
      goto failed;
    }

  /* bn = p-2 */
  MP_set(bn, p);
  MP_sub_w(bn, 1);
  if (MP_cmp(y, bn) > 0)
    {
      RTMP_Log(RTMP_LOGERROR, "DH public key must be at most p-2");
      ret = FALSE;
      goto failed;
    }

  /* Verify with Sophie-Germain prime
   *
   * This is a nice test to make sure the public key position is calculated
   * correctly. This test will fail in about 50% of the cases if applied to
   * random data.
   */
  if (q)
    {
      /* y must fulfill y^q mod p = 1 */
      MP_modexp(bn, y, q, p);

      if (MP_cmp_1(bn) != 0)
	{
	  RTMP_Log(RTMP_LOGWARNING, "DH public key does not fulfill y^q mod p = 1");
	}
    }

failed:
  MP_free(bn);
  return ret;
}

static MDH *
DHInit(int nKeyBits)
{
  size_t res;
  MDH *dh = MDH_new();

  if (!dh)
    goto failed;

  MP_new(dh->g);
  if (!dh->g)
    goto failed;

  MP_gethex(dh->p, P1024, res);	/* prime P1024, see dhgroups.h */
  if (!res)
    {
      goto failed;
    }

  MP_set_w(dh->g, 2);	/* base 2 */

  dh->length = nKeyBits;

  return dh;

failed:
  if (dh)
    MDH_free(dh);

  return 0;
}

static int
DHGenerateKey(MDH *dh)
{
  size_t res = 0;
  if (!dh)
    return 0;

  while (!res)
    {
      MP_t q1 = NULL;

      if (!MDH_generate_key(dh))
	return 0;

      MP_gethex(q1, Q1024, res);
      assert(res);

      res = isValidPublicKey(dh->pub_key, dh->p, q1);
      if (!res)
	{
	  MP_free(dh->pub_key);
	  MP_free(dh->priv_key);
	  dh->pub_key = dh->priv_key = 0;
	}

      MP_free(q1);
    }
  return 1;
}

/* fill pubkey with the public key in BIG ENDIAN order
 * 00 00 00 00 00 x1 x2 x3 .....
 */

static int
DHGetPublicKey(MDH *dh, uint8_t *pubkey, size_t nPubkeyLen)
{
  int len;
  if (!dh || !dh->pub_key)
    return 0;

  len = MP_bytes(dh->pub_key);
  if (len <= 0 || len > (int) nPubkeyLen)
    return 0;

  memset(pubkey, 0, nPubkeyLen);
  MP_setbin(dh->pub_key, pubkey + (nPubkeyLen - len), len);
  return 1;
}

#if 0	/* unused */
static int
DHGetPrivateKey(MDH *dh, uint8_t *privkey, size_t nPrivkeyLen)
{
  if (!dh || !dh->priv_key)
    return 0;

  int len = MP_bytes(dh->priv_key);
  if (len <= 0 || len > (int) nPrivkeyLen)
    return 0;

  memset(privkey, 0, nPrivkeyLen);
  MP_setbin(dh->priv_key, privkey + (nPrivkeyLen - len), len);
  return 1;
}
#endif

/* computes the shared secret key from the private MDH value and the
 * other party's public key (pubkey)
 */
static int
DHComputeSharedSecretKey(MDH *dh, uint8_t *pubkey, size_t nPubkeyLen,
			 uint8_t *secret)
{
  MP_t q1 = NULL, pubkeyBn = NULL;
  size_t len;
  int res;

  if (!dh || !secret || nPubkeyLen >= INT_MAX)
    return -1;

  MP_getbin(pubkeyBn, pubkey, nPubkeyLen);
  if (!pubkeyBn)
    return -1;

  MP_gethex(q1, Q1024, len);
  assert(len);

  if (isValidPublicKey(pubkeyBn, dh->p, q1))
    res = MDH_compute_key(secret, nPubkeyLen, pubkeyBn, dh);
  else
    res = -1;

  MP_free(q1);
  MP_free(pubkeyBn);

  return res;
}

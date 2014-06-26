/* crypto/aes/aes_test.c */
/* Written by Petr Spacek (pspacek@redhat.com).
 */
/* ====================================================================
 * Copyright (c) 2014 Red Hat.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "e_os.h"

#include <openssl/crypto.h>
#include <openssl/err.h>
#ifdef OPENSSL_NO_AES
int main(int argc, char *argv[])
{
	printf("No AES support\n");
	return(0);
}
#else
#include <openssl/aes.h>
#include <openssl/modes.h>

struct value {
	const size_t len;
	const unsigned char *val;
	};

struct test {
	const char *name;
	const struct value kek;
	const struct value iv;
	const struct value ptext;
	const struct value ctext;
	const int wrap_ret;
	const int unwrap_ret;
	};

#define VALUE(value) {(sizeof(value)-1), ((unsigned char *)value)}
#define PT_VALUE(value) .ptext = {(sizeof(value)-1), ((unsigned char *)value)}, .unwrap_ret = (sizeof(value)-1)
#define CT_VALUE(value) .ctext = {(sizeof(value)-1), ((unsigned char *)value)}, .wrap_ret = (sizeof(value)-1)

struct test tests_nopad[] =
	{
		/* Test vectors from RFC 3394 section 4. */
		{
		"RFC 3394 section 4.1: 128 bits of Key Data with a 128-bit KEK",
		VALUE("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"),
		{0, NULL},
		PT_VALUE("\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF"),
		CT_VALUE("\x1F\xA6\x8B\x0A\x81\x12\xB4\x47\xAE\xF3\x4B\xD8\xFB\x5A\x7B\x82\x9D\x3E\x86\x23\x71\xD2\xCF\xE5"),
		},
		{
		"RFC 3394 section 4.2: 128 bits of Key Data with a 192-bit KEK",
		VALUE("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17"),
		{0, NULL},
		PT_VALUE("\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF"),
		CT_VALUE("\x96\x77\x8B\x25\xAE\x6C\xA4\x35\xF9\x2B\x5B\x97\xC0\x50\xAE\xD2\x46\x8A\xB8\xA1\x7A\xD8\x4E\x5D"),
		},
		{
		"RFC 3394 section 4.3: 128 bits of Key Data with a 256-bit KEK",
		VALUE("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"),
		{0, NULL},
		PT_VALUE("\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF"),
		CT_VALUE("\x64\xE8\xC3\xF9\xCE\x0F\x5B\xA2\x63\xE9\x77\x79\x05\x81\x8A\x2A\x93\xC8\x19\x1E\x7D\x6E\x8A\xE7"),
		},
		{
		"RFC 3394 section 4.4: 192 bits of Key Data with a 192-bit KEK",
		VALUE("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17"),
		{0, NULL},
		PT_VALUE("\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00\x01\x02\x03\x04\x05\x06\x07"),
		CT_VALUE("\x03\x1D\x33\x26\x4E\x15\xD3\x32\x68\xF2\x4E\xC2\x60\x74\x3E\xDC\xE1\xC6\xC7\xDD\xEE\x72\x5A\x93\x6B\xA8\x14\x91\x5C\x67\x62\xD2"),
		},
		{
		"RFC 3394 section 4.5: 192 bits of Key Data with a 256-bit KEK",
		VALUE("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"),
		{0, NULL},
		PT_VALUE("\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00\x01\x02\x03\x04\x05\x06\x07"),
		CT_VALUE("\xA8\xF9\xBC\x16\x12\xC6\x8B\x3F\xF6\xE6\xF4\xFB\xE3\x0E\x71\xE4\x76\x9C\x8B\x80\xA3\x2C\xB8\x95\x8C\xD5\xD1\x7D\x6B\x25\x4D\xA1"),
		},
		{
		"RFC 3394 section 4.6: 256 bits of Key Data with a 256-bit KEK",
		VALUE("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"),
		{0, NULL},
		PT_VALUE("\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"),
		CT_VALUE("\x28\xC9\xF4\x04\xC4\xB8\x10\xF4\xCB\xCC\xB3\x5C\xFB\x87\xF8\x26\x3F\x57\x86\xE2\xD8\x0E\xD3\x26\xCB\xC7\xF0\xE7\x1A\x99\xF4\x3B\xFB\x98\x8B\x9B\x7A\x02\xDD\x21"),
		},
		/* Inputs invalid according to RFC 3394 section 2. */
		{
		"RFC 3394 section 2  : 0 byte input",
		VALUE("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"),
		{0, NULL},
		.ptext = VALUE(""),
		.wrap_ret = 0,
		},
		{
		"RFC 3394 section 2  : 0 byte input",
		VALUE("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"),
		{0, NULL},
		.ctext = VALUE(""),
		.unwrap_ret = 0,
		},
		{
		"RFC 3394 section 2  : 1 byte input",
		VALUE("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"),
		{0, NULL},
		.ptext = VALUE("\x66"),
		.wrap_ret = 0,
		},
		{
		"RFC 3394 section 2  : 1 byte input",
		VALUE("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"),
		{0, NULL},
		.ctext = VALUE("\x66"),
		.unwrap_ret = 0,
		},
		{
		NULL
		}
	};

void print_hex(const unsigned char *val, size_t len)
	{
	size_t i;
	for (i = 0; i < len; i++)
		{
		printf("%02x", val[i]);
		}
	}

int compare_results(int got_ret, int exp_ret, const unsigned char *got_out,
		const unsigned char *exp_out, int len,
		const char *msg_prefix, const char *name)
	{
	if (got_ret != exp_ret)
		{
		printf("error in AES %swrap test '%s': "\
			"got retval %d instead of %d\n",
			msg_prefix, name, got_ret, exp_ret);
		}
	else if (exp_out != NULL && memcmp(got_out, exp_out, len) != 0)
		{
		printf("error in AES %swrap test '%s': got\n",
			msg_prefix, name);
		print_hex(got_out, len);
		printf("\ninstead of\n");
		print_hex(exp_out, len);
		printf("\n");
		}
	else
		{
		printf("AES %2swrap test '%s' ok\n", msg_prefix, name);
		return 0;
		}
	return 1;
	}

int run_tests(struct test *tests,
		int (*wrap_f)(AES_KEY *key, const unsigned char *iv,
		unsigned char *out, const unsigned char *in,
		unsigned int inlen),
		int (*unwrap_f)(AES_KEY *key, const unsigned char *iv,
		unsigned char *out, const unsigned char *in,
		unsigned int inlen))
	{
	int ret = 0;
	int err = 0;
	struct test *t = tests;
	unsigned char outbuf[255];
	AES_KEY kek;

	while (t->name != NULL)
		{
		if (t->ptext.val != NULL)
		{
			assert(sizeof(outbuf) >= t->ctext.len);
			ret = AES_set_encrypt_key(t->kek.val, t->kek.len*8,
							&kek);
			assert(ret == 0);
			memcpy(outbuf, t->ptext.val, t->ptext.len);
			ret = wrap_f(&kek, t->iv.val, outbuf, outbuf,
					t->ptext.len);
			err += compare_results(ret, t->wrap_ret, outbuf,
						t->ctext.val, t->ctext.len,
						"", t->name);
		}

		if (t->ctext.val != NULL)
			{
			assert(sizeof(outbuf) >= t->ptext.len);
			ret = AES_set_decrypt_key(t->kek.val, t->kek.len*8,
							&kek);
			assert(ret == 0);
			memcpy(outbuf, t->ctext.val, t->ctext.len);
			ret = unwrap_f(&kek, t->iv.val, outbuf, outbuf,
					t->ctext.len);
			err += compare_results(ret, t->unwrap_ret, outbuf,
						t->ptext.val, t->ptext.len,
						"un", t->name);
			}

		t++;
		}

	return err;
	}

int main(int argc, char *argv[])
	{
	int err = 0;
	err += run_tests(tests_nopad, AES_wrap_key, AES_unwrap_key);

#ifdef OPENSSL_SYS_NETWARE
	if (err) printf("ERROR: %d\n", err);
#endif
	EXIT(err);
	return(err);
	}

#endif

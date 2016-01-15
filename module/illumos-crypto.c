#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <sys/crypto/common.h>
#include <sys/crypto/api.h>
#include <sys/crypto/impl.h>
#include <sys/crypto/sched_impl.h>
#include <sys/modhash_impl.h>
#include <sys/crypto/algs.h>

#define ZIO_CRYPT_WRAPKEY_IVLEN 13
#define WRAPPING_MAC_LEN 16
#define CTBUF_LEN(len) ((len) + ZIO_CRYPT_WRAPKEY_IVLEN + WRAPPING_MAC_LEN)

#define	SET_CRYPTO_DATA(cd, buf, len)	\
	(cd).cd_format = CRYPTO_DATA_RAW;\
	(cd).cd_offset = 0;\
	(cd).cd_length = (len);\
	(cd).cd_miscdata = NULL;\
	(cd).cd_raw.iov_base = (buf);\
	(cd).cd_raw.iov_len = (len);

#define SHA_CKSUM_SIZE 32

static int rand_seed = 0;
	
int random_get_bytes(uint8_t *ptr, size_t len){
	int i;
	
	for(i = 0; i < len; i++){
		ptr[i] = ((i + rand_seed) * 472882049) % 255;
	}
	
	rand_seed += 100;
	
	return 0;
}

static void __test_digest(uint8_t *buf, uint64_t size){
	int ret, i;
	crypto_data_t ddata, digest;
	crypto_mechanism_t mech;
	uint8_t out[32] = { 0 };

	mech.cm_type = crypto_mech2id(SUN_CKM_SHA256);
	mech.cm_param = NULL;
	mech.cm_param_len = 0;

	ddata.cd_format = CRYPTO_DATA_RAW;
	ddata.cd_offset = 0;
	ddata.cd_length = size;
	ddata.cd_raw.iov_base = (char *)buf;
	ddata.cd_raw.iov_len = size;

	digest.cd_format = CRYPTO_DATA_RAW;
	digest.cd_offset = 0;
	digest.cd_length = SHA_CKSUM_SIZE;
	digest.cd_raw.iov_base = (char *)out;
	digest.cd_raw.iov_len = SHA_CKSUM_SIZE;

	ret = crypto_digest(&mech, &ddata, &digest, NULL);
	printk(KERN_INFO "CRYPTO_DIGEST RETURNED: %d DIGEST = \n", ret);
	
	for(i = 0; i < 32; i++){
		printk(KERN_INFO "%02x", (unsigned char)out[i]);
	}
}

static void test_digest(void){
	uint8_t *str = "Hello world";
	
	printk(KERN_DEBUG "--------------- ATTEMPTING DIGEST TEST--------------");
	__test_digest(str, strlen(str));
}

static void __test_crypt(int encrypt, crypto_key_t *key, uint64_t guid, uint8_t *ct_buf){
	int ret;
	crypto_data_t pt, ct;
	uchar_t *clear_check = NULL;
	uint_t clear_check_len, ct_buf_len;
	crypto_mechanism_t mech;
	crypto_ctx_template_t ctx = NULL;
	CK_AES_CCM_PARAMS *ccmp;
	
	//setup mechanism
	mech.cm_type = crypto_mech2id(SUN_CKM_AES_CCM);
	printk(KERN_INFO "CRYPTO_MECH2ID RETURNED: %llu\n", (unsigned long long)mech.cm_type);
	
	ccmp = kmem_zalloc(sizeof (CK_AES_CCM_PARAMS), KM_SLEEP);
	ccmp->ulNonceSize = ZIO_CRYPT_WRAPKEY_IVLEN;
	ccmp->ulAuthDataSize = 0;
	ccmp->authData = NULL;
	ccmp->ulMACSize = WRAPPING_MAC_LEN;
	mech.cm_param = (char *)ccmp;
	mech.cm_param_len = sizeof(CK_AES_CCM_PARAMS);
	
	ct_buf_len = CTBUF_LEN(sizeof(guid));
	
	if(encrypt){
		random_get_bytes(ct_buf, ZIO_CRYPT_WRAPKEY_IVLEN);
		clear_check_len = sizeof(guid);
		clear_check = kmem_alloc(clear_check_len, KM_SLEEP);
		bcopy(&guid, clear_check, clear_check_len);
		
		ccmp->nonce = ct_buf;
		ccmp->ulDataSize = clear_check_len;
		SET_CRYPTO_DATA(pt, (char *)clear_check, clear_check_len);
		ct.cd_format = CRYPTO_DATA_RAW;
		ct.cd_offset = ZIO_CRYPT_WRAPKEY_IVLEN;
		ct.cd_length = ct_buf_len - ZIO_CRYPT_WRAPKEY_IVLEN;
		ct.cd_miscdata = NULL;
		ct.cd_raw.iov_base = (char *)ct_buf;
		ct.cd_raw.iov_len = ct_buf_len;
		
		crypto_create_ctx_template(&mech, key, &ctx, KM_SLEEP);
		
		//perform encryption
		ret = crypto_encrypt(&mech, &pt, key, ctx, &ct, NULL);
		printk(KERN_INFO "CRYPTO_ENCRYPT RETURNED: %d PT = %llu CT = %llu\n", ret, (unsigned long long)(*(uint64_t *)pt.cd_raw.iov_base), (unsigned long long)(*(uint64_t *)ct.cd_raw.iov_base));
	
	}else{
		clear_check_len = sizeof (guid) + ccmp->ulMACSize;
		clear_check = kmem_alloc(clear_check_len, KM_SLEEP);
		
		ccmp->nonce = ct_buf;
		ccmp->ulDataSize = clear_check_len;
		SET_CRYPTO_DATA(pt, (char *)clear_check, clear_check_len);
		ct.cd_format = CRYPTO_DATA_RAW;
		ct.cd_offset = ZIO_CRYPT_WRAPKEY_IVLEN;
		ct.cd_length = ct_buf_len - ZIO_CRYPT_WRAPKEY_IVLEN;
		ct.cd_miscdata = NULL;
		ct.cd_raw.iov_base = (char *)ct_buf;
		ct.cd_raw.iov_len = ct_buf_len;
		
		crypto_create_ctx_template(&mech, key, &ctx, KM_SLEEP);
		
		//perform decryption
		ret = crypto_decrypt(&mech, &ct, key, NULL, &pt, NULL);
		printk(KERN_INFO "CRYPTO_DECRYPT RETURNED: %d CT = %llu PT = %llu\n", ret, (unsigned long long)(*(uint64_t *)ct.cd_raw.iov_base), (unsigned long long)(*(uint64_t *)pt.cd_raw.iov_base));
	}

	//clean up
	if(ctx) crypto_destroy_ctx_template(ctx);
	if(clear_check) kmem_free(clear_check, clear_check_len);
	if(ccmp) kmem_free(ccmp, sizeof(CK_AES_CCM_PARAMS));
}

static void test_crypt(void){
	crypto_key_t key;
	size_t keydatalen = 16;
	uint64_t guid = 123456;
	uint8_t ct_buf[100];
	
	printk(KERN_DEBUG "------------- ATTEMPTING ENCRYPTION TEST------------");
	
	//setup key
	key.ck_format = CRYPTO_KEY_RAW;
	key.ck_length = keydatalen * 8;
	key.ck_data = kmem_alloc(keydatalen, KM_SLEEP);
	random_get_bytes(key.ck_data, keydatalen);
	
	//test
	__test_crypt(1, &key, guid, ct_buf);
	__test_crypt(0, &key, guid, ct_buf);
	
	//cleanup
	if(key.ck_data) kmem_free(key.ck_data, keydatalen);
}

static void __exit illumos_crypto_exit(void){
	sha2_mod_fini();
	aes_mod_fini();
	kcf_sched_destroy();
	kcf_prov_tab_destroy();
	kcf_destroy_mech_tabs();
	mod_hash_fini();
}
module_exit(illumos_crypto_exit);

/* roughly equivalent to kcf.c: _init() */
static int __init illumos_crypto_init(void){
	/* initialize the mod hash module */
	mod_hash_init();
	
	/* initialize the mechanisms tables supported out-of-the-box */
	kcf_init_mech_tabs();

	/* initialize the providers tables */
	kcf_prov_tab_init();
	
	/*
	 * Initialize scheduling structures. Note that this does NOT
	 * start any threads since it might not be safe to do so.
	 */
	kcf_sched_init();
	
	/* initialize algorithms */
	aes_mod_init();
	sha2_mod_init();
	
	//run tests
	test_crypt();
	test_digest();
	
	return 0;
}
module_init(illumos_crypto_init);

MODULE_LICENSE("CDDL");

/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <TEEencrypt_ta.h>

int random_key, root_key;

#define RSA_KEY_SIZE 1024
#define MAX_PLAIN_LEN_1024 86
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

struct rsa_session {
	TEE_OperationHandle op_handle;
	TEE_ObjectHandle key_handle;
};

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __unused **session)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	root_key = 9;

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	struct rsa_session *sess;
	sess = TEE_Malloc(sizeof(*sess), 0);
	if (!sess)
		return TEE_ERROR_OUT_OF_MEMORY;

	sess->key_handle = TEE_HANDLE_NULL;
	sess->op_handle = TEE_HANDLE_NULL;
	*session = (void *)sess;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	IMSG("Hello World!\n");

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	IMSG("Goodbye!\n");
}

// decryption text
static TEE_Result dec_value(uint32_t param_types,
	TEE_Param params[4])
{

	DMSG("Text decryption has been called");

	char* input_text = (char *)params[0].memref.buffer;
	int input_text_length = strlen(params[0].memref.buffer);

	char* input_key = (char *)params[1].memref.buffer;
	char decryptText[64] = {0,};
	memcpy(decryptText, input_text, input_text_length);
	int decryptKey = (*input_key + 26 - root_key - 'a') % 26;
	DMSG("decryptKey : %d", decryptKey);

	for(int i = 0; i < input_text_length; i++){
		if(decryptText[i]>='a' && decryptText[i] <='z'){
			decryptText[i] -= 'a';
			decryptText[i] -= decryptKey;
			decryptText[i] += 26;
			decryptText[i] = decryptText[i] % 26;
			decryptText[i] += 'a';
		}
		else if (decryptText[i] >= 'A' && decryptText[i] <= 'Z') {
			decryptText[i] -= 'A';
			decryptText[i] -= decryptKey;
			decryptText[i] += 26;
			decryptText[i] = decryptText[i] % 26;
			decryptText[i] += 'A';
		}
	}
	memcpy(input_text, decryptText, input_text_length);

	return TEE_SUCCESS;
}

// encryption text
static TEE_Result enc_value(uint32_t param_types,
	TEE_Param params[4])
{

	DMSG("Text encryption has been called");
	DMSG("Memref : %s", params[0].memref.buffer);
	char* input = (char *) params[0].memref.buffer;
	int input_length = strlen(params[0].memref.buffer);
	char encryptedText[64] = {0,};

	DMSG("input : %s", input);
	DMSG("inputLen : %d", input_length);
	memcpy(encryptedText, input, input_length);
	for(int i = 0; i < input_length; i++) {
		if(encryptedText[i] >= 'a' && encryptedText[i] <= 'z') {
			encryptedText[i] -= 'a';
			encryptedText[i] += random_key;
			encryptedText[i] = encryptedText[i] % 26;
			encryptedText[i] += 'a';
			DMSG("%c", encryptedText[i]);
		} else if(encryptedText[i] >= 'A' && encryptedText[i] <= 'Z') {
			encryptedText[i] -= 'A';
			encryptedText[i] += random_key;	
			encryptedText[i] = encryptedText[i] % 26;
			encryptedText[i] += 'A';
		}
	}
	DMSG("encryptedText : %s", encryptedText);
	memcpy(input, encryptedText, input_length);

	return TEE_SUCCESS;
}

// make randomkey
static TEE_Result randomkey_get(uint32_t param_types,
	TEE_Param params[4])
{

	DMSG("Get Random Key has been called");

	random_key = 0;
	TEE_GenerateRandom(&random_key, sizeof(random_key));
	random_key = random_key < 0 ? random_key * -1 : random_key;
	random_key = random_key % 25 + 1;

	IMSG("Random Key: %d", random_key);

	return TEE_SUCCESS;
}

// randomkey_encryption
static TEE_Result randomkey_enc(uint32_t param_types,
	TEE_Param params[4])
{

	DMSG("Random Key Encryption has been called");

	char* input = (char *)params[0].memref.buffer;
	char encryptKey[2] ={0};
	
	encryptKey[0] = 'a' + ((random_key + root_key) % 26);
	
	memcpy(input, encryptKey, 2);
	IMSG("encryptKey : %s", encryptKey);


	return TEE_SUCCESS;
}

TEE_Result prepare_rsa_operation(TEE_OperationHandle *handle, uint32_t alg, TEE_OperationMode mode, TEE_ObjectHandle key) {
	TEE_Result ret = TEE_SUCCESS;
	TEE_ObjectInfo key_info;
	ret = TEE_GetObjectInfo1(key, &key_info);
	if(ret != TEE_SUCCESS) {
		EMSG("\nTEE_GetObjectInfo: %#\n" PRIx32, ret);
		return ret;
	}
	
	ret = TEE_AllocateOperation(handle, alg, mode, key_info.keySize);
	if(ret != TEE_SUCCESS) {
		EMSG("\nFailed to alloc operation handle : 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========= Operation allocated successfully. ==========\n");
	
	ret = TEE_SetOperationKey(*handle, key);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to set key: 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========= Operation key already set. ===========\n");
	return ret;

}

TEE_Result RSA_create_key_pair(void *session) {
	TEE_Result ret;
	size_t key_size = RSA_KEY_SIZE;
	struct rsa_session *sess = (struct rsa_session *)session;

	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &sess->key_handle);
	if(ret != TEE_SUCCESS) {
		EMSG("\nFailed to alloc transient object handle: 0x%x\n", ret);
		return ret;
	}
	DMSG("\n======== Transient object allocated. ========\n");
	
	ret = TEE_GenerateKey(sess->key_handle, key_size, (TEE_Attribute *)NULL, 0);
	if (ret != TEE_SUCCESS) {
		EMSG("\nGenerate key failure: 0x%x\n", ret);
		return ret;
	}
	DMSG("\n======== Keys generated. ===========\n");
	return ret;
}

TEE_Result RSA_encrypt(void *session, uint32_t param_types, TEE_Param params[4]) {
	TEE_Result ret;
	uint32_t rsa_alg = TEE_ALG_RSAES_PKCS1_V1_5;
	struct rsa_session *sess = (struct rsa_session *)session;

	void *plain_txt = params[0].memref.buffer;
	size_t plain_len = params[0].memref.size;
	void *cipher = params[1].memref.buffer;
	size_t cipher_len = params[1].memref.size;

	DMSG("\n=========== Prepare encryption operation ============\n");
	ret = prepare_rsa_operation(&sess->op_handle, rsa_alg, TEE_MODE_ENCRYPT, sess->key_handle);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to prepare RSA operation: 0x%x\n", ret);
		goto err;
	}
	
	DMSG("\n Data to encrypt: %s\n", (char *) plain_txt);
	ret = TEE_AsymmetricEncrypt(sess->op_handle, (TEE_Attribute *)NULL, 0, plain_txt, plain_len, cipher, &cipher_len);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to encrypt the passed buffer : 0x%x\n", ret);
		goto err;
	}
	DMSG("\nEncrypted data: %s\n", (char *) cipher);
	DMSG("\n========= Encryption successfully =========\n");
	return ret;

err:
	TEE_FreeOperation(sess->op_handle);
	TEE_FreeOperation(sess->key_handle);
	return ret;
}
/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	
	(void)&sess_ctx;

	switch (cmd_id) {
	case TA_TEEencrypt_CMD_ENC_VALUE:
		return enc_value(param_types, params);
	case TA_TEEencrypt_CMD_DEC_VALUE:
		return dec_value(param_types, params);
	case TA_TEEencrypt_CMD_RANDOMKEY_GET:
		return randomkey_get(param_types, params);
	case TA_TEEencrypt_CMD_RANDOMKEY_ENC:
		return randomkey_enc(param_types, params);
	case TA_RSA_CMD_GENKEYS:
		return RSA_create_key_pair(sess_ctx);
	case TA_RSA_CMD_ENCRYPT:
		return RSA_encrypt(sess_ctx, param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

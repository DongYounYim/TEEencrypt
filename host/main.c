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

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

int main(int argc, char* argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	FILE *fp = 0;

	int len = 64;
	char text[64] = {0,};
	char encrypt_text[64] = {0,};
	char encrypt_key[2] = {0,};

	res = TEEC_InitializeContext(NULL, &ctx);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	
	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = text;
	op.params[0].tmpref.size = len;
	op.params[1].tmpref.buffer = encrypt_key;
	op.params[1].tmpref.size = 2;

	if (strcmp(argv[0], "TEEencrypt") == 0) {
		if(strcmp(argv[1], "-e") == 0) {
			//normal encryption	
			//openfile and get normalText in file
			if(fp=fopen(argv[2], "r")) {
				fgets(text, sizeof(text), fp);
				memcpy(op.params[0].tmpref.buffer, text, len);
				printf("Text : %s", op.params[0].tmpref.buffer);
				fclose(fp);
			}
			//get_RANDOM_KEY
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_GET, &op,
						&err_origin);
			
			//encrypt text			
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
						&err_origin);
			
			//write encryptText in New File and Save
			if(fp = fopen("ciphertext.txt", "w")) {
				fprintf(fp, op.params[0].tmpref.buffer);
				printf("Ciphertext : %s", op.params[0].tmpref.buffer);
				fclose(fp);
			}
			//encrypt randomKey
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_ENC, &op,
						&err_origin);
			//write encryptRandomKey in New File and Save
			if(fp = fopen("encryptedkey.txt", "w")) {
				fprintf(fp, op.params[0].tmpref.buffer);
				printf("encryptedKey : %s\n", op.params[0].tmpref.buffer);
				fclose(fp);
			}
		}
		else if(strcmp(argv[1], "-d") == 0) {
			//normal decryption
			//openfile and get encrptText in file
			if(fp = fopen(argv[2], "r")) {
				fgets(encrypt_text, sizeof(encrypt_text), fp);
				memcpy(op.params[0].tmpref.buffer, encrypt_text, len);
				printf("Encrypt_text : %s", op.params[0].tmpref.buffer);
				fclose(fp);
			}
			//openfile and get RANDOMKey in file
			if(fp=fopen(argv[3], "r")) {
				fgets(encrypt_key, sizeof(encrypt_key), fp);
				memcpy(op.params[1].tmpref.buffer, encrypt_key, 2);
				printf("Encrypt_key : %s\n", op.params[1].tmpref.buffer);
				fclose(fp);
			}
			// Decryption Text
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
						&err_origin);
			if(fp = fopen("Decryptedtext.txt", "w"))
			{
				fprintf(fp, op.params[0].tmpref.buffer);
				printf("Plaintext : %s\n", op.params[0].tmpref.buffer);
				fclose(fp);
			}
		}
		else {
			// command error
			printf("Command Not Found\n");
		}
	} 

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}

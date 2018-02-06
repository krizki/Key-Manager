#pragma GCC diagnostic ignored "-fpermissive"

#include <stdio.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <fstream>
#include <cstring>
#include <iostream>
#include <net/if.h>
#include "Shared-1to1.h"

//http://www.askyb.com/cpp/openssl-hmac-hasing-example-in-cpp/
int doHMAC(unsigned char* inKey, int inKey_len, unsigned char* inData, int inData_len, unsigned char* out)
{
    //Ensure that the input is not to large
    if(inKey_len >= 50 || inData_len >= 50)
    {
      printf("*** HMAC FAILED ***\n");
      return 1;
    }

    // The secret key for hashing
    const char key[50];
    memcpy(key, inKey, inKey_len);

    // The data that we're going to hash
    char data[50];
    memcpy(data, inData, inData_len);
    
    // Be careful of the length of string with the choosen hash engine. SHA1 needed 20 characters.
    // Change the length accordingly with your choosen hash engine.     
    unsigned int len = 32;
    unsigned char result[32];

    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);

    // Using sha1 hash engine here.
    // You may use other hash engines. e.g EVP_md5(), EVP_sha224, EVP_sha512, etc
    HMAC_Init_ex(&ctx, key, inKey_len, EVP_sha256(), NULL);
    HMAC_Update(&ctx, (unsigned char*)&data, inData_len);
    HMAC_Final(&ctx, result, &len);
    HMAC_CTX_cleanup(&ctx);

    /*printf("HMAC digest: ");
    for (int i = 0; i != len; i++)
      printf("%02x", (unsigned int)result[i]);
    printf("\n");*/

    memcpy(out, result, len);

    return 0;
}

//Concatenates and hashes two pieces of data
int doSHA(unsigned char* in1, int in1_len, unsigned char* in2, int in2_len, unsigned char* out)
{
    //Ensure that the input is not to large
    if(in1_len >= 50 || in2_len >= 50)
    {
      printf("*** SHA FAILED - Input too big ***\n");
      return 1;
    }

    // The first piece of data for hashing
    const char key[50];
    memcpy(key, in1, in1_len);

    // The second piece of data for hashing
    char data[50];
    memcpy(data, in2, in2_len);

    // Concatenate the pieces
    unsigned char input[in1_len + in2_len];
    memcpy(input, in1, in1_len);
    memcpy(input + in1_len, in2, in2_len);
    
    // Be careful of the length of string with the choosen hash engine. SHA1 needed 20 characters.
    // Change the length accordingly with your choosen hash engine.     
    unsigned int len = 32;
    unsigned char result[32];

    SHA256_CTX context;
    SHA256_Init(&context);

    // Using sha1 hash engine here.
    // You may use other hash engines. e.g EVP_md5(), EVP_sha224, EVP_sha512, etc
    SHA256_Update(&context, (unsigned char*)&input, in1_len + in2_len);
    SHA256_Final(result, &context);

    /*printf("SHA digest: ");
    for (int i = 0; i != len; i++)
      printf("%02x", (unsigned int)result[i]);
    printf("\n");*/

    memcpy(out, result, len);

    return 0;
}

//https://web.archive.org/web/20150319173633/http://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
int doAESEncrypt(unsigned char* inKey, unsigned char* inCleartext, int inCleartext_len, unsigned char* out)
{
   /*printf("*Encrypt: AES Key: ");
   for(int i = 0 ; i < 32 ; i++)
     printf("%02x", inKey[i]);
   printf("\n");
   printf("*Encrypt: AES cleartext: ");
   for(int i = 0 ; i < inCleartext_len ; i++)
     printf("%02x", inCleartext[i]);
   printf("\n");*/

  /* A 256 bit key */
  //unsigned char *key = "01234567890123456789012345678901";
  unsigned char *key = inKey;

  /* A 128 bit IV */
  unsigned char *iv = "0123456789012345";

  /* Message to be encrypted */
  //unsigned char *plaintext = "The quick brown fox jumps over the lazy dog";
  unsigned char *plaintext = inCleartext;

  /* Buffer for ciphertext. Ensure the buffer is long enough for the
   * ciphertext which may be longer than the plaintext, dependant on the
   * algorithm and mode
   */
  unsigned char ciphertext[128];

  /* Initialise the library */
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(NULL);

  /* Encrypt the plaintext */
  int ciphertext_len = encrypt(plaintext, inCleartext_len, key, iv, ciphertext);
  if(ciphertext_len <= 0)
  {
      printf("*** AES Encrypt failed. ***\n");
  }
  else
  {
      db_printf("AES Encrypt successful.\n");
  }

  /* Do something useful with the ciphertext here */
  //printf("Ciphertext is (len %i):\n", ciphertext_len);
  //BIO_dump_fp(stdout, ciphertext, ciphertext_len);

  /* Stores ciphertext in output */
  memcpy(out, ciphertext, ciphertext_len);
  //db_printf("\n\n%i\n\n", ciphertext_len);

  /* Clean up */
  EVP_cleanup();
  ERR_free_strings();

  /*printf("*Encrypt: AES ciphertext: ");
  for(int i = 0 ; i < ciphertext_len ; i++)
    printf("%02x", ciphertext[i]);
  printf("\n"); */

  return ciphertext_len;
}

int doAESDecrypt(unsigned char* inKey, unsigned char* inCiphertext, int inCiphertext_len, unsigned char* out)
{
   /*printf("*Decrypt: AES Key: ");
   for(int i = 0 ; i < 32 ; i++)
     printf("%02x", inKey[i]);
   printf("\n");
   printf("*Decrypt: AES ciphertext: ");
   for(int i = 0 ; i < inCiphertext_len ; i++)
     printf("%02x", inCiphertext[i]);
   printf("\n");*/

  /* A 256 bit key */
  //unsigned char *key = "01234567890123456789012345678901";
  unsigned char *key = inKey;

  /* A 128 bit IV */
  unsigned char *iv = "0123456789012345";

  /* Buffer for ciphertext. Ensure the buffer is long enough for the
   * ciphertext which may be longer than the plaintext, dependant on the
   * algorithm and mode
   */
  unsigned char* ciphertext = inCiphertext;

  /* Buffer for the decrypted text */
  unsigned char decryptedtext[128];

  int decryptedtext_len, ciphertext_len;

  /* Initialise the library */
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(NULL);

  /* Store size of ciphertext */
  ciphertext_len = inCiphertext_len;

  /* Do something useful with the ciphertext here */
  //printf("Ciphertext is (len %i):\n", ciphertext_len);
  //BIO_dump_fp(stdout, ciphertext, ciphertext_len);

  /* Decrypt the ciphertext */
  decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);
  if(decryptedtext_len <= 0)
  {
      printf("*** AES Decrypt failed. ***\n");
  }
  else
  {
      db_printf("AES Decrypt successful.\n");
  }

  /* Add a NULL terminator. We are expecting printable text */
  decryptedtext[decryptedtext_len] = '\0';

  /* Show the decrypted text */
  //printf("Decrypted text is (len %i):\n", decryptedtext_len);
  //printf("%s\n", decryptedtext);

  /* Stores decrypted text in output */
  memcpy(out, decryptedtext, decryptedtext_len);

  /* Clean up */
  EVP_cleanup();
  ERR_free_strings();

  /*printf("*Decrypt: AES cleartext: ");
  for(int i = 0 ; i < decryptedtext_len ; i++)
    printf("%02x", decryptedtext[i]);
  printf("\n");*/

  return decryptedtext_len;
}

/* Various support functions */
//Dummy HMAC
int doHMAC2(char in1[], char in2[], char* out)
{
    for(int i = 0 ; i < 32 ; i++)
      out[i] = 10 + i + in1[0]+ in2[1];

    return 0;
}

unsigned int toInt(char c)
{
  if (c >= '0' && c <= '9') return      c - '0';
  if (c >= 'A' && c <= 'F') return 10 + c - 'A';
  if (c >= 'a' && c <= 'f') return 10 + c - 'a';
  return -1;
}

std::vector<unsigned char> intToBytes(int paramInt)
{
     std::vector<unsigned char> arrayOfByte(4);
     for (int i = 0; i < 4; i++)
         arrayOfByte[3 - i] = (paramInt >> (i * 8));
     return arrayOfByte;
}

/* Base AES functions below */
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int plaintext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

void handleErrors()
{
  printf("*** AES error occurred! ***\n");
}

/* Various support functions */

//Reads a file with configuration information for Node or KeyManager
ConfigInfo readConfig(const char filename[])
{
  //Checks if config file exists
  std::ifstream ifile(filename);
  if (!ifile)
  {
    printf("Error: Configuration file %s not found!\n", filename);
  }

  //Declare instance of structure to store the read configuration  
  ConfigInfo inConf;

  //Tries to open file and read configuration
  FILE *ifp;
  ifp = fopen(filename, "r");
    
  if (ifp == NULL)
  {
    printf("Error: Unable to open configuration file!\n"); 
    exit(0);
    return;
  }
  
  fscanf(ifp, "IP %49s\n", inConf.IP);
  fscanf(ifp, "Port %d\n", &inConf.port);
  fscanf(ifp, "Interface %19s", inConf.interface);

  fclose(ifp);

  //ConfigInfo inConf;
  //strcpy(inConf.IP, "226.0.0.1");
  //inConf.port = 4096;
  
  //Determines name of interface to be used
  int interfaceIndex;
  char interfaceName[30];
  //If DEFAULT is specified in configuration file call interface that
  if(strcmp(inConf.interface, "DEFAULT") == 0)
  {
    strcpy(interfaceName, inConf.interface);
  }
  //Otherwise identify name of interface from its index (may not exist)
  else
  {
    interfaceIndex = if_nametoindex(inConf.interface);
    char *namePointer = if_indextoname(interfaceIndex, interfaceName);
    if(namePointer == NULL)
    {
      printf("Error: Could not find interface '%s'!\n", inConf.interface);
      exit(0);
      return;
    }
  }
  
  printf("Configuration is multicast: [%s]:%i on interface '%s' (%s) \n", inConf.IP, inConf.port, interfaceName, filename);
  
  return inConf;
}


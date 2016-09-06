#include <vector>

#define DEBUG 1

//Debug printf
#define db_printf(...) \
            do { if (DEBUG) fprintf(stdout, __VA_ARGS__); } while (0)

//Printf to screen and file (useful for saving node configuration)        
#define cfg_printf(fp, fmt, ...)                                \
            do { db_printf (fmt, __VA_ARGS__); fprintf (fp, fmt, __VA_ARGS__); } while (0)

int doHMAC(unsigned char* inKey, int inKey_len, unsigned char* inData, int inData_len, unsigned char* out);
int doSHA(unsigned char* in1, int in1_len, unsigned char* in2, int in2_len, unsigned char* out);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);
int doAESEncrypt(unsigned char* inKey, unsigned char* inCleartext, int inCleartext_len, unsigned char* out);
int doAESDecrypt(unsigned char* inKey, unsigned char* inCiphertext, int inCiphertext_len, unsigned char* out);
void handleErrors();

int doHMAC2(char in1[], char in2[], char* out);
unsigned int toInt(char c);
std::vector<unsigned char> intToBytes(int paramInt);

enum MessageType { DUMMY, JOIN1, JOIN2, JOIN3, LEAVE1, LEAVE2, LEAVE3, REKEY1, REKEY2, REKEY3, REKEY4, REKEY5, DATA };

//Structure to hold configuration information (also saved in file)
struct ConfigInfo
{
   char IP[50];
   int port;
   char interface[20];
};

ConfigInfo readConfig(const char filename[]);

/**
 * 
 * AES 128 CBC Mode implemented using Intrinsic AES instructions _mm_aes*
 * 
 * Tested with 64Bytes file size
 * 
 */


#define AES128 
//#define AES192 
//#define AES256 
 
#ifndef LENGTH 
#define LENGTH 64 
#endif 
 
#include <stdint.h> 
#include <stdio.h> 
#include <wmmintrin.h> 
 
#if !defined (ALIGN16) 
# if defined (__GNUC__) 
# define ALIGN16 __attribute__ ( (aligned (16))) 
# else 
# define ALIGN16 __declspec (align (16)) 
# endif 
#endif 
 
typedef struct KEY_SCHEDULE{ 
 ALIGN16 unsigned char KEY[16*15]; 
 unsigned int nr; 
 }AES_KEY; 
 
/*test vectors were taken from http://csrc.nist.gov/publications/nistpubs/800-
38a/sp800-38a.pdf*/ 
/*ALIGN16 uint8_t AES128_TEST_KEY[] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6, 
 0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c}; */
ALIGN16 uint8_t AES128_TEST_KEY[] = {0xf0, 0x0d, 0xff, 0x46, 0xaf, 0xf7, 0x6d, 0x37, 0xa3, 0x25, 0x0d, 0x5c, 0x58, 0x30, 0x14, 0xf1 }; 
ALIGN16 uint8_t AES192_TEST_KEY[] = {0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52, 
 0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5, 
 0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b}; 
ALIGN16 uint8_t AES256_TEST_KEY[] = {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe, 
 0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81, 0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7, 
 0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4}; 
ALIGN16 uint8_t AES_TEST_VECTOR[] = {'a','c','b','e','e',0x40,0x9f,0x96, 
 0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a, 
 0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c, 
 0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51, 
 0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11, 
 0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef, 
 0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17, 
 0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37, 'x'}; 

ALIGN16 uint8_t CBC_IV[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
ALIGN16 uint8_t CBC128_EXPECTED[] = {0x76,0x49,0xab,0xac,0x81,0x19,0xb2,0x46, 
 0xce,0xe9,0x8e,0x9b,0x12,0xe9,0x19,0x7d, 
 0x50,0x86,0xcb,0x9b,0x50,0x72,0x19,0xee, 
 0x95,0xdb,0x11,0x3a,0x91,0x76,0x78,0xb2, 
 0x73,0xbe,0xd6,0xb8,0xe3,0xc1,0x74,0x3b, 
 0x71,0x16,0xe6,0x9e,0x22,0x22,0x95,0x16, 
 0x3f,0xf1,0xca,0xa1,0x68,0x1f,0xac,0x09, 
 0x12,0x0e,0xca,0x30,0x75,0x86,0xe1,0xa7}; 
ALIGN16 uint8_t CBC192_EXPECTED[] = {0x4f,0x02,0x1d,0xb2,0x43,0xbc,0x63,0x3d, 
 0x71,0x78,0x18,0x3a,0x9f,0xa0,0x71,0xe8, 
 0xb4,0xd9,0xad,0xa9,0xad,0x7d,0xed,0xf4, 
 0xe5,0xe7,0x38,0x76,0x3f,0x69,0x14,0x5a, 
 0x57,0x1b,0x24,0x20,0x12,0xfb,0x7a,0xe0, 
 0x7f,0xa9,0xba,0xac,0x3d,0xf1,0x02,0xe0, 
 0x08,0xb0,0xe2,0x79,0x88,0x59,0x88,0x81, 
 0xd9,0x20,0xa9,0xe6,0x4f,0x56,0x15,0xcd}; 
ALIGN16 uint8_t CBC256_EXPECTED[] = {0xf5,0x8c,0x4c,0x04,0xd6,0xe5,0xf1,0xba, 
 0x77,0x9e,0xab,0xfb,0x5f,0x7b,0xfb,0xd6, 
 0x9c,0xfc,0x4e,0x96,0x7e,0xdb,0x80,0x8d, 
 0x67,0x9f,0x77,0x7b,0xc6,0x70,0x2c,0x7d, 
 0x39,0xf2,0x33,0x69,0xa9,0xd9,0xba,0xcf, 
 0xa5,0x30,0xe2,0x63,0x04,0x23,0x14,0x61, 
 0xb2,0xeb,0x05,0xe2,0xc3,0x9b,0xe9,0xfc, 
 0xda,0x6c,0x19,0x07,0x8c,0x6a,0x9d,0x1b}; 
/*****************************************************************************/ 

inline __m128i AES_128_ASSIST (__m128i temp1, __m128i temp2) 
 { 
 __m128i temp3; 
 temp2 = _mm_shuffle_epi32 (temp2 ,0xff); 
 temp3 = _mm_slli_si128 (temp1, 0x4); 
 temp1 = _mm_xor_si128 (temp1, temp3); 
 temp3 = _mm_slli_si128 (temp3, 0x4); 
 temp1 = _mm_xor_si128 (temp1, temp3); 
 temp3 = _mm_slli_si128 (temp3, 0x4); 
 temp1 = _mm_xor_si128 (temp1, temp3); 
 temp1 = _mm_xor_si128 (temp1, temp2); 
 return temp1; 
 } 


void AES_128_Key_Expansion (const unsigned char *userkey, 
 unsigned char *key) 
 { 
 __m128i temp1, temp2; 
 __m128i *Key_Schedule = (__m128i*)key; 
 
 temp1 = _mm_loadu_si128((__m128i*)userkey); 
 Key_Schedule[0] = temp1; 
 temp2 = _mm_aeskeygenassist_si128 (temp1 ,0x1); 
 temp1 = AES_128_ASSIST(temp1, temp2); 
 Key_Schedule[1] = temp1; 
 temp2 = _mm_aeskeygenassist_si128 (temp1,0x2); 
 temp1 = AES_128_ASSIST(temp1, temp2); 
 Key_Schedule[2] = temp1; 
 temp2 = _mm_aeskeygenassist_si128 (temp1,0x4); 
 temp1 = AES_128_ASSIST(temp1, temp2); 
 Key_Schedule[3] = temp1; 
 temp2 = _mm_aeskeygenassist_si128 (temp1,0x8); 
 temp1 = AES_128_ASSIST(temp1, temp2); 
 Key_Schedule[4] = temp1; 
 temp2 = _mm_aeskeygenassist_si128 (temp1,0x10); 
 temp1 = AES_128_ASSIST(temp1, temp2); 
 Key_Schedule[5] = temp1; 
 temp2 = _mm_aeskeygenassist_si128 (temp1,0x20); 
 temp1 = AES_128_ASSIST(temp1, temp2); 
 Key_Schedule[6] = temp1; 
 temp2 = _mm_aeskeygenassist_si128 (temp1,0x40); 
 temp1 = AES_128_ASSIST(temp1, temp2); 
 Key_Schedule[7] = temp1; 
 temp2 = _mm_aeskeygenassist_si128 (temp1,0x80); 
 temp1 = AES_128_ASSIST(temp1, temp2); 
 Key_Schedule[8] = temp1; 
 temp2 = _mm_aeskeygenassist_si128 (temp1,0x1b); 
 temp1 = AES_128_ASSIST(temp1, temp2); 
 Key_Schedule[9] = temp1; 
 temp2 = _mm_aeskeygenassist_si128 (temp1,0x36); 
 temp1 = AES_128_ASSIST(temp1, temp2); 
 Key_Schedule[10] = temp1; 
 } 
 
int AES_set_encrypt_key (const unsigned char *userKey, 
 const int bits, 
 AES_KEY *key) 
 { 
 if (!userKey || !key) 
 return -1; 
 if (bits == 128) 
 { 
 AES_128_Key_Expansion (userKey,key->KEY); 
 key->nr = 10; 
 return 0; 
 } 

 return -2; 
 } 


int AES_set_decrypt_key (const unsigned char *userKey, 
 const int bits, 
 AES_KEY *key) 
 { 
 int i,nr;; 
 AES_KEY temp_key; 
 __m128i *Key_Schedule = (__m128i*)key->KEY; 
 __m128i *Temp_Key_Schedule = (__m128i*)temp_key.KEY; 
 if (!userKey || !key) 
 return -1; 
 
 if (AES_set_encrypt_key(userKey,bits,&temp_key) == -2) 
 return -2; 
 
 nr = temp_key.nr; 
 key->nr = nr; 
 
 Key_Schedule[nr] = Temp_Key_Schedule[0]; 
 Key_Schedule[nr-1] = _mm_aesimc_si128(Temp_Key_Schedule[1]); 
 Key_Schedule[nr-2] = _mm_aesimc_si128(Temp_Key_Schedule[2]); 
 Key_Schedule[nr-3] = _mm_aesimc_si128(Temp_Key_Schedule[3]); 
 Key_Schedule[nr-4] = _mm_aesimc_si128(Temp_Key_Schedule[4]); 
 Key_Schedule[nr-5] = _mm_aesimc_si128(Temp_Key_Schedule[5]); 
 Key_Schedule[nr-6] = _mm_aesimc_si128(Temp_Key_Schedule[6]); 
 Key_Schedule[nr-7] = _mm_aesimc_si128(Temp_Key_Schedule[7]); 
 Key_Schedule[nr-8] = _mm_aesimc_si128(Temp_Key_Schedule[8]); 
 Key_Schedule[nr-9] = _mm_aesimc_si128(Temp_Key_Schedule[9]); 
 if(nr>10){ 
 Key_Schedule[nr-10] = _mm_aesimc_si128(Temp_Key_Schedule[10]); 
 Key_Schedule[nr-11] = _mm_aesimc_si128(Temp_Key_Schedule[11]); 
 } 
 if(nr>12){ 
 Key_Schedule[nr-12] = _mm_aesimc_si128(Temp_Key_Schedule[12]); 
 Key_Schedule[nr-13] = _mm_aesimc_si128(Temp_Key_Schedule[13]); 
 } 
 Key_Schedule[0] = Temp_Key_Schedule[nr]; 
 return 0; 
 } 


void AES_CBC_encrypt(const unsigned char *in, 
 unsigned char *out, 
 unsigned char ivec[16], 
 unsigned long length, 
 unsigned char *key, 
 int number_of_rounds) 
 { 
 __m128i feedback,data; 
 int i,j; 
 
 if (length%16) 
 length = length/16+1; 
 else length /=16; 
 
 feedback=_mm_loadu_si128 ((__m128i*)ivec); 
 for(i=0; i < length; i++){ 
 data = _mm_loadu_si128 (&((__m128i*)in)[i]); 
 feedback = _mm_xor_si128 (data,feedback); 
 feedback = _mm_xor_si128 (feedback,((__m128i*)key)[0]); 
 for(j=1; j <number_of_rounds; j++) 
 feedback = _mm_aesenc_si128 (feedback,((__m128i*)key)[j]); 
 feedback = _mm_aesenclast_si128 (feedback,((__m128i*)key)[j]); 
 _mm_storeu_si128 (&((__m128i*)out)[i],feedback); 
 } 
 } 

void AES_CBC_decrypt(const unsigned char *in, 
 unsigned char *out, 
 unsigned char ivec[16], 
 unsigned long length, 
 unsigned char *key, 
 int number_of_rounds) 
 { 
 __m128i data,feedback,last_in; 
 int i,j; 
 
 if (length%16) 
 length = length/16+1; 
 else length /=16; 
 
 feedback=_mm_loadu_si128 ((__m128i*)ivec); 
 for(i=0; i < length; i++){ 
 last_in=_mm_loadu_si128 (&((__m128i*)in)[i]); 
 data = _mm_xor_si128 (last_in,((__m128i*)key)[0]); 
 for(j=1; j <number_of_rounds; j++){ 
 data = _mm_aesdec_si128 (data,((__m128i*)key)[j]); 
 } 
 data = _mm_aesdeclast_si128 (data,((__m128i*)key)[j]); 
 data = _mm_xor_si128 (data,feedback); 
 _mm_storeu_si128 (&((__m128i*)out)[i],data); 
 feedback=last_in; 
 } 
 } 



/*****************************************************************************/ 
void print_m128i_with_string(char* string,__m128i data) 
 { 
 unsigned char *pointer = (unsigned char*)&data; 
 int i; 
 printf("%-40s[0x",string); 
 for (i=0; i<16; i++) 
 printf("%02x",pointer[i]); 
 printf("]\n"); 
 } 

void print_m128i_with_string_short(char* string,__m128i data,int length) 
 { 
 unsigned char *pointer = (unsigned char*)&data; 
 int i; 
 printf("%-40s[0x",string); 
 for (i=0; i<length; i++) 
 printf("%02x",pointer[i]); 
 printf("]\n"); 
 } 
/*****************************************************************************/ 

 int main(){ 
	 AES_KEY key;
	 AES_KEY decrypt_key; 
	 uint8_t *PLAINTEXT; 
	 uint8_t *CIPHERTEXT; 
	 uint8_t *DECRYPTEDTEXT; 
	 uint8_t *EXPECTED_CIPHERTEXT; 
	 uint8_t *CIPHER_KEY; 
	 int i,j; 
	 int key_length; 

	// if (!Check_CPU_support_AES()){ 
	//  printf("Cpu does not support AES instruction set. Bailing out.\n"); 
	//  return 1; 
	//  } 
	//  printf("CPU support AES instruction set.\n\n");

	 #ifdef AES128 
	#define STR "Performing AES128 CBC.\n" 
	 CIPHER_KEY = AES128_TEST_KEY; 
	 EXPECTED_CIPHERTEXT = CBC128_EXPECTED; 
	 key_length = 128; 
	#elif defined AES192 
	#define STR "Performing AES192 CBC.\n" 
	 CIPHER_KEY = AES192_TEST_KEY; 
	 EXPECTED_CIPHERTEXT = CBC192_EXPECTED; 
	 key_length = 192; 
	#elif defined AES256 
	#define STR "Performing AES256 CBC.\n" 
	 CIPHER_KEY = AES256_TEST_KEY; 
	 EXPECTED_CIPHERTEXT = CBC256_EXPECTED; 
	 key_length = 256; 
	#endif 
 
	PLAINTEXT = (uint8_t*)malloc(LENGTH); 
	 CIPHERTEXT = (uint8_t*)malloc(LENGTH); 
	 DECRYPTEDTEXT = (uint8_t*)malloc(LENGTH); 
	 
	 for(i=0 ;i<LENGTH/16/4; i++){ 
	 for(j=0; j<4; j++){ 
	 _mm_storeu_si128(&((__m128i*)PLAINTEXT)[i*4+j], 
	 ((__m128i*)AES_TEST_VECTOR)[j]); 
	 } 
	 } 
	 for(j=i*4 ; j<LENGTH/16; j++){ 
	 _mm_storeu_si128(&((__m128i*)PLAINTEXT)[j], 
	 ((__m128i*)AES_TEST_VECTOR)[j%4]); 
	 } 
	 if (LENGTH%16){ 
	 _mm_storeu_si128(&((__m128i*)PLAINTEXT)[j], 
	 ((__m128i*)AES_TEST_VECTOR)[j%4]); 
	 } 
	 
	 AES_set_encrypt_key(CIPHER_KEY, key_length, &key); 
	 AES_set_decrypt_key(CIPHER_KEY, key_length, &decrypt_key); 
	 
	 AES_CBC_encrypt(PLAINTEXT, 
	 CIPHERTEXT, 
	 CBC_IV,
	 LENGTH, 
	 key.KEY, 
	 key.nr); 
	 
	 FILE * fin = fopen("ENCRYPTED_piece_of_shit.txt", "rb");
	 static char buf[LENGTH];
	 fread(buf, 1, LENGTH, fin);
	 CIPHERTEXT = buf;
	 
	 AES_CBC_decrypt(CIPHERTEXT, 
	 DECRYPTEDTEXT, 
	 CBC_IV, 
	 LENGTH, 
	 decrypt_key.KEY, 
	 decrypt_key.nr);
	 
	 FILE *fout = fopen("piece_of_shit.txt", "wb");
	 fwrite(DECRYPTEDTEXT, 1, LENGTH, fout);

	 printf("%s\n",STR); 
	 printf("The Cipher Key:\n"); 
	 print_m128i_with_string("",((__m128i*)CIPHER_KEY)[0]); 
	 if (key_length > 128) 
	 print_m128i_with_string_short("",((__m128i*)CIPHER_KEY)[1],(key_length/8) -16); 
	 
	 printf("The Key Schedule:\n"); 
	 for (i=0; i< key.nr; i++) 
	 print_m128i_with_string("",((__m128i*)key.KEY)[i]); 
	 
	 printf("The PLAINTEXT:\n"); 
	 for (i=0; i< LENGTH/16; i++) 
	 //print_m128i_with_string("",((__m128i*)PLAINTEXT)[i]); 
	 if (LENGTH%16) 
	 print_m128i_with_string_short("",((__m128i*)PLAINTEXT)[i],LENGTH%16); 
	 
	 printf("\n\nThe CIPHERTEXT:\n"); 
	 for (i=0; i< LENGTH/16; i++) 
	 print_m128i_with_string("",((__m128i*)CIPHERTEXT)[i]); 
	 if (LENGTH%16) 
	 print_m128i_with_string_short("",((__m128i*)CIPHERTEXT)[i],LENGTH%16); 
	 
	 for(i=0; i<((64<LENGTH)? 64 : LENGTH); i++){ 
	 if (CIPHERTEXT[i] != EXPECTED_CIPHERTEXT[i%64]){ 
	 printf("The ciphertext is not equal to the expected ciphertext.\n\n"); 
	 return 1; 
	 } 
	 } 
	 printf("The CIPHERTEXT equals to the EXPECTED CIHERTEXT" 
	 " for bytes where expected text was entered.\n\n"); 
	 
	 for(i=0; i<LENGTH; i++){ 
	 if (DECRYPTEDTEXT[i] != PLAINTEXT[i%(16*4)]){ 
	 printf("%x",DECRYPTEDTEXT[i]); 
	 printf("The DECRYPTED TEXT is not equal to the original" 
	 "PLAINTEXT.\n\n"); 
	 return 1; 
	 } 
	 } 
	 printf("The DECRYPTED TEXT equals to the original PLAINTEXT.\n\n"); 
 } 

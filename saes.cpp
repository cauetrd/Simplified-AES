#include <cstdint>
#include <iostream>
#include <vector>
#include <cryptopp/rijndael.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/modes.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>

#include "base64.h"

/******************************* SAES Global Variables ***************************************/

#define GF_MUL_PRECOMPUTED_TERM    0x03
#define NIBBLE_MASK 0x0F

uint8_t Sbox[16] =
{
	0x9,0x4,0xA,0xB,
	0xD,0x1,0x8,0x5,
	0x6,0x2,0x0,0x3,
	0xC,0xE,0xF,0x7
};

uint8_t InverseSbox[16] =
{
	0xA,0x5,0x9,0xB,
	0x1,0x7,0x8,0xF,
	0x6,0x0,0x2,0x3,
	0xC,0x4,0xD,0xE
};

uint8_t RCON[2] = { 0x80, 0x30 };

/******************************* SAES Utility Functions ***************************************/

uint16_t convert_state_matrix_to_int(std::vector<std::vector<uint8_t> > state) {
  uint16_t result = 0;

  result |= (state[0][0] << 12);
  result |= (state[1][0] << 8);
  result |= (state[0][1] << 4);
  result |= (state[1][1] << 0);

  return result;
}

std::vector<std::vector<uint8_t> > convert_int_to_state_matrix(uint16_t state) {
  std::vector<std::vector<uint8_t> > result(2, std::vector<uint8_t>(2, 0));

  result[0][0] = (state >> 12) & NIBBLE_MASK;
  result[1][0] = (state >> 8) & NIBBLE_MASK;
  result[0][1] = (state >> 4) & NIBBLE_MASK;
  result[1][1] = (state >> 0) & NIBBLE_MASK;

  return result;
}

uint8_t rotate_nibble(uint8_t word) {
  uint8_t upper = word << 4;
  uint8_t lower = (word >> 4) & NIBBLE_MASK;

  return upper | lower;
}

uint8_t key_expansion_subnibble(uint8_t word) {
  uint8_t upper = (word >> 4) & NIBBLE_MASK;
  uint8_t lower = word & NIBBLE_MASK;

  return Sbox[upper] << 4 | Sbox[lower];    
}

std::vector<uint16_t> saes_key_expansion(uint16_t key) {
  std::vector<uint16_t> keys (3, 0);

  keys[0] = key;

  uint8_t w0 = (keys[0] >> 8) & 0xFF;
  uint8_t w1 = keys[0] & 0xFF;

  uint8_t w2 = w0 ^ RCON[0] ^ key_expansion_subnibble(rotate_nibble(w1));
  uint8_t w3 = w2 ^ w1;

  keys[1] = w2 << 8 | w3;

  uint8_t w4 = w2 ^ RCON[1] ^ key_expansion_subnibble(rotate_nibble(w3));
  uint8_t w5 = w4 ^ w3;

  keys[2] = w4 << 8 | w5;

  return keys;
}

/******************************* SAES Common Functions ***************************************/

// Galois Field multiplication by 2, 4, and 9 - copied code
uint8_t GF_MultiplyBy(uint8_t data, uint8_t mulValue)
{
	uint8_t result = data;

	switch (mulValue)
	{
	case 2: /* Used in SAES Decryption */

		/* Reading Bit 3 in data to determine what will be done in the multiplication operation */
		if ((result >> 3) == 1)
		{
			result = ((result << 1) & 0x0F) ^ GF_MUL_PRECOMPUTED_TERM;
		}
		else
			result = (result << 1) & 0x0F;

		break;

	case 4: /* Used in SAES Encryption */

		for (int i = 0; i < 2; i++)
		{
			/* Reading Bit 3 in data to determine what will be done in the multiplication operation */
			if ((result >> 3) == 1)
			{
				result = ((result << 1) & 0x0F) ^ GF_MUL_PRECOMPUTED_TERM;
			}
			else
			{
				result = (result << 1) & 0x0F;
			}
		}

		break;

	case 9: /* Used in SAES Decryption */

		for (int i = 0; i < 3; i++)
		{
			/* Reading Bit 3 in data to determine what will be done in the multiplication operation */
			if ((result >> 3) == 1)
			{
				result = ((result << 1) & 0x0F) ^ GF_MUL_PRECOMPUTED_TERM;
			}
			else
			{
				result = (result << 1) & 0x0F;
			}
		}

		result = result ^ data;
		break;

	default:
		break;
	}

	return result;
}

std::vector<std::vector<uint8_t> > saes_shift_rows(std::vector<std::vector<uint8_t> > currentState) {
  std::vector<std::vector<uint8_t> > result(2, std::vector<uint8_t>(2, 0));

  result[0][0] = currentState[0][0];
  result[0][1] = currentState[0][1];
  result[1][0] = currentState[1][1];
  result[1][1] = currentState[1][0];

  return result;
}

std::vector<std::vector<uint8_t> > saes_nibble_substitution(std::vector<std::vector<uint8_t> > currentState, uint8_t* Sbox) {
  std::vector<std::vector<uint8_t> > result(2, std::vector<uint8_t>(2, 0));

  for (int i = 0; i < 2; i++) {
    for (int j = 0; j < 2; j++) {
      result[i][j] = Sbox[currentState[i][j]];
    }
  }

  return result;
}

std::vector<std::vector<uint8_t> > saes_add_round_key(std::vector<std::vector<uint8_t> > currentState, uint16_t key) {
  uint16_t currentStateNumber = convert_state_matrix_to_int(currentState);

  uint16_t newStateNumber = currentStateNumber ^ key;

  return convert_int_to_state_matrix(newStateNumber);
}

/******************************* SAES Decryption Functions ***************************************/

std::vector<std::vector<uint8_t> > saes_inverse_mix_columns(std::vector<std::vector<uint8_t> > currentState) {
  std::vector<std::vector<uint8_t> > result(2, std::vector<uint8_t>(2, 0));

  for (int i = 0; i < 2; i++) {
    for (int j = 0; j < 2; j++) {
      result[i][j] = GF_MultiplyBy(currentState[i][j], 9) ^ GF_MultiplyBy(currentState[(i + 1) % 2][j], 2);
    }
  }

  return result;
}

uint16_t saes_decrypt(uint16_t cipherText, uint16_t key) {
  std::vector<std::vector<uint8_t> > state = convert_int_to_state_matrix(cipherText);

  std::vector<uint16_t> keys = saes_key_expansion(key);

  state = saes_add_round_key(state, keys[2]);

  state = saes_shift_rows(state);
  
  state = saes_nibble_substitution(state, InverseSbox);

  state = saes_add_round_key(state, keys[1]);

  state = saes_inverse_mix_columns(state);

  state = saes_shift_rows(state);
  
  state = saes_nibble_substitution(state, InverseSbox);

  state = saes_add_round_key(state, keys[0]);

  uint16_t result = convert_state_matrix_to_int(state);

  return result;
}

/******************************* SAES Encryption Functions ***************************************/


std::vector<std::vector<uint8_t> > saes_mix_columns(std::vector<std::vector<uint8_t> > currentState) {
  std::vector<std::vector<uint8_t> > result(2, std::vector<uint8_t>(2, 0));

  for (int i = 0; i < 2; i++) {
    for (int j = 0; j < 2; j++) {
      result[i][j] = currentState[i][j] ^ GF_MultiplyBy(currentState[(i + 1) % 2][j], 4);
    }
  }

  return result;
}

uint16_t saes_encrypt(uint16_t plainText, uint16_t key) {
  std::vector<std::vector<uint8_t> > state = convert_int_to_state_matrix(plainText);

  std::vector<uint16_t> keys = saes_key_expansion(key);

  state = saes_add_round_key(state, keys[0]); 
  
  state = saes_nibble_substitution(state, Sbox);

  state = saes_shift_rows(state);
  
  state = saes_mix_columns(state);

  state = saes_add_round_key(state, keys[1]);

  state = saes_nibble_substitution(state, Sbox);

  state = saes_shift_rows(state);
  
  state = saes_add_round_key(state, keys[2]);

  uint16_t result = convert_state_matrix_to_int(state);

  return result;
}

/******************************* SAES ECB Functions ***************************************/

std::string ecb_saes_decrypt(std::string base64Input, uint16_t key) {
  std::vector<uint16_t> inputWords;

  std::string decodedInput = base64_decode(base64Input);

  for (size_t i = 0; i < decodedInput.size() - 1; i += 2) {
    char firstChar = decodedInput[i];
    char secondChar = decodedInput[i + 1];

    uint16_t word = (uint8_t) firstChar << 8 | (uint8_t) secondChar;

    inputWords.push_back(word);
  }

  std::vector<uint16_t> outputWords(inputWords.size());

  for (size_t i = 0; i < inputWords.size(); i++) {
    outputWords[i] = saes_decrypt(inputWords[i], key);
  }

  // base64_encode(outputWords);
  std::string outputStr;
  for (int i = 0; i < outputWords.size(); i++) {
    char firstChar = (char) (outputWords[i] >> 8) & 0xFF;
    char secondChar = (char) (outputWords[i] & 0xFF);

    outputStr += firstChar;
    outputStr += secondChar;
  }

  // Encode the output string to base64
  std::string output = base64_encode(outputStr);

  return output;
}

std::string ecb_saes_encrypt(std::string base64Input, uint16_t key) {
  std::vector<uint16_t> inputWords;

  std::string decodedInput = base64_decode(base64Input);

  if (decodedInput.size() % 2) {
    decodedInput += ' ';
  }

  for (size_t i = 0; i < decodedInput.size() - 1; i += 2) {
    char firstChar = decodedInput[i];
    char secondChar = decodedInput[i + 1];

    uint16_t word = (uint8_t) firstChar << 8 | (uint8_t) secondChar;

    inputWords.push_back(word);
  }

  std::vector<uint16_t> outputWords(inputWords.size());

  for (size_t i = 0; i < inputWords.size(); i++) {
    outputWords[i] = saes_encrypt(inputWords[i], key);
  }

  // base64_encode(outputWords);
  std::string outputStr;
  for (const auto& word : outputWords) {
    std::cout << std::hex << word << std::endl;

    char firstChar = (char) (word >> 8) & 0xFF;
    char secondChar = (char) (word & 0xFF);

    outputStr += firstChar;
    outputStr += secondChar;
  }

  // Encode the output string to base64
  std::string output = base64_encode(outputStr);

  return output;
}

void test() {
  using namespace CryptoPP;

  AutoSeededRandomPool prng;
  HexEncoder encoder(new FileSink(std::cout));

  SecByteBlock key(AES::DEFAULT_KEYLENGTH);
  SecByteBlock iv(AES::BLOCKSIZE);

  prng.GenerateBlock(key, key.size());
  prng.GenerateBlock(iv, iv.size());

  std::string plain = "CBC Mode Test";
  std::string cipher, recovered;

  std::cout << "plain text: " << plain << std::endl;

  /*********************************\
  \*********************************/

  try
  {
      CBC_Mode< AES >::Encryption e;
      e.SetKeyWithIV(key, key.size(), iv);

      StringSource s(plain, true, 
          new StreamTransformationFilter(e,
              new StringSink(cipher)
          ) // StreamTransformationFilter
      ); // StringSource
  }
  catch(const Exception& e)
  {
      std::cerr << e.what() << std::endl;
      exit(1);
  }

  /*********************************\
  \*********************************/

  std::cout << "key: ";
  encoder.Put(key, key.size());
  encoder.MessageEnd();
  std::cout << std::endl;

  std::cout << "iv: ";
  encoder.Put(iv, iv.size());
  encoder.MessageEnd();
  std::cout << std::endl;

  std::cout << "cipher text: ";
  encoder.Put((const byte*)&cipher[0], cipher.size());
  encoder.MessageEnd();
  std::cout << std::endl;
  
  /*********************************\
  \*********************************/

  try
  {
      CBC_Mode< AES >::Decryption d;
      d.SetKeyWithIV(key, key.size(), iv);

      StringSource s(cipher, true, 
          new StreamTransformationFilter(d,
              new StringSink(recovered)
          ) // StreamTransformationFilter
      ); // StringSource

      std::cout << "recovered text: " << recovered << std::endl;
  }
  catch(const Exception& e)
  {
      std::cerr << e.what() << std::endl;
      exit(1);
  }
}

int main() {
  uint16_t plainText = 0xD728;
  uint16_t key = 0x4AF5;

  uint16_t cipherText = saes_encrypt(plainText, key);

  uint16_t decryptedText = saes_decrypt(cipherText, key);

  std::string ecb_input = "testando esse algoritmo doido";

  std::string cipherTextECB = ecb_saes_encrypt(base64_encode(ecb_input), key);

  std::string decryptedTextECB = ecb_saes_decrypt(cipherTextECB, key);

  test();

  return 0;
}


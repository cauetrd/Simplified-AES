#include <cstdint>
#include <iostream>
#include <vector>

#include "base64.h"
#include "saes.h"

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

  std::cout << "Expansão da chave: " << std::endl;

  keys[0] = key;

  std::cout << "Chave 1: 0x" << std::hex << keys[0] << std::endl;

  uint8_t w0 = (keys[0] >> 8) & 0xFF;
  uint8_t w1 = keys[0] & 0xFF;

  uint8_t w2 = w0 ^ RCON[0] ^ key_expansion_subnibble(rotate_nibble(w1));
  uint8_t w3 = w2 ^ w1;

  keys[1] = w2 << 8 | w3;

  std::cout << "Chave 2: 0x" << std::hex << keys[1] << std::endl;

  uint8_t w4 = w2 ^ RCON[1] ^ key_expansion_subnibble(rotate_nibble(w3));
  uint8_t w5 = w4 ^ w3;

  keys[2] = w4 << 8 | w5;

  std::cout << "Chave 3: 0x" << std::hex << keys[2] << std::endl;

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

  std::cout << "Estado após a adição da chave 3: 0x" << std::hex << convert_state_matrix_to_int(state) << std::endl;

  state = saes_shift_rows(state);

  std::cout << "Estado após a troca de linhas 1: 0x" << std::hex << convert_state_matrix_to_int(state) << std::endl;
  
  state = saes_nibble_substitution(state, InverseSbox);

  std::cout << "Estado após a substituição de nibbles com a sbox invertida: 0x" << std::hex << convert_state_matrix_to_int(state) << std::endl;

  state = saes_add_round_key(state, keys[1]);

  std::cout << "Estado após a adição da chave 2: 0x" << std::hex << convert_state_matrix_to_int(state) << std::endl;

  state = saes_inverse_mix_columns(state);

  std::cout << "Estado após a mistura de colunas inversa: 0x" << std::hex << convert_state_matrix_to_int(state) << std::endl;

  state = saes_shift_rows(state);

  std::cout << "Estado após a troca de linhas 2: 0x" << std::hex << convert_state_matrix_to_int(state) << std::endl;
  
  state = saes_nibble_substitution(state, InverseSbox);

  std::cout << "Estado após a substituição de nibbles com a sbox invertida: 0x" << std::hex << convert_state_matrix_to_int(state) << std::endl;

  state = saes_add_round_key(state, keys[0]);

  std::cout << "Estado após a adição da chave 1: 0x" << std::hex << convert_state_matrix_to_int(state) << std::endl;

  uint16_t result = convert_state_matrix_to_int(state);

  return result;
}

std::string saes_decrypt_base64(std::string base64cipherText, std::string base64key) {
  // Decode the input
  std::vector<BYTE> decodedCipherText = base64_decode(base64cipherText);
  uint16_t cipherText = decodedCipherText[0] << 8 | decodedCipherText[1];

  if (decodedCipherText.size() > 2) {
    std::cout << "O texto cifrado deve ter 16 bits" << std::endl;
    return "";
  }

  // Decode the key
  std::vector<BYTE> decodedKey = base64_decode(base64key);

  // Check if the key is 16 bits
  if (decodedKey.size() > 2) {
    std::cout << "A chave deve ter 16 bits" << std::endl;
    return "";
  }

  // Transform the key into a 16-bit word
  uint16_t key = decodedKey[0] << 8 | decodedKey[1];

  uint16_t result = saes_decrypt(cipherText, key);

  BYTE resultBytes[2] = {0, 0};
  resultBytes[0] = (result >> 8) & 0xFF;
  resultBytes[1] = (result >> 0) & 0xFF;

  std::string base64Result = base64_encode(resultBytes, 2);

  return base64Result;
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

std::uint16_t saes_encrypt(uint16_t plainText, uint16_t key) {
  std::vector<std::vector<uint8_t> > state = convert_int_to_state_matrix(plainText);

  std::vector<uint16_t> keys = saes_key_expansion(key);

  state = saes_add_round_key(state, keys[0]); 

  std::cout << "Estado após a adição da chave 1: 0x" << std::hex << convert_state_matrix_to_int(state) << std::endl;
  
  state = saes_nibble_substitution(state, Sbox);

  std::cout << "Estado após a substituição de nibbles: 0x" << std::hex << convert_state_matrix_to_int(state) << std::endl;

  state = saes_shift_rows(state);

  std::cout << "Estado após a troca de linhas 1: 0x" << std::hex << convert_state_matrix_to_int(state) << std::endl;
  
  state = saes_mix_columns(state);

  std::cout << "Estado após a mistura de colunas: 0x" << std::hex << convert_state_matrix_to_int(state) << std::endl;

  state = saes_add_round_key(state, keys[1]);

  std::cout << "Estado após a adição da chave 2: 0x" << std::hex << convert_state_matrix_to_int(state) << std::endl;

  state = saes_nibble_substitution(state, Sbox);

  std::cout << "Estado após a substituição de nibbles: 0x" << std::hex << convert_state_matrix_to_int(state) << std::endl;

  state = saes_shift_rows(state);

  std::cout << "Estado após a troca de linhas 2: 0x" << std::hex << convert_state_matrix_to_int(state) << std::endl;
  
  state = saes_add_round_key(state, keys[2]);

  std::cout << "Estado após a adição da chave 3: 0x" << std::hex << convert_state_matrix_to_int(state) << std::endl;

  uint16_t result = convert_state_matrix_to_int(state);

  return result;
}

std::string saes_encrypt_base64(std::string base64plainText, std::string base64key) {
  // Decode the input
  std::vector<BYTE> decodedInput = base64_decode(base64plainText);
  uint16_t input = decodedInput[0] << 8 | decodedInput[1];

  if (decodedInput.size() > 2) {
    std::cout << "O texto plano deve ter 16 bits" << std::endl;
    return "";
  }

  // Decode the key
  std::vector<BYTE> decodedKey = base64_decode(base64key);

  // Check if the key is 16 bits
  if (decodedKey.size() > 2) {
    std::cout << "A chave deve ter 16 bits" << std::endl;
    return "";
  }

  // Transform the key into a 16-bit word
  uint16_t key = decodedKey[0] << 8 | decodedKey[1];

  uint16_t result = saes_encrypt(input, key);

  BYTE resultBytes[2] = {0, 0};
  resultBytes[0] = (result >> 8) & 0xFF;
  resultBytes[1] = (result >> 0) & 0xFF;

  std::string base64Result = base64_encode(resultBytes, 2);

  return base64Result;
}

/******************************* SAES ECB Functions ***************************************/

std::string ecb_saes_decrypt(std::string base64Input, std::string key) {
  // Decode the input
  std::vector<BYTE> decodedInput = base64_decode(base64Input);

  std::vector<uint16_t> inputWords;

  // transform the input into 16-bit words
  for (size_t i = 0; i < decodedInput.size() - 1; i += 2) {
    char firstChar = decodedInput[i];
    char secondChar = decodedInput[i + 1];

    uint16_t word = (uint8_t) firstChar << 8 | (uint8_t) secondChar;

    inputWords.push_back(word);
  }

  // Decode the key
  std::vector<BYTE> decodedKey = base64_decode(key);

  // Check if the key is 16 bits
  if (decodedKey.size() > 2) {
    std::cout << "A chave deve ter 16 bits" << std::endl;
    return "";
  }

  // Transform the key into a 16-bit word
  uint16_t keyWord = 0;
  for (size_t i = 0; i < decodedKey.size(); i++) {
    keyWord = (keyWord << 8) | decodedKey[i];
  }

  std::vector<uint16_t> outputWords(inputWords.size());

  for (size_t i = 0; i < inputWords.size(); i++) {
    outputWords[i] = saes_decrypt(inputWords[i], keyWord);
  }

  // base64_encode(outputWords);
  std::string outputStr;
  for (size_t i = 0; i < outputWords.size(); i++) {
    char firstChar = (char) (outputWords[i] >> 8) & 0xFF;
    char secondChar = (char) (outputWords[i] & 0xFF);

    outputStr += firstChar;
    outputStr += secondChar;
  }

  // Encode the output string to base64
  std::string output = base64_encode((unsigned char*) outputStr.c_str(), outputStr.size());

  return output;
}

std::string ecb_saes_encrypt(std::string base64Input, std::string key) {
  // Decode the input
  std::vector<BYTE> decodedInput = base64_decode(base64Input);

  // Check if the input is even and add a space if odd
  if (decodedInput.size() % 2) {
    decodedInput.push_back((unsigned char) ' ');
  }

  std::vector<uint16_t> inputWords;

  // Transform the input into 16-bit words
  for (size_t i = 0; i < decodedInput.size() - 1; i += 2) {
    char firstChar = decodedInput[i];
    char secondChar = decodedInput[i + 1];

    uint16_t word = (uint8_t) firstChar << 8 | (uint8_t) secondChar;

    inputWords.push_back(word);
  }

  // Decode the key
  std::vector<BYTE> decodedKey = base64_decode(key);

  // Check if the key is 16 bits
  if (decodedKey.size() > 2) {
    std::cout << "A chave deve ter 16 bits" << std::endl;
    return "";
  }

  // Transform the key into a 16-bit word
  uint16_t keyWord = 0;
  for (size_t i = 0; i < decodedKey.size(); i++) {
    keyWord = (keyWord << 8) | decodedKey[i];
  }

  // Encrypt the input words
  std::vector<uint16_t> outputWords(inputWords.size());
  for (size_t i = 0; i < inputWords.size(); i++) {
    outputWords[i] = saes_encrypt(inputWords[i], keyWord);
  }

  // base64_encode(outputWords);
  std::string outputStr;
  for (const auto& word : outputWords) {
    char firstChar = (char) (word >> 8) & 0xFF;
    char secondChar = (char) (word & 0xFF);

    outputStr += firstChar;
    outputStr += secondChar;
  }

  // Encode the output string to base64
  std::string output = base64_encode((unsigned char*) outputStr.c_str(), outputStr.size());

  return output;
}

void test_saes() {
  std::string input;
  std::string key;

  int operation = 0;

  std::cout << std::endl;

  std::cout << "Escolha a operação: " << std::endl;

  std::cout << "1 - Encrypt" << std::endl;
  std::cout << "2 - Decrypt" << std::endl;

  std::cin >> operation;

  if (operation != 1 && operation != 2) {
    std::cout << "Operação inválida" << std::endl;
    return;
  }

  if (operation == 1) {
    std::cout << "Digite a string base64 a ser encpriptada (até 16bits): ";

    std::cin >> input;

    std::cout << "Digite a chave de 16bits em base64: ";

    std::cin >> key;

    std::string result = saes_encrypt_base64(input, key);

    if (result.empty()) {
      std::cout << "Erro ao cifrar o texto" << std::endl;
      return;
    }

    std::cout << "Texto cifrado em base64: " << result << std::endl;
  } else {
    std::cout << "Digite a string base64 a ser decriptada (até 16bits): ";

    std::cin >> input;

    std::cout << "Digite a chave de 16bits em base64: ";

    std::cin >> key;

    std::string result = saes_decrypt_base64(input, key);

    if (result.empty()) {
      std::cout << "Erro ao decifrar o texto" << std::endl;
      return;
    }

    std::cout << "Texto em claro em base64: " << result << std::endl;
  }
}

void test_saes_ecb() {
  std::string input;
  std::string key;

  int operation = 0;

  std::cout << std::endl;

  std::cout << "Escolha a operação: " << std::endl;

  std::cout << "1 - Encrypt" << std::endl;
  std::cout << "2 - Decrypt" << std::endl;

  std::cin >> operation;

  if (operation != 1 && operation != 2) {
    std::cout << "Operação inválida" << std::endl;
    return;
  }

  if (operation == 1) {
    std::cout << "Digite a string base64 a ser encpriptada: ";

    std::cin >> input;

    std::cout << "Digite a chave de 16bits em base64: ";

    std::cin >> key;

    std::string result = ecb_saes_encrypt(input, key);

    if (result.empty()) {
      std::cout << "Erro ao cifrar o texto" << std::endl;
      return;
    }

    std::cout << "Texto cifrado em base64: " << result << std::endl;
  } else {
    std::cout << "Digite a string base64 a ser decriptada: ";

    std::cin >> input;

    std::cout << "Digite a chave de 16bits em base64: ";

    std::cin >> key;

    std::string result = ecb_saes_decrypt(input, key);

    if (result.empty()) {
      std::cout << "Erro ao decifrar o texto" << std::endl;
      return;
    }

    std::cout << "Texto em claro em base64: " << result << std::endl;
  }
}

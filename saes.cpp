#include <cstdint>
#include <iostream>
#include <vector>

#define GF_MUL_PRECOMPUTED_TERM    0x03

#define NIBBLE_MASK 0x0F

uint8_t Sbox[16] =
{
	0x9,0x4,0xA,0xB,
	0xD,0x1,0x8,0x5,
	0x6,0x2,0x0,0x3,
	0xC,0xE,0xF,0x7
};

uint8_t RCON[2] = { 0x80, 0x30 };

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

std::vector<std::vector<uint8_t> > saes_encrypt_mix_columns(std::vector<std::vector<uint8_t> > currentState) {
  std::vector<std::vector<uint8_t> > result(2, std::vector<uint8_t>(2, 0));

  for (int i = 0; i < 2; i++) {
    for (int j = 0; j < 2; j++) {
      result[i][j] = currentState[i][j] ^ GF_MultiplyBy(currentState[(i + 1) % 2][j], 4);
    }
  }

  return result;
}

std::vector<std::vector<uint8_t> > saes_encrypt_shift_rows(std::vector<std::vector<uint8_t> > currentState) {
  std::vector<std::vector<uint8_t> > result(2, std::vector<uint8_t>(2, 0));

  result[0][0] = currentState[0][0];
  result[0][1] = currentState[0][1];
  result[1][0] = currentState[1][1];
  result[1][1] = currentState[1][0];

  return result;
}

std::vector<std::vector<uint8_t> > saes_encrypt_nibble_substitution(std::vector<std::vector<uint8_t> > currentState) {
  std::vector<std::vector<uint8_t> > result(2, std::vector<uint8_t>(2, 0));

  for (int i = 0; i < 2; i++) {
    for (int j = 0; j < 2; j++) {
      result[i][j] = Sbox[currentState[i][j]];
    }
  }

  return result;
}

std::vector<std::vector<uint8_t> > saes_encrypt_add_round_key(std::vector<std::vector<uint8_t> > currentState, uint16_t key) {
  uint16_t currentStateNumber = convert_state_matrix_to_int(currentState);

  uint16_t newStateNumber = currentStateNumber ^ key;

  return convert_int_to_state_matrix(newStateNumber);
}

void printStateMatrix(std::vector<std::vector<uint8_t> > state) {
  for (int i = 0; i < 2; i++) {
    for (int j = 0; j < 2; j++) {
      std::cout << std::hex << (int)state[i][j] << " ";
    }
    std::cout << std::endl;
  }
}

uint16_t saes_encrypt(uint16_t plainText, uint16_t key) {
  std::vector<std::vector<uint8_t> > state = convert_int_to_state_matrix(plainText);

  std::vector<uint16_t> keys = saes_key_expansion(key);

  for (int i = 0; i < 3; i++) {
    std::cout << "Key " << i << ": " << std::hex << keys[i] << std::endl;
  }

  std::cout << "Initial State: " << std::endl;

  printStateMatrix(state);

  state = saes_encrypt_add_round_key(state, keys[0]); 

  std::cout << "Added roundKey 1: " << std::endl;

  printStateMatrix(state);
  
  state = saes_encrypt_nibble_substitution(state);

  std::cout << "Nibble substitution 1: " << std::endl;

  printStateMatrix(state);

  state = saes_encrypt_shift_rows(state);

  std::cout << "Shift rows 1: " << std::endl;

  printStateMatrix(state);
  
  state = saes_encrypt_mix_columns(state);

  std::cout << "Mix columns 1: " << std::endl;

  printStateMatrix(state);

  state = saes_encrypt_add_round_key(state, keys[1]);

  std::cout << "Added roundKey 2: " << std::endl;

  printStateMatrix(state);

  state = saes_encrypt_nibble_substitution(state);

  std::cout << "Nibble substitution 2: " << std::endl;

  printStateMatrix(state);

  state = saes_encrypt_shift_rows(state);
  
  std::cout << "Shift rows 2: " << std::endl;

  printStateMatrix(state);

  state = saes_encrypt_add_round_key(state, keys[2]);

  std::cout << "Added roundKey 3: " << std::endl;

  printStateMatrix(state);

  uint16_t result = convert_state_matrix_to_int(state);

  std::cout << "Ciphertext: " << std::hex << result << std::endl;

  return result;
}

int main() {
  uint16_t plainText = 0xD728;
  uint16_t key = 0x4AF5;

  std::cout << "Plaintext: " << std::hex << plainText << std::endl;

  std::cout << "Key: " << std::hex << key << std::endl;

  uint16_t cipherText = saes_encrypt(plainText, key);

  std::cout << "Ciphertext: " << std::hex << cipherText << std::endl;

  return 0;
}


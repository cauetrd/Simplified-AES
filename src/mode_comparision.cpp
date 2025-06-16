/**
 * @file mode_comparision.cpp
 * @brief AES encryption mode comparison
 * @author Vinícius da Silva Araujo & Cauê Trindade
 * @date 2025-06-09
 * 
 * This program compares the runtime and safety of different AES encryption modes using the Crypto++ library.
 */

#include "mode_comparision.h"
#include "rijndael.h"
#include "cryptlib.h"
#include "modes.h"
#include "files.h"
#include "osrng.h"
#include "hex.h"
#include "base64.h"

#include <string>


/**************************************** CTR mode ****************************************/

std::string CTR_mode_AES_encryption(
    const std::string& plain,
    const CryptoPP::SecByteBlock& key,
    const CryptoPP::SecByteBlock& iv
) {
  using namespace CryptoPP;

  std::string cipher;
  try {
      CTR_Mode< AES >::Encryption e;
      e.SetKeyWithIV(key, key.size(), iv);

      StringSource s(plain, true, 
          new StreamTransformationFilter(e,
              new Base64Encoder(
                new StringSink(cipher),
                false
              )
          ) // StreamTransformationFilter
      ); // StringSource
  } catch(const Exception& e) {
      std::cerr << e.what() << std::endl;
      exit(1);
  }

  return cipher;
}

std::string CTR_mode_AES_decryption(
    const std::string& cipher,
    const CryptoPP::SecByteBlock& key,
    const CryptoPP::SecByteBlock& iv
) {
  using namespace CryptoPP;

  std::string recovered;

  try {
      CTR_Mode< AES >::Decryption d;
      d.SetKeyWithIV(key, key.size(), iv);

      StringSource s(cipher, true, 
          new Base64Decoder(
              new StreamTransformationFilter(d,
                  new StringSink(recovered)
              ) // StreamTransformationFilter
          ) // Base64Decoder
      ); // StringSource
  } catch(const Exception& e) {
      std::cerr << e.what() << std::endl;
      exit(1);
  }

  return recovered;
}

/**************************************** OFB mode ****************************************/

std::string OFB_mode_AES_encryption(
    const std::string& plain,
    const CryptoPP::SecByteBlock& key,
    const CryptoPP::SecByteBlock& iv
) {
  using namespace CryptoPP;

  std::string cipher;
  try {
      OFB_Mode< AES >::Encryption e;
      e.SetKeyWithIV(key, key.size(), iv);

      StringSource s(plain, true, 
          new StreamTransformationFilter(e,
              new Base64Encoder(
                new StringSink(cipher),
                false
              )
          ) // StreamTransformationFilter
      ); // StringSource
  } catch(const Exception& e) {
      std::cerr << e.what() << std::endl;
      exit(1);
  }

  return cipher;
}

std::string OFB_mode_AES_decryption(
    const std::string& cipher,
    const CryptoPP::SecByteBlock& key,
    const CryptoPP::SecByteBlock& iv
) {
  using namespace CryptoPP;

  std::string recovered;

  try {
      OFB_Mode< AES >::Decryption d;
      d.SetKeyWithIV(key, key.size(), iv);

      StringSource s(cipher, true, 
          new Base64Decoder(
              new StreamTransformationFilter(d,
                  new StringSink(recovered)
              ) // StreamTransformationFilter
          ) // Base64Decoder
      ); // StringSource
  } catch(const Exception& e) {
      std::cerr << e.what() << std::endl;
      exit(1);
  }

  return recovered;
}

/**************************************** CFB mode ****************************************/

std::string CFB_mode_AES_encryption(
    const std::string& plain,
    const CryptoPP::SecByteBlock& key,
    const CryptoPP::SecByteBlock& iv
) 
{
  using namespace CryptoPP;

  std::string cipher;
  try
  {
      CFB_Mode< AES >::Encryption e;
      e.SetKeyWithIV(key, key.size(), iv);

      StringSource s(plain, true, 
          new StreamTransformationFilter(e,
              new Base64Encoder(
                new StringSink(cipher),
                false
              )
          ) // StreamTransformationFilter
      ); // StringSource
  }
  catch(const Exception& e)
  {
      std::cerr << e.what() << std::endl;
      exit(1);
  }

  return cipher;
}

std::string CFB_mode_AES_decryption(
    const std::string& cipher,
    const CryptoPP::SecByteBlock& key,
    const CryptoPP::SecByteBlock& iv
) {
  using namespace CryptoPP;

  std::string recovered;

  try {
      CFB_Mode< AES >::Decryption d;
      d.SetKeyWithIV(key, key.size(), iv);

      StringSource s(cipher, true, 
          new Base64Decoder(
              new StreamTransformationFilter(d,
                  new StringSink(recovered)
              ) // StreamTransformationFilter
          ) // Base64Decoder
      ); // StringSource
  } catch(const Exception& e) {
      std::cerr << e.what() << std::endl;
      exit(1);
  }

  return recovered;
}

/**************************************** ECB mode ****************************************/

std::string ECB_mode_AES_encryption(
    const std::string& plain,
    const CryptoPP::SecByteBlock& key
) 
{
  using namespace CryptoPP;

  std::string cipher;
  try
  {
      ECB_Mode< AES >::Encryption e;
      e.SetKey(key, key.size());

      StringSource s(plain, true, 
          new StreamTransformationFilter(e,
              new Base64Encoder(
                new StringSink(cipher),
                false
              )
          ) // StreamTransformationFilter
      ); // StringSource
  }
  catch(const Exception& e)
  {
      std::cerr << e.what() << std::endl;
      exit(1);
  }

  return cipher;
}

std::string ECB_mode_AES_decryption(
    const std::string& cipher,
    const CryptoPP::SecByteBlock& key
) {
  using namespace CryptoPP;

  std::string recovered;

  try {
      ECB_Mode< AES >::Decryption d;
      d.SetKey(key, key.size());

      StringSource s(cipher, true, 
          new Base64Decoder(
              new StreamTransformationFilter(d,
                  new StringSink(recovered)
              ) // StreamTransformationFilter
          ) // Base64Decoder
      ); // StringSource
  } catch(const Exception& e) {
      std::cerr << e.what() << std::endl;
      exit(1);
  }

  return recovered;
}

/**************************************** CBC mode ****************************************/

std::string CBC_mode_AES_encryption(
    const std::string& plain,
    const CryptoPP::SecByteBlock& key,
    const CryptoPP::SecByteBlock& iv
) 
{
  using namespace CryptoPP;

  std::string cipher;
  try
  {
      CBC_Mode< AES >::Encryption e;
      e.SetKeyWithIV(key, key.size(), iv);

      StringSource s(plain, true, 
          new StreamTransformationFilter(e,
              new Base64Encoder(
                new StringSink(cipher),
                false
              )
          ) // StreamTransformationFilter
      ); // StringSource
  }
  catch(const Exception& e)
  {
      std::cerr << e.what() << std::endl;
      exit(1);
  }

  return cipher;
}

std::string CBC_mode_AES_decryption(
    const std::string& cipher,
    const CryptoPP::SecByteBlock& key,
    const CryptoPP::SecByteBlock& iv
) {
  using namespace CryptoPP;

  std::string recovered;

  try {
      CBC_Mode< AES >::Decryption d;
      d.SetKeyWithIV(key, key.size(), iv);
      StringSource s(cipher, true, 
          new Base64Decoder(
              new StreamTransformationFilter(d,
                  new StringSink(recovered)
              ) // StreamTransformationFilter
          ) // Base64Decoder
      ); // StringSource
  }
  catch(const Exception& e)
  {
      std::cerr << e.what() << std::endl;
      exit(1);
  }

  return recovered;
}

std::vector<long> get_mode_duration(bool print, std::string input) 
{
  using namespace CryptoPP;

  AutoSeededRandomPool prng;

  SecByteBlock key(AES::DEFAULT_KEYLENGTH);
  SecByteBlock iv(AES::BLOCKSIZE);

  prng.GenerateBlock(key, key.size());
  prng.GenerateBlock(iv, iv.size());

  std::string plain = "Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet. ";
  std::string cipher;

    if (input.size() > 0) {
        plain = input;
    }

  std::vector<long> durations;

  /*********************************\
   * ECB mode
  \*********************************/

  auto p1_ecb = std::chrono::system_clock::now();

  cipher = ECB_mode_AES_encryption(plain, key);

  auto p2_ecb = std::chrono::system_clock::now();

  auto ecb_duration = std::chrono::duration_cast<std::chrono::microseconds>(p2_ecb - p1_ecb).count();

  durations.push_back(ecb_duration);
  
  if (print) {
    std::cout << "ECB mode:" << std::endl;
    std::cout << "CipherText base64: " << cipher << std::endl;
  }

  /*********************************\
   * CBC mode
  \*********************************/

  auto p1_cbc = std::chrono::system_clock::now();

  cipher = CBC_mode_AES_encryption(plain, key, iv);

  auto p2_cbc = std::chrono::system_clock::now();

  auto cbc_duration = std::chrono::duration_cast<std::chrono::microseconds>(p2_cbc - p1_cbc).count();

  durations.push_back(cbc_duration);

  if (print) {
    std::cout << "CBC mode:" << std::endl;
    std::cout << "CipherText base64: " << cipher << std::endl;
  }

  /*********************************\
   * CFB mode
  \*********************************/

  auto p1_cfb = std::chrono::system_clock::now();

  cipher = CFB_mode_AES_encryption(plain, key, iv);

  auto p2_cfb = std::chrono::system_clock::now();

  auto cfb_duration = std::chrono::duration_cast<std::chrono::microseconds>(p2_cfb - p1_cfb).count();

  durations.push_back(cfb_duration);

  if (print) {
    std::cout << "CFB mode:" << std::endl;
    std::cout << "CipherText base64: " << cipher << std::endl;
  }

  /*********************************\
   * OFB mode
  \*********************************/

  auto p1_ofb = std::chrono::system_clock::now();

  cipher = OFB_mode_AES_encryption(plain, key, iv);

  auto p2_ofb = std::chrono::system_clock::now();

  auto ofb_duration = std::chrono::duration_cast<std::chrono::microseconds>(p2_ofb - p1_ofb).count();

  durations.push_back(ofb_duration);

  if (print) {
    std::cout << "OFB mode:" << std::endl;
    std::cout << "CipherText base64: " << cipher << std::endl;
  }

  /*********************************\
   * CTR mode
  \*********************************/

  auto p1_ctr = std::chrono::system_clock::now();

  cipher = CTR_mode_AES_encryption(plain, key, iv);

  auto p2_ctr = std::chrono::system_clock::now();

  auto ctr_duration = std::chrono::duration_cast<std::chrono::microseconds>(p2_ctr - p1_ctr).count();

  durations.push_back(ctr_duration);

  if (print) {
    std::cout << "CTR mode:" << std::endl;
    std::cout << "CipherText base64: " << cipher << std::endl;
}
  
  return durations;
}

void test_mode_comp() 
{
  using namespace CryptoPP;

  std::cout << "Como deseja testar os modos de criptografia?" << std::endl;
  std::cout << "1. Testar com uma entrada padrão" << std::endl;
  std::cout << "2. Testar com uma entrada específica" << std::endl;

  int choice;
  std::cin>> choice;

  if(choice != 1 && choice != 2) {
    std::cout << "Opção inválida. Saindo do programa." << std::endl;
    return;
  }

  std::string input ="";
if(choice == 2) {
    std::cin.ignore();
    std::getline(std::cin, input);
}
  get_mode_duration(true,input);

  std::vector<long> durations(5, 0);

  for (int i = 0; i < 1000; i++) {
    auto d = get_mode_duration(false,input);

    durations[0] += d[0];
    durations[1] += d[1];
    durations[2] += d[2];
    durations[3] += d[3];
    durations[4] += d[4];
  }

  for (int i = 0; i < 5; i++) {
    durations[i] /= 1000;
  }

  std::cout << "Média de duração para 1000 execuções (in microseconds):" << std::endl;
  std::cout << "ECB: " << durations[0] << std::endl;
  std::cout << "CBC: " << durations[1] << std::endl;
  std::cout << "CFB: " << durations[2] << std::endl;
  std::cout << "OFB: " << durations[3] << std::endl;
  std::cout << "CTR: " << durations[4] << std::endl;
}

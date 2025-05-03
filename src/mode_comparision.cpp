/**
 * @file mode_comparision.cpp
 * @brief AES encryption mode comparison
 * @author Vinícius da Silva Araujo
 * @date 2025-05-01
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

#include <string>


/**************************************** CTR mode ****************************************/

std::string CTR_mode_AES_encryption(
    const std::string& plain,
    const CryptoPP::SecByteBlock& key,
    const CryptoPP::SecByteBlock& iv
) 
{
  using namespace CryptoPP;

  std::string cipher;
  try
  {
      CTR_Mode< AES >::Encryption e;
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

  return cipher;
}

std::string CTR_mode_AES_decryption(
    const std::string& cipher,
    const CryptoPP::SecByteBlock& key,
    const CryptoPP::SecByteBlock& iv
) 
{
  using namespace CryptoPP;

  std::string recovered;

  try
  {
      CTR_Mode< AES >::Decryption d;
      d.SetKeyWithIV(key, key.size(), iv);

      StringSource s(cipher, true, 
          new StreamTransformationFilter(d,
              new StringSink(recovered)
          ) // StreamTransformationFilter
      ); // StringSource

  }
  catch(const Exception& e)
  {
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
) 
{
  using namespace CryptoPP;

  std::string cipher;
  try
  {
      OFB_Mode< AES >::Encryption e;
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

  return cipher;
}

std::string OFB_mode_AES_decryption(
    const std::string& cipher,
    const CryptoPP::SecByteBlock& key,
    const CryptoPP::SecByteBlock& iv
) 
{
  using namespace CryptoPP;

  std::string recovered;

  try
  {
      OFB_Mode< AES >::Decryption d;
      d.SetKeyWithIV(key, key.size(), iv);

      StringSource s(cipher, true, 
          new StreamTransformationFilter(d,
              new StringSink(recovered)
          ) // StreamTransformationFilter
      ); // StringSource

  }
  catch(const Exception& e)
  {
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
              new StringSink(cipher)
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
) 
{
  using namespace CryptoPP;

  std::string recovered;

  try
  {
      CFB_Mode< AES >::Decryption d;
      d.SetKeyWithIV(key, key.size(), iv);

      StringSource s(cipher, true, 
          new StreamTransformationFilter(d,
              new StringSink(recovered)
          ) // StreamTransformationFilter
      ); // StringSource

  }
  catch(const Exception& e)
  {
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
              new StringSink(cipher)
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
) 
{
  using namespace CryptoPP;

  std::string recovered;

  try
  {
      ECB_Mode< AES >::Decryption d;
      d.SetKey(key, key.size());

      StringSource s(cipher, true, 
          new StreamTransformationFilter(d,
              new StringSink(recovered)
          ) // StreamTransformationFilter
      ); // StringSource

  }
  catch(const Exception& e)
  {
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
              new StringSink(cipher)
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
) 
{
  using namespace CryptoPP;

  std::string recovered;

  try
  {
      CBC_Mode< AES >::Decryption d;
      d.SetKeyWithIV(key, key.size(), iv);

      StringSource s(cipher, true, 
          new StreamTransformationFilter(d,
              new StringSink(recovered)
          ) // StreamTransformationFilter
      ); // StringSource

  }
  catch(const Exception& e)
  {
      std::cerr << e.what() << std::endl;
      exit(1);
  }

  return recovered;
}

std::vector<long> get_mode_duration() 
{
  using namespace CryptoPP;

  AutoSeededRandomPool prng;
  HexEncoder encoder(new FileSink(std::cout));
  BaseN_Encoder base64_encoder(new FileSink(std::cout));

  SecByteBlock key(AES::DEFAULT_KEYLENGTH);
  SecByteBlock iv(AES::BLOCKSIZE);

  prng.GenerateBlock(key, key.size());
  prng.GenerateBlock(iv, iv.size());

  std::string plain = "ZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMuZXhhbXBsZWZpbGUuY29tfFlvdXJFeGFtcGxlRmlsZXMu";

  std::string cipher;

  std::vector<long> durations;

  /*********************************\
   * ECB mode
  \*********************************/

  auto p1_ecb = std::chrono::system_clock::now();

  cipher = ECB_mode_AES_encryption(plain, key);

  auto p2_ecb = std::chrono::system_clock::now();

  auto ecb_duration = std::chrono::duration_cast<std::chrono::microseconds>(p2_ecb - p1_ecb).count();

  durations.push_back(ecb_duration);

  /*********************************\
   * CBC mode
  \*********************************/

  auto p1_cbc = std::chrono::system_clock::now();

  cipher = CBC_mode_AES_encryption(plain, key, iv);

  auto p2_cbc = std::chrono::system_clock::now();

  auto cbc_duration = std::chrono::duration_cast<std::chrono::microseconds>(p2_cbc - p1_cbc).count();

  durations.push_back(cbc_duration);

  /*********************************\
   * CFB mode
  \*********************************/

  auto p1_cfb = std::chrono::system_clock::now();

  cipher = CFB_mode_AES_encryption(plain, key, iv);

  auto p2_cfb = std::chrono::system_clock::now();

  auto cfb_duration = std::chrono::duration_cast<std::chrono::microseconds>(p2_cfb - p1_cfb).count();

  durations.push_back(cfb_duration);

  /*********************************\
   * OFB mode
  \*********************************/

  auto p1_ofb = std::chrono::system_clock::now();

  cipher = OFB_mode_AES_encryption(plain, key, iv);

  auto p2_ofb = std::chrono::system_clock::now();

  auto ofb_duration = std::chrono::duration_cast<std::chrono::microseconds>(p2_ofb - p1_ofb).count();

  durations.push_back(ofb_duration);

  /*********************************\
   * CTR mode
  \*********************************/

  auto p1_ctr = std::chrono::system_clock::now();

  cipher = CTR_mode_AES_encryption(plain, key, iv);

  auto p2_ctr = std::chrono::system_clock::now();

  auto ctr_duration = std::chrono::duration_cast<std::chrono::microseconds>(p2_ctr - p1_ctr).count();

  durations.push_back(ctr_duration);

  return durations;
}

void test_mode_comp() 
{
  using namespace CryptoPP;

  std::vector<long> durations(5, 0);

  for (int i = 0; i < 100; i++) {
    auto d = get_mode_duration();

    durations[0] += d[0];
    durations[1] += d[1];
    durations[2] += d[2];
    durations[3] += d[3];
    durations[4] += d[4];
  }

  for (int i = 0; i < 5; i++) {
    durations[i] /= 100;
  }

  std::cout << "Média de duração (in microseconds):" << std::endl;
  std::cout << "ECB: " << durations[0] << std::endl;
  std::cout << "CBC: " << durations[1] << std::endl;
  std::cout << "CFB: " << durations[2] << std::endl;
  std::cout << "OFB: " << durations[3] << std::endl;
  std::cout << "CTR: " << durations[4] << std::endl;
}

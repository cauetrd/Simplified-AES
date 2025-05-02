/**
 * @file mode_comparision.cpp
 * @brief AES encryption mode comparison
 * @author Vinícius da Silva Araujo
 * @date 2025-05-01
 * 
 * This program compares the runtime and safety of different AES encryption modes using the Crypto++ library.
 */

#include "cryptopp/basecode.h"
#include <cryptopp/rijndael.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/modes.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>


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

void print_cipher(const std::string& cipher)
{
  using namespace CryptoPP;

  HexEncoder encoder(new FileSink(std::cout));
  BaseN_Encoder base64_encoder(new FileSink(std::cout));

  std::cout << "cipher text hex: ";
  encoder.Put((const byte*)&cipher[0], cipher.size());
  encoder.MessageEnd();
  std::cout << std::endl;
}

void test() 
{
  using namespace CryptoPP;

  AutoSeededRandomPool prng;
  HexEncoder encoder(new FileSink(std::cout));
  BaseN_Encoder base64_encoder(new FileSink(std::cout));

  SecByteBlock key(AES::DEFAULT_KEYLENGTH);
  SecByteBlock iv(AES::BLOCKSIZE);

  prng.GenerateBlock(key, key.size());
  prng.GenerateBlock(iv, iv.size());

  std::string plain = "examplefile.com|YourExampleFiles.examplefile.com|YourExampleFiles.examplefile.com|YourExampleFiles.examplefile.com|YourExampleFiles.examplefile.com|YourExampleFiles.examplefile.com|YourExampleFiles.examplefile.com|YourExampleFiles.examplefile.com|YourExampleFiles.examplefile.com|YourExampleFiles.examplefile.com|YourExampleFiles.examplefile.com|YourExampleFiles.examplefile.com|YourExampleFiles.examplefile.com|YourExampleFiles.examplefile.com|YourExampleFiles.examplefile.com|YourExampleFiles.examplefile.com|YourExampleFiles.examplefile.com|YourExampleFiles.examplefile.com|YourExampleFiles.examplefile.com|YourExampleFiles.examplefile.com|YourExampleFiles.examplefile.com|YourExampleFiles.examplefile.com|YourExampleFiles.examplefile.com|YourExampleFiles.examplefile.com|YourExampleFiles.examplefile.com|YourExampleFiles.examplefile.com|YourExampleFiles.examplefile.com|YourExampleFiles.examplefile.com|YourExampleFiles.examplefile.com|YourExampleFiles.examplefile.com|YourExampleFiles.";

  std::string cipher, recovered;

  std::cout << "plain text: " << plain << std::endl;

  std::cout << "key: ";
  encoder.Put(key, key.size());
  encoder.MessageEnd();
  std::cout << std::endl;

  std::cout << "iv: ";
  encoder.Put(iv, iv.size());
  encoder.MessageEnd();
  std::cout << std::endl;

  /*********************************\
   * ECB mode
  \*********************************/

  auto p1 = std::chrono::system_clock::now();

  cipher = ECB_mode_AES_encryption(plain, key);

  auto p2 = std::chrono::system_clock::now();

  std::cout << "ECB mode encryption time: "
            << std::chrono::duration_cast<std::chrono::microseconds>(p2 - p1).count()
            << " microseconds" << std::endl;

  print_cipher(cipher);

  /*********************************\
   * CBC mode
  \*********************************/

  p1 = std::chrono::system_clock::now();

  cipher = CBC_mode_AES_encryption(plain, key, iv);

  p2 = std::chrono::system_clock::now();

  std::cout << "CBC mode encryption time: "
            << std::chrono::duration_cast<std::chrono::microseconds>(p2 - p1).count()
            << " microseconds" << std::endl;

  print_cipher(cipher);

  /*********************************\
   * CFB mode
  \*********************************/

  p1 = std::chrono::system_clock::now();

  cipher = CFB_mode_AES_encryption(plain, key, iv);

  p2 = std::chrono::system_clock::now();

  std::cout << "CFB mode encryption time: "
            << std::chrono::duration_cast<std::chrono::microseconds>(p2 - p1).count()
            << " microseconds" << std::endl;

  print_cipher(cipher);

  /*********************************\
   * OFB mode
  \*********************************/

  p1 = std::chrono::system_clock::now();

  cipher = OFB_mode_AES_encryption(plain, key, iv);

  p2 = std::chrono::system_clock::now();

  std::cout << "OFB mode encryption time: "
            << std::chrono::duration_cast<std::chrono::microseconds>(p2 - p1).count()
            << " microseconds" << std::endl;

  print_cipher(cipher);

  /*********************************\
   * CTR mode
  \*********************************/

  p1 = std::chrono::system_clock::now();

  cipher = CTR_mode_AES_encryption(plain, key, iv);

  p2 = std::chrono::system_clock::now();

  std::cout << "CTR mode encryption time: "
            << std::chrono::duration_cast<std::chrono::microseconds>(p2 - p1).count()
            << " microseconds" << std::endl;

  print_cipher(cipher);
}

int main(int argc, char* argv[])
{
  test();

  return 0;
}

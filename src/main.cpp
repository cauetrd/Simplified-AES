#include "saes.h"
#include "mode_comparision.h"
#include <iostream>

int main() {
  int operation;

  std::cout << "Bem vindo ao programa SAES do vini" << std::endl;

  std::cout << "Por favor selecione uma operação" << std::endl;

  std::cout << "1. Testar o programa SAES" << std::endl;

  std::cout << "2. Testar o programa SAES_ECB" << std::endl;

  std::cout << "3. Compare os diferentes modos de opereração do AES" << std::endl;

  std::cout << "4. Sair" << std::endl;

  std::cin >> operation;

  switch(operation) {
    case 1:
      test_saes();
      break;
    case 2:
      test_saes_ecb();
      break;
    case 3:
      test_mode_comp();
      break;
    case 4:
      std::cout << "Saindo do programa..." << std::endl;
      return 0;
    default:
      std::cout << "Operação inválida. Tente novamente." << std::endl;
  }

  return 0;
}

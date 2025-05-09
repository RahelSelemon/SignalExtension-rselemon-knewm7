#pragma once

#include <iostream>
#include <mutex>

#include <boost/chrono.hpp>
#include <boost/thread.hpp>
#include <crypto++/cryptlib.h>
#include <crypto++/dh.h>
#include <crypto++/dh2.h>
#include <crypto++/integer.h>
#include <crypto++/nbtheory.h>
#include <crypto++/osrng.h>

#include "../../include-shared/messages.hpp"
#include "../../include/drivers/cli_driver.hpp"
#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/network_driver.hpp"

class Client {
public:
  Client(std::shared_ptr<NetworkDriver> network_driver,
         std::shared_ptr<CryptoDriver> crypto_driver);
  void prepare_keys(CryptoPP::DH DH_obj,
                    CryptoPP::SecByteBlock DH_private_value,
                    CryptoPP::SecByteBlock DH_other_public_value);
  Message_Message send(std::string plaintext);
  std::pair<std::string, bool> receive(Message_Message ciphertext);
  void run(std::string command);
  void HandleKeyExchange(std::string command);

  // Expose internal state for testing

// private:
  void ReceiveThread();
  void SendThread();

  CryptoPP::SecByteBlock get_CKs() { return CKs; }
  int get_Ns() { return Ns; }
  int get_PN() { return PN; }

  std::mutex mtx;

  std::shared_ptr<CLIDriver> cli_driver;
  std::shared_ptr<CryptoDriver> crypto_driver;
  std::shared_ptr<NetworkDriver> network_driver;

  SecByteBlock AES_key;
  SecByteBlock HMAC_key;
  
  SecByteBlock root_key;

  // DH Ratchet Fields
  DHParams_Message DH_params;
  bool DH_switched;
  SecByteBlock DH_current_private_value;
  SecByteBlock DH_current_public_value;
  SecByteBlock DH_last_other_public_value;
 
  // // Chain Ratchet Fields 
  // These fields are made public for testing 
  CryptoPP::SecByteBlock CKs; // Chain key for sending
  CryptoPP::SecByteBlock CKr; // Chain key for receiving
  int Ns = 0;                 // Number of messages sent in current sending chain
  int Nr = 0;                 // Number of messages received in current receiving chain
  int PN = 0;                 // Number of messages in previous sending chain

  // Skipped message keys (indexed by ratchet pub key + message number)
  std::map<std::string, CryptoPP::SecByteBlock> MKSKIPPED;
  const int MAX_SKIP = 1000;

};

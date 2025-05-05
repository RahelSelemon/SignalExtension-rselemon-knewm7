#include "../../include/pkg/client.hpp"

#include <sys/ioctl.h>

#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

#include "../../include-shared/util.hpp"
#include "colors.hpp"

/**
 * Constructor. Sets up TCP socket and starts REPL
 * @param network_driver NetworkDriver to handle network operations i.e. sending and receiving msgs 
 * @param crypto_driver CryptoDriver to handle crypto related functionality
 */
Client::Client(std::shared_ptr<NetworkDriver> network_driver,
               std::shared_ptr<CryptoDriver> crypto_driver) {
  // Make shared variables.
  this->cli_driver = std::make_shared<CLIDriver>();
  this->crypto_driver = crypto_driver;
  this->network_driver = network_driver;
}

/**
 * Generates a new DH secret and replaces the keys. This function should:
 * 1) Call `DH_generate_shared_key`
 * 2) Use the resulting key in `AES_generate_key` and `HMAC_generate_key`
 * 3) Update private key variables
 */
void Client::prepare_keys(CryptoPP::DH DH_obj,
                          CryptoPP::SecByteBlock DH_private_value,
                          CryptoPP::SecByteBlock DH_other_public_value) {
  // TODO: implement me!

  CryptoPP::SecByteBlock DH_shared_key = crypto_driver->DH_generate_shared_key(DH_obj, DH_private_value, DH_other_public_value);
  this->AES_key = crypto_driver->AES_generate_key(DH_shared_key);

  this->HMAC_key = crypto_driver->HMAC_generate_key(DH_shared_key);


}

/**
 * Encrypts the given message and returns a Message struct. This function
 * should:
 * 1) Check if the DH Ratchet keys need to change; if so, update them.
 * 2) Encrypt and tag the message.
 */
// Message_Message Client::send(std::string plaintext) {
//   // Grab the lock to avoid race conditions between the receive and send threads
//   // Lock will automatically release at the end of the function.
//   std::unique_lock<std::mutex> lck(this->mtx);

//   // TODO: implement me!

//   if (this->DH_switched) {
//     // DHParams_Message DH = crypto_driver->DH_generate_params();
//     auto [DH_obj, DH_private_value, DH_public_value] = crypto_driver->DH_initialize(this->DH_params);
    
//     Client::prepare_keys(DH_obj, DH_private_value, this->DH_last_other_public_value);

//     this->DH_current_private_value = DH_private_value;
//     this->DH_current_public_value = DH_public_value;
//     this->DH_switched = false; 
//   }

//   auto [ciphertext, iv] = crypto_driver->AES_encrypt(this->AES_key, plaintext);
//   std::string hmac = crypto_driver->HMAC_generate(this->HMAC_key, concat_msg_fields(iv,ciphertext));
//   Message_Message msg;

//   msg.iv = iv;
//   msg.mac = hmac;
//   msg.ciphertext = ciphertext;
//   msg.public_value = this->DH_current_public_value;

//   this->DH_switched = true;


//   return msg;

// }

//Rewritten for project

Message_Message Client::send(std::string plaintext) {
  if(this->DH_switched) {
    this->PN = this->Ns;
    auto [DH_obj, DH_private_value, DH_public_value] = crypto_driver->DH_initialize(this->DH_params);
    this->prepare_keys(DH_obj, DH_private_value, this->DH_last_other_public_value);

    this->DH_current_private_value = DH_private_value;
    this->DH_current_public_value = DH_public_value;
    this->DH_switched = false;
    this->Ns = 0; // Reset message number for new chain
    
  }

  SecByteBlock MK = crypto_driver->HMAC_generate_key_with_byte(this->CKs, 0x01);
  this->CKs = crypto_driver->HMAC_generate_key_with_byte(this->CKs, 0x02);

  // Encrypt and tag
  auto [ciphertext, iv] = crypto_driver->AES_encrypt(MK, plaintext);
  std::string hmac = crypto_driver->HMAC_generate(MK, concat_msg_fields(iv, ciphertext));

  // Build message
  Message_Message msg;
  msg.iv = iv;
  msg.mac = hmac;
  msg.ciphertext = ciphertext;
  msg.public_value = this->DH_current_public_value;
  msg.pn = this->PN;
  msg.n = this->Ns;

  this->Ns += 1;
  this->DH_switched = true;

  return msg;
}

/**
 * Decrypts the given Message into a tuple containing the plaintext and
 * an indicator if the MAC was valid (true if valid; false otherwise).
 * 1) Check if the DH Ratchet keys need to change; if so, update them.
 * 2) Decrypt and verify the message.
 */
// std::pair<std::string, bool> Client::receive(Message_Message msg) {
//     // Grab the lock to avoid race conditions between the receive and send threads
//     std::unique_lock<std::mutex> lck(this->mtx);

//     if (msg.public_value != this->DH_last_other_public_value) {
//         this->DH_last_other_public_value = msg.public_value;  
//         this->DH_switched = true;  

//         // DHParams_Message DH = crypto_driver->DH_generate_params();
//         auto [DH_obj, _, __] = crypto_driver->DH_initialize(this->DH_params);

//         this->prepare_keys(DH_obj, this->DH_current_private_value, this->DH_last_other_public_value);

//         this->DH_switched = false;
//     }

//     std::string concatenated_msg = concat_msg_fields(msg.iv, msg.ciphertext);
//     bool mac_valid = crypto_driver->HMAC_verify(this->HMAC_key, concatenated_msg, msg.mac);
//     if (!mac_valid) {
//         return {"", false}; 
//     }

//     std::string plaintext = crypto_driver->AES_decrypt(this->AES_key, msg.iv, msg.ciphertext);

//     return {plaintext, true};  
// }

//Function rewritten for project
std::pair<std::string, bool> Client::receive(Message_Message msg) {
  std::unique_lock<std::mutex> lck(this->mtx);
  //DH Ratchet if new public key
  if (msg.public_value != this->DH_last_other_public_value) {
    this->DH_last_other_public_value = msg.public_value;
    this->DH_switched = true;

    auto [DH_obj, _, __] = crypto_driver->DH_initialize(this->DH_params);
    this->prepare_keys(DH_obj, this->DH_current_private_value, this->DH_last_other_public_value);

    this->DH_switched = false;
    this->Nr = 0; // reset message number
  }

  // Handle skipped messages
  std::string key_id = byteblock_to_string(msg.public_value) + std::to_string(msg.n);
  if (this->MKSKIPPED.find(key_id) != this->MKSKIPPED.end()) {
    SecByteBlock MK = this->MKSKIPPED[key_id];
    this->MKSKIPPED.erase(key_id);

    std::string concat = concat_msg_fields(msg.iv, msg.ciphertext);
    bool valid = crypto_driver->HMAC_verify(MK, concat, msg.mac);
    if (!valid) return {"", false};
    return {crypto_driver->AES_decrypt(MK, msg.iv, msg.ciphertext), true};
  }

  // If message number is too far ahead, derive skipped keys
  if (msg.n - this->Nr > this->MAX_SKIP) {
    throw std::runtime_error("Too many skipped messages.");
  }

  while (this->Nr < msg.n) {
    SecByteBlock MKskipped = crypto_driver->HMAC_generate_key_with_byte(this->CKr, 0x01);
    this->CKr = crypto_driver->HMAC_generate_key_with_byte(this->CKr, 0x02);

    std::string skip_id = byteblock_to_string(msg.public_value) + std::to_string(this->Nr);
    this->MKSKIPPED[skip_id] = MKskipped;
    this->Nr++;
  }
  // Use current CKr to derive MK for this message
  SecByteBlock MK = crypto_driver->HMAC_generate_key_with_byte(this->CKr, 0x01);
  this->CKr = crypto_driver->HMAC_generate_key_with_byte(this->CKr, 0x02);
  this->Nr++;

  std::string concat = concat_msg_fields(msg.iv, msg.ciphertext);
  bool valid = crypto_driver->HMAC_verify(MK, concat, msg.mac);
  if (!valid) return {"", false};

  return {crypto_driver->AES_decrypt(MK, msg.iv, msg.ciphertext), true};


}

/**
 * Run the client.
 */
void Client::run(std::string command) {
  // Initialize cli_driver.
  this->cli_driver->init();

  // Run key exchange.
  this->HandleKeyExchange(command);

  // Start msgListener thread.
  boost::thread msgListener =
      boost::thread(boost::bind(&Client::ReceiveThread, this));
  msgListener.detach();

  // Start sending thread.
  this->SendThread();
}

/**
 * Run key exchange. This function:
 * 1) Listen for or generate and send DHParams_Message depending on `command`.
 * `command` can be either "listen" or "connect"; the listener should `read()`
 * for params, and the connector should generate and send params.
 * 2) Initialize DH object and keys
 * 3) Send your public value
 * 4) Listen for the other party's public value
 * 5) Generate DH, AES, and HMAC keys and set local variables
 */
void Client::HandleKeyExchange(std::string command) {
    std::cout << "[DEBUG] Starting HandleKeyExchange..." << std::endl;

    if (command == "listen") {
        std::vector<unsigned char> received_data = network_driver->read();

        this->DH_params.deserialize(received_data);


    } else if (command == "connect") {
        this->DH_params = crypto_driver->DH_generate_params();

        // Send DHParams_Message to the peer
        std::vector<unsigned char> msg_data;
        DH_params.serialize(msg_data);
        network_driver->send(msg_data);
    }

    auto [DH_obj, DH_private_value, DH_public_value] = crypto_driver->DH_initialize(this->DH_params);

    PublicValue_Message pub_msg;
    pub_msg.public_value = DH_public_value;
    
    std::vector<unsigned char> msg_data;
    
    pub_msg.serialize(msg_data);
    network_driver->send(msg_data);
    // std::cout << "[DEBUG] Sent PublicValue_Message (public key) to peer." << std::endl;

    // 4. Listen for the other party's public value
    std::vector<unsigned char> their_msg_data = network_driver->read();
    // std::cout << "[DEBUG] Received PublicValue_Message (public key) from peer." << std::endl;

    PublicValue_Message other_pub;
    other_pub.deserialize(their_msg_data);

    this->DH_last_other_public_value = other_pub.public_value;
    this->prepare_keys(DH_obj, DH_private_value, other_pub.public_value);


    this->DH_current_private_value = DH_private_value;
    this->DH_current_public_value = DH_public_value;
    
    this->DH_switched = false; 


}
/**
 * Listen for messages and print to cli_driver.
 */
void Client::ReceiveThread() {
  while (true) {
    // Try reading data from the other user.
    std::vector<unsigned char> data;
    try {
      data = this->network_driver->read();
    } catch (std::runtime_error &_) {
      // Exit cleanly.
      this->cli_driver->print_left("Received EOF; closing connection");
      this->network_driver->disconnect();
      return;
    }

    // Deserialize, decrypt, and verify message.
    Message_Message msg;
    msg.deserialize(data);
    auto decrypted_data = this->receive(msg);
    if (!decrypted_data.second) {
      this->cli_driver->print_left("Received invalid HMAC; the following "
                                   "message may have been tampered with.");
      throw std::runtime_error("Received invalid MAC!");
    }
    this->cli_driver->print_left(std::get<0>(decrypted_data));
  }
}

/**
 * Listen for stdin and send to other party.
 */
void Client::SendThread() {
  std::string plaintext;
  while (true) {
    // Read from STDIN.
    std::getline(std::cin, plaintext);
    if (std::cin.eof()) {
      this->cli_driver->print_left("Received EOF; closing connection");
      this->network_driver->disconnect();
      return;
    }

    // Encrypt and send message.
    if (plaintext != "") {
      Message_Message msg = this->send(plaintext);
      std::vector<unsigned char> data;
      msg.serialize(data);
      this->network_driver->send(data);
    }
    this->cli_driver->print_right(plaintext);
  }
}
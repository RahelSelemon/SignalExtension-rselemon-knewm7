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
Client::Client(std::shared_ptr<NetworkDriver> network_driver, std::shared_ptr<CryptoDriver> crypto_driver) {
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
// void Client::prepare_keys(CryptoPP::DH DH_obj, CryptoPP::SecByteBlock DH_private_value,
//  CryptoPP::SecByteBlock DH_other_public_value) {
//   // TODO: implement me!

//   CryptoPP::SecByteBlock DH_shared_key = crypto_driver->DH_generate_shared_key(DH_obj, DH_private_value, DH_other_public_value);
//   // this->AES_key = crypto_driver->AES_generate_key(DH_shared_key);
//   // this->HMAC_key = crypto_driver->HMAC_generate_key(DH_shared_key);

//   // KDF root key → derive new root key and receiving chain key
//   auto [new_root_key, new_CKr] = crypto_driver->KDF_RK(this->root_key, DH_shared_key);

//   this->root_key = new_root_key;
//   this->CKr = new_CKr;

//   // Generate fresh sending chain key (CKs) for new key pair
//   this->CKs = crypto_driver->HMAC_generate_key_with_byte(this->root_key, 0xFF); // or use another salt/tag if needed
// }
void Client::prepare_keys(CryptoPP::DH DH_obj,
                          CryptoPP::SecByteBlock DH_private_value,
                          CryptoPP::SecByteBlock DH_other_public_value) {
  // Step 1: DH shared secret
  CryptoPP::SecByteBlock DH_shared_key =
      crypto_driver->DH_generate_shared_key(DH_obj, DH_private_value, DH_other_public_value);

  // Step 2: KDF_RK → update root key and chain key
  auto [new_root_key, chain_key] =
      crypto_driver->KDF_RK(this->root_key, DH_shared_key);

  // Step 3: Save the new keys
  this->root_key = new_root_key;
  this->CKr = chain_key;
  this->CKs = chain_key;  // Initially the same — will diverge after DH ratchet
}

//Rewritten for project
Message_Message Client::send(std::string plaintext) {
  if(this->DH_switched) {
    this->DH_switched = false;

    auto [DH_obj, DH_private_value, DH_public_value] = crypto_driver->DH_initialize(this->DH_params);
    this->prepare_keys(DH_obj, DH_private_value, this->DH_last_other_public_value);
    this->DH_current_private_value = DH_private_value;
    this->DH_current_public_value = DH_public_value;

    this->PN = this->Ns;
    this->Ns = 0; // Reset message number for new chain
    
  }

  SecByteBlock MK_enc = crypto_driver->HMAC_generate_key_with_byte(this->CKs, 0x01);
  SecByteBlock CK_next = crypto_driver->HMAC_generate_key_with_byte(this->CKs, 0x02);
  // SecByteBlock MK_mac = crypto_driver->HMAC_generate_key_with_byte(this->CKs, 0x03);
  this->CKs = CK_next;

  // Encrypt and tag
  auto [ciphertext, iv] = crypto_driver->AES_encrypt(MK_enc, plaintext);
  std::string hmac = crypto_driver->HMAC_generate(MK_enc, concat_msg_fields(iv, ciphertext));

  // Build message
  Message_Message msg;
  msg.iv = iv;
  msg.mac = hmac;
  msg.ciphertext = ciphertext;
  msg.public_value = this->DH_current_public_value;
  msg.pn = this->PN;
  msg.n = this->Ns;

  this->Ns += 1;
  std::cout << "[DEBUG] Derived MK (send/recv): " << byteblock_to_hex(MK_enc) << std::endl;
  // std::cout << "[DEBUG] Derived MK (send/recv): " << byteblock_to_hex(MK_mac) << std::endl;

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

    auto [DH_obj, _, __] = crypto_driver->DH_initialize(this->DH_params);
    this->prepare_keys(DH_obj, this->DH_current_private_value, this->DH_last_other_public_value);

    this->Nr = 0; // reset message number

    this->DH_switched = true;
  }

  // Handle skipped messages
  std::string key_id = byteblock_to_string(msg.public_value) + std::to_string(msg.n);
  if (this->MKSKIPPED.find(key_id) != this->MKSKIPPED.end()) {
    SecByteBlock MK = this->MKSKIPPED[key_id];
    this->MKSKIPPED.erase(key_id);

    std::string concat = concat_msg_fields(msg.iv, msg.ciphertext);
    bool valid = crypto_driver->HMAC_verify(MK, concat, msg.mac);
    if (!valid) {
      throw std::runtime_error("invalid skipped message detected!!!");
      //return {"", false};
    } 
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

  std::cout << "[DEBUG] Derived MK (send/recv): " << byteblock_to_hex(MK) << std::endl;


  std::string concat = concat_msg_fields(msg.iv, msg.ciphertext);
  bool valid = crypto_driver->HMAC_verify(MK, concat, msg.mac);
  if (!valid){
      // std::cerr << "FAILED HMAC: expected=" << crypto_driver->HMAC_generate(MK, concat)
      //       << " vs received=" << msg.mac << std::endl;
      // std::cout << "made it here!!!" << std::endl;

    throw std::runtime_error("invalid message detected!!!");
    // return {"", false};
  } 

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

    // After prepare_keys, initialize symmetric ratchets
    // SecByteBlock DH_shared_key = crypto_driver->DH_generate_shared_key(DH_obj, DH_private_value, other_pub.public_value);
    // this->CKs = crypto_driver->HMAC_generate_key_with_byte(DH_shared_key, 0x10);  // for sending
    // this->CKr = crypto_driver->HMAC_generate_key_with_byte(DH_shared_key, 0x11);  // for receiving

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
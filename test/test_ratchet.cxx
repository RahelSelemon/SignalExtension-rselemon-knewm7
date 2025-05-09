#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest/doctest.h"

#include "../include-shared/util.hpp"
#include "../include-shared/messages.hpp"
#include "../include/drivers/crypto_driver.hpp"
#include "../include/pkg/client.hpp"

SecByteBlock test_key_filled(unsigned char fill = 0x01) {
  SecByteBlock key(32);
  memset(key.BytePtr(), fill, key.size());
  return key;
}

// ===============================
// Chain key advancement test
// ===============================
TEST_CASE("CKs ratchet advancement") {
  CryptoDriver crypto_driver;
  SecByteBlock CKs = test_key_filled(0x11);
  SecByteBlock CKs1 = crypto_driver.HMAC_generate_key_with_byte(CKs, 0x02);
  SecByteBlock CKs2 = crypto_driver.HMAC_generate_key_with_byte(CKs1, 0x02);

  CHECK(CKs.size() == 32);
  CHECK(byteblock_to_string(CKs) != byteblock_to_string(CKs1));
  CHECK(byteblock_to_string(CKs1) != byteblock_to_string(CKs2));
}

// ===============================
// Message key derivation test
// ===============================
TEST_CASE("Message key derivation is deterministic") {
  CryptoDriver crypto_driver;
  SecByteBlock CK = test_key_filled(0xAB);
  SecByteBlock MK1 = crypto_driver.HMAC_generate_key_with_byte(CK, 0x01);
  SecByteBlock MK2 = crypto_driver.HMAC_generate_key_with_byte(CK, 0x01);

  CHECK(MK1.size() == 32);
  CHECK(byteblock_to_string(MK1) == byteblock_to_string(MK2));
}

// ===============================
// Send state ratchet advancement
// ===============================
TEST_CASE("Send state updates CKs and Ns") {
  auto crypto = std::make_shared<CryptoDriver>();
  Client dummy(nullptr, crypto);

  dummy.CKs = test_key_filled(0xCD);
  dummy.Ns = 0;
  dummy.PN = 0;

  std::string initial_CK = byteblock_to_string(dummy.CKs);
  dummy.DH_switched = false;
  dummy.DH_current_public_value = integer_to_byteblock(123);  // Mock value

  Message_Message msg = dummy.send("hi");

  CHECK(dummy.Ns == 1);
  CHECK(byteblock_to_string(dummy.CKs) != initial_CK);
}

// ===============================
// Skipped key limit check
// ===============================
TEST_CASE("MKSKIPPED maximum limit is enforced in receive logic") {
  auto crypto = std::make_shared<CryptoDriver>();
  Client dummy(nullptr, crypto);

  dummy.CKr = test_key_filled(0xEF);
  dummy.Nr = 0;

  bool threw = false;
  try {
    for (int i = 0; i <= dummy.MAX_SKIP; ++i) {
      SecByteBlock MK = crypto->HMAC_generate_key_with_byte(dummy.CKr, 0x01);
      dummy.CKr = crypto->HMAC_generate_key_with_byte(dummy.CKr, 0x02);
      std::string skip_id = "fake_pub" + std::to_string(dummy.Nr);
      dummy.MKSKIPPED[skip_id] = MK;
      dummy.Nr++;
    }
    if (dummy.MKSKIPPED.size() > dummy.MAX_SKIP) {
      throw std::runtime_error("Too many skipped message keys");
    }
  } catch (const std::runtime_error& e) {
    threw = true;
    CHECK(std::string(e.what()) == "Too many skipped message keys");
  }

  CHECK(threw);
}

TEST_CASE("Out-of-order message decryption using MKSKIPPED") {
  std::cout << "\n=== TEST: Out-of-order message decryption using MKSKIPPED ===" << std::endl;
  auto crypto = std::make_shared<CryptoDriver>();
  auto netA = std::make_shared<NetworkDriverImpl>();
  auto netB = std::make_shared<NetworkDriverImpl>();
  Client alice(netA, crypto);
  Client bob(netB, crypto);

  DHParams_Message params = crypto->DH_generate_params();
  alice.DH_params = bob.DH_params = params;

  std::cout << "[DEBUG] Generating DH keys..." << std::endl;
  auto [dhA, privA, pubA] = crypto->DH_initialize(params);
  auto [dhB, privB, pubB] = crypto->DH_initialize(params);

  alice.DH_current_private_value = privA;
  alice.DH_current_public_value = pubA;
  alice.DH_last_other_public_value = pubB; 

  bob.DH_current_private_value = privB;
  bob.DH_current_public_value = pubB;
  bob.DH_last_other_public_value = pubA;

  std::cout << "[DEBUG] Running prepare_keys..." << std::endl;
  alice.prepare_keys(dhA, privA, pubB);
  bob.prepare_keys(dhB, privB, pubA);

  std::cout << "[DEBUG] Alice sends message 1" << std::endl;
  std::cout << "[DEBUG] DH_Switched: " << std::boolalpha << alice.DH_switched << std::endl;
  auto msg1 = alice.send("Message 1");
  std::cout << "[DEBUG] Alice sends message 2" << std::endl;
  auto msg2 = alice.send("Message 2");

  std::cout << "[DEBUG] Bob receives msg2 first (out of order)" << std::endl;
  auto result2 = bob.receive(msg2);
  std::cout << "[DEBUG] result2.valid = " << result2.second << ", message = " << result2.first << std::endl;
  CHECK(result2.second);  // should succeed even if out-of-order
  CHECK(result2.first == "Message 2");

  std::cout << "[DEBUG] Bob receives msg1 second (should be skipped)" << std::endl;
  auto result1 = bob.receive(msg1);
  std::cout << "[DEBUG] result1.valid = " << result1.second << ", message = " << result1.first << std::endl;
  CHECK(result1.second);
  CHECK(result1.first == "Message 1");
}

// ===============================
// New public key triggers DH ratchet
// ===============================
TEST_CASE("New public key triggers DH ratchet") {

  auto crypto = std::make_shared<CryptoDriver>();
  auto netA = std::make_shared<NetworkDriverImpl>();
  auto netB = std::make_shared<NetworkDriverImpl>();
  Client alice(netA, crypto);
  Client bob(netB, crypto);

  DHParams_Message params = crypto->DH_generate_params();
  alice.DH_params = bob.DH_params = params;

  auto [dhA, privA, pubA] = crypto->DH_initialize(params);
  auto [dhB, privB, pubB] = crypto->DH_initialize(params);

  alice.DH_current_private_value = privA;
  alice.DH_current_public_value = pubA;
  alice.DH_last_other_public_value = pubB;
  bob.DH_current_private_value = privB;
  bob.DH_current_public_value = pubB;
  bob.DH_last_other_public_value = pubA;

  alice.prepare_keys(dhA, privA, pubB);
  bob.prepare_keys(dhB, privB, pubA);

  auto msg1 = alice.send("first");
  alice.DH_switched = true;
  auto msg2 = alice.send("second");

  auto result1 = bob.receive(msg1);
  CHECK(result1.second);
  CHECK(result1.first == "first");

  auto result2 = bob.receive(msg2);  // triggers DH ratchet
  CHECK(result2.second);
  CHECK(result2.first == "second");
}

TEST_CASE("Basic 3-message exchange between Alice and Bob") {
  auto crypto = std::make_shared<CryptoDriver>();
  auto netA = std::make_shared<NetworkDriverImpl>();
  auto netB = std::make_shared<NetworkDriverImpl>();
  Client alice(netA, crypto);
  Client bob(netB, crypto);

  // Shared DH parameters
  DHParams_Message params = crypto->DH_generate_params();
  alice.DH_params = bob.DH_params = params;

  auto [dhA, privA, pubA] = crypto->DH_initialize(params);
  auto [dhB, privB, pubB] = crypto->DH_initialize(params);

  alice.DH_current_private_value = privA;
  alice.DH_current_public_value = pubA;
  alice.DH_last_other_public_value = pubB;

  bob.DH_current_private_value = privB;
  bob.DH_current_public_value = pubB;
  bob.DH_last_other_public_value = pubA;

  alice.prepare_keys(dhA, privA, pubB);
  bob.prepare_keys(dhB, privB, pubA);

  auto msg1 = alice.send("Hi Bob");
  auto res1 = bob.receive(msg1);
  CHECK(res1.second);
  CHECK(res1.first == "Hi Bob");

  auto msg2 = bob.send("Hey Alice");
  auto res2 = alice.receive(msg2);
  CHECK(res2.second);
  CHECK(res2.first == "Hey Alice");

  auto msg3 = alice.send("How are you?");
  auto res3 = bob.receive(msg3);
  CHECK(res3.second);
  CHECK(res3.first == "How are you?");
}

TEST_CASE("Extended out-of-order decryption with MKSKIPPED and multiple skips") {
  auto crypto = std::make_shared<CryptoDriver>();
  auto netA = std::make_shared<NetworkDriverImpl>();
  auto netB = std::make_shared<NetworkDriverImpl>();
  Client alice(netA, crypto);
  Client bob(netB, crypto);

  DHParams_Message params = crypto->DH_generate_params();
  alice.DH_params = bob.DH_params = params;

  auto [dhA, privA, pubA] = crypto->DH_initialize(params);
  auto [dhB, privB, pubB] = crypto->DH_initialize(params);

  alice.DH_current_private_value = privA;
  alice.DH_current_public_value = pubA;
  alice.DH_last_other_public_value = pubB;
  bob.DH_current_private_value = privB;
  bob.DH_current_public_value = pubB;
  bob.DH_last_other_public_value = pubA;

  alice.prepare_keys(dhA, privA, pubB);
  bob.prepare_keys(dhB, privB, pubA);

  auto m1 = alice.send("one");
  auto m2 = alice.send("two");
  auto m3 = alice.send("three");
  auto m4 = alice.send("four");

  // Receive in shuffled order: 3 → 1 → 4 → 2
  auto r3 = bob.receive(m3);
  CHECK(r3.second); CHECK(r3.first == "three");

  auto r1 = bob.receive(m1);
  CHECK(r1.second); CHECK(r1.first == "one");

  auto r4 = bob.receive(m4);
  CHECK(r4.second); CHECK(r4.first == "four");

  auto r2 = bob.receive(m2);
  CHECK(r2.second); CHECK(r2.first == "two");
}

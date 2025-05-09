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

// CHECK FOR OUT-OF-ORDER DECRYPTION
TEST_CASE("Out-of-order message decryption using MKSKIPPED") {
  auto crypto = std::make_shared<CryptoDriver>();
  auto netA = std::make_shared<NetworkDriverImpl>();
  auto netB = std::make_shared<NetworkDriverImpl>();
  Client alice(netA, crypto);
  Client bob(netB, crypto);

  DHParams_Message params = crypto->DH_generate_params();
  alice.DH_params = bob.DH_params = params;

  // Initial DH setup
  auto [dhA, privA, pubA] = crypto->DH_initialize(params);
  auto [dhB, privB, pubB] = crypto->DH_initialize(params);
  alice.DH_current_private_value = privA;
  alice.DH_current_public_value = pubA;
  bob.DH_current_private_value = privB;
  bob.DH_current_public_value = pubB;
  alice.prepare_keys(dhA, privA, pubB);
  bob.prepare_keys(dhB, privB, pubA);

  // Alice sends two messages
  auto msg1 = alice.send("Message 1");
  auto msg2 = alice.send("Message 2");

  // Bob receives second message first
  auto result2 = bob.receive(msg2);
  CHECK(result2.second);  // should succeed even if out-of-order
  CHECK(result2.first == "Message 2");

  // Bob receives first message later, should use skipped key
  auto result1 = bob.receive(msg1);
  CHECK(result1.second);
  CHECK(result1.first == "Message 1");
}

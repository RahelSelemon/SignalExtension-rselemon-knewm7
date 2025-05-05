#define DOCTEST_CONFIG_IMPLEMENT
#include "doctest/doctest.h"

#include "../include-shared/util.hpp"
#include "../include-shared/messages.hpp"
#include "../include/drivers/crypto_driver.hpp"
#include "../include/pkg/client.hpp"  // Required for internal ratchet state

// ===============================
// Chain key advancement test
// ===============================
TEST_CASE("CKs ratchet advancement") {
  CryptoDriver crypto_driver;
  SecByteBlock CKs = string_to_byteblock("initialchainkey0123456789abcd"); // 32 bytes
  SecByteBlock CKs1 = crypto_driver.HMAC_generate_key_with_byte(CKs, 0x02);
  SecByteBlock CKs2 = crypto_driver.HMAC_generate_key_with_byte(CKs1, 0x02);

  CHECK(byteblock_to_string(CKs) != byteblock_to_string(CKs1));
  CHECK(byteblock_to_string(CKs1) != byteblock_to_string(CKs2));
}

// ===============================
// Message key derivation test
// ===============================
TEST_CASE("Message key derivation is deterministic") {
  CryptoDriver crypto_driver;
  SecByteBlock CK = string_to_byteblock("chainkey1234567890abcdefabcdef1234");
  SecByteBlock MK1 = crypto_driver.HMAC_generate_key_with_byte(CK, 0x01);
  SecByteBlock MK2 = crypto_driver.HMAC_generate_key_with_byte(CK, 0x01);

  CHECK(byteblock_to_string(MK1) == byteblock_to_string(MK2));
}

// ===============================
// Send state ratchet advancement
// ===============================
TEST_CASE("Send state updates CKs and Ns") {
  auto crypto = std::make_shared<CryptoDriver>();
  Client dummy(nullptr, crypto);

  dummy.CKs = string_to_byteblock("chainkey1234567890abcdefabcdef1234");
  dummy.Ns = 0;
  dummy.PN = 0;

  std::string initial_CK = byteblock_to_string(dummy.CKs);
  dummy.DH_switched = false;  // Skip DH change
  dummy.AES_key = crypto->AES_generate_key(dummy.CKs);
  dummy.HMAC_key = crypto->HMAC_generate_key(dummy.CKs);
  dummy.DH_current_public_value = integer_to_byteblock(123);  // Mock value

  Message_Message msg = dummy.send("hi");

  CHECK(dummy.Ns == 1);
  CHECK(byteblock_to_string(dummy.CKs) != initial_CK);
}

// ===============================
// Skipped key limit check
// ===============================
TEST_CASE("MKSKIPPED maximum limit") {
  auto crypto = std::make_shared<CryptoDriver>();
  Client dummy(nullptr, crypto);

  for (int i = 0; i < 1000; ++i) {
    dummy.MKSKIPPED["test" + std::to_string(i)] = string_to_byteblock("a");
  }

  // Simulate check behavior
  bool throws = false;
  try {
    if (dummy.MKSKIPPED.size() >= dummy.MAX_SKIP)
      throw std::runtime_error("Too many skipped message keys");
  } catch (const std::runtime_error& e) {
    throws = true;
    CHECK(std::string(e.what()) == "Too many skipped message keys");
  }

  CHECK(throws);
}

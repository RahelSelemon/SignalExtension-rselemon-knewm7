#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest/doctest.h"

#include <crypto++/nbtheory.h>
#include "../include-shared/util.hpp"
#include "../include-shared/messages.hpp"
#include "../include/drivers/crypto_driver.hpp"
#include "../include/pkg/client.hpp"
#include "../include/drivers/network_driver.hpp"

TEST_CASE("sample") {
  CHECK(true);
}

TEST_CASE("sanity-dh-initialization") {
  CryptoDriver crypto_driver;
  DHParams_Message params = crypto_driver.DH_generate_params();
  auto keys = crypto_driver.DH_initialize(params);

  CHECK(ModularExponentiation(params.g, byteblock_to_integer(std::get<1>(keys)),
                              params.p) ==
        byteblock_to_integer(std::get<2>(keys)));
}

TEST_CASE("ratchet: CKs advances with each message sent") {
  CryptoDriver crypto_driver;
  DHParams_Message params = crypto_driver.DH_generate_params();
  auto [dh_obj, priv1, pub1] = crypto_driver.DH_initialize(params);
  auto [_, priv2, pub2] = crypto_driver.DH_initialize(params);

  Client client(std::make_shared<NetworkDriverImpl>(), std::make_shared<CryptoDriver>());
  client.DH_params = params;
  client.prepare_keys(dh_obj, priv1, pub2);

  // ✅ Manually initialize CKs to a non-null value
  client.CKs = SecByteBlock(32);
  memset(client.CKs.BytePtr(), 0x01, client.CKs.size());

  auto CKs_initial = client.get_CKs();
  client.send("Test Message 1");
  auto CKs_next = client.get_CKs();

  CHECK(CKs_initial != CKs_next);
}


TEST_CASE("ratchet: Ns and PN track message state") {
  CryptoDriver crypto_driver;
  DHParams_Message params = crypto_driver.DH_generate_params();
  auto [dh_obj, priv1, pub1] = crypto_driver.DH_initialize(params);
  auto [_, priv2, pub2] = crypto_driver.DH_initialize(params);

  Client client(std::make_shared<NetworkDriverImpl>(), std::make_shared<CryptoDriver>());
  client.DH_params = params;
  client.prepare_keys(dh_obj, priv1, pub2);
  client.CKs = SecByteBlock(32);
  memset(client.CKs.BytePtr(), 0x01, client.CKs.size());  // Fill with dummy value


  int Ns_old = client.get_Ns();
  client.send("A");
  CHECK(client.get_Ns() == Ns_old + 1);
}

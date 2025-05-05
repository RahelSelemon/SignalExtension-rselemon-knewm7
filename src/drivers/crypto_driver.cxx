#include <stdexcept>

#include "../../include-shared/util.hpp"
#include "../../include/drivers/crypto_driver.hpp"

using namespace CryptoPP;

/**
 * @brief Returns (p, q, g) DH parameters. This function should:
 * 1) Initialize a `CryptoPP::AutoSeededRandomPool` object
 *    and a `CryptoPP::PrimeAndGenerator` object.
 * 2) Generate a prime p, sub-prime q, and generator g
 *    using `CryptoPP::PrimeAndGenerator::Generate(...)`
 *    with a `delta` of 1, a `pbits` of 512, and a `qbits` of 511.
 * 3) Store and return the parameters in a `DHParams_Message` object.
 * @note In practice, DH should have a prime p with 2048 bits and order q
 * with ~2047 bits. You are welcome to put these values into PrimeAndGenerator,
 * although you will notice that generating these primes frequently is very
 * expensive. Something optional to consider - how could you speed up this
 * process?
 * @return `DHParams_Message` object that stores Diffie-Hellman parameters
 */
DHParams_Message CryptoDriver::DH_generate_params() {
  // TODO: implement me!

  CryptoPP::AutoSeededRandomPool prng;
  CryptoPP::Integer p, q, g;
  CryptoPP::PrimeAndGenerator pg;

  
  pg.Generate(1, prng, 512, 511);
  p = pg.Prime();
  q = pg.SubPrime();
  g = pg.Generator();


  DHParams_Message dh_params;
  dh_params.p = p;
  dh_params.q = q;
  dh_params.g = g;


  return dh_params;
}

/**
 * @brief Generate DH keypair. This function should
 * 1) Create a DH object and `SecByteBlock`s for the private and public keys.
 * Use `DH_obj.PrivateKeyLength()` and `PublicKeyLength()` to get key sizes.
 * 2) Generate a DH keypair using the `GenerateKeyPair(...)` method.
 * @param DH_params Diffie-Hellman parameters
 * @return Tuple containing DH object, private value, public value.
 */
std::tuple<DH, SecByteBlock, SecByteBlock>
CryptoDriver::DH_initialize(const DHParams_Message &DH_params) {
  // TODO: implement me!


  CryptoPP::DH dh(DH_params.p, DH_params.q, DH_params.g);
  CryptoPP::SecByteBlock pu(dh.PublicKeyLength()), pr(dh.PrivateKeyLength());

  CryptoPP::AutoSeededRandomPool prng;
  dh.GenerateKeyPair(prng, pr, pu);

  return std::make_tuple(dh, pr, pu);

}

/**
 * @brief Generates a shared secret. This function should
 * 1) Allocate space in a `SecByteBlock` of size `DH_obj.AgreedValueLength()`.
 * 2) Run `DH_obj.Agree(...)` to store the shared key in the allocated space.
 * 3) Throw an `std::runtime_error` if failed to agree.
 * @param DH_obj Diffie-Hellman object
 * @param DH_private_value user's private value for Diffie-Hellman
 * @param DH_other_public_value other user's public value for Diffie-Hellman
 * @return Diffie-Hellman shared key
 */
SecByteBlock CryptoDriver::DH_generate_shared_key(
    const DH &DH_obj, const SecByteBlock &DH_private_value,
    const SecByteBlock &DH_other_public_value) {
  // TODO: implement me!

  CryptoPP::SecByteBlock shared(DH_obj.AgreedValueLength());

  if(!DH_obj.Agree(shared, DH_private_value, DH_other_public_value))
	  throw std::runtime_error("DH key sharing failed");

  return shared;

}

/**
 * @brief Generates AES key using HKDF with a salt. This function should
 * 1) Allocate a `SecByteBlock` of size `AES::DEFAULT_KEYLENGTH`.
 * 2) Use an `HKDF<SHA256>` to derive and return a key for AES using the
 * provided salt. See the `DeriveKey` function. (Use NULL for the "info"
 * argument and 0 for "infolen".)
 * 3) Important tip: use .size() on a SecByteBlock instead of sizeof()
 * @param DH_shared_key Diffie-Hellman shared key
 * @return AES key
 */
SecByteBlock CryptoDriver::AES_generate_key(const SecByteBlock &DH_shared_key) {
  std::string aes_salt_str("salt0000");
  SecByteBlock aes_salt((const unsigned char *)(aes_salt_str.data()),
                        aes_salt_str.size());
  // TODO: implement me!

  CryptoPP::SecByteBlock blk(AES::DEFAULT_KEYLENGTH);


  CryptoPP::HKDF<SHA256> hkdf;
  hkdf.DeriveKey(blk, blk.size(), DH_shared_key, DH_shared_key.size(), aes_salt, aes_salt.size(), NULL, 0);


  return blk;

}

/**
 * @brief Encrypts the given plaintext. This function should:
 * 1) Initialize `CBC_Mode<AES>::Encryption` using GetNextIV and SetKeyWithIV.
 * 1.5) IV should be of size `AES::BLOCKSIZE`
 * 2) Run the plaintext through a `StreamTransformationFilter` using
 * the AES encryptor.
 * 3) Return ciphertext and iv used in encryption or throw an
 * `std::runtime_error`.
 * 4) Important tip: use .size() on a SecByteBlock instead of sizeof()
 * @param key AES key
 * @param plaintext text to encrypt
 * @return Pair of ciphertext and iv
 */
std::pair<std::string, SecByteBlock>
CryptoDriver::AES_encrypt(SecByteBlock key, std::string plaintext) {
  try {
    // TODO: implement me!

    // std::cout << "plain text: " << plaintext << std::endl;

    CryptoPP::SecByteBlock iv(AES::BLOCKSIZE);
    
    // rndm.GenerateBlock(iv, iv.size());
    CBC_Mode<AES>::Encryption ec;
    CryptoPP::AutoSeededRandomPool rndm;
    // rndm.GenerateBlock(iv, iv.size());
    ec.GetNextIV(rndm, iv);
    ec.SetKeyWithIV(key, key.size(), iv);


    std::string cipher;
    CryptoPP::StringSource s(plaintext, true, new CryptoPP::StreamTransformationFilter(ec, new CryptoPP::StringSink(cipher)));
    return {cipher, iv};

  } catch (CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    std::cerr << "This function was likely called with an incorrect shared key."
              << std::endl;
    throw std::runtime_error("CryptoDriver AES encryption failed.");
  }
}

/**
 * @brief Decrypts the given ciphertext, encoded as a hex string. This function
 * should:
 * 1) Initialize `CBC_Mode<AES>::Decryption` using `SetKeyWithIV` on the key and
 * iv. 2) Run the decoded ciphertext through a `StreamTransformationFilter`
 * using the AES decryptor.
 * 3) Return the plaintext or throw an `std::runtime_error`.
 * 4) Important tip: use .size() on a SecByteBlock instead of sizeof()
 * @param key AES key
 * @param iv iv used in encryption
 * @param ciphertext text to decrypt
 * @return decrypted message
 */
std::string CryptoDriver::AES_decrypt(SecByteBlock key, SecByteBlock iv,
                                      std::string ciphertext) {
  try {
    

    CBC_Mode<AES>::Decryption decryptor;
    decryptor.SetKeyWithIV(key, key.size(), iv);

    std::string plaintext;
    CryptoPP::StringSource sc(ciphertext, true,
        new CryptoPP::StreamTransformationFilter(decryptor,
            new CryptoPP::StringSink(plaintext)));

    return plaintext;

  } catch (CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    std::cerr << "This function was likely called with an incorrect shared key."
              << std::endl;
    throw std::runtime_error("CryptoDriver AES decryption failed.");
  }
}

/**
 * @brief Generates an HMAC key using HKDF with a salt. This function should
 * 1) Allocate a `SecByteBlock` of size `SHA256::BLOCKSIZE` for the shared key.
 * 2) Use an `HKDF<SHA256>` to derive and return a key for HMAC using the
 * provided salt. See the `DeriveKey` function.
 * 3) Important tip: use .size() on a SecByteBlock instead of sizeof()
 * @param DH_shared_key shared key from Diffie-Hellman
 * @return HMAC key
 */
SecByteBlock
CryptoDriver::HMAC_generate_key(const SecByteBlock &DH_shared_key) {
  std::string hmac_salt_str("salt0001");
  SecByteBlock hmac_salt((const unsigned char *)(hmac_salt_str.data()),
                         hmac_salt_str.size());
  // TODO: implement me!

  CryptoPP::SecByteBlock shared_key(SHA256::BLOCKSIZE);
  CryptoPP::HKDF<SHA256> hkdf;
  hkdf.DeriveKey(shared_key, shared_key.size(), DH_shared_key, DH_shared_key.size(), hmac_salt, hmac_salt.size(), NULL, 0);

  return shared_key;

}

/**
 * @brief Given a ciphertext, generates an HMAC. This function should
 * 1) Initialize an HMAC<SHA256> with the provided key.
 * 2) Run the ciphertext through a `HashFilter` to generate an HMAC.
 * 3) Throw `std::runtime_error` upon failure.
 * @param key HMAC key
 * @param ciphertext message to tag
 * @return HMAC (Hashed Message Authentication Code)
 */
std::string CryptoDriver::HMAC_generate(SecByteBlock key,
                                        std::string ciphertext) {
  try {
    // TODO: implement me!

    
    CryptoPP::HMAC<SHA256> hmac(key, key.size());

    std::string mc;
    CryptoPP::StringSource(ciphertext, true, new CryptoPP::HashFilter(hmac, new CryptoPP::StringSink(mc)));

    return mc; // Return computed HMAC
    

  } catch (const CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    throw std::runtime_error("CryptoDriver HMAC generation failed.");
  }
}

/**
 * @brief Given a message and MAC, checks if the MAC is valid. This function
 * should 1) Initialize an `HMAC<SHA256>` with the provided key. 2) Run the
 * message through a `HashVerificationFilter` to verify the HMAC. 3) Return
 * false upon failure.
 * @param key HMAC key
 * @param ciphertext message to verify
 * @param mac associated MAC
 * @return true if MAC is valid, else false
 */
bool CryptoDriver::HMAC_verify(SecByteBlock key, std::string ciphertext,
                               std::string mac) {
  try {
    // TODO: implement me!

    CryptoPP::HMAC<SHA256> hmac(key, key.size());
    std::string combined = ciphertext + mac; 

    CryptoPP::StringSource(combined, true, new CryptoPP::HashVerificationFilter(hmac, NULL, CryptoPP::HashVerificationFilter::THROW_EXCEPTION | CryptoPP::HashVerificationFilter::HASH_AT_END));
    return true;

  } catch (const CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    return false;
  }
}

std::pair<SecByteBlock, SecByteBlock>
CryptoDriver::KDF_CK(const SecByteBlock &CK) {
  CryptoPP::HKDF<SHA256> hkdf;
  SecByteBlock CK_new(32);
  SecByteBlock MK(32);

  std::string info_ck = "ratchet_chain_ck";
  std::string info_mk = "ratchet_chain_mk";

  hkdf.DeriveKey(CK_new, CK_new.size(), CK, CK.size(),
                 (const byte*)info_ck.data(), info_ck.size(), NULL, 0);
  hkdf.DeriveKey(MK, MK.size(), CK, CK.size(),
                 (const byte*)info_mk.data(), info_mk.size(), NULL, 0);
  return {CK_new, MK};
}

SecByteBlock CryptoDriver::HMAC_generate_key_with_byte(const SecByteBlock &key_material, unsigned char byte) {
  // Use byte as salt 
  std::string salt_str(1, byte);  // Single byte string
  SecByteBlock salt((const unsigned char*)salt_str.data(), salt_str.size());

  // Allocate space for the HMAC key
  SecByteBlock hmac_key(32);

  // HKDF with SHA256
  CryptoPP::HKDF<SHA256> hkdf;
  hkdf.DeriveKey(hmac_key, hmac_key.size(),
                 key_material, key_material.size(),
                 salt, salt.size(),
                 nullptr, 0);

  return hmac_key;
}



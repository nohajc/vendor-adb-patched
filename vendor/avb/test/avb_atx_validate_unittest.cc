/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <string.h>

#include <base/files/file_util.h>
#include <gtest/gtest.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <libavb_atx/libavb_atx.h>

#include "avb_unittest_util.h"
#include "fake_avb_ops.h"

namespace {

const char kMetadataPath[] = "test/data/atx_metadata.bin";
const char kPermanentAttributesPath[] =
    "test/data/atx_permanent_attributes.bin";
const char kPRKPrivateKeyPath[] = "test/data/testkey_atx_prk.pem";
const char kPIKPrivateKeyPath[] = "test/data/testkey_atx_pik.pem";
const char kPSKPrivateKeyPath[] = "test/data/testkey_atx_psk.pem";
const char kPUKPrivateKeyPath[] = "test/data/testkey_atx_puk.pem";
const char kUnlockChallengePath[] = "test/data/atx_unlock_challenge.bin";
const char kUnlockCredentialPath[] = "test/data/atx_unlock_credential.bin";

class ScopedRSA {
 public:
  ScopedRSA(const char* pem_key_path) {
    FILE* file = fopen(pem_key_path, "r");
    rsa_ = PEM_read_RSAPrivateKey(file, nullptr, nullptr, nullptr);
    fclose(file);
  }

  ~ScopedRSA() {
    if (rsa_) {
      RSA_free(rsa_);
    }
  }

  // PKCS #1 v1.5 signature using SHA512. Returns true on success.
  bool Sign(const void* data_to_sign, size_t length, uint8_t signature[]) {
    uint8_t digest[AVB_SHA512_DIGEST_SIZE];
    const unsigned char* data_to_sign_buf =
        reinterpret_cast<const unsigned char*>(data_to_sign);
    SHA512(data_to_sign_buf, length, digest);
    unsigned int signature_length = 0;
    return (1 == RSA_sign(NID_sha512,
                          digest,
                          AVB_SHA512_DIGEST_SIZE,
                          signature,
                          &signature_length,
                          rsa_));
  }

 private:
  RSA* rsa_;
};

} /* namespace */

namespace avb {

class AvbAtxValidateTest : public ::testing::Test,
                           public FakeAvbOpsDelegateWithDefaults {
 public:
  ~AvbAtxValidateTest() override {}

  void SetUp() override {
    ReadDefaultData();
    ops_.set_delegate(this);
    ops_.set_permanent_attributes(attributes_);
    ops_.set_stored_rollback_indexes(
        {{AVB_ATX_PIK_VERSION_LOCATION, 0}, {AVB_ATX_PSK_VERSION_LOCATION, 0}});
  }

  // FakeAvbOpsDelegate methods.
  AvbIOResult read_from_partition(const char* partition,
                                  int64_t offset,
                                  size_t num_bytes,
                                  void* buffer,
                                  size_t* out_num_read) override {
    // Expect method not used.
    return AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION;
  }

  AvbIOResult get_preloaded_partition(
      const char* partition,
      size_t num_bytes,
      uint8_t** out_pointer,
      size_t* out_num_bytes_preloaded) override {
    // Expect method not used.
    return AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION;
  }

  AvbIOResult write_to_partition(const char* partition,
                                 int64_t offset,
                                 size_t num_bytes,
                                 const void* buffer) override {
    // Expect method not used.
    return AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION;
  }

  AvbIOResult validate_vbmeta_public_key(AvbOps* ops,
                                         const uint8_t* public_key_data,
                                         size_t public_key_length,
                                         const uint8_t* public_key_metadata,
                                         size_t public_key_metadata_length,
                                         bool* out_key_is_trusted) override {
    // Expect method not used.
    return AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION;
  }

  AvbIOResult read_rollback_index(AvbOps* ops,
                                  size_t rollback_index_slot,
                                  uint64_t* out_rollback_index) override {
    if ((fail_read_pik_rollback_index_ &&
         rollback_index_slot == AVB_ATX_PIK_VERSION_LOCATION) ||
        (fail_read_psk_rollback_index_ &&
         rollback_index_slot == AVB_ATX_PSK_VERSION_LOCATION)) {
      return AVB_IO_RESULT_ERROR_IO;
    }
    return ops_.read_rollback_index(
        ops, rollback_index_slot, out_rollback_index);
  }

  AvbIOResult write_rollback_index(AvbOps* ops,
                                   size_t rollback_index_slot,
                                   uint64_t rollback_index) override {
    // Expect method not used.
    return AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION;
  }

  AvbIOResult read_is_device_unlocked(AvbOps* ops,
                                      bool* out_is_device_unlocked) override {
    // Expect method not used.
    return AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION;
  }

  AvbIOResult get_unique_guid_for_partition(AvbOps* ops,
                                            const char* partition,
                                            char* guid_buf,
                                            size_t guid_buf_size) override {
    // Expect method not used.
    return AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION;
  }

  AvbIOResult get_size_of_partition(AvbOps* ops,
                                    const char* partition,
                                    uint64_t* out_size) override {
    // Expect method not used.
    return AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION;
  }

  AvbIOResult read_persistent_value(const char* name,
                                    size_t buffer_size,
                                    uint8_t* out_buffer,
                                    size_t* out_num_bytes_read) override {
    // Expect method not used.
    return AVB_IO_RESULT_ERROR_NO_SUCH_VALUE;
  }

  AvbIOResult write_persistent_value(const char* name,
                                     size_t value_size,
                                     const uint8_t* value) override {
    // Expect method not used.
    return AVB_IO_RESULT_ERROR_NO_SUCH_VALUE;
  }

  AvbIOResult read_permanent_attributes(
      AvbAtxPermanentAttributes* attributes) override {
    if (fail_read_permanent_attributes_) {
      return AVB_IO_RESULT_ERROR_IO;
    }
    return ops_.read_permanent_attributes(attributes);
  }

  AvbIOResult read_permanent_attributes_hash(
      uint8_t hash[AVB_SHA256_DIGEST_SIZE]) override {
    if (fail_read_permanent_attributes_hash_) {
      return AVB_IO_RESULT_ERROR_IO;
    }
    return ops_.read_permanent_attributes_hash(hash);
  }

  void set_key_version(size_t rollback_index_location,
                       uint64_t key_version) override {
    ops_.set_key_version(rollback_index_location, key_version);
  }

  AvbIOResult get_random(size_t num_bytes, uint8_t* output) override {
    if (fail_get_random_) {
      return AVB_IO_RESULT_ERROR_IO;
    }
    if (fake_random_.size() >= num_bytes) {
      memcpy(output, fake_random_.data(), num_bytes);
      return AVB_IO_RESULT_OK;
    }
    return ops_.get_random(num_bytes, output);
  }

 protected:
  virtual AvbIOResult Validate(bool* is_trusted) {
    return avb_atx_validate_vbmeta_public_key(
        ops_.avb_ops(),
        metadata_.product_signing_key_certificate.signed_data.public_key,
        AVB_ATX_PUBLIC_KEY_SIZE,
        reinterpret_cast<const uint8_t*>(&metadata_),
        sizeof(metadata_),
        is_trusted);
  }

  AvbIOResult ValidateUnlock(bool* is_trusted) {
    return avb_atx_validate_unlock_credential(
        ops_.avb_atx_ops(), &unlock_credential_, is_trusted);
  }

  void SignPIKCertificate() {
    memset(metadata_.product_intermediate_key_certificate.signature,
           0,
           AVB_RSA4096_NUM_BYTES);
    ScopedRSA key(kPRKPrivateKeyPath);
    ASSERT_TRUE(
        key.Sign(&metadata_.product_intermediate_key_certificate.signed_data,
                 sizeof(AvbAtxCertificateSignedData),
                 metadata_.product_intermediate_key_certificate.signature));
  }

  void SignPSKCertificate() {
    memset(metadata_.product_signing_key_certificate.signature,
           0,
           AVB_RSA4096_NUM_BYTES);
    ScopedRSA key(kPIKPrivateKeyPath);
    ASSERT_TRUE(key.Sign(&metadata_.product_signing_key_certificate.signed_data,
                         sizeof(AvbAtxCertificateSignedData),
                         metadata_.product_signing_key_certificate.signature));
  }

  void SignUnlockCredentialPIKCertificate() {
    memset(unlock_credential_.product_intermediate_key_certificate.signature,
           0,
           AVB_RSA4096_NUM_BYTES);
    ScopedRSA key(kPRKPrivateKeyPath);
    ASSERT_TRUE(key.Sign(
        &unlock_credential_.product_intermediate_key_certificate.signed_data,
        sizeof(AvbAtxCertificateSignedData),
        unlock_credential_.product_intermediate_key_certificate.signature));
  }

  void SignUnlockCredentialPUKCertificate() {
    memset(unlock_credential_.product_unlock_key_certificate.signature,
           0,
           AVB_RSA4096_NUM_BYTES);
    ScopedRSA key(kPIKPrivateKeyPath);
    ASSERT_TRUE(
        key.Sign(&unlock_credential_.product_unlock_key_certificate.signed_data,
                 sizeof(AvbAtxCertificateSignedData),
                 unlock_credential_.product_unlock_key_certificate.signature));
  }

  void SignUnlockCredentialChallenge(const char* key_path) {
    memset(unlock_credential_.challenge_signature, 0, AVB_RSA4096_NUM_BYTES);
    ScopedRSA key(key_path);
    ASSERT_TRUE(key.Sign(unlock_challenge_.data(),
                         unlock_challenge_.size(),
                         unlock_credential_.challenge_signature));
  }

  bool PrepareUnlockCredential() {
    // Stage a challenge to be remembered as the 'most recent challenge'. Then
    // the next call to unlock with |unlock_credential_| is expected to succeed.
    fake_random_ = unlock_challenge_;
    AvbAtxUnlockChallenge challenge;
    return (AVB_IO_RESULT_OK ==
            avb_atx_generate_unlock_challenge(ops_.avb_atx_ops(), &challenge));
  }

  AvbAtxPermanentAttributes attributes_;
  AvbAtxPublicKeyMetadata metadata_;
  bool fail_read_permanent_attributes_{false};
  bool fail_read_permanent_attributes_hash_{false};
  bool fail_read_pik_rollback_index_{false};
  bool fail_read_psk_rollback_index_{false};
  bool fail_get_random_{false};
  std::string fake_random_;
  AvbAtxUnlockCredential unlock_credential_;
  std::string unlock_challenge_;

 private:
  void ReadDefaultData() {
    std::string tmp;
    ASSERT_TRUE(base::ReadFileToString(base::FilePath(kMetadataPath), &tmp));
    ASSERT_EQ(tmp.size(), sizeof(AvbAtxPublicKeyMetadata));
    memcpy(&metadata_, tmp.data(), tmp.size());
    ASSERT_TRUE(
        base::ReadFileToString(base::FilePath(kPermanentAttributesPath), &tmp));
    ASSERT_EQ(tmp.size(), sizeof(AvbAtxPermanentAttributes));
    memcpy(&attributes_, tmp.data(), tmp.size());
    ASSERT_TRUE(base::ReadFileToString(base::FilePath(kUnlockChallengePath),
                                       &unlock_challenge_));
    ASSERT_EQ(size_t(AVB_ATX_UNLOCK_CHALLENGE_SIZE), unlock_challenge_.size());
    ASSERT_TRUE(
        base::ReadFileToString(base::FilePath(kUnlockCredentialPath), &tmp));
    ASSERT_EQ(tmp.size(), sizeof(AvbAtxUnlockCredential));
    memcpy(&unlock_credential_, tmp.data(), tmp.size());
  }
};

TEST_F(AvbAtxValidateTest, Success) {
  bool is_trusted = false;
  EXPECT_EQ(AVB_IO_RESULT_OK, Validate(&is_trusted));
  EXPECT_TRUE(is_trusted);

  // Check that the key versions were reported correctly.
  EXPECT_EQ(
      ops_.get_verified_rollback_indexes()[AVB_ATX_PIK_VERSION_LOCATION],
      metadata_.product_intermediate_key_certificate.signed_data.key_version);
  EXPECT_EQ(ops_.get_verified_rollback_indexes()[AVB_ATX_PSK_VERSION_LOCATION],
            metadata_.product_signing_key_certificate.signed_data.key_version);
  EXPECT_EQ(2UL, ops_.get_verified_rollback_indexes().size());
}

TEST_F(AvbAtxValidateTest, SuccessAfterNewSign) {
  std::string old_pik_sig(
      reinterpret_cast<char*>(
          metadata_.product_intermediate_key_certificate.signature),
      AVB_RSA4096_NUM_BYTES);
  std::string old_psk_sig(
      reinterpret_cast<char*>(
          metadata_.product_signing_key_certificate.signature),
      AVB_RSA4096_NUM_BYTES);
  SignPIKCertificate();
  SignPSKCertificate();
  std::string new_pik_sig(
      reinterpret_cast<char*>(
          metadata_.product_intermediate_key_certificate.signature),
      AVB_RSA4096_NUM_BYTES);
  std::string new_psk_sig(
      reinterpret_cast<char*>(
          metadata_.product_signing_key_certificate.signature),
      AVB_RSA4096_NUM_BYTES);
  EXPECT_EQ(old_pik_sig, new_pik_sig);
  EXPECT_EQ(old_psk_sig, new_psk_sig);
  bool is_trusted = false;
  EXPECT_EQ(AVB_IO_RESULT_OK, Validate(&is_trusted));
  EXPECT_TRUE(is_trusted);
}

TEST_F(AvbAtxValidateTest, FailReadPermamentAttributes) {
  fail_read_permanent_attributes_ = true;
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_ERROR_IO, Validate(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, FailReadPermamentAttributesHash) {
  fail_read_permanent_attributes_hash_ = true;
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_ERROR_IO, Validate(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, UnsupportedPermanentAttributesVersion) {
  attributes_.version = 25;
  ops_.set_permanent_attributes(attributes_);
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, Validate(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, PermanentAttributesHashMismatch) {
  ops_.set_permanent_attributes_hash("bad_hash");
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, Validate(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

// A fixture with parameterized metadata length.
class AvbAtxValidateTestWithMetadataLength
    : public AvbAtxValidateTest,
      public ::testing::WithParamInterface<size_t> {
 protected:
  AvbIOResult Validate(bool* is_trusted) override {
    return avb_atx_validate_vbmeta_public_key(
        ops_.avb_ops(),
        metadata_.product_signing_key_certificate.signed_data.public_key,
        AVB_ATX_PUBLIC_KEY_SIZE,
        reinterpret_cast<const uint8_t*>(&metadata_),
        GetParam(),
        is_trusted);
  }
};

TEST_P(AvbAtxValidateTestWithMetadataLength, InvalidMetadataLength) {
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, Validate(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

// Test a bunch of invalid metadata length values.
INSTANTIATE_TEST_CASE_P(P,
                        AvbAtxValidateTestWithMetadataLength,
                        ::testing::Values(0,
                                          1,
                                          sizeof(AvbAtxPublicKeyMetadata) - 1,
                                          sizeof(AvbAtxPublicKeyMetadata) + 1,
                                          -1));

TEST_F(AvbAtxValidateTest, UnsupportedMetadataVersion) {
  metadata_.version = 25;
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, Validate(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, FailReadPIKRollbackIndex) {
  fail_read_pik_rollback_index_ = true;
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_ERROR_IO, Validate(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, UnsupportedPIKCertificateVersion) {
  metadata_.product_intermediate_key_certificate.signed_data.version = 25;
  SignPIKCertificate();
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, Validate(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, BadPIKCert_ModifiedSubjectPublicKey) {
  metadata_.product_intermediate_key_certificate.signed_data.public_key[0] ^= 1;
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, Validate(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, BadPIKCert_ModifiedSubject) {
  metadata_.product_intermediate_key_certificate.signed_data.subject[0] ^= 1;
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, Validate(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, BadPIKCert_ModifiedUsage) {
  metadata_.product_intermediate_key_certificate.signed_data.usage[0] ^= 1;
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, Validate(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, BadPIKCert_ModifiedKeyVersion) {
  metadata_.product_intermediate_key_certificate.signed_data.key_version ^= 1;
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, Validate(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, BadPIKCert_BadSignature) {
  metadata_.product_intermediate_key_certificate.signature[0] ^= 1;
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, Validate(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, PIKCertSubjectIgnored) {
  metadata_.product_intermediate_key_certificate.signed_data.subject[0] ^= 1;
  SignPIKCertificate();
  bool is_trusted = false;
  EXPECT_EQ(AVB_IO_RESULT_OK, Validate(&is_trusted));
  EXPECT_TRUE(is_trusted);
}

TEST_F(AvbAtxValidateTest, PIKCertUnexpectedUsage) {
  metadata_.product_intermediate_key_certificate.signed_data.usage[0] ^= 1;
  SignPIKCertificate();
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, Validate(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, PIKRollback) {
  ops_.set_stored_rollback_indexes(
      {{AVB_ATX_PIK_VERSION_LOCATION,
        metadata_.product_intermediate_key_certificate.signed_data.key_version +
            1},
       {AVB_ATX_PSK_VERSION_LOCATION, 0}});
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, Validate(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, FailReadPSKRollbackIndex) {
  fail_read_psk_rollback_index_ = true;
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_ERROR_IO, Validate(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, UnsupportedPSKCertificateVersion) {
  metadata_.product_signing_key_certificate.signed_data.version = 25;
  SignPSKCertificate();
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, Validate(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, BadPSKCert_ModifiedSubjectPublicKey) {
  metadata_.product_signing_key_certificate.signed_data.public_key[0] ^= 1;
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, Validate(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, BadPSKCert_ModifiedSubject) {
  metadata_.product_signing_key_certificate.signed_data.subject[0] ^= 1;
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, Validate(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, BadPSKCert_ModifiedUsage) {
  metadata_.product_signing_key_certificate.signed_data.usage[0] ^= 1;
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, Validate(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, BadPSKCert_ModifiedKeyVersion) {
  metadata_.product_signing_key_certificate.signed_data.key_version ^= 1;
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, Validate(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, BadPSKCert_BadSignature) {
  metadata_.product_signing_key_certificate.signature[0] ^= 1;
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, Validate(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, PSKCertUnexpectedSubject) {
  metadata_.product_signing_key_certificate.signed_data.subject[0] ^= 1;
  SignPSKCertificate();
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, Validate(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, PSKCertUnexpectedUsage) {
  metadata_.product_signing_key_certificate.signed_data.usage[0] ^= 1;
  SignPSKCertificate();
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, Validate(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, PSKRollback) {
  ops_.set_stored_rollback_indexes(
      {{AVB_ATX_PIK_VERSION_LOCATION, 0},
       {AVB_ATX_PSK_VERSION_LOCATION,
        metadata_.product_signing_key_certificate.signed_data.key_version +
            1}});
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, Validate(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

// A fixture with parameterized public key length.
class AvbAtxValidateTestWithPublicKeyLength
    : public AvbAtxValidateTest,
      public ::testing::WithParamInterface<size_t> {
 protected:
  AvbIOResult Validate(bool* is_trusted) override {
    return avb_atx_validate_vbmeta_public_key(
        ops_.avb_ops(),
        metadata_.product_signing_key_certificate.signed_data.public_key,
        GetParam(),
        reinterpret_cast<const uint8_t*>(&metadata_),
        sizeof(metadata_),
        is_trusted);
  }
};

TEST_P(AvbAtxValidateTestWithPublicKeyLength, InvalidPublicKeyLength) {
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, Validate(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

// Test a bunch of invalid public key length values.
INSTANTIATE_TEST_CASE_P(P,
                        AvbAtxValidateTestWithPublicKeyLength,
                        ::testing::Values(0,
                                          1,
                                          AVB_ATX_PUBLIC_KEY_SIZE - 1,
                                          AVB_ATX_PUBLIC_KEY_SIZE + 1,
                                          AVB_ATX_PUBLIC_KEY_SIZE - 512,
                                          -1));

TEST_F(AvbAtxValidateTest, PSKMismatch) {
  uint8_t bad_key[AVB_ATX_PUBLIC_KEY_SIZE] = {};
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK,
            avb_atx_validate_vbmeta_public_key(
                ops_.avb_ops(),
                bad_key,
                AVB_ATX_PUBLIC_KEY_SIZE,
                reinterpret_cast<const uint8_t*>(&metadata_),
                sizeof(metadata_),
                &is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, GenerateUnlockChallenge) {
  fake_random_ = std::string(AVB_ATX_UNLOCK_CHALLENGE_SIZE, 'C');
  AvbAtxUnlockChallenge challenge;
  EXPECT_EQ(AVB_IO_RESULT_OK,
            avb_atx_generate_unlock_challenge(ops_.avb_atx_ops(), &challenge));
  EXPECT_EQ(1UL, challenge.version);
  EXPECT_EQ(0,
            memcmp(fake_random_.data(),
                   challenge.challenge,
                   AVB_ATX_UNLOCK_CHALLENGE_SIZE));
  uint8_t expected_pid_hash[AVB_SHA256_DIGEST_SIZE];
  SHA256(attributes_.product_id, AVB_ATX_PRODUCT_ID_SIZE, expected_pid_hash);
  EXPECT_EQ(0,
            memcmp(expected_pid_hash,
                   challenge.product_id_hash,
                   AVB_SHA256_DIGEST_SIZE));
}

TEST_F(AvbAtxValidateTest, GenerateUnlockChallenge_NoAttributes) {
  fail_read_permanent_attributes_ = true;
  AvbAtxUnlockChallenge challenge;
  EXPECT_NE(AVB_IO_RESULT_OK,
            avb_atx_generate_unlock_challenge(ops_.avb_atx_ops(), &challenge));
}

TEST_F(AvbAtxValidateTest, GenerateUnlockChallenge_NoRNG) {
  fail_get_random_ = true;
  AvbAtxUnlockChallenge challenge;
  EXPECT_NE(AVB_IO_RESULT_OK,
            avb_atx_generate_unlock_challenge(ops_.avb_atx_ops(), &challenge));
}

TEST_F(AvbAtxValidateTest, ValidateUnlockCredential) {
  ASSERT_TRUE(PrepareUnlockCredential());
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, ValidateUnlock(&is_trusted));
  EXPECT_TRUE(is_trusted);
}

TEST_F(AvbAtxValidateTest, ValidateUnlockCredential_UnsupportedVersion) {
  ASSERT_TRUE(PrepareUnlockCredential());
  unlock_credential_.version++;
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, ValidateUnlock(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, ValidateUnlockCredential_NoAttributes) {
  PrepareUnlockCredential();
  fail_read_permanent_attributes_ = true;
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_ERROR_IO, ValidateUnlock(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, ValidateUnlockCredential_NoAttributesHash) {
  PrepareUnlockCredential();
  fail_read_permanent_attributes_hash_ = true;
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_ERROR_IO, ValidateUnlock(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest,
       ValidateUnlockCredential_UnsupportedAttributesVersion) {
  ASSERT_TRUE(PrepareUnlockCredential());
  attributes_.version = 25;
  ops_.set_permanent_attributes(attributes_);
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, ValidateUnlock(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, ValidateUnlockCredential_AttributesHashMismatch) {
  ASSERT_TRUE(PrepareUnlockCredential());
  ops_.set_permanent_attributes_hash("bad_hash");
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, ValidateUnlock(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, ValidateUnlockCredential_FailReadPIKRollbackIndex) {
  ASSERT_TRUE(PrepareUnlockCredential());
  fail_read_pik_rollback_index_ = true;
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_ERROR_IO, ValidateUnlock(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest,
       ValidateUnlockCredential_UnsupportedPIKCertificateVersion) {
  ASSERT_TRUE(PrepareUnlockCredential());
  unlock_credential_.product_intermediate_key_certificate.signed_data.version =
      25;
  SignUnlockCredentialPIKCertificate();
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, ValidateUnlock(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest,
       ValidateUnlockCredential_BadPIKCert_ModifiedSubjectPublicKey) {
  ASSERT_TRUE(PrepareUnlockCredential());
  unlock_credential_.product_intermediate_key_certificate.signed_data
      .public_key[0] ^= 1;
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, ValidateUnlock(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest,
       ValidateUnlockCredential_BadPIKCert_ModifiedSubject) {
  ASSERT_TRUE(PrepareUnlockCredential());
  unlock_credential_.product_intermediate_key_certificate.signed_data
      .subject[0] ^= 1;
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, ValidateUnlock(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, ValidateUnlockCredential_BadPIKCert_ModifiedUsage) {
  ASSERT_TRUE(PrepareUnlockCredential());
  unlock_credential_.product_intermediate_key_certificate.signed_data
      .usage[0] ^= 1;
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, ValidateUnlock(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest,
       ValidateUnlockCredential_BadPIKCert_ModifiedKeyVersion) {
  ASSERT_TRUE(PrepareUnlockCredential());
  unlock_credential_.product_intermediate_key_certificate.signed_data
      .key_version ^= 1;
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, ValidateUnlock(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, ValidateUnlockCredential_BadPIKCert_BadSignature) {
  ASSERT_TRUE(PrepareUnlockCredential());
  unlock_credential_.product_intermediate_key_certificate.signature[0] ^= 1;
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, ValidateUnlock(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, ValidateUnlockCredential_PIKCertSubjectIgnored) {
  ASSERT_TRUE(PrepareUnlockCredential());
  unlock_credential_.product_intermediate_key_certificate.signed_data
      .subject[0] ^= 1;
  SignUnlockCredentialPIKCertificate();
  bool is_trusted = false;
  EXPECT_EQ(AVB_IO_RESULT_OK, ValidateUnlock(&is_trusted));
  EXPECT_TRUE(is_trusted);
}

TEST_F(AvbAtxValidateTest, ValidateUnlockCredential_PIKCertUnexpectedUsage) {
  ASSERT_TRUE(PrepareUnlockCredential());
  unlock_credential_.product_intermediate_key_certificate.signed_data
      .usage[0] ^= 1;
  SignUnlockCredentialPIKCertificate();
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, ValidateUnlock(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, ValidateUnlockCredential_PIKRollback) {
  ASSERT_TRUE(PrepareUnlockCredential());
  ops_.set_stored_rollback_indexes(
      {{AVB_ATX_PIK_VERSION_LOCATION,
        unlock_credential_.product_intermediate_key_certificate.signed_data
                .key_version +
            1},
       {AVB_ATX_PSK_VERSION_LOCATION, 0}});
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, ValidateUnlock(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, ValidateUnlockCredential_FailReadPSKRollbackIndex) {
  ASSERT_TRUE(PrepareUnlockCredential());
  fail_read_psk_rollback_index_ = true;
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_ERROR_IO, ValidateUnlock(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest,
       ValidateUnlockCredential_UnsupportedPUKCertificateVersion) {
  ASSERT_TRUE(PrepareUnlockCredential());
  unlock_credential_.product_unlock_key_certificate.signed_data.version = 25;
  SignUnlockCredentialPUKCertificate();
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, ValidateUnlock(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest,
       ValidateUnlockCredential_BadPUKCert_ModifiedSubjectPublicKey) {
  ASSERT_TRUE(PrepareUnlockCredential());
  unlock_credential_.product_unlock_key_certificate.signed_data.public_key[0] ^=
      1;
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, ValidateUnlock(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest,
       ValidateUnlockCredential_BadPUKCert_ModifiedSubject) {
  ASSERT_TRUE(PrepareUnlockCredential());
  unlock_credential_.product_unlock_key_certificate.signed_data.subject[0] ^= 1;
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, ValidateUnlock(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, ValidateUnlockCredential_BadPUKCert_ModifiedUsage) {
  ASSERT_TRUE(PrepareUnlockCredential());
  unlock_credential_.product_unlock_key_certificate.signed_data.usage[0] ^= 1;
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, ValidateUnlock(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest,
       ValidateUnlockCredential_BadPUKCert_ModifiedKeyVersion) {
  ASSERT_TRUE(PrepareUnlockCredential());
  unlock_credential_.product_unlock_key_certificate.signed_data.key_version ^=
      1;
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, ValidateUnlock(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, ValidateUnlockCredential_BadPUKCert_BadSignature) {
  ASSERT_TRUE(PrepareUnlockCredential());
  unlock_credential_.product_unlock_key_certificate.signature[0] ^= 1;
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, ValidateUnlock(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, ValidateUnlockCredential_PUKCertUnexpectedSubject) {
  ASSERT_TRUE(PrepareUnlockCredential());
  unlock_credential_.product_unlock_key_certificate.signed_data.subject[0] ^= 1;
  SignUnlockCredentialPUKCertificate();
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, ValidateUnlock(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, ValidateUnlockCredential_PUKCertUnexpectedUsage) {
  ASSERT_TRUE(PrepareUnlockCredential());
  unlock_credential_.product_unlock_key_certificate.signed_data.usage[0] ^= 1;
  SignUnlockCredentialPUKCertificate();
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, ValidateUnlock(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, ValidateUnlockCredential_PUKRollback) {
  ASSERT_TRUE(PrepareUnlockCredential());
  ops_.set_stored_rollback_indexes(
      {{AVB_ATX_PIK_VERSION_LOCATION, 0},
       {AVB_ATX_PSK_VERSION_LOCATION,
        unlock_credential_.product_unlock_key_certificate.signed_data
                .key_version +
            1}});
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, ValidateUnlock(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, ValidateUnlockCredential_BadChallengeSignature) {
  ASSERT_TRUE(PrepareUnlockCredential());
  unlock_credential_.challenge_signature[10] ^= 1;
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, ValidateUnlock(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, ValidateUnlockCredential_ChallengeMismatch) {
  ASSERT_TRUE(PrepareUnlockCredential());
  unlock_challenge_ = "bad";
  SignUnlockCredentialChallenge(kPUKPrivateKeyPath);
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, ValidateUnlock(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, ValidateUnlockCredential_UnlockWithPSK) {
  ASSERT_TRUE(PrepareUnlockCredential());
  // Copy the PSK cert as the PUK cert.
  memcpy(&unlock_credential_.product_unlock_key_certificate,
         &metadata_.product_signing_key_certificate,
         sizeof(AvbAtxCertificate));
  // Sign the challenge with the PSK instead of the PUK.
  SignUnlockCredentialChallenge(kPSKPrivateKeyPath);
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, ValidateUnlock(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, ValidateUnlockCredential_ReplayChallenge) {
  ASSERT_TRUE(PrepareUnlockCredential());
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, ValidateUnlock(&is_trusted));
  EXPECT_TRUE(is_trusted);
  // A second attempt with the same challenge should fail.
  EXPECT_EQ(AVB_IO_RESULT_OK, ValidateUnlock(&is_trusted));
  EXPECT_FALSE(is_trusted);
}

TEST_F(AvbAtxValidateTest, ValidateUnlockCredential_MultipleUnlock) {
  ASSERT_TRUE(PrepareUnlockCredential());
  bool is_trusted = true;
  EXPECT_EQ(AVB_IO_RESULT_OK, ValidateUnlock(&is_trusted));
  EXPECT_TRUE(is_trusted);
  // A second attempt with a newly staged challenge should succeed.
  ASSERT_TRUE(PrepareUnlockCredential());
  EXPECT_EQ(AVB_IO_RESULT_OK, ValidateUnlock(&is_trusted));
  EXPECT_TRUE(is_trusted);
}

// A fixture for testing avb_slot_verify() with ATX.
class AvbAtxSlotVerifyTest : public BaseAvbToolTest,
                             public FakeAvbOpsDelegateWithDefaults {
 public:
  ~AvbAtxSlotVerifyTest() override = default;

  void SetUp() override {
    BaseAvbToolTest::SetUp();
    ReadAtxDefaultData();
    ops_.set_partition_dir(testdir_);
    ops_.set_delegate(this);
    ops_.set_permanent_attributes(attributes_);
    ops_.set_stored_rollback_indexes({{0, 0},
                                      {1, 0},
                                      {2, 0},
                                      {3, 0},
                                      {AVB_ATX_PIK_VERSION_LOCATION, 0},
                                      {AVB_ATX_PSK_VERSION_LOCATION, 0}});
    ops_.set_stored_is_device_unlocked(false);
  }

  // FakeAvbOpsDelegate override.
  AvbIOResult validate_vbmeta_public_key(AvbOps* ops,
                                         const uint8_t* public_key_data,
                                         size_t public_key_length,
                                         const uint8_t* public_key_metadata,
                                         size_t public_key_metadata_length,
                                         bool* out_key_is_trusted) override {
    // Send to ATX implementation.
    ++num_atx_calls_;
    return avb_atx_validate_vbmeta_public_key(ops_.avb_ops(),
                                              public_key_data,
                                              public_key_length,
                                              public_key_metadata,
                                              public_key_metadata_length,
                                              out_key_is_trusted);
  }

 protected:
  AvbAtxPermanentAttributes attributes_;
  int num_atx_calls_ = 0;

 private:
  void ReadAtxDefaultData() {
    std::string tmp;
    ASSERT_TRUE(
        base::ReadFileToString(base::FilePath(kPermanentAttributesPath), &tmp));
    ASSERT_EQ(tmp.size(), sizeof(AvbAtxPermanentAttributes));
    memcpy(&attributes_, tmp.data(), tmp.size());
  }
};

TEST_F(AvbAtxSlotVerifyTest, SlotVerifyWithAtx) {
  std::string metadata_option = "--public_key_metadata=";
  metadata_option += kMetadataPath;
  GenerateVBMetaImage("vbmeta_a.img",
                      "SHA512_RSA4096",
                      0,
                      base::FilePath("test/data/testkey_atx_psk.pem"),
                      metadata_option);

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_atx_psk.pem")));

  AvbSlotVerifyData* slot_data = NULL;
  const char* requested_partitions[] = {"boot", NULL};
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_NONE,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_NE(nullptr, slot_data);
  avb_slot_verify_data_free(slot_data);
  EXPECT_EQ(1, num_atx_calls_);
}

}  // namespace avb

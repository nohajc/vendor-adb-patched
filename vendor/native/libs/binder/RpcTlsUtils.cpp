/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "RpcTlsUtils"
#include <log/log.h>

#include <binder/RpcTlsUtils.h>

#include "Utils.h"

namespace android {

namespace {

static_assert(sizeof(unsigned char) == sizeof(uint8_t));

template <typename PemReadBioFn,
          typename T = std::remove_pointer_t<std::invoke_result_t<
                  PemReadBioFn, BIO*, std::nullptr_t, std::nullptr_t, std::nullptr_t>>>
bssl::UniquePtr<T> fromPem(const std::vector<uint8_t>& data, PemReadBioFn fn) {
    if (data.size() > std::numeric_limits<int>::max()) return nullptr;
    bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(data.data(), static_cast<int>(data.size())));
    return bssl::UniquePtr<T>(fn(bio.get(), nullptr, nullptr, nullptr));
}

template <typename D2iFn,
          typename T = std::remove_pointer_t<
                  std::invoke_result_t<D2iFn, std::nullptr_t, const unsigned char**, long>>>
bssl::UniquePtr<T> fromDer(const std::vector<uint8_t>& data, D2iFn fn) {
    if (data.size() > std::numeric_limits<long>::max()) return nullptr;
    const unsigned char* dataPtr = data.data();
    auto expectedEnd = dataPtr + data.size();
    bssl::UniquePtr<T> ret(fn(nullptr, &dataPtr, static_cast<long>(data.size())));
    if (dataPtr != expectedEnd) {
        ALOGE("%s: %td bytes remaining!", __PRETTY_FUNCTION__, expectedEnd - dataPtr);
        return nullptr;
    }
    return ret;
}

template <typename T, typename WriteBioFn = int (*)(BIO*, T*)>
std::vector<uint8_t> serialize(T* object, WriteBioFn writeBio) {
    bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
    TEST_AND_RETURN({}, writeBio(bio.get(), object));
    const uint8_t* data;
    size_t len;
    TEST_AND_RETURN({}, BIO_mem_contents(bio.get(), &data, &len));
    return std::vector<uint8_t>(data, data + len);
}

} // namespace

bssl::UniquePtr<X509> deserializeCertificate(const std::vector<uint8_t>& data,
                                             RpcCertificateFormat format) {
    switch (format) {
        case RpcCertificateFormat::PEM:
            return fromPem(data, PEM_read_bio_X509);
        case RpcCertificateFormat::DER:
            return fromDer(data, d2i_X509);
    }
    LOG_ALWAYS_FATAL("Unsupported format %d", static_cast<int>(format));
}

std::vector<uint8_t> serializeCertificate(X509* x509, RpcCertificateFormat format) {
    switch (format) {
        case RpcCertificateFormat::PEM:
            return serialize(x509, PEM_write_bio_X509);
        case RpcCertificateFormat::DER:
            return serialize(x509, i2d_X509_bio);
    }
    LOG_ALWAYS_FATAL("Unsupported format %d", static_cast<int>(format));
}

bssl::UniquePtr<EVP_PKEY> deserializeUnencryptedPrivatekey(const std::vector<uint8_t>& data,
                                                           RpcKeyFormat format) {
    switch (format) {
        case RpcKeyFormat::PEM:
            return fromPem(data, PEM_read_bio_PrivateKey);
        case RpcKeyFormat::DER:
            return fromDer(data, d2i_AutoPrivateKey);
    }
    LOG_ALWAYS_FATAL("Unsupported format %d", static_cast<int>(format));
}

std::vector<uint8_t> serializeUnencryptedPrivatekey(EVP_PKEY* pkey, RpcKeyFormat format) {
    switch (format) {
        case RpcKeyFormat::PEM:
            return serialize(pkey, [](BIO* bio, EVP_PKEY* pkey) {
                return PEM_write_bio_PrivateKey(bio, pkey, nullptr /* enc */, nullptr /* kstr */,
                                                0 /* klen */, nullptr, nullptr);
            });
        case RpcKeyFormat::DER:
            return serialize(pkey, i2d_PrivateKey_bio);
    }
    LOG_ALWAYS_FATAL("Unsupported format %d", static_cast<int>(format));
}

} // namespace android

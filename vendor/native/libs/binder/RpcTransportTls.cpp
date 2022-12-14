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

#define LOG_TAG "RpcTransportTls"
#include <log/log.h>

#include <poll.h>

#include <openssl/bn.h>
#include <openssl/ssl.h>

#include <binder/RpcTlsUtils.h>
#include <binder/RpcTransportTls.h>

#include "FdTrigger.h"
#include "RpcState.h"
#include "Utils.h"

#define SHOULD_LOG_TLS_DETAIL false

#if SHOULD_LOG_TLS_DETAIL
#define LOG_TLS_DETAIL(...) ALOGI(__VA_ARGS__)
#else
#define LOG_TLS_DETAIL(...) ALOGV(__VA_ARGS__) // for type checking
#endif

namespace android {
namespace {

// Implement BIO for socket that ignores SIGPIPE.
int socketNew(BIO* bio) {
    BIO_set_data(bio, reinterpret_cast<void*>(-1));
    BIO_set_init(bio, 0);
    return 1;
}
int socketFree(BIO* bio) {
    LOG_ALWAYS_FATAL_IF(bio == nullptr);
    return 1;
}
int socketRead(BIO* bio, char* buf, int size) {
    android::base::borrowed_fd fd(static_cast<int>(reinterpret_cast<intptr_t>(BIO_get_data(bio))));
    int ret = TEMP_FAILURE_RETRY(::recv(fd.get(), buf, size, MSG_NOSIGNAL));
    BIO_clear_retry_flags(bio);
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        BIO_set_retry_read(bio);
    }
    return ret;
}

int socketWrite(BIO* bio, const char* buf, int size) {
    android::base::borrowed_fd fd(static_cast<int>(reinterpret_cast<intptr_t>(BIO_get_data(bio))));
    int ret = TEMP_FAILURE_RETRY(::send(fd.get(), buf, size, MSG_NOSIGNAL));
    BIO_clear_retry_flags(bio);
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        BIO_set_retry_write(bio);
    }
    return ret;
}

long socketCtrl(BIO* bio, int cmd, long num, void*) { // NOLINT
    android::base::borrowed_fd fd(static_cast<int>(reinterpret_cast<intptr_t>(BIO_get_data(bio))));
    if (cmd == BIO_CTRL_FLUSH) return 1;
    LOG_ALWAYS_FATAL("sockCtrl(fd=%d, %d, %ld)", fd.get(), cmd, num);
    return 0;
}

bssl::UniquePtr<BIO> newSocketBio(android::base::borrowed_fd fd) {
    static const BIO_METHOD* gMethods = ([] {
        auto methods = BIO_meth_new(BIO_get_new_index(), "socket_no_signal");
        LOG_ALWAYS_FATAL_IF(0 == BIO_meth_set_write(methods, socketWrite), "BIO_meth_set_write");
        LOG_ALWAYS_FATAL_IF(0 == BIO_meth_set_read(methods, socketRead), "BIO_meth_set_read");
        LOG_ALWAYS_FATAL_IF(0 == BIO_meth_set_ctrl(methods, socketCtrl), "BIO_meth_set_ctrl");
        LOG_ALWAYS_FATAL_IF(0 == BIO_meth_set_create(methods, socketNew), "BIO_meth_set_create");
        LOG_ALWAYS_FATAL_IF(0 == BIO_meth_set_destroy(methods, socketFree), "BIO_meth_set_destroy");
        return methods;
    })();
    bssl::UniquePtr<BIO> ret(BIO_new(gMethods));
    if (ret == nullptr) return nullptr;
    BIO_set_data(ret.get(), reinterpret_cast<void*>(fd.get()));
    BIO_set_init(ret.get(), 1);
    return ret;
}

[[maybe_unused]] void sslDebugLog(const SSL* ssl, int type, int value) {
    switch (type) {
        case SSL_CB_HANDSHAKE_START:
            LOG_TLS_DETAIL("Handshake started.");
            break;
        case SSL_CB_HANDSHAKE_DONE:
            LOG_TLS_DETAIL("Handshake done.");
            break;
        case SSL_CB_ACCEPT_LOOP:
            LOG_TLS_DETAIL("Handshake progress: %s", SSL_state_string_long(ssl));
            break;
        default:
            LOG_TLS_DETAIL("SSL Debug Log: type = %d, value = %d", type, value);
            break;
    }
}

// Helper class to ErrorQueue::toString
class ErrorQueueString {
public:
    static std::string toString() {
        ErrorQueueString thiz;
        ERR_print_errors_cb(staticCallback, &thiz);
        return thiz.mSs.str();
    }

private:
    static int staticCallback(const char* str, size_t len, void* ctx) {
        return reinterpret_cast<ErrorQueueString*>(ctx)->callback(str, len);
    }
    int callback(const char* str, size_t len) {
        if (len == 0) return 1; // continue
        // ERR_print_errors_cb place a new line at the end, but it doesn't say so in the API.
        if (str[len - 1] == '\n') len -= 1;
        if (!mIsFirst) {
            mSs << '\n';
        }
        mSs << std::string_view(str, len);
        mIsFirst = false;
        return 1; // continue
    }
    std::stringstream mSs;
    bool mIsFirst = true;
};

// Handles libssl's error queue.
//
// Call into any of its member functions to ensure the error queue is properly handled or cleared.
// If the error queue is not handled or cleared, the destructor will abort.
class ErrorQueue {
public:
    ~ErrorQueue() { LOG_ALWAYS_FATAL_IF(!mHandled); }

    // Clear the error queue.
    void clear() {
        ERR_clear_error();
        mHandled = true;
    }

    // Stores the error queue in |ssl| into a string, then clears the error queue.
    std::string toString() {
        auto ret = ErrorQueueString::toString();
        // Though ERR_print_errors_cb should have cleared it, it is okay to clear again.
        clear();
        return ret;
    }

    status_t toStatus(int sslError, const char* fnString) {
        switch (sslError) {
            case SSL_ERROR_SYSCALL: {
                auto queue = toString();
                LOG_TLS_DETAIL("%s(): %s. Treating as DEAD_OBJECT. Error queue: %s", fnString,
                               SSL_error_description(sslError), queue.c_str());
                return DEAD_OBJECT;
            }
            default: {
                auto queue = toString();
                ALOGE("%s(): %s. Error queue: %s", fnString, SSL_error_description(sslError),
                      queue.c_str());
                return UNKNOWN_ERROR;
            }
        }
    }

    // |sslError| should be from Ssl::getError().
    // If |sslError| is WANT_READ / WANT_WRITE, poll for POLLIN / POLLOUT respectively. Otherwise
    // return error. Also return error if |fdTrigger| is triggered before or during poll().
    status_t pollForSslError(
            const android::RpcTransportFd& fd, int sslError, FdTrigger* fdTrigger,
            const char* fnString, int additionalEvent,
            const std::optional<android::base::function_ref<status_t()>>& altPoll) {
        switch (sslError) {
            case SSL_ERROR_WANT_READ:
                return handlePoll(POLLIN | additionalEvent, fd, fdTrigger, fnString, altPoll);
            case SSL_ERROR_WANT_WRITE:
                return handlePoll(POLLOUT | additionalEvent, fd, fdTrigger, fnString, altPoll);
            default:
                return toStatus(sslError, fnString);
        }
    }

private:
    bool mHandled = false;

    status_t handlePoll(int event, const android::RpcTransportFd& fd, FdTrigger* fdTrigger,
                        const char* fnString,
                        const std::optional<android::base::function_ref<status_t()>>& altPoll) {
        status_t ret;
        if (altPoll) {
            ret = (*altPoll)();
            if (fdTrigger->isTriggered()) ret = DEAD_OBJECT;
        } else {
            ret = fdTrigger->triggerablePoll(fd, event);
        }

        if (ret != OK && ret != DEAD_OBJECT) {
            ALOGE("poll error while after %s(): %s", fnString, statusToString(ret).c_str());
        }
        clear();
        return ret;
    }
};

// Helper to call a function, with its return value instantiable.
template <typename Fn, typename... Args>
struct FuncCaller {
    struct Monostate {};
    static constexpr bool sIsVoid = std::is_void_v<std::invoke_result_t<Fn, Args...>>;
    using Result = std::conditional_t<sIsVoid, Monostate, std::invoke_result_t<Fn, Args...>>;
    static inline Result call(Fn fn, Args&&... args) {
        if constexpr (std::is_void_v<std::invoke_result_t<Fn, Args...>>) {
            std::invoke(fn, std::forward<Args>(args)...);
            return {};
        } else {
            return std::invoke(fn, std::forward<Args>(args)...);
        }
    }
};

// Helper to Ssl::call(). Returns the result to the SSL_* function as well as an ErrorQueue object.
template <typename Fn, typename... Args>
struct SslCaller {
    using RawCaller = FuncCaller<Fn, SSL*, Args...>;
    struct ResultAndErrorQueue {
        typename RawCaller::Result result;
        ErrorQueue errorQueue;
    };
    static inline ResultAndErrorQueue call(Fn fn, SSL* ssl, Args&&... args) {
        LOG_ALWAYS_FATAL_IF(ssl == nullptr);
        auto result = RawCaller::call(fn, std::forward<SSL*>(ssl), std::forward<Args>(args)...);
        return ResultAndErrorQueue{std::move(result), ErrorQueue()};
    }
};

// A wrapper over bssl::UniquePtr<SSL>. This class ensures that all SSL_* functions are called
// through call(), which returns an ErrorQueue object that requires the caller to either handle
// or clear it.
// Example:
//   auto [ret, errorQueue] = ssl.call(SSL_read, buf, size);
//   if (ret >= 0) errorQueue.clear();
//   else ALOGE("%s", errorQueue.toString().c_str());
class Ssl {
public:
    explicit Ssl(bssl::UniquePtr<SSL> ssl) : mSsl(std::move(ssl)) {
        LOG_ALWAYS_FATAL_IF(mSsl == nullptr);
    }

    template <typename Fn, typename... Args>
    inline typename SslCaller<Fn, Args...>::ResultAndErrorQueue call(Fn fn, Args&&... args) {
        return SslCaller<Fn, Args...>::call(fn, mSsl.get(), std::forward<Args>(args)...);
    }

    int getError(int ret) {
        LOG_ALWAYS_FATAL_IF(mSsl == nullptr);
        return SSL_get_error(mSsl.get(), ret);
    }

private:
    bssl::UniquePtr<SSL> mSsl;
};

} // namespace

class RpcTransportTls : public RpcTransport {
public:
    RpcTransportTls(RpcTransportFd socket, Ssl ssl)
          : mSocket(std::move(socket)), mSsl(std::move(ssl)) {}
    status_t pollRead(void) override;
    status_t interruptableWriteFully(
            FdTrigger* fdTrigger, iovec* iovs, int niovs,
            const std::optional<android::base::function_ref<status_t()>>& altPoll,
            const std::vector<std::variant<base::unique_fd, base::borrowed_fd>>* ancillaryFds)
            override;
    status_t interruptableReadFully(
            FdTrigger* fdTrigger, iovec* iovs, int niovs,
            const std::optional<android::base::function_ref<status_t()>>& altPoll,
            std::vector<std::variant<base::unique_fd, base::borrowed_fd>>* ancillaryFds) override;

    bool isWaiting() { return mSocket.isInPollingState(); };

private:
    android::RpcTransportFd mSocket;
    Ssl mSsl;
};

// Error code is errno.
status_t RpcTransportTls::pollRead(void) {
    uint8_t buf;
    auto [ret, errorQueue] = mSsl.call(SSL_peek, &buf, sizeof(buf));
    if (ret < 0) {
        int err = mSsl.getError(ret);
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
            // Seen EAGAIN / EWOULDBLOCK on recv(2) / send(2).
            // Like RpcTransportRaw::peek(), don't handle it here.
            errorQueue.clear();
            return WOULD_BLOCK;
        }
        return errorQueue.toStatus(err, "SSL_peek");
    }
    errorQueue.clear();
    LOG_TLS_DETAIL("TLS: Peeked %d bytes!", ret);
    return OK;
}

status_t RpcTransportTls::interruptableWriteFully(
        FdTrigger* fdTrigger, iovec* iovs, int niovs,
        const std::optional<android::base::function_ref<status_t()>>& altPoll,
        const std::vector<std::variant<base::unique_fd, base::borrowed_fd>>* ancillaryFds) {
    (void)ancillaryFds;

    MAYBE_WAIT_IN_FLAKE_MODE;

    if (niovs < 0) return BAD_VALUE;

    // Before doing any I/O, check trigger once. This ensures the trigger is checked at least
    // once. The trigger is also checked via triggerablePoll() after every SSL_write().
    if (fdTrigger->isTriggered()) return DEAD_OBJECT;

    size_t size = 0;
    for (int i = 0; i < niovs; i++) {
        const iovec& iov = iovs[i];
        if (iov.iov_len == 0) {
            continue;
        }
        size += iov.iov_len;

        auto buffer = reinterpret_cast<const uint8_t*>(iov.iov_base);
        const uint8_t* end = buffer + iov.iov_len;
        while (buffer < end) {
            size_t todo = std::min<size_t>(end - buffer, std::numeric_limits<int>::max());
            auto [writeSize, errorQueue] = mSsl.call(SSL_write, buffer, todo);
            if (writeSize > 0) {
                buffer += writeSize;
                errorQueue.clear();
                continue;
            }
            // SSL_write() should never return 0 unless BIO_write were to return 0.
            int sslError = mSsl.getError(writeSize);
            // TODO(b/195788248): BIO should contain the FdTrigger, and send(2) / recv(2) should be
            //   triggerablePoll()-ed. Then additionalEvent is no longer necessary.
            status_t pollStatus = errorQueue.pollForSslError(mSocket, sslError, fdTrigger,
                                                             "SSL_write", POLLIN, altPoll);
            if (pollStatus != OK) return pollStatus;
            // Do not advance buffer. Try SSL_write() again.
        }
    }
    LOG_TLS_DETAIL("TLS: Sent %zu bytes!", size);
    return OK;
}

status_t RpcTransportTls::interruptableReadFully(
        FdTrigger* fdTrigger, iovec* iovs, int niovs,
        const std::optional<android::base::function_ref<status_t()>>& altPoll,
        std::vector<std::variant<base::unique_fd, base::borrowed_fd>>* ancillaryFds) {
    (void)ancillaryFds;

    MAYBE_WAIT_IN_FLAKE_MODE;

    if (niovs < 0) return BAD_VALUE;

    // Before doing any I/O, check trigger once. This ensures the trigger is checked at least
    // once. The trigger is also checked via triggerablePoll() after every SSL_write().
    if (fdTrigger->isTriggered()) return DEAD_OBJECT;

    size_t size = 0;
    for (int i = 0; i < niovs; i++) {
        const iovec& iov = iovs[i];
        if (iov.iov_len == 0) {
            continue;
        }
        size += iov.iov_len;

        auto buffer = reinterpret_cast<uint8_t*>(iov.iov_base);
        const uint8_t* end = buffer + iov.iov_len;
        while (buffer < end) {
            size_t todo = std::min<size_t>(end - buffer, std::numeric_limits<int>::max());
            auto [readSize, errorQueue] = mSsl.call(SSL_read, buffer, todo);
            if (readSize > 0) {
                buffer += readSize;
                errorQueue.clear();
                continue;
            }
            if (readSize == 0) {
                // SSL_read() only returns 0 on EOF.
                errorQueue.clear();
                return DEAD_OBJECT;
            }
            int sslError = mSsl.getError(readSize);
            status_t pollStatus = errorQueue.pollForSslError(mSocket, sslError, fdTrigger,
                                                             "SSL_read", 0, altPoll);
            if (pollStatus != OK) return pollStatus;
            // Do not advance buffer. Try SSL_read() again.
        }
    }
    LOG_TLS_DETAIL("TLS: Received %zu bytes!", size);
    return OK;
}

// For |ssl|, set internal FD to |fd|, and do handshake. Handshake is triggerable by |fdTrigger|.
static bool setFdAndDoHandshake(Ssl* ssl, const android::RpcTransportFd& socket,
                                FdTrigger* fdTrigger) {
    bssl::UniquePtr<BIO> bio = newSocketBio(socket.fd);
    TEST_AND_RETURN(false, bio != nullptr);
    auto [_, errorQueue] = ssl->call(SSL_set_bio, bio.get(), bio.get());
    (void)bio.release(); // SSL_set_bio takes ownership.
    errorQueue.clear();

    MAYBE_WAIT_IN_FLAKE_MODE;

    while (true) {
        auto [ret, errorQueue] = ssl->call(SSL_do_handshake);
        if (ret > 0) {
            errorQueue.clear();
            return true;
        }
        if (ret == 0) {
            // SSL_do_handshake() only returns 0 on EOF.
            ALOGE("SSL_do_handshake(): EOF: %s", errorQueue.toString().c_str());
            return false;
        }
        int sslError = ssl->getError(ret);
        status_t pollStatus = errorQueue.pollForSslError(socket, sslError, fdTrigger,
                                                         "SSL_do_handshake", 0, std::nullopt);
        if (pollStatus != OK) return false;
    }
}

class RpcTransportCtxTls : public RpcTransportCtx {
public:
    template <typename Impl,
              typename = std::enable_if_t<std::is_base_of_v<RpcTransportCtxTls, Impl>>>
    static std::unique_ptr<RpcTransportCtxTls> create(
            std::shared_ptr<RpcCertificateVerifier> verifier, RpcAuth* auth);
    std::unique_ptr<RpcTransport> newTransport(RpcTransportFd fd,
                                               FdTrigger* fdTrigger) const override;
    std::vector<uint8_t> getCertificate(RpcCertificateFormat) const override;

protected:
    static ssl_verify_result_t sslCustomVerify(SSL* ssl, uint8_t* outAlert);
    virtual void preHandshake(Ssl* ssl) const = 0;
    bssl::UniquePtr<SSL_CTX> mCtx;
    std::shared_ptr<RpcCertificateVerifier> mCertVerifier;
};

std::vector<uint8_t> RpcTransportCtxTls::getCertificate(RpcCertificateFormat format) const {
    X509* x509 = SSL_CTX_get0_certificate(mCtx.get()); // does not own
    return serializeCertificate(x509, format);
}

// Verify by comparing the leaf of peer certificate with every certificate in
// mTrustedPeerCertificates. Does not support certificate chains.
ssl_verify_result_t RpcTransportCtxTls::sslCustomVerify(SSL* ssl, uint8_t* outAlert) {
    LOG_ALWAYS_FATAL_IF(outAlert == nullptr);
    const char* logPrefix = SSL_is_server(ssl) ? "Server" : "Client";

    auto ctx = SSL_get_SSL_CTX(ssl); // Does not set error queue
    LOG_ALWAYS_FATAL_IF(ctx == nullptr);
    // void* -> RpcTransportCtxTls*
    auto rpcTransportCtxTls = reinterpret_cast<RpcTransportCtxTls*>(SSL_CTX_get_app_data(ctx));
    LOG_ALWAYS_FATAL_IF(rpcTransportCtxTls == nullptr);

    status_t verifyStatus = rpcTransportCtxTls->mCertVerifier->verify(ssl, outAlert);
    if (verifyStatus == OK) {
        return ssl_verify_ok;
    }
    LOG_TLS_DETAIL("%s: Failed to verify client: status = %s, alert = %s", logPrefix,
                   statusToString(verifyStatus).c_str(), SSL_alert_desc_string_long(*outAlert));
    return ssl_verify_invalid;
}

// Common implementation for creating server and client contexts. The child class, |Impl|, is
// provided as a template argument so that this function can initialize an |Impl| object.
template <typename Impl, typename>
std::unique_ptr<RpcTransportCtxTls> RpcTransportCtxTls::create(
        std::shared_ptr<RpcCertificateVerifier> verifier, RpcAuth* auth) {
    bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
    TEST_AND_RETURN(nullptr, ctx != nullptr);

    if (status_t authStatus = auth->configure(ctx.get()); authStatus != OK) {
        ALOGE("%s: Failed to configure auth info: %s", __PRETTY_FUNCTION__,
              statusToString(authStatus).c_str());
        return nullptr;
    };

    // Enable two-way authentication by setting SSL_VERIFY_FAIL_IF_NO_PEER_CERT on server.
    // Client ignores SSL_VERIFY_FAIL_IF_NO_PEER_CERT flag.
    SSL_CTX_set_custom_verify(ctx.get(), SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                              sslCustomVerify);

    // Require at least TLS 1.3
    TEST_AND_RETURN(nullptr, SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION));

    if constexpr (SHOULD_LOG_TLS_DETAIL) { // NOLINT
        SSL_CTX_set_info_callback(ctx.get(), sslDebugLog);
    }

    auto ret = std::make_unique<Impl>();
    // RpcTransportCtxTls* -> void*
    TEST_AND_RETURN(nullptr, SSL_CTX_set_app_data(ctx.get(), reinterpret_cast<void*>(ret.get())));
    ret->mCtx = std::move(ctx);
    ret->mCertVerifier = std::move(verifier);
    return ret;
}

std::unique_ptr<RpcTransport> RpcTransportCtxTls::newTransport(android::RpcTransportFd socket,
                                                               FdTrigger* fdTrigger) const {
    bssl::UniquePtr<SSL> ssl(SSL_new(mCtx.get()));
    TEST_AND_RETURN(nullptr, ssl != nullptr);
    Ssl wrapped(std::move(ssl));

    preHandshake(&wrapped);
    TEST_AND_RETURN(nullptr, setFdAndDoHandshake(&wrapped, socket, fdTrigger));
    return std::make_unique<RpcTransportTls>(std::move(socket), std::move(wrapped));
}

class RpcTransportCtxTlsServer : public RpcTransportCtxTls {
protected:
    void preHandshake(Ssl* ssl) const override {
        ssl->call(SSL_set_accept_state).errorQueue.clear();
    }
};

class RpcTransportCtxTlsClient : public RpcTransportCtxTls {
protected:
    void preHandshake(Ssl* ssl) const override {
        ssl->call(SSL_set_connect_state).errorQueue.clear();
    }
};

std::unique_ptr<RpcTransportCtx> RpcTransportCtxFactoryTls::newServerCtx() const {
    return android::RpcTransportCtxTls::create<RpcTransportCtxTlsServer>(mCertVerifier,
                                                                         mAuth.get());
}

std::unique_ptr<RpcTransportCtx> RpcTransportCtxFactoryTls::newClientCtx() const {
    return android::RpcTransportCtxTls::create<RpcTransportCtxTlsClient>(mCertVerifier,
                                                                         mAuth.get());
}

const char* RpcTransportCtxFactoryTls::toCString() const {
    return "tls";
}

std::unique_ptr<RpcTransportCtxFactory> RpcTransportCtxFactoryTls::make(
        std::shared_ptr<RpcCertificateVerifier> verifier, std::unique_ptr<RpcAuth> auth) {
    if (verifier == nullptr) {
        ALOGE("%s: Must provide a certificate verifier", __PRETTY_FUNCTION__);
        return nullptr;
    }
    if (auth == nullptr) {
        ALOGE("%s: Must provide an auth provider", __PRETTY_FUNCTION__);
        return nullptr;
    }
    return std::unique_ptr<RpcTransportCtxFactoryTls>(
            new RpcTransportCtxFactoryTls(std::move(verifier), std::move(auth)));
}

} // namespace android

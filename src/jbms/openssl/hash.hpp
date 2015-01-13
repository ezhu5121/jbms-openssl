#ifndef HEADER_GUARD_aa87e568d4a9ccf7840d38f6e859ed68
#define HEADER_GUARD_aa87e568d4a9ccf7840d38f6e859ed68

#include <openssl/md5.h>
#include <openssl/sha.h>
#include "jbms/array_view.hpp"
#include <stdexcept>

namespace jbms {
namespace openssl {

#define JBMS_OPENSSL_HASH_WRAPPER(state_name, func_name, prefix, ctx_type, DIGEST_LENGTH)                            \
  struct state_name {                                                                                                \
    ctx_type ctx;                                                                                                    \
    void init() { prefix##_Init(&ctx); }                                                                             \
    state_name() { init(); }                                                                                         \
    void operator()(const void *data, size_t len) { prefix##_Update(&ctx, data, len); }                              \
    void operator()(array_view<void const> data) { prefix##_Update(&ctx, data.data(), data.size()); }                \
                                                                                                                     \
    using Digest = std::array<uint8_t, DIGEST_LENGTH>;                                                               \
    static constexpr size_t digest_length = DIGEST_LENGTH;                                                           \
                                                                                                                     \
    Digest digest() {                                                                                                \
      Digest md;                                                                                                     \
      prefix##_Final(md.data(), &ctx);                                                                               \
      return md;                                                                                                     \
    }                                                                                                                \
                                                                                                                     \
    void digest(array_view<uint8_t> digest) {                                                                        \
      if (digest.size() > digest_length)                                                                             \
        throw std::invalid_argument(#state_name "::digest: digest.size()=" + std::to_string(digest.size()) + " > " + \
                                    std::to_string(digest_length));                                                  \
      Digest buf = this->digest();                                                                                   \
      std::copy_n(buf.begin(), digest.size(), digest.begin());                                                       \
    }                                                                                                                \
  };                                                                                                                 \
  inline auto func_name(array_view<void const> data) {                                                               \
    state_name s;                                                                                                    \
    s(data);                                                                                                         \
    return s.digest();                                                                                               \
  }                                                                                                                  \
  inline void func_name(array_view<uint8_t> digest_out, array_view<void const> data) {                               \
    state_name s;                                                                                                    \
    s(data);                                                                                                         \
    s.digest(digest_out);                                                                                            \
  } /**/

JBMS_OPENSSL_HASH_WRAPPER(sha2_512_state, sha2_512, SHA512, SHA512_CTX, SHA512_DIGEST_LENGTH)
JBMS_OPENSSL_HASH_WRAPPER(sha2_384_state, sha2_384, SHA384, SHA512_CTX, SHA384_DIGEST_LENGTH)

JBMS_OPENSSL_HASH_WRAPPER(sha2_256_state, sha2_256, SHA256, SHA256_CTX, SHA256_DIGEST_LENGTH)
JBMS_OPENSSL_HASH_WRAPPER(sha2_224_state, sha2_224, SHA224, SHA256_CTX, SHA224_DIGEST_LENGTH)

JBMS_OPENSSL_HASH_WRAPPER(sha1_state, sha1, SHA1, SHA_CTX, SHA_DIGEST_LENGTH)
JBMS_OPENSSL_HASH_WRAPPER(md5_state, md5, MD5, MD5_CTX, MD5_DIGEST_LENGTH)

#undef JBMS_OPENSSL_HASH_WRAPPER
}
}

#endif /* HEADER GUARD */

#ifndef HEADER_GUARD_150cedda09269cb541726f767911f2cd
#define HEADER_GUARD_150cedda09269cb541726f767911f2cd

#include <openssl/rand.h>
#include "./error.hpp"
#include "jbms/array_view.hpp"

namespace jbms {
namespace openssl {

inline void rand_bytes(array_view<uint8_t> buf) {
  throw_last_error_if(RAND_bytes(buf.data(), buf.size()) != 1);
}

inline void rand_pseudo_bytes(array_view<uint8_t> buf) {
  throw_last_error_if(RAND_pseudo_bytes(buf.data(), buf.size()) != 1);
}


}
}

#endif /* HEADER GUARD */

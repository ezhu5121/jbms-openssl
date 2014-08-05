#ifndef HEADER_GUARD_26d1e5df835991af15ef74e032b84ddf
#define HEADER_GUARD_26d1e5df835991af15ef74e032b84ddf

#include <openssl/ec.h>
#include "./bn.hpp"
#include "./error.hpp"

namespace jbms {
namespace openssl {

class ec_group {
  EC_GROUP *group_;

public:
  ec_group() : group_(nullptr) {}

  explicit ec_group(EC_GROUP *group_) : group_(group_) {}

  ~ec_group() {
    if (group_)
      EC_GROUP_free(group_);
  }

  static ec_group by_curve_name(int nid) {
    auto x = EC_GROUP_new_by_curve_name(nid);
    throw_last_error_if(x == nullptr);
    return ec_group(x);
  }

  operator EC_GROUP const *() const { return group_; }
  operator EC_GROUP *() { return group_; }

  EC_GROUP const *get() const { return group_; }
  EC_GROUP *get() { return group_; }

  ec_group(ec_group const &other) {
    if (other.group_) {
      group_ = EC_GROUP_dup(other.get());
      throw_last_error_if(group_ == nullptr);
    } else {
      group_ = nullptr;
    }
  }

  ec_group(ec_group &&other) {
    group_ = other.group_;
    other.group_ = nullptr;
  }

  void reset() {
    if (group_) {
      EC_GROUP_free(group_);
      group_ = nullptr;
    }
  }

  explicit operator bool () const { return bool(group_); }

  EC_GROUP *release() { auto tmp = group_; group_ = nullptr; return tmp; }

  EC_METHOD const *method() const { return EC_GROUP_method_of(get()); }

  ec_group &operator=(ec_group const &other) {
    if (!other) {
      reset();
      return *this;
    }
    else {
      if (group_) {
        if (method() == other.method()) {
          throw_last_error_if(EC_GROUP_copy(get(), other.get()) != 1);
          return *this;
        } else {
          reset();
        }
      }
      group_ = EC_GROUP_dup(other.get());
      throw_last_error_if(group_ == nullptr);
    }
    return *this;
  }

  void swap(ec_group &other) {
    std::swap(group_, other.group_);
  }

  void get_curve_GF2m(BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *ctx = nullptr) const {
    throw_last_error_if(EC_GROUP_get_curve_GF2m(get(), p, a, b, ctx) != 1);
  }

  /* Returns number of bits required to represent a field element */
  int degree() const {
    return EC_GROUP_get_degree(get());
  }
};

class ec_point {
  EC_POINT *point_;
public:

  operator EC_POINT const *() const { return point_; }
  operator EC_POINT *() { return point_; }

  EC_POINT const *get() const { return point_; }
  EC_POINT *get() { return point_; }


  ec_point() : point_(nullptr) {}

  explicit ec_point(ec_group const &group) {
    throw_last_error_if((point_ = EC_POINT_new(group.get())) == nullptr);
  }

  ~ec_point() {
    if (point_)
      EC_POINT_free(point_);
  }

  EC_METHOD const *method() const { return EC_POINT_method_of(get()); }

  EC_POINT *release() { auto tmp = point_; point_ = nullptr; return tmp; }

  void reset() {
    if (point_) {
      EC_POINT_free(point_);
      point_ = nullptr;
    }
  }

  ec_point(ec_point const &other) = delete;

  ec_point(ec_point const &other, ec_group const &group) {
    throw_last_error_if((point_ = EC_POINT_dup(other.get(), group.get())) == nullptr);
  }

  ec_point(ec_point &&other) {
    point_ = other.point_;
    other.point_ = nullptr;
  }

  ec_point &operator=(ec_point const &other) {
    if (point_)
      throw_last_error_if(EC_POINT_copy(point_, other.point_) != 1);
    else
      point_ = nullptr;
    return *this;
  }

  ec_point &operator=(ec_point &&other) {
    if (point_)
      EC_POINT_free(point_);
    point_ = other.point_;
    other.point_ = nullptr;
    return *this;
  }
};

inline void set_to_infinity(ec_group const &group, EC_POINT *point) {
  throw_last_error_if(EC_POINT_set_to_infinity(group.get(), point) == 0);
}


inline void get_affine_coordinates_GFp(ec_group const &group, const EC_POINT *p, BIGNUM *x, BIGNUM *y, BN_CTX *ctx = nullptr) {
  throw_last_error_if(EC_POINT_get_affine_coordinates_GFp(group.get(), p, x, y, ctx) == 0);
}

inline void set_affine_coordinates_GFp(ec_group const &group, EC_POINT *p, const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx = nullptr) {
  throw_last_error_if(EC_POINT_set_affine_coordinates_GFp(group.get(), p, x, y, ctx) == 0);
}



inline void get_affine_coordinates_GF2m(ec_group const &group, const EC_POINT *p, BIGNUM *x, BIGNUM *y, BN_CTX *ctx = nullptr) {
  throw_last_error_if(EC_POINT_get_affine_coordinates_GF2m(group.get(), p, x, y, ctx) == 0);
}

inline void set_affine_coordinates_GF2m(ec_group const &group, EC_POINT *p, const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx = nullptr) {
  throw_last_error_if(EC_POINT_set_affine_coordinates_GF2m(group.get(), p, x, y, ctx) == 0);
}



inline void add(ec_group const &group, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *ctx = nullptr) {
  throw_last_error_if(EC_POINT_add(group.get(), r, a, b, ctx) == 0);
}

inline void dbl(ec_group const &group, EC_POINT *r, const EC_POINT *a, BN_CTX *ctx = nullptr) {
  throw_last_error_if(EC_POINT_dbl(group.get(), r, a, ctx) == 0);
}

inline void invert(ec_group const &group, EC_POINT *a, BN_CTX *ctx = nullptr) {
  throw_last_error_if(EC_POINT_invert(group.get(), a, ctx) == 0);
}

inline bool is_at_infinity(ec_group const &group, EC_POINT const *p) {
  return EC_POINT_is_at_infinity(group.get(), p);
}

inline bool is_on_curve(ec_group const &group, EC_POINT const *point, BN_CTX *ctx = nullptr) {
  return EC_POINT_is_on_curve(group.get(), point, ctx);
}

inline bool equal(ec_group const &group, EC_POINT const *a, EC_POINT const *b, BN_CTX *ctx = nullptr) {
  return EC_POINT_cmp(group.get(), a, b, ctx) == 0;
}


}
}

#endif /* HEADER GUARD */

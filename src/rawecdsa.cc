#include "node.h"
#include "nan.h"
#include "node_buffer.h"
#include "node_object_wrap.h"
#include "openssl/evp.h"
#include "openssl/ec.h"
#include "openssl/ecdsa.h"
#include "openssl/pem.h"
#include "openssl/x509.h"
#include "v8.h"

namespace rawrsa {

using namespace node;
using namespace v8;

class Key : public ObjectWrap {
 public:
  static void Init(Handle<Object> target) {
    Local<FunctionTemplate> t = NanNew<FunctionTemplate>(Key::New);

    t->InstanceTemplate()->SetInternalFieldCount(1);
    t->SetClassName(NanNew<String>("Key"));

    NODE_SET_PROTOTYPE_METHOD(t, "sign", Key::Sign);
    NODE_SET_PROTOTYPE_METHOD(t, "verify", Key::Verify);

    target->Set(NanNew<String>("Key"), t->GetFunction());
  }

 protected:
  Key(EVP_PKEY* evp, EC_KEY* ec) : evp_(evp), ec_(ec) {
    if (evp_ != NULL) {
      assert(ec_ == NULL);
      ec_ = evp_->pkey.ec;
    }
  }

  ~Key() {
    if (evp_ != NULL)
      EVP_PKEY_free(evp_);
    else
      EC_KEY_free(ec_);
    evp_ = NULL;
    ec_ = NULL;
  }

  static NAN_METHOD(New) {
    NanScope();

    if (args.Length() != 1 || !Buffer::HasInstance(args[0])) {
      return NanThrowError("Invalid arguments length, expected "
                           "new Key(buffer)");
    }

    unsigned char* buf = reinterpret_cast<unsigned char*>(
        Buffer::Data(args[0]));
    int buf_len = Buffer::Length(args[0]);

    EC_KEY* ec;
    EVP_PKEY* evp = NULL;

    const unsigned char* pbuf;

    pbuf = buf;
    ec = d2i_ECPrivateKey(NULL, &pbuf, buf_len);
    if (ec != NULL)
      goto done;

    pbuf = buf;
    ec = o2i_ECPublicKey(NULL, &pbuf, buf_len);
    if (ec != NULL)
      goto done;

    {
      BIO* bio = BIO_new_mem_buf(buf, buf_len);
      evp = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
      if (evp == NULL)
        ec = PEM_read_bio_EC_PUBKEY(bio, NULL, NULL, NULL);
      if (evp == NULL && ec == NULL)
        ec = PEM_read_bio_ECPrivateKey(bio, NULL, NULL, NULL);

      BIO_free_all(bio);
    }

 done:
    if (evp == NULL && ec == NULL)
      return NanThrowError("Failed to read EVP_PKEY/EC_KEY");

    Key* k = new Key(evp, ec);
    k->Wrap(args.This());

    NanReturnValue(args.This());
  }

  static NAN_METHOD(Sign) {
    NanScope();

    if (args.Length() != 1 ||
        !Buffer::HasInstance(args[0])) {
      return NanThrowError("Invalid arguments length, expected (hash)");
    }

    Key* k = ObjectWrap::Unwrap<Key>(args.This());

    unsigned char* from = reinterpret_cast<unsigned char*>(
        Buffer::Data(args[0]));
    int from_len = Buffer::Length(args[0]);

    unsigned int to_len = ECDSA_size(k->ec_);
    unsigned char* to = new unsigned char[to_len];

    if (ECDSA_sign(0, from, from_len, to, &to_len, k->ec_) != 1) {
      delete[] to;
      return NanThrowError("Failed to sign the data");
    }

    Local<Value> buf = Buffer::New(reinterpret_cast<char*>(to), to_len);
    delete[] to;

    NanReturnValue(buf);
  }

  static NAN_METHOD(Verify) {
    NanScope();

    if (args.Length() != 2 ||
        !Buffer::HasInstance(args[0]) ||
        !Buffer::HasInstance(args[1])) {
      return NanThrowError("Invalid arguments length, expected (sig, hash)");
    }

    Key* k = ObjectWrap::Unwrap<Key>(args.This());

    unsigned char* sig = reinterpret_cast<unsigned char*>(
        Buffer::Data(args[0]));
    int sig_len = Buffer::Length(args[0]);
    unsigned char* hash = reinterpret_cast<unsigned char*>(
        Buffer::Data(args[1]));
    int hash_len = Buffer::Length(args[1]);

    int r = ECDSA_verify(0, hash, hash_len, sig, sig_len, k->ec_);
    if (r == -1)
      return NanThrowError("Failed to decode the signature");

    NanReturnValue(NanNew(r == 1));
  }

  EVP_PKEY* evp_;
  EC_KEY* ec_;
};

static void Init(Handle<Object> target) {
  // Init OpenSSL
  OpenSSL_add_all_algorithms();

  Key::Init(target);
}

NODE_MODULE(rawrsa, Init);

}  // namespace rawcipher

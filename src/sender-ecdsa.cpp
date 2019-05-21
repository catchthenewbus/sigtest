#include "sender-ecdsa.hpp"

#include <glog/logging.h>

#include <openssl/obj_mac.h>
#include <openssl/pem.h>

SenderECDSA::SenderECDSA(void)
{

    int ret;

    this->key = EC_KEY_new();
    if (this->key == NULL)
    {
        LOG(ERROR) << "unable to create ec key";
        throw std::runtime_error("unable to create ec key");
    }

    this->group = 
        EC_GROUP_new_by_curve_name(NID_secp192k1);
    if (this->group == NULL)
    {
        LOG(ERROR) << "unable to create ec group";
        throw std::runtime_error("unable to create ec group");
    }

    ret = EC_KEY_set_group(this->key, this->group);
    if (ret != 1)
    {
        LOG(ERROR) << "unable to set group for ec key";
        throw std::runtime_error("unable to set group for ec key");
    }

}

SenderECDSA::~SenderECDSA(void)
{
    EC_GROUP_free(this->group);
    EC_KEY_free(this->key);
}

int SenderECDSA::readPrivateKey(const char *filename)
{

    int ret;
    EC_KEY* key;
    BIO* bio;
    
    bio = BIO_new(BIO_s_file());
    BIO_read_filename(bio, filename);

    key = PEM_read_bio_ECPrivateKey(bio, &this->key, NULL, NULL);
    if (key == NULL)
    {
        LOG(ERROR) << "unable to read ec key from file";
        return -1;
    }

    return 0;

}

int SenderECDSA::sign(
    const char *data,
    std::size_t dataLen,
    unsigned char **signature,
    int *signatureLen
)
{

    int ret;
    ECDSA_SIG *sig;
    unsigned char *p;

    sig = ECDSA_do_sign(
        (const unsigned char *) data,
        dataLen, this->key);
    if (sig == NULL)
    {
        LOG(ERROR) << "unable to sign data";
        return -1;
    }
    
    *signatureLen = i2d_ECDSA_SIG(sig, NULL);
    *signature = (unsigned char *) malloc(*signatureLen);

    p = *signature;
    ret = i2d_ECDSA_SIG(sig, &p);
    if (ret == 0)
    {
        LOG(ERROR) << "unable to der encode signature";
        return -1;
    }

    return 0;

}

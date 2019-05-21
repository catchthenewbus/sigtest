#include "receiver-ecdsa.hpp"

#include <glog/logging.h>

#include <openssl/obj_mac.h>
#include <openssl/pem.h>

ReceiverECDSA::ReceiverECDSA(void)
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

ReceiverECDSA::~ReceiverECDSA(void)
{
    EC_GROUP_free(this->group);
    EC_KEY_free(this->key);
}

int ReceiverECDSA::readPublicKey(const char *filename)
{

    int ret;
    EC_KEY* key;
    BIO* bio;

    bio = BIO_new(BIO_s_file());
    BIO_read_filename(bio, filename);

    key = PEM_read_bio_EC_PUBKEY(bio, &this->key, NULL, NULL);
    if (key == NULL)
    {
        LOG(ERROR) << "unable to read ec key from file";
        return -1;
    }

    return 0;

}

int ReceiverECDSA::verify(
    const char *data,
    std::size_t dataLen,
    unsigned char *signature,
    int signatureLen
)
{

    int ret;
    const unsigned char *p;
    ECDSA_SIG *sig;

    p = signature;
    sig = d2i_ECDSA_SIG(NULL, &p, signatureLen);
    if (sig == NULL)
    {
        LOG(ERROR) << "unable to der decode signature";
        return -1;
    }

    ret = ECDSA_do_verify(
        (const unsigned char *) data,
        dataLen, sig, this->key);
    if (ret != 1)
    {
        LOG(ERROR) << "unable to verify signature";
        return -1;
    }

    return 0;

}

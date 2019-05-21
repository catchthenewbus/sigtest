#pragma once

#include <string>

#include <openssl/ec.h>

class ReceiverECDSA
{

private:

    EC_KEY *key;
    EC_GROUP *group;

public:

    ReceiverECDSA(void);
    ~ReceiverECDSA(void);

    int readPublicKey(const char *filename);

    int verify(
        const char *data,
        std::size_t dataLen,
        unsigned char *signature,
        int signatureLen
    );

};

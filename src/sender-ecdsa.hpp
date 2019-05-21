#pragma once

#include <string>

#include <openssl/ec.h>

class SenderECDSA
{

private:

    EC_KEY *key;
    EC_GROUP *group;

public:

    SenderECDSA(void);
    ~SenderECDSA(void);

    int readPrivateKey(const char *filename);
    
    int sign(
        const char *data,
        std::size_t dataLen,
        unsigned char **signature,
        int *signatureLen
    );

};

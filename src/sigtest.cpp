#include <iostream>

#include <glog/logging.h>

#include "sender-ecdsa.hpp"
#include "receiver-ecdsa.hpp"

SenderECDSA senderECDSA;
ReceiverECDSA receiverECDSA;

int main(int argc, char **argv)
{

    int ret, signatureLen, someDataLen, otherDataLen;
    char *senderKeyFile, *receiverKeyFile;
    unsigned char *signature;
    const char *someData, *otherData;

    // initialize logging
    FLAGS_logtostderr = 1;
    FLAGS_colorlogtostderr = 1;
    google::InitGoogleLogging(argv[0]);

    if (argc < 2)
    {
        LOG(ERROR) << "usage: " << argv[0] <<
            " <private key file> <public key file>";
        return EXIT_FAILURE;
    }

    senderKeyFile = argv[1];
    receiverKeyFile = argv[2];

    // read senders private key
    ret = senderECDSA.readPrivateKey(senderKeyFile);
    if (ret < 0) return EXIT_FAILURE;

    // read receivers public key
    ret = receiverECDSA.readPublicKey(receiverKeyFile);
    if (ret < 0) return EXIT_FAILURE;

    // generate some data
    someData = "somedata";
    someDataLen = strlen(someData);
    otherData = "otherdata";
    otherDataLen = strlen(otherData);

    // sign data
    ret = senderECDSA.sign(someData, someDataLen,
        &signature, &signatureLen);
    if (ret < 0) return EXIT_FAILURE;

    // print signature
    for (int i = 0; i < signatureLen; i++)
        std::cout << std::hex <<
            int(signature[i]);
    std::cout << "\n";

    ret = receiverECDSA.verify(someData, someDataLen,
        signature, signatureLen);
    // ret should be 0 (valid)
    LOG(INFO) << "ret=" << ret;

    ret = receiverECDSA.verify(otherData, otherDataLen,
        signature, signatureLen);
    // ret should be -1 (invalid)
    LOG(INFO) << "ret=" << ret;

}

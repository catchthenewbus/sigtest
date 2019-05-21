sigtest
=======

```
$ openssl ecparam -name secp192k1 -genkey -noout -out private.pem
$ openssl ec -in private.pem -pubout -out public.pem
$ ./sigtest private.pem public.pem 
30352190f0395b4c82705aee9a407cbeb837b8a3237e33feef38a3e52182715c2902c119ff18d99e35061c347daa87a7a6ef152526d
I0521 22:25:08.882766 260736448 sigtest.cpp:62] ret=0
E0521 22:25:08.885776 260736448 receiver-ecdsa.cpp:89] unable to verify signature
I0521 22:25:08.885808 260736448 sigtest.cpp:67] ret=-1
```

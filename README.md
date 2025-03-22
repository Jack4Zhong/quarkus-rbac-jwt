# quarkus-rbac-jwt
A simple role base access control Quarkus project


## Private and Public keys
In order to JWT to work, we need to sign it with private key. Without this step anybody can just pass fake data to our Quarkus app, and it will think that it’s valid credentials. This way anybody can use admin endpoints, for example. Luckly get private and public key is super easy:

```sh
openssl genrsa -out publicKey.pem
openssl pkcs8 -topk8 -inform PEM -in publicKey.pem -out privateKey.pem -nocrypt
openssl rsa -in publicKey.pem -pubout -outform PEM -out publicKey.pem
```
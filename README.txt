This is a sample project for RSA encryption and decryption, designed for cross-language integration. For example, encrypting with Java and then decrypting with C#, or vice versa.


Generate your own key pair via the command line like this:

openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in private_key.pem -pubout -out public_key.pem
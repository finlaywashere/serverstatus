# ServerStatus protocol v1.0

# 0 - Conventions

## 0.0 - Example Conventions

In given examples, anything inside brackets marked as code (`(` or `)`) must be substituted with a value, the brackets are not part of the data's format unless otherwise specified and must be removed after the value is substituted in.

## 0.1 - Encoding Keys

Keys must be encoded in the format `(algorithm):(base64 encoded key with line endings replaced with &l)`.

## 0.2 - Encoding Signatures and Encrypted Data

Signatures must be encoded with base64 and have all line endings replaced with `&l`.

# 1 - Security

## 1.1 - Authentication

The ServerStatus protocol authenticates both the server and client using keys signed by a certificate authority. First the client authenticates with the server, then the server authenticates with the client, this prevents clients from tricking the server into authenticating with another server by manipulating the nonce. The authentication is the same for both sides, but the roles are reversed when the server authenticates.

The authentication starts with the authenticating device sending a nonce value (integer) followed by a new line. (ex: `1234567\n`).

Then the device being authenticated must send its public key (see #0.1 for format) followed by a new line.

Then the device being authenticated must send its CA signed public key (see #0.2 for format) followed by a new line.

Finally the device being authenticated must send the nonce signed by its private key (see #0.2 for format) followed by a new line. This is used to verify that the device actually possesses the key.

After all this data is received, the authenticating device verifies that A) the CA signed public key is correct and B) the signed nonce is correct, the authenticating device responds with either `true` or `false` followed by a new line to indicate whether or not the authentication has been successful.

## 1.2 - Encryption

Directly after authentication, a key must be agreed upon, and all traffic must be encrypted.

This key handshake implements perfect forward secrecy, after it is completed any data sent will be effectively impossible to recover after the temporary asymmetric and symmetric keys are deleted.

The first step in this process is the server generating a temporary asymmetric key, encrypting it with the client's public key, and sending it (see #0.2 for format) followed by a new line.

The client must then decrypt this public key, generate a symmetric key, encrypt it with the temporary public key, and then send it (see #0.1 for format) followed by a new line.

After the server receives this key, ALL traffic must be encrypted with it until the end of this session.

# 2 - Commands

## 2.1 - Command Format

All commands must be sent in the format `(command name)` followed by a new line, commands optionally may send or receive extra data on seperate lines.

Note: Command names are case sensitive

## 2.2 - Command List

## 2.2.1 - Ping

Ping is used to verify that a server is still online and responsive, the command name for ping is `ping`. The expected response is `pong` (case sensitive).

# CryptChat

A secure, end-to-end encrypted chat application designed to prioritize privacy, with plans for Tor integration to further enhance anonymity.

## About

CryptChat is a secure messaging app that uses asymmetric encryption for private communications. Currently, it ensures message confidentiality and integrity between users but will soon support Tor routing to provide an additional layer of anonymity. This feature is ideal for users who need added privacy in their communications

🛠️ **Tor Integration**: Tor routing support is under development. Once completed, all messages will be routed through the Tor network for enhanced privacy.

## Features

- **End-to-End Encryption**: Messages are encrypted on the sender's device and only decrypted on the recipient's, ensuring secure communications.
- **Tor Network Routing** (COMING SOON): All messages are routed through the Tor network for anonymity and additional privacy.
- **Public/Private Key Exchange**: Users exchange public keys for secure, encrypted message delivery.
- **File uploads**: Provides secure & encrypted file uploads.
- **Persistent Encrypted Messages**: Messages are stored on the server in encrypted form, accessible only to authorized users.


## How it works


1. User signs up for service
    - A private and public is created for that User
    - Private key stays on user's device, while the public key is sent to the server

2. User can add or accept friends 
    - When user adds or accepts a friend , whoever accepted the friend request will generate a **symmetric key** locally, then encrypt that key with each user's public key and send it to the server which will get stored between those 2 unique users, this will ensure only the user with the private key can access the symmetric key.

3. User can chat with friends
    - After accepting friend request, users can now communicate to each other.
    - When a user sends a message or file it will encrypt it using the symmetric key, so only the recipient with the same symmetric key could decrypt and view the message or file.


# pch: a end-to-end encrypted chat app

The code contains a X3DH implementation as described [here](https://signal.org/docs/specifications/x3dh/). After the key exchange messages are to be sent over using the double ratchet algorithm which also provides forward secrecy. Both implementations are implemeted using x/crypto library and the Go standard library.

The communication between clients and the server is done using gRPC and the proto definitions can be found in the `/proto`. Since the client does a lot of the heavy lifting the gRPC server should not be used without the client together. Both crypto implementations are pretty well documented with comments.

Currently the server supports having conversations between two terminals the UI is just lacking.

## TODO

- [x] X3DH
- [x] Double ratchet
- [x] Basic chatting and server and client
- [x] Store the user's OTP on disk.
- [x] Store messages persistently
- [ ] Proper terminal interface
- [ ] Auth challenge from server to verify identity
- [ ] Persisting keys between sessions
- [ ] Automatically update keys in some time frame

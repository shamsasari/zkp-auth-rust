# ZKP Authentication

A simple authentication server which allows a client to authenticate with a server without having to send its password.
This is done by using the Chaum-Pedersen ZKP protocol.

## Building

gRPC is used for communication, which will require the protobuf compiler to build the project. On Debian systems this
can be installed with:

```shell
sudo apt-get install protobuf-compiler
```

```shell
cargo build --release
```

## Running the server

Chaum-Pedersen requires parameters which are shared between the server and client. In this implementation, the server
reads them in via a config file, and sends them to the client.

This repo has a sample config file with parameters taken from [RFC 5114](https://datatracker.ietf.org/doc/html/rfc5114#section-2.3).

```shell
./target/release/server 127.0.0.1:5000 rfc_5114_params.toml 
```

## Running the client

First register a new user:

```shell
./target/release/client http://127.0.0.1:5000 register
```

Enter a username and password at the prompt.

To authenticate and receive a session token:

```shell
./target/release/client http://127.0.0.1:5000 authenticate
```

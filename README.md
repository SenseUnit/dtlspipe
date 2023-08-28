# dtlspipe

Generic DTLS wrapper for UDP sessions. Suitable for wrapping Wireguard or UDP OpenVPN or any other connection-oriented UDP sessions.

"Client" receives plaintest UDP traffic and forwards it to "Server" via encrypted DTLS connection. "Server" listens UDP port and accepts encrypted DTLS sessions, forwarding messages from each session as a separate UDP connection to plaintext UDP port.

## Features

* Cross-platform (Windows/Mac OS/Linux/Android (via shell)/\*BSD)
* Uses proven DTLS crypto for secure datagram tunneling
* Simple configuration: just pre-shared key, listen address and forward address.

## Installation

#### Binaries

Pre-built binaries are available [here](https://github.com/Snawoot/dtlspipe/releases/latest).

#### Build from source

Alternatively, you may install dtlspipe from source. Run the following command within the source directory:

```
make install
```

## Synopsis

```
$ dtlspipe -h
Usage:

dtlspipe [OPTION]... server <BIND ADDRESS> <REMOTE ADDRESS>
dtlspipe [OPTION]... client <BIND ADDRESS> <REMOTE ADDRESS>
dtlspipe [OPTION]... genpsk
dtlspipe version

Options:
  -cpuprofile string
    	write cpu profile to file
  -identity string
    	client identity sent to server
  -idle-time duration
    	max idle time for UDP session (default 1m30s)
  -key-length uint
    	generate key with specified length (default 16)
  -mtu int
    	MTU used for DTLS fragments (default 1400)
  -psk string
    	hex-encoded pre-shared key. Can be generated with genpsk subcommand
  -timeout duration
    	network operation timeout (default 10s)
```

# dtlspipe

Generic DTLS wrapper for UDP sessions. Like `stunnel`, but for UDP. Suitable for wrapping Wireguard or UDP OpenVPN or any other connection-oriented UDP sessions.

"Client" receives plaintest UDP traffic and forwards it to "Server" via encrypted DTLS connection. "Server" listens UDP port and accepts encrypted DTLS sessions, forwarding messages from each session as a separate UDP connection to plaintext UDP port.

## Features

* Cross-platform (Windows/Mac OS/Linux/Android/\*BSD)
* Uses proven DTLS crypto for secure datagram tunneling
* Simple configuration: just pre-shared key, listen address and forward address.

## Installation

### Binaries

Pre-built binaries are available [here](https://github.com/Snawoot/dtlspipe/releases/latest).

### Build from source

Alternatively, you may install dtlspipe from source. Run the following command within the source directory:

```
make install
```

## Usage

### Generic case

Let's assume you have following setup: you have server with public IP address 203.0.113.11, running some UDP service on port 514. You want to access this service securely and have UDP datagrams between you and this service encrypted and authenticated.

1. Generate pre-shared key with command `dtlspipe genpsk`
2. Run dtlspipe-server on server machine: `dtlspipe -psk xxxxxxxxxxxx server 0.0.0.0:2815 127.0.0.1:514`
3. Run dtlspipe-client on your machine: `dtlspipe -psk xxxxxxxxxxxx client 127.0.0.1:2816 203.0.113.11:2815`
4. Use address `127.0.0.1:2816` instead of `203.0.113.11:514` for communication with the service.

Few notes:

* You may use any ports instead of 2815 and 2816.
* Use of localhost address `127.0.0.1` for port bind is optional too and used in example to restrict port access from localhost only. Use `0.0.0.0` to allow network access from outside.
* PSK can be also specified via `DTLSPIPE_PSK` environment variable.

### Wireguard

dtlspipe setup can be done using example for generic case, but more specifically, dtlspipe server should point to the wireguard server port and wireguard client should communicate with port of dtlspipe client.

You need to make following adjustments to wireguard client config:

1. Use bind address of the dtlspipe client as endpoint for client's wireguard connection.
2. Use smaller MTU for wireguard tunnel, add `MTU = 1280` to the `[Peer]` section of wireguard client and server tunnel config.
3. Exclude dtlspipe server address from `AllowedIPs` in the wireguard client config. [This calculator](https://www.procustodibus.com/blog/2021/03/wireguard-allowedips-calculator/) may help you. Example for server address `203.0.113.11`:

```
AllowedIPs = 0.0.0.0/1, 128.0.0.0/2, 192.0.0.0/5, 200.0.0.0/7, 202.0.0.0/8, 203.0.0.0/18, 203.0.64.0/19, 203.0.96.0/20, 203.0.112.0/24, 203.0.113.0/29, 203.0.113.8/31, 203.0.113.10/32, 203.0.113.12/30, 203.0.113.16/28, 203.0.113.32/27, 203.0.113.64/26, 203.0.113.128/25, 203.0.114.0/23, 203.0.116.0/22, 203.0.120.0/21, 203.0.128.0/17, 203.1.0.0/16, 203.2.0.0/15, 203.4.0.0/14, 203.8.0.0/13, 203.16.0.0/12, 203.32.0.0/11, 203.64.0.0/10, 203.128.0.0/9, 204.0.0.0/6, 208.0.0.0/4, 224.0.0.0/3, ::/0
```

**Note:** consider use of `-skip-hello-verify` option on server to workaround DPI if such filtering is the case for you.

## Synopsis

```
$ dtlspipe -h
Usage:

dtlspipe [OPTION]... server <BIND ADDRESS> <REMOTE ADDRESS>
dtlspipe [OPTION]... client <BIND ADDRESS> <REMOTE ADDRESS>
dtlspipe [OPTION]... genpsk
dtlspipe ciphers
dtlspipe version

Options:
  -ciphers value
    	colon-separated list of ciphers to use
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
  -skip-hello-verify
    	(server only) skip hello verify request. Useful to workaround DPI
  -timeout duration
    	network operation timeout (default 10s)
```

## See also

* [Project Wiki](https://github.com/Snawoot/dtlspipe/wiki)
* [Community in Telegram](https://t.me/dtlspipe)

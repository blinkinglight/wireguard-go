
# Go Implementation of [WireGuard](https://www.wireguard.com/)

This is an experimental LLM optimized implementation of WireGuard in Go.


experimental eBPF:

WG_XDP_IFACE=br255 WG_XDP_ZEROCOPY=1 WG_XDP_NATIVE=1   WG_XDP_QUEUE=0    WG_PROCESS_FOREGROUND=1 LOG_LEVEL=debug wireguard-go -f wglo0

experimental mode for encryption:

Example (userspace wireguard-go interface wglo0):

printf 'set=1\nexperimental_cipher=aesgcm\n\n' | socat - UNIX-CONNECT:/var/run/wireguard/wglo0.sock

Switch back:

printf 'set=1\nexperimental_cipher=chacha20poly1305\n\n' | socat - UNIX-CONNECT:/var/run/wireguard/wglo0.sock


setup host1: 

```
wireguard-go wglo0
PRIV_A=$(wg genkey)
PUB_A=$(echo $PRIV_A | wg pubkey)
echo "Host A Public Key: $PUB_A"

ip link add dev wglo0 type wireguard
ip addr add 10.253.255.2/24 dev wglo0
wg set wglo0 private-key <(echo $PRIV_A) listen-port 51821
ip link set up dev wglo0
```

setup host2:

```
wireguard-go wglo0
PRIV_A=$(wg genkey)
PUB_A=$(echo $PRIV_A | wg pubkey)
echo "Host A Public Key: $PUB_A"

ip link add dev wglo0 type wireguard
ip addr add 10.253.255.1/24 dev wglo0
wg set wglo0 private-key <(echo $PRIV_A) listen-port 51821
ip link set up dev wglo0
```

peer hosts1 to host2:

```
wg set wglo0 peer [host2publickey] allowed-ips 10.253.255.0/24 endpoint 10.255.255.1:51821 persistent-keepalive 25
```


peer host2 to host1:

```
wg set wglo0 peer [host1publickey] allowed-ips 10.253.255.0/24
```



## Usage

Most Linux kernel WireGuard users are used to adding an interface with `ip link add wg0 type wireguard`. With wireguard-go, instead simply run:

```
$ wireguard-go wg0
```

This will create an interface and fork into the background. To remove the interface, use the usual `ip link del wg0`, or if your system does not support removing interfaces directly, you may instead remove the control socket via `rm -f /var/run/wireguard/wg0.sock`, which will result in wireguard-go shutting down.

To run wireguard-go without forking to the background, pass `-f` or `--foreground`:

```
$ wireguard-go -f wg0
```

When an interface is running, you may use [`wg(8)`](https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8) to configure it, as well as the usual `ip(8)` and `ifconfig(8)` commands.

To run with more logging you may set the environment variable `LOG_LEVEL=debug`.

## Platforms

### Linux

This will run on Linux; however you should instead use the kernel module, which is faster and better integrated into the OS. See the [installation page](https://www.wireguard.com/install/) for instructions.

### macOS

This runs on macOS using the utun driver. It does not yet support sticky sockets, and won't support fwmarks because of Darwin limitations. Since the utun driver cannot have arbitrary interface names, you must either use `utun[0-9]+` for an explicit interface name or `utun` to have the kernel select one for you. If you choose `utun` as the interface name, and the environment variable `WG_TUN_NAME_FILE` is defined, then the actual name of the interface chosen by the kernel is written to the file specified by that variable.

### Windows

This runs on Windows, but you should instead use it from the more [fully featured Windows app](https://git.zx2c4.com/wireguard-windows/about/), which uses this as a module.

### FreeBSD

This will run on FreeBSD. It does not yet support sticky sockets. Fwmark is mapped to `SO_USER_COOKIE`.

### OpenBSD

This will run on OpenBSD. It does not yet support sticky sockets. Fwmark is mapped to `SO_RTABLE`. Since the tun driver cannot have arbitrary interface names, you must either use `tun[0-9]+` for an explicit interface name or `tun` to have the program select one for you. If you choose `tun` as the interface name, and the environment variable `WG_TUN_NAME_FILE` is defined, then the actual name of the interface chosen by the kernel is written to the file specified by that variable.

## Building

This requires an installation of the latest version of [Go](https://go.dev/).

```
$ git clone https://git.zx2c4.com/wireguard-go
$ cd wireguard-go
$ make
```

## License

    Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
    
    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
    of the Software, and to permit persons to whom the Software is furnished to do
    so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

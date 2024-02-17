# exceed2go

Exceed2go is an eBPF based ICMPv6 time-exceeded packet generator. It attaches 
an eBPF program to a given interface and replies to packets matching the
configured address with ICMPv6 time-exceeded messages. By default, an XDP
program is used. With Linux 6.6 or newer also a tc program (using TCX) can be 
used.

It's inspired by this news post about someone distributing their CV by
traceroute: https://news.ycombinator.com/item?id=32609588

See it in action by running traceroute or mtr to at `exceed2go.aibor.de`.

## Usage:

You need to be able to set DNS PTR (rDNS) records for address in a IPv6 subnet
you control, e.g. if your server has an IPv6 subnet you probably can set
reverse DNS entries for addresses.

Then load `exceed2go` for those addresses:

```
# exceed2go load --iface eth0 2001:db8::5 2001:db8::aa 2001:db8::dd 2001:db8::ee 2001:db8::ff
```

or a bit more convenient with the help of bash expansion:

```
# exceed2go load --iface eth0 2001:db8::{5,aa,dd,ee,ff}
```

`eth0` is the name of the interface to attach the eBPF program to. So it should
be the interface the packets reach your server at. Additional interfaces can
be given by using the flag repeatedly or specify the interfaces as 
comma-separated list.

The last address (2001:db8::ff in the example) is the target address to run
a traceroute to.

All additional addresses are the hops to be replied as in the order they should
appear in the traceroute.

So with the above values the traceroute will look like this:

```
(... hops before your host)
11:  start.here (2001:db8::5)
12:  three.more (2001:db8::aa)
13:  two.more (2001:db8::dd)
14:  one.more (2001:db8::ee)
15:  the.end (2001:db8::ff)
```

To unload the program run the cleanup command:

```
# exceed2go cleanup
```

## Troubleshooting

In case the program didn't exit correctly the XDP program might be still
attached. It can be easily detached with:

```
ip link set dev eth0 xdp off
```

If the traceroute doesn't work you can check the eBPF maps the program uses:

For the list off configured addresses (key 0 is the target address):
```
bpftool map dump name exceeded_addrs
```

For the packet counters: 
```
bpftool map dump name exceeded_counters
```

See `bpf/exceeded2go.c` for the counter keys and where the packets are counted.

# Introduction

## Why ipset-firewall

Simply because [ipset](https://ipset.netfilter.org/) is just designed for it.

Just take a look at below picture. You can clearly see that using only iptables is a pain for your system.

![alt text](https://pchaigno.github.io/assets/egress-filtering-benchmark/udp-throughput-with-jit.svg)

## How it works

The purpose of ipsetfw is for automation. You just give it a yaml file, setup a cronjob and go watch a movie or something.

It works like this:

Takes a list of IPs, either via fetching from github with country code you provided, or a list of IP networks you passed to the binary.

After that, it will create a ipset `set`, and if you choose, it will also add the required iptable rule for it.

Next time you run the same command, it will clear everything and start again from scratch. So, it will:

* Take an IP list
* Create `set`and add IPs to it
* Setup iptable rules (optional)
* Repeat

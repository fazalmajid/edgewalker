# edgewalker
An opinionated DIY VPN setup script based on OpenBSD, OpenIKEd, Wireguard and Let's Encrypt

## Rationale

Most VPN services are [untrustworthy](https://mjtsai.com/blog/2019/07/16/most-free-vpn-apps-secretly-owned-by-china/). You depend on the VPN provider's assurances to protect your privacy, which completely defeats the purpose of a VPN. The only way you can be sure is to run your own, but baroque network protocols engendering complex software makes it difficult to do so even for the technically savvy.

[Streisand](https://github.com/StreisandEffect/streisand) was one of the first efforts to automate the process, using cloud virtual servers as the hosts operating the VPN. Trail of Bits implemented [Algo](https://blog.trailofbits.com/2016/12/12/meet-algo-the-vpn-that-works/) to simplify if and remove some questionable choices Streisand made (although, to be fair, the Streisand project seems to have jettisoned many of them and converged on WireGuard).

Edgewalker is similar, but [awesomer](https://xkcd.com/483/):

* It is based on [OpenBSD](https://www.openbsd.org/), widely considered the most secure general-purpose OS, rather than Linux.
* Like Algo, it implements IPsec/IKEv2/MOBIKE rather than OpenVPN (read the [Algo announcement](https://blog.trailofbits.com/2016/12/12/meet-algo-the-vpn-that-works/) for the reasons why).
  * IPsec/IKEv2 works out of the box on iOS, iPadOS and macOS.
  * In theory on Windows as well, although I have no idea how to make it work or simplify setup, any help is welcome.
  * For Linux and Android I'd recommend waiting until I have Wireguard support implemented.
* It uses QR codes to simplify installation as much as possible on the client devices.
* It uses [Let's Encrypt](https://letsencrypt.org/) so your IPsec certificates just work.
* It has no dependencies on Ansible or anything else exotic you need to add on your own machine, other than a SSH client.
* It is just a shell script with little bits of Python thrown in like [Acme-Tiny](https://github.com/diafygi/acme-tiny), and easily auditable.

While you can run the script again as your Let's Encrypt certificates expire (although it generates new credentials each time), I recommend simply destroying the VM and creating a new one. Of course, if you are running on physical hardware, you will want to rerun the script.

## Prerequisites

You need:

* A Let's Encrypt account and key (I'm working on setting this up automatically for you, in the meantime you can use Step 1 on [this page](https://gethttpsforfree.com/) to do that for you).
* An OpenBSD machine reachable from the Internet (it can be a physical machine you own, or a cloud VM like [Vultr](https://www.vultr.com/)).
* The ability to add a DNS record for the machine's IP address (IPv4 only for now).

If you have a firewall in front of the OpenBSD machine, it needs to allow the following inbound traffic:

* SSH (TCP port `22`) so you can actually log in to your machine.
* HTTP (TCP port `80`) and HTTPS (TCP port `443`) to allow Let's Encrypt certificate issual and allow you to get the Apple-format Profiles that will ease setup on your iDevice.
* UDP ports `500` (IKE), `1701` (IPsec) and `4500` (IPsec NAT traversal).
* Optionally IPsec protocols `ESP` (IP protocol number `50`, hex `0x32`)) and `AH` (decimal `51` hex `0x33`) and ESP for maximum efficiency, although many firewalls won't support this.

## Instructions

Clone this repository into one of your own.
Edit the first lines in the script edggewalker.sh (`X509` and `USERNAME`). Not strictly necessary, but make it your own.

Log in as root on your OpenBSD machine, then:

```
wget -c https://raw.githubusercontent.com/YOUR_GITHUB_ACCOUNT_HERE/edgewalker/main/edgewalker.sh
sh edgewalker.sh
```

The script will ask you for:

* The DNS name of your OpenBSD machine.
* To copy-paste your Let's Encrypt account key in PEM format.

It will then obtain Let's Encrypt certificates, generate a QR code that you can use to download the profile on your iDevice to set up the VPN.

## Credits

* The OpenBSD team, for making their wonderful security-focused OS.
* Reyk Flöter for making OpenIKEd, a breath of fresh air in the unnecessarily convoluted world of VPN software.
* Let's Encrypt, for making certificates cheap and easy.
* Daniel Roseler for the fantastic Acme-Tiny.

## Demo

I created a fresh OpenBSD 6.8 VM `vpn42.majid.org` on Vultr ([see how](vultr.m4v)), and here is what the experience looks like:

![Sample run of Edgewalker](edgewalker.svg)

This [Vimeo video](https://vimeo.com/485183891) shows how to use the generated QR code on an iPhone.

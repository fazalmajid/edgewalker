#!/bin/sh
########################################################################
########################################################################
########################################################################
# CHANGE THESE SETTINGS TO SUITE YOUR NEEDS
########################################################################
########################################################################
########################################################################

# Contact info that will be embedded in the Let's Encrypt Certificates
# used to secure the VPN. Be aware spammers may harvest the email
# ITU X.509 format, C=country L=location O=organization
X509="/C=UK/L=London/O=Fazal Majid/emailAddress=ssladministrator@majid.org"

# user name for the VPN account. Feel free to leave it unchanged,
# as it is mostly cosmetic
USERNAME=majid

########################################################################
########################################################################
########################################################################
# NO USER-SERVICEABLE PARTS BELOW
PATH=${PATH}:/usr/local/bin
export PATH

echo -n "What is the FQDN hostname to use? "
read hostname
#echo -n "What is the IKEv2 username? "
#read USERNAME

secret=`python3 -c "import random,string;print(''.join(random.choice(string.ascii_letters+string.digits) for x in range(16)))"`
secret2=`python3 -c "import random,string;print(''.join(random.choice(string.ascii_letters+string.digits) for x in range(16)))"`
uuid=`python3 -c "import uuid;print(str(uuid.uuid1()).upper())"`
uuid2=`python3 -c "import uuid;print(str(uuid.uuid1()).upper())"`
printf '\033[1;33m%s\033[0m\n' "Secret: $secret"

printf '\033[1;33m%s\033[0m\n' "setting up sysctl.conf"
cat > /etc/sysctl.conf <<EOF
net.inet.ip.forwarding=1
net.inet.ip.redirect=0
net.inet.ipcomp.enable=1
net.inet.ah.enable=1
net.inet.esp.enable=1
net.inet.esp.udpencap=1
EOF

printf '\033[1;32m%s\033[0m\n' "Setting up PF"
hcf=`ls -1 /etc/hostname.*|grep -v enc0|grep -v wg0|head -1`
main_if=`echo $hcf|cut -d. -f 2`
main_ip=`ifconfig $main_if|awk '/inet/{print $2}'`
ipsecnet="172.17.0.0/16"
wgnet="172.18.0.0/16"
printf '\033[1;33m%s\033[0m\n' "Primary net interface $main_if $main_ip"
cat > /etc/pf.conf <<EOF
set skip on lo
block return log
pass
block in log on $main_if
block return in on ! lo0 proto tcp to port 6000:6010
block return out log proto {tcp udp} user _pbuild
# IPsec, over IP or over UDP
pass in quick on $main_if proto { ah esp } from any to $main_ip
pass in quick proto udp to $main_ip port {500 4500 1701 1194}
pass out on $main_if inet from $ipsecnet to any nat-to $main_if
# Wireguard
pass in quick proto udp to $main_ip port 51820
pass on wg0
pass out on $main_if inet from $wgnet nat-to $main_if
# other services
pass in quick on $main_if proto tcp from any to $main_ip port 22
pass in quick on $main_if proto tcp from any to $main_ip port 80
pass in quick on $main_if proto tcp from any to $main_ip port 443
pass in log proto icmp
EOF
printf '\033[1;33m%s\033[0m\n' "Restarting PF"
pfctl -f /etc/pf.conf

########################################################################
# Set up Let's Encrypt
mkdir -p /etc/iked/acme-tiny/challenges
cd /etc/iked/acme-tiny

# wget -q https://raw.githubusercontent.com/diafygi/acme-tiny/master/acme_tiny.py
cat > acme_tiny.py <<EOF
#!/usr/bin/env python
# Copyright Daniel Roesler, under MIT license, see LICENSE at github.com/diafygi/acme-tiny
import argparse, subprocess, json, os, sys, base64, binascii, time, hashlib, re, copy, textwrap, logging
try:
    from urllib.request import urlopen, Request # Python 3
except ImportError:
    from urllib2 import urlopen, Request # Python 2

DEFAULT_CA = "https://acme-v02.api.letsencrypt.org" # DEPRECATED! USE DEFAULT_DIRECTORY_URL INSTEAD
DEFAULT_DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory"

LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)

def get_crt(account_key, csr, acme_dir, log=LOGGER, CA=DEFAULT_CA, disable_check=False, directory_url=DEFAULT_DIRECTORY_URL, contact=None):
    directory, acct_headers, alg, jwk = None, None, None, None # global variables

    # helper functions - base64 encode for jose spec
    def _b64(b):
        return base64.urlsafe_b64encode(b).decode('utf8').replace("=", "")

    # helper function - run external commands
    def _cmd(cmd_list, stdin=None, cmd_input=None, err_msg="Command Line Error"):
        proc = subprocess.Popen(cmd_list, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate(cmd_input)
        if proc.returncode != 0:
            raise IOError("{0}\n{1}".format(err_msg, err))
        return out

    # helper function - make request and automatically parse json response
    def _do_request(url, data=None, err_msg="Error", depth=0):
        try:
            resp = urlopen(Request(url, data=data, headers={"Content-Type": "application/jose+json", "User-Agent": "acme-tiny"}))
            resp_data, code, headers = resp.read().decode("utf8"), resp.getcode(), resp.headers
        except IOError as e:
            resp_data = e.read().decode("utf8") if hasattr(e, "read") else str(e)
            code, headers = getattr(e, "code", None), {}
        try:
            resp_data = json.loads(resp_data) # try to parse json results
        except ValueError:
            pass # ignore json parsing errors
        if depth < 100 and code == 400 and resp_data['type'] == "urn:ietf:params:acme:error:badNonce":
            raise IndexError(resp_data) # allow 100 retrys for bad nonces
        if code not in [200, 201, 204]:
            raise ValueError("{0}:\nUrl: {1}\nData: {2}\nResponse Code: {3}\nResponse: {4}".format(err_msg, url, data, code, resp_data))
        return resp_data, code, headers

    # helper function - make signed requests
    def _send_signed_request(url, payload, err_msg, depth=0):
        payload64 = "" if payload is None else _b64(json.dumps(payload).encode('utf8'))
        new_nonce = _do_request(directory['newNonce'])[2]['Replay-Nonce']
        protected = {"url": url, "alg": alg, "nonce": new_nonce}
        protected.update({"jwk": jwk} if acct_headers is None else {"kid": acct_headers['Location']})
        protected64 = _b64(json.dumps(protected).encode('utf8'))
        protected_input = "{0}.{1}".format(protected64, payload64).encode('utf8')
        out = _cmd(["openssl", "dgst", "-sha256", "-sign", account_key], stdin=subprocess.PIPE, cmd_input=protected_input, err_msg="OpenSSL Error")
        data = json.dumps({"protected": protected64, "payload": payload64, "signature": _b64(out)})
        try:
            return _do_request(url, data=data.encode('utf8'), err_msg=err_msg, depth=depth)
        except IndexError: # retry bad nonces (they raise IndexError)
            return _send_signed_request(url, payload, err_msg, depth=(depth + 1))

    # helper function - poll until complete
    def _poll_until_not(url, pending_statuses, err_msg):
        result, t0 = None, time.time()
        while result is None or result['status'] in pending_statuses:
            assert (time.time() - t0 < 3600), "Polling timeout" # 1 hour timeout
            time.sleep(0 if result is None else 2)
            result, _, _ = _send_signed_request(url, None, err_msg)
        return result

    # parse account key to get public key
    log.info("Parsing account key...")
    out = _cmd(["openssl", "rsa", "-in", account_key, "-noout", "-text"], err_msg="OpenSSL Error")
    pub_pattern = r"modulus:[\s]+?00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)"
    pub_hex, pub_exp = re.search(pub_pattern, out.decode('utf8'), re.MULTILINE|re.DOTALL).groups()
    pub_exp = "{0:x}".format(int(pub_exp))
    pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
    alg = "RS256"
    jwk = {
        "e": _b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
        "kty": "RSA",
        "n": _b64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))),
    }
    accountkey_json = json.dumps(jwk, sort_keys=True, separators=(',', ':'))
    thumbprint = _b64(hashlib.sha256(accountkey_json.encode('utf8')).digest())

    # find domains
    log.info("Parsing CSR...")
    out = _cmd(["openssl", "req", "-in", csr, "-noout", "-text"], err_msg="Error loading {0}".format(csr))
    domains = set([])
    common_name = re.search(r"Subject:.*? CN\s?=\s?([^\s,;/]+)", out.decode('utf8'))
    if common_name is not None:
        domains.add(common_name.group(1))
    subject_alt_names = re.search(r"X509v3 Subject Alternative Name: (?:critical)?\n +([^\n]+)\n", out.decode('utf8'), re.MULTILINE|re.DOTALL)
    if subject_alt_names is not None:
        for san in subject_alt_names.group(1).split(", "):
            if san.startswith("DNS:"):
                domains.add(san[4:])
    log.info("Found domains: {0}".format(", ".join(domains)))

    # get the ACME directory of urls
    log.info("Getting directory...")
    directory_url = CA + "/directory" if CA != DEFAULT_CA else directory_url # backwards compatibility with deprecated CA kwarg
    directory, _, _ = _do_request(directory_url, err_msg="Error getting directory")
    log.info("Directory found!")

    # create account, update contact details (if any), and set the global key identifier
    log.info("Registering account...")
    reg_payload = {"termsOfServiceAgreed": True}
    account, code, acct_headers = _send_signed_request(directory['newAccount'], reg_payload, "Error registering")
    log.info("Registered!" if code == 201 else "Already registered!")
    if contact is not None:
        account, _, _ = _send_signed_request(acct_headers['Location'], {"contact": contact}, "Error updating contact details")
        log.info("Updated contact details:\n{0}".format("\n".join(account['contact'])))

    # create a new order
    log.info("Creating new order...")
    order_payload = {"identifiers": [{"type": "dns", "value": d} for d in domains]}
    order, _, order_headers = _send_signed_request(directory['newOrder'], order_payload, "Error creating new order")
    log.info("Order created!")

    # get the authorizations that need to be completed
    for auth_url in order['authorizations']:
        authorization, _, _ = _send_signed_request(auth_url, None, "Error getting challenges")
        domain = authorization['identifier']['value']
        log.info("Verifying {0}...".format(domain))

        # find the http-01 challenge and write the challenge file
        challenge = [c for c in authorization['challenges'] if c['type'] == "http-01"][0]
        token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge['token'])
        keyauthorization = "{0}.{1}".format(token, thumbprint)
        wellknown_path = os.path.join(acme_dir, token)
        with open(wellknown_path, "w") as wellknown_file:
            wellknown_file.write(keyauthorization)

        # check that the file is in place
        try:
            wellknown_url = "http://{0}/.well-known/acme-challenge/{1}".format(domain, token)
            assert (disable_check or _do_request(wellknown_url)[0] == keyauthorization)
        except (AssertionError, ValueError) as e:
            raise ValueError("Wrote file to {0}, but couldn't download {1}: {2}".format(wellknown_path, wellknown_url, e))

        # say the challenge is done
        _send_signed_request(challenge['url'], {}, "Error submitting challenges: {0}".format(domain))
        authorization = _poll_until_not(auth_url, ["pending"], "Error checking challenge status for {0}".format(domain))
        if authorization['status'] != "valid":
            raise ValueError("Challenge did not pass for {0}: {1}".format(domain, authorization))
        os.remove(wellknown_path)
        log.info("{0} verified!".format(domain))

    # finalize the order with the csr
    log.info("Signing certificate...")
    csr_der = _cmd(["openssl", "req", "-in", csr, "-outform", "DER"], err_msg="DER Export Error")
    _send_signed_request(order['finalize'], {"csr": _b64(csr_der)}, "Error finalizing order")

    # poll the order to monitor when it's done
    order = _poll_until_not(order_headers['Location'], ["pending", "processing"], "Error checking order status")
    if order['status'] != "valid":
        raise ValueError("Order failed: {0}".format(order))

    # download the certificate
    certificate_pem, _, _ = _send_signed_request(order['certificate'], None, "Certificate download failed")
    log.info("Certificate signed!")
    return certificate_pem

def main(argv=None):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            This script automates the process of getting a signed TLS certificate from Let's Encrypt using
            the ACME protocol. It will need to be run on your server and have access to your private
            account key, so PLEASE READ THROUGH IT! It's only ~200 lines, so it won't take long.

            Example Usage:
            python acme_tiny.py --account-key ./account.key --csr ./domain.csr --acme-dir /usr/share/nginx/html/.well-known/acme-challenge/ > signed_chain.crt

            Example Crontab Renewal (once per month):
            0 0 1 * * python /path/to/acme_tiny.py --account-key /path/to/account.key --csr /path/to/domain.csr --acme-dir /usr/share/nginx/html/.well-known/acme-challenge/ > /path/to/signed_chain.crt 2>> /var/log/acme_tiny.log
            """)
    )
    parser.add_argument("--account-key", required=True, help="path to your Let's Encrypt account private key")
    parser.add_argument("--csr", required=True, help="path to your certificate signing request")
    parser.add_argument("--acme-dir", required=True, help="path to the .well-known/acme-challenge/ directory")
    parser.add_argument("--quiet", action="store_const", const=logging.ERROR, help="suppress output except for errors")
    parser.add_argument("--disable-check", default=False, action="store_true", help="disable checking if the challenge file is hosted correctly before telling the CA")
    parser.add_argument("--directory-url", default=DEFAULT_DIRECTORY_URL, help="certificate authority directory url, default is Let's Encrypt")
    parser.add_argument("--ca", default=DEFAULT_CA, help="DEPRECATED! USE --directory-url INSTEAD!")
    parser.add_argument("--contact", metavar="CONTACT", default=None, nargs="*", help="Contact details (e.g. mailto:aaa@bbb.com) for your account-key")

    args = parser.parse_args(argv)
    LOGGER.setLevel(args.quiet or LOGGER.level)
    signed_crt = get_crt(args.account_key, args.csr, args.acme_dir, log=LOGGER, CA=args.ca, disable_check=args.disable_check, directory_url=args.directory_url, contact=args.contact)
    sys.stdout.write(signed_crt)

if __name__ == "__main__": # pragma: no cover
    main(sys.argv[1:])
EOF
chmod +x acme_tiny.py

cat > genkey <<SOP
#!/bin/sh
PATH=/usr/local/bin:/usr/local/ssl/bin:\$PATH
export PATH
cd /etc/iked/acme-tiny
printf '\033[1;31m%s\033[0m\n' vpn
if [ ! -f vpn.key ]; then
   echo generating vpn.key
   openssl genrsa -out vpn.key 4096
   cp /etc/ssl/openssl.cnf /tmp/genkey.\$\$
   cat >> /tmp/genkey.\$\$ <<EOF
[SAN]
subjectAltName=DNS:$hostname
EOF
        openssl req -new -key vpn.key -out vpn.csr -nodes -subj \
        "$X509/CN=$hostname" -config /tmp/genkey.\$\$ -reqexts SAN
        rm /tmp/genkey.\$\$
    fi
echo ""
SOP
chmod +x genkey

rm lets-encrypt-x3-cross-signed.pem*
wget -q https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem
cp lets-encrypt-x3-cross-signed.pem /etc/iked/ca/ca.crt

if [ ! -f /etc/iked/acme-tiny/account.key ]; then
    printf '\033[1;32m%s\033[0m\n' "Enter Let's Encrypt account.key"
    echo "Copy and paste your account secret key below, then press Control-D"
    echo "If you do not have a Let's Encrypt account, type 'NEW' then Ctrl-D"
    cat > /etc/iked/acme-tiny/account.key
    if [ `cat /etc/iked/acme-tiny/account.key` = NEW ]; then
        printf '\033[1;31m%s\033[0m\n' "Account key generation not implemented"
        exit 1
        #openssl genrsa 4096 > account.key  
    fi
fi

cat > renew <<SOP
#!/bin/sh
PATH=/usr/local/bin:/usr/local/ssl/bin:\$PATH
export PATH
set -e
cd /etc/iked/acme-tiny
printf '\033[1;32m%s\033[0m\n' "Renewing certificates"
cd /etc/iked/acme-tiny
if [ ! -f renew.last ]; then touch renew.last; fi
printf '\033[1;33m%s\033[0m\n' vpn
if test vpn.crt -nt renew.last -a -s vpn.crt ; then
  echo skipping vpn
  continue
fi
python3 acme_tiny.py --account-key ./account.key --csr ./vpn.csr \
        --disable-check --acme-dir `pwd`/challenges/ > vpn.crt || exit
cp vpn.* /etc/iked/
cat vpn.crt lets-encrypt-x3-cross-signed.pem > /etc/iked/vpn.crt
cp vpn.crt /etc/iked/certs/$hostname.crt
touch renew.last
/etc/rc.d/iked reload
SOP
chmod +x renew

printf '\033[1;32m%s\033[0m\n' "Setting up httpd"
mkdir -p /var/log/httpd
cat > /etc/iked/httpd.conf <<EOF
chroot "/etc/iked/acme-tiny/challenges"
logdir "/var/log/httpd"
server "default" {
        listen on 0.0.0.0 port 80
        location "/.well-known/acme-challenge/*" {
                root "/"
                request strip 2
        }
}
EOF
cat > /etc/rc.conf.local <<EOF
httpd_flags=-f /etc/iked/httpd.conf
iked_flags=-v -v -v -v -f /etc/iked.conf
EOF
/etc/rc.d/httpd stop
/etc/rc.d/httpd start

printf '\033[1;32m%s\033[0m\n' "Setting up OpenIKEd"
echo up > /etc/hostname.enc0
ifconfig enc0 up

cat > /etc/iked.conf <<EOF
ikev2 VPN passive ipcomp esp \
        from 0.0.0.0/0 to 0.0.0.0/0 \
        local $main_ip \
        peer any \
        srcid $hostname \
        psk "$secret" \
        config address $ipsecnet \
        config name-server 1.1.1.1 \
        config protected-subnet 0.0.0.0/0 \
        tag "IKED" tap enc0

user $USERNAME $secret
EOF
chmod 600 /etc/iked.conf

printf '\033[1;32m%s\033[0m\n' "Getting LE certificates"
cd /etc/iked/acme-tiny
printf '\033[1;33m%s\033[0m\n' "Generating private keys"
./genkey
printf '\033[1;33m%s\033[0m\n' "Renewing certificates"
./renew

printf '\033[1;33m%s\033[0m\n' "Applying sysctl settings"
xargs -n 1 sysctl < /etc/sysctl.conf
printf '\033[1;33m%s\033[0m\n' "Starting OpenIKEd"
/etc/rc.d/iked stop
/etc/rc.d/iked start

########################################################################
mkdir -p /etc/iked/wwwroot/$secret2
# Apple Configurator 2 format for iDevices VPN. It will appear as "unsigned"
# in System Preferences, sadly
cat > /etc/iked/wwwroot/$secret2/$hostname.mobileconfig <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>IKEv2</key>
			<dict>
				<key>AuthenticationMethod</key>
				<string>SharedSecret</string>
				<key>ChildSecurityAssociationParameters</key>
				<dict>
					<key>DiffieHellmanGroup</key>
					<integer>14</integer>
					<key>EncryptionAlgorithm</key>
					<string>AES-256</string>
					<key>IntegrityAlgorithm</key>
					<string>SHA2-256</string>
					<key>LifeTimeInMinutes</key>
					<integer>1440</integer>
				</dict>
				<key>DeadPeerDetectionRate</key>
				<string>Medium</string>
				<key>DisableMOBIKE</key>
				<integer>0</integer>
				<key>DisableRedirect</key>
				<integer>0</integer>
				<key>EnableCertificateRevocationCheck</key>
				<integer>0</integer>
				<key>EnableFallback</key>
				<integer>0</integer>
				<key>EnablePFS</key>
				<true/>
				<key>IKESecurityAssociationParameters</key>
				<dict>
					<key>DiffieHellmanGroup</key>
					<integer>14</integer>
					<key>EncryptionAlgorithm</key>
					<string>AES-256-GCM</string>
					<key>IntegrityAlgorithm</key>
					<string>SHA2-256</string>
					<key>LifeTimeInMinutes</key>
					<integer>1440</integer>
				</dict>
				<key>LocalIdentifier</key>
				<string>$USERNAME</string>
				<key>RemoteAddress</key>
				<string>$hostname</string>
				<key>RemoteIdentifier</key>
				<string>$hostname</string>
				<key>SharedSecret</key>
				<string>$secret</string>
				<key>UseConfigurationAttributeInternalIPSubnet</key>
				<integer>0</integer>
			</dict>
			<key>PayloadDescription</key>
			<string>Configures VPN settings</string>
			<key>PayloadDisplayName</key>
			<string>VPN</string>
			<key>PayloadIdentifier</key>
			<string>com.apple.vpn.managed.$uuid</string>
			<key>PayloadType</key>
			<string>com.apple.vpn.managed</string>
			<key>PayloadUUID</key>
			<string>$uuid</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
			<key>Proxies</key>
			<dict>
				<key>HTTPEnable</key>
				<integer>0</integer>
				<key>HTTPSEnable</key>
				<integer>0</integer>
			</dict>
			<key>UserDefinedName</key>
			<string>$hostname</string>
			<key>VPNType</key>
			<string>IKEv2</string>
		</dict>
	</array>
	<key>PayloadDisplayName</key>
	<string>$hostname</string>
	<key>PayloadIdentifier</key>
	<string>$hostname</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>$uuid2</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
EOF

# Now that we've obtained our Let's Encrypt certificates, reconfigure
# the web server so it can serve the configuration files
printf '\033[1;33m%s\033[0m\n' "Enabling SSL on HTTPd"

echo "<h1>$hostname</h1>" > /etc/iked/wwwroot/index.html

cat > /etc/iked/httpd.conf <<EOF
chroot "/etc/iked/wwwroot"
logdir "/var/log/httpd"
server "$hostname" {
	listen on * port 80
	root "/"
	location * {
		block return 302 "https://\$HTTP_HOST\$REQUEST_URI"
	}
}
server "$hostname" {
	listen on * tls port 443
	tls {
		key "/etc/iked/vpn.key"
		certificate "/etc/iked/vpn.crt"
	}
	root "/"
}
EOF
/etc/rc.d/httpd stop
/etc/rc.d/httpd start

########################################################################
# this package is used to generate the Apple .mobileconfig and Wireguard
# QR codes to make setting up your devices easier
pkg_add libqrencode

printf '\033[1;33m%s\033[0m\n' "iOS/iPadOS/macOS VPN config QR code"
echo https://$hostname/$secret2/$hostname.mobileconfig
#qrencode -o - -t ANSI https://$hostname/$secret2/$hostname.mobileconfig
qrencode -o - -t UTF8 https://$hostname/$secret2/$hostname.mobileconfig

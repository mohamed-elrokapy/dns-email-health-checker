"""Offline demo DNS server for trying the app without internet access.

It serves a small zone for the made-up domains below on 127.0.0.1:5353. Start the API with
DNS_NAMESERVERS=127.0.0.1 DNS_PORT=5353 and check one of the demo domains.

    demo-good.test      all four checks pass
    demo-weak.test      SPF is +all, DMARC is p=none, only one MX host
    demo-broken.test    no SPF, no DMARC, MX host does not resolve

Run from the backend directory:  python -m dev.demo_dns
"""

from __future__ import annotations

import time

from tests.conftest import dkim_record
from tests.dnsserver import LocalDnsServer, txt_rdata

SOA = "ns1.demo.test. admin.demo.test. 1 7200 3600 1209600 300"


def demo_zone() -> list[tuple[str, str, str]]:
    key = dkim_record(2048)
    weak_key = dkim_record(1024)
    return [
        # demo-good.test
        ("demo-good.test", "SOA", SOA),
        ("demo-good.test", "MX", "10 mx1.demo-good.test."),
        ("demo-good.test", "MX", "20 mx2.demo-good.test."),
        ("mx1.demo-good.test", "A", "192.0.2.10"),
        ("mx2.demo-good.test", "A", "192.0.2.11"),
        (
            "demo-good.test",
            "TXT",
            txt_rdata("v=spf1 ip4:192.0.2.0/24 include:_spf.vendor.test -all"),
        ),
        ("_spf.vendor.test", "TXT", txt_rdata("v=spf1 ip4:198.51.100.0/24 -all")),
        (
            "_dmarc.demo-good.test",
            "TXT",
            txt_rdata("v=DMARC1; p=reject; rua=mailto:r@demo-good.test"),
        ),
        ("selector1._domainkey.demo-good.test", "TXT", txt_rdata(key)),
        # demo-weak.test
        ("demo-weak.test", "SOA", SOA),
        ("demo-weak.test", "MX", "10 mx1.demo-weak.test."),
        ("mx1.demo-weak.test", "A", "192.0.2.20"),
        ("demo-weak.test", "TXT", txt_rdata("v=spf1 +all")),
        ("_dmarc.demo-weak.test", "TXT", txt_rdata("v=DMARC1; p=none")),
        ("default._domainkey.demo-weak.test", "TXT", txt_rdata(weak_key)),
        # demo-broken.test
        ("demo-broken.test", "SOA", SOA),
        ("demo-broken.test", "MX", "10 mx1.demo-broken.test."),
    ]


if __name__ == "__main__":
    with LocalDnsServer(demo_zone(), port=5353) as server:
        print(f"Demo DNS server listening on 127.0.0.1:{server.port}. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

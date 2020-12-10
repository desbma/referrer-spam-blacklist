#!/usr/bin/env python3

""" Remove dead domains from list. """

import argparse
import asyncio
import collections
import errno
import itertools
import random
import resource
from typing import Dict, List, Optional

import aiodns
import tqdm

DNS_SERVERS = (
    ("8.8.8.8", "8.8.4.4"),  # Google DNS
    ("208.67.222.222", "208.67.220.220"),  # OpenDNS
    ("84.200.69.80", "84.200.70.40"),  # DNS.WATCH
    ("209.244.0.3", "209.244.0.4"),  # Level3 DNS
    ("8.26.56.26", "8.20.247.20"),  # Comodo Secure DNS
)
WEB_PORTS = (80, 443)
MAX_CONCURRENT_REQUESTS_PER_DNS_SERVER = 10
MAX_DNS_ATTEMPTS = 10
BASE_DNS_TIMEOUT_S = 3


async def dns_resolve(domain: str, dns_server: str, sem: asyncio.BoundedSemaphore) -> Optional[str]:
    """ Return IP string if domain has a DNA A record on this DNS server, False otherwise. """
    resolver = aiodns.DNSResolver(nameservers=(dns_server,))
    timeout: float = BASE_DNS_TIMEOUT_S
    for attempt in range(1, MAX_DNS_ATTEMPTS + 1):
        coroutine = resolver.query(domain, "A")
        try:
            async with sem:
                response = await asyncio.wait_for(coroutine, timeout=timeout)
        except asyncio.TimeoutError:
            jitter = random.randint(-20, 20) / 100
            timeout = BASE_DNS_TIMEOUT_S + jitter
            continue
        except aiodns.error.DNSError:
            return None
        try:
            ip = response[0].host
        except IndexError:
            return None
        break
    else:
        # too many failed attemps
        return None
    return ip


async def dns_resolve_domain(
    domain: str, progress: tqdm.tqdm, sems: Dict[str, asyncio.BoundedSemaphore]
) -> List[Optional[str]]:
    """ Return IP string if domain has a DNA A record on this DNS server, False otherwise. """
    dns_servers = list(DNS_SERVERS)
    random.shuffle(dns_servers)
    r = []
    for dns_server_ips in dns_servers:
        dns_server_ip = random.choice(dns_server_ips)
        ip = await dns_resolve(domain, dns_server_ip, sems[dns_server_ip])
        r.append(ip)
    progress.update(1)
    return r


async def has_tcp_port_open(ip: str, port: int, progress: tqdm.tqdm) -> bool:
    """ Return True if domain is listening on a TCP port, False instead. """
    r = True
    coroutine = asyncio.open_connection(ip, port)
    try:
        _, writer = await asyncio.wait_for(coroutine, timeout=10)
    except (ConnectionRefusedError, asyncio.TimeoutError):
        r = False
    except OSError as e:
        if e.errno == errno.EHOSTUNREACH:
            r = False
        else:
            raise
    else:
        writer.close()
    progress.update(1)
    return r


if __name__ == "__main__":
    # parse args
    arg_parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    arg_parser.add_argument("list_file", help="Domain list file path")
    args = arg_parser.parse_args()

    # read list
    with open(args.list_file, "rt") as list_file:
        domains = tuple(map(str.rstrip, list_file.readlines()))
    dead_domains = set()

    # bump limits
    soft_lim, hard_lim = resource.getrlimit(resource.RLIMIT_NOFILE)
    if (soft_lim != resource.RLIM_INFINITY) and ((soft_lim < hard_lim) or (hard_lim == resource.RLIM_INFINITY)):
        resource.setrlimit(resource.RLIMIT_NOFILE, (hard_lim, hard_lim))
        print("Max open files count set from %u to %u" % (soft_lim, hard_lim))

    # resolve domains
    sems: Dict[str, asyncio.BoundedSemaphore] = collections.defaultdict(
        lambda: asyncio.BoundedSemaphore(MAX_CONCURRENT_REQUESTS_PER_DNS_SERVER)
    )
    dns_check_futures = []
    tcp_check_domain_ips = {}
    with tqdm.tqdm(total=len(domains), miniters=1, smoothing=0, desc="Domains checks", unit=" domains") as progress:
        for domain in domains:
            coroutine = dns_resolve_domain(domain, progress, sems)
            future = asyncio.ensure_future(coroutine)
            dns_check_futures.append(future)

        asyncio.get_event_loop().run_until_complete(asyncio.gather(*dns_check_futures))

        for domain, future in zip(domains, dns_check_futures):
            ips = future.result()
            if not any(ips):
                # all dns resolutions failed for this domain
                dead_domains.add(domain)
            elif not all(ips):
                # at least one dns resolution failed, but at least one succeeded for this domain
                tcp_check_domain_ips[domain] = ips

    # for domains with at least one failed DNS resolution, check open ports
    tcp_check_futures = collections.defaultdict(list)
    with tqdm.tqdm(
        total=len(tcp_check_domain_ips) * len(WEB_PORTS),
        miniters=1,
        desc="TCP domain checks",
        unit=" domains",
        leave=True,
    ) as progress:
        for domain, ips in tcp_check_domain_ips.items():
            ip = next(filter(None, ips))  # take result of first successful resolution
            for port in WEB_PORTS:
                coroutine = has_tcp_port_open(ip, port, progress)
                future = asyncio.ensure_future(coroutine)
                tcp_check_futures[domain].append(future)

        asyncio.get_event_loop().run_until_complete(
            asyncio.gather(*itertools.chain.from_iterable(tcp_check_futures.values()))
        )

        for domain, futures in tcp_check_futures.items():
            status = tuple(future.result() for future in futures)
            if not any(status):
                # no web port open for this domain
                dead_domains.add(domain)

    # write new file
    with open(args.list_file, "wt") as list_file:
        for domain in domains:
            if domain not in dead_domains:
                list_file.write("%s\n" % (domain))
    print("\n%u dead domain(s) removed" % (len(dead_domains)))

"""
resolve.py: a recursive resolver built using dnspython
"""

import argparse
from ast import For
from urllib import error, response

import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.flags
#from numpy import record
import dns.exception
import dns.rcode

FORMATS = (("CNAME", "{alias} is an alias for {name}"),
           ("A", "{name} has address {address}"),
           ("AAAA", "{name} has IPv6 address {address}"),
           ("MX", "{name} mail is handled by {preference} {exchange}"))

ROOT_SERVERS = ("198.41.0.4",
                "199.9.14.201",
                "192.33.4.12",
                "199.7.91.13",
                "192.203.230.10",
                "192.5.5.241",
                "192.112.36.4",
                "198.97.190.53",
                "192.36.148.17",
                "192.58.128.30",
                "193.0.14.129",
                "199.7.83.42",
                "202.12.27.33")



# Cache completed DNS responses
DNS_CACHE = {}

# Cache intermediate DNS zone nameservers
REFERRAL_CACHE = {}


def collect_results(name: str) -> dict:
    """
    This function parses final answers into the proper data structure that
    print_results requires. The main work is done within the `lookup` function.
    """
    full_response = {}
    target_name = dns.name.from_text(name)
    # lookup CNAME
    response = lookup(target_name, dns.rdatatype.CNAME)
    cnames = []
    tmp = name
    for answers in response.answer:
        for answer in answers:
            cnames.append({"name": answer, "alias": tmp})
            tmp = answer
    # lookup A
    response = lookup(target_name, dns.rdatatype.A)
    arecords = []
    for answers in response.answer:
        a_name = answers.name
        for answer in answers:
            if answer.rdtype == 1:  # A record
                arecords.append({"name": a_name, "address": str(answer)})
    # lookup AAAA
    response = lookup(target_name, dns.rdatatype.AAAA)
    aaaarecords = []
    for answers in response.answer:
        aaaa_name = answers.name
        for answer in answers:
            if answer.rdtype == 28:  # AAAA record
                aaaarecords.append({"name": aaaa_name, "address": str(answer)})
    # lookup MX
    response = lookup(target_name, dns.rdatatype.MX)
    mxrecords = []
    for answers in response.answer:
        mx_name = answers.name
        for answer in answers:
            if answer.rdtype == 15:  # MX record
                mxrecords.append({"name": mx_name,
                                  "preference": answer.preference,
                                  "exchange": str(answer.exchange)})

    full_response["CNAME"] = cnames
    full_response["A"] = arecords
    full_response["AAAA"] = aaaarecords
    full_response["MX"] = mxrecords

    return full_response


def get_ipv4_servers(response):
    
    servers = []

    # Nameservers listed in the referral
    ns_names = set()

    # collect nameserver names from the authority section
    for rrset in response.authority:
        if rrset.rdtype == dns.rdatatype.NS:
            for record in rrset:
                ns_names.add(record.target)

    # Extract matching IPv4 glue records
    for rrset in response.additional:
        if rrset.rdtype == dns.rdatatype.A:
            if rrset.name in ns_names:
                for record in rrset:
                    servers.append(record.address)

    return servers



def lookup(target_name: dns.name.Name,
           qtype: int,
           seen_cnames=None,
           resolving_ns=None) -> dns.message.Message:

    #  Resolve a name by starting at the root servers and following referrals.
    # Returns the final DNS response (or a SERVFAIL response on failure).
    
    #  Track nameservers being resolved (prevents infinite loops)
    if resolving_ns is None:
        resolving_ns = set()

    # Create the cache key
    cache_key = (target_name.to_text().lower(), qtype)

    # return cahe 
    if cache_key in DNS_CACHE:
        print("CACHE HIT:", cache_key)
        return DNS_CACHE[cache_key]

    # Create DNS query question without recursion
    outbound_query = dns.message.make_query(target_name, qtype)
    outbound_query.flags &= ~dns.flags.RD

    # prevent CNAME loops
    if seen_cnames is None:
        seen_cnames = set()

    name_key = target_name.to_text().lower()

    if name_key in seen_cnames or len(seen_cnames) >= 16:
        print("CNAME loop detected:", target_name)
        return dns.message.make_response(outbound_query)

    seen_cnames.add(name_key)

    #  Check for cached nameservers
    matching_zones = [
        zone for zone in REFERRAL_CACHE
        if target_name.is_subdomain(zone)
    ]

    if matching_zones:
        # pick the most specific cached DNS zone
        zone = max(matching_zones, key=lambda z: len(z.labels))

        print("USING REFERRAL CACHE:", zone)

        # Start with cached servers, keep roots as fallback
        servers = list(REFERRAL_CACHE[zone]) + list(ROOT_SERVERS)
    else:
           # No cache, start at the root
        servers = list(ROOT_SERVERS)

    visited = set()

    #  Query DNS servers
    while servers:
        server_ip = servers.pop(0)


        #Skip servers already asked
        if server_ip in visited:
            continue

        visited.add(server_ip)

        
        try:
            # Send DNS query with a 3-second timeout
            response = dns.query.udp(
                outbound_query,
                server_ip,
                timeout=3
            )

        except dns.exception.Timeout:
            # No reply, try next server
            print("TIMEOUT: Server did not respond:", server_ip)
            continue

        except (dns.exception.DNSException, OSError) as error:
            print("SERVER ERROR:", server_ip, error)
            continue

        print("QUERYING:", server_ip)

        # Check for incomplete responses
        if response.flags & dns.flags.TC:
            print("TRUNCATED RESPONSE:", server_ip)
            continue

        # Check DNS response status
        status = response.rcode()

        if status == dns.rcode.NXDOMAIN:
            # The domain does not exist, if confirmed
            # by an authoritative server
            if response.flags & dns.flags.AA:
                DNS_CACHE[cache_key] = response
                return response

            continue

        if status != dns.rcode.NOERROR:
            print(
                "DNS ERROR:",
                dns.rcode.to_text(status),
                "FROM:",
                server_ip
            )
            continue


       

        # Check returned answers
        if response.answer:

            has_requested_type = any(
                rrset.rdtype == qtype
                for rrset in response.answer
            )

            if has_requested_type:
                DNS_CACHE[cache_key] = response
                return response

            # Handle CNAME restart
            for rrset in response.answer:

                if rrset.rdtype == dns.rdatatype.CNAME:

                    for record in rrset:
                        print("CNAME FOUND:", rrset.name)
                        print("POINTS TO:", record.target)

                        
                        alias_response = lookup(
                            record.target,
                            qtype,
                            seen_cnames,
                            resolving_ns
                        )

                        # Check whether the CNAME target lookup succeeded
                        if alias_response.rcode() != dns.rcode.NOERROR:
                            print("CNAME target resolution failed:", record.target)

                            failure_response = dns.message.make_response(outbound_query)
                            failure_response.set_rcode(alias_response.rcode())

                            return failure_response

                            # Combine the CNAME with the target's records
                        response.answer.extend(alias_response.answer)

                            # Cache the completed result
                        DNS_CACHE[cache_key] = response

                        return response


        # handle authoritative empty answers
        if response.flags & dns.flags.AA:
            DNS_CACHE[cache_key] = response
            return response

        # Extract and cache DNS referrals
        next_servers = get_ipv4_servers(response)

        # Handle referrals without IPv4 glue records
        if not next_servers:

            for rrset in response.authority:

                if rrset.rdtype != dns.rdatatype.NS:
                    continue

                for ns_record in rrset:
                    ns_name = ns_record.target

                    # Prevent circular nameserver resolution
                    if ns_name in resolving_ns:
                        continue

                    print("UNGLUED NAMESERVER:", ns_name)

                    resolving_ns.add(ns_name)

                    try:
                        # Find the nameserver's IPv4 address
                        ns_response = lookup(
                            ns_name,
                            dns.rdatatype.A,
                            resolving_ns=resolving_ns
                        )

                        # Extract A records from the result
                        for a_rrset in ns_response.answer:
                            if a_rrset.rdtype == dns.rdatatype.A:
                                for a_record in a_rrset:
                                    next_servers.append(a_record.address)

                    finally:
                        resolving_ns.remove(ns_name)


        for rrset in response.authority:
            if rrset.rdtype == dns.rdatatype.NS:

                if next_servers:
                    REFERRAL_CACHE[rrset.name] = next_servers.copy()

                    print("REFERRAL CACHE SAVED:", rrset.name)

        # Follow the referral
        if next_servers:
            print("FOLLOWING REFERRAL:", next_servers)
            servers = next_servers + servers
            continue

    # Handle unsuccessful lookup
    # All available DNS servers have been exhausted
    print(
        "ERROR: Unable to resolve",
        target_name,
     "after trying available DNS servers."
    )

    # Return a response indicating server failure
    failure_response = dns.message.make_response(outbound_query)
    failure_response.set_rcode(dns.rcode.SERVFAIL)

    return failure_response









def print_results(results: dict) -> None:
    """
    take the results of a `lookup` and print them to the screen like the host
    program would.
    """

    for rtype, fmt_str in FORMATS:
        for result in results.get(rtype, []):
            print(fmt_str.format(**result))


def main():
    """
    if run from the command line, take args and call
    printresults(lookup(hostname))
    """
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("name", nargs="+",
                                 help="DNS name(s) to look up")
    argument_parser.add_argument("-v", "--verbose",
                                 help="increase output verbosity",
                                 action="store_true")
    program_args = argument_parser.parse_args()
    for a_domain_name in program_args.name:
        print_results(collect_results(a_domain_name))

if __name__ == "__main__":
    main()

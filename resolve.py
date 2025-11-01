"""
resolve.py: a recursive resolver built using dnspython
"""

import argparse

import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype

FORMATS = (("CNAME", "{alias} is an alias for {name}"),
           ("A", "{name} has address {address}"),
           ("AAAA", "{name} has IPv6 address {address}"),
           ("MX", "{name} mail is handled by {preference} {exchange}"))

# current as of 25 October 2018
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

CACHE = {}

def collect_results(name: str) -> dict:
    """
    This function parses final answers into the proper data structure that
    print_results requires. The main work is done within the `lookup` function.
    """
    full_response = {}
    target_name = dns.name.from_text(name)
    
    # CNAME 체인 추적
    cnames = []
    current_name = target_name
    
    # CNAME을 따라가며 모두 수집
    while True:
        response = lookup(current_name, dns.rdatatype.CNAME)
        found_cname = False
        
        for answers in response.answer:
            for answer in answers:
                if answer.rdtype == dns.rdatatype.CNAME:
                    cnames.append({"name": answer.target, "alias": current_name})
                    current_name = answer.target
                    found_cname = True
                    break
            if found_cname:
                break
        
        if not found_cname:
            break
    
    # 최종 도메인 이름 (CNAME 체인의 끝)
    final_name = current_name
    
    # lookup A
    response = lookup(final_name, dns.rdatatype.A)
    arecords = []
    for answers in response.answer:
        a_name = answers.name
        for answer in answers:
            if answer.rdtype == 1:  # A record
                arecords.append({"name": a_name, "address": str(answer)})
    
    # lookup AAAA
    response = lookup(final_name, dns.rdatatype.AAAA)
    aaaarecords = []
    for answers in response.answer:
        aaaa_name = answers.name
        for answer in answers:
            if answer.rdtype == 28:  # AAAA record
                aaaarecords.append({"name": aaaa_name, "address": str(answer)})
    
    # lookup MX
    response = lookup(final_name, dns.rdatatype.MX)
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


def lookup(target_name: dns.name.Name,
           qtype: dns.rdata.Rdata) -> dns.message.Message:
    """
    This function uses a recursive resolver to find the relevant answer to the
    query.
    """
    # 캐시 키 생성
    cache_key = (str(target_name), qtype)
    
    # 캐시에 있으면 반환
    if cache_key in CACHE:
        return CACHE[cache_key]
    
    # 캐시에서 가장 가까운 네임서버 찾기
    nameservers = None
    labels = target_name.labels
    
    for i in range(len(labels)):
        parent = dns.name.Name(labels[i:])
        ns_cache_key = (str(parent), dns.rdatatype.NS)
        if ns_cache_key in CACHE:
            cached_response = CACHE[ns_cache_key]
            ns_names = []
            for answer in cached_response.answer:
                if answer.rdtype == dns.rdatatype.NS:
                    for rdata in answer:
                        ns_names.append(rdata.target)
            
            nameservers = []
            for ns_name in ns_names:
                ns_ip_key = (str(ns_name), dns.rdatatype.A)
                if ns_ip_key in CACHE:
                    ns_response = CACHE[ns_ip_key]
                    for ans in ns_response.answer:
                        if ans.rdtype == dns.rdatatype.A:
                            for rdata in ans:
                                nameservers.append(rdata.address)
            
            if nameservers:
                break
    
    if not nameservers:
        nameservers = list(ROOT_SERVERS)
    
    current_target = target_name
    
    while True:
        found_next = False
        
        for ns in nameservers:
            try:
                outbound_query = dns.message.make_query(current_target, qtype)
                
                try:
                    response = dns.query.udp(outbound_query, ns, 3)
                except dns.exception.Timeout:
                    continue
                except OSError:
                    continue
                
                # ANSWER 섹션 확인
                if len(response.answer) > 0:
                    # CNAME 타입으로 조회한 경우 - CNAME 응답 그대로 반환
                    if qtype == dns.rdatatype.CNAME:
                        for answer in response.answer:
                            if answer.rdtype == dns.rdatatype.CNAME:
                                CACHE[cache_key] = response
                                return response
                        # CNAME이 없으면 빈 응답
                        empty_response = dns.message.make_response(outbound_query)
                        CACHE[cache_key] = empty_response
                        return empty_response
                    
                    # 다른 타입 조회 시 CNAME을 따라감
                    for answer in response.answer:
                        if answer.rdtype == dns.rdatatype.CNAME:
                            current_target = answer[0].target
                            nameservers = list(ROOT_SERVERS)
                            found_next = True
                            break
                    
                    if not found_next:
                        CACHE[cache_key] = response
                        return response
                    break
                
                # AUTHORITY 섹션에서 다음 네임서버 찾기
                if len(response.authority) > 0:
                    new_nameservers = []
                    ns_names = []
                    
                    for authority in response.authority:
                        if authority.rdtype == dns.rdatatype.NS:
                            for rdata in authority:
                                ns_names.append(rdata.target)
                    
                    if ns_names:
                        zone_name = response.authority[0].name
                        zone_cache_key = (str(zone_name), dns.rdatatype.NS)
                        if zone_cache_key not in CACHE:
                            ns_response = dns.message.make_response(outbound_query)
                            ns_response.answer = response.authority
                            CACHE[zone_cache_key] = ns_response
                        
                        for additional in response.additional:
                            if additional.rdtype == dns.rdatatype.A:
                                new_nameservers.append(additional[0].address)
                                ns_ip_key = (str(additional.name), dns.rdatatype.A)
                                if ns_ip_key not in CACHE:
                                    ns_ip_response = dns.message.make_response(outbound_query)
                                    ns_ip_response.answer = [additional]
                                    CACHE[ns_ip_key] = ns_ip_response
                        
                        if not new_nameservers:
                            for ns_name in ns_names:
                                try:
                                    ns_response = lookup(ns_name, dns.rdatatype.A)
                                    for answer in ns_response.answer:
                                        if answer.rdtype == dns.rdatatype.A:
                                            for rdata in answer:
                                                new_nameservers.append(rdata.address)
                                    if new_nameservers:
                                        break
                                except Exception:
                                    continue
                        
                        if new_nameservers:
                            nameservers = new_nameservers
                            found_next = True
                            break
                    else:
                        CACHE[cache_key] = response
                        return response
                        
            except Exception as e:
                continue
        
        if not found_next:
            response = dns.message.make_response(outbound_query)
            CACHE[cache_key] = response
            return response

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

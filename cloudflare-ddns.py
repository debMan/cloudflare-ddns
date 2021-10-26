import json, sys, signal, os, time, threading

import requests


class GracefulExit:
    def __init__(self):
        self.kill_now = threading.Event()
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    def exit_gracefully(self):
        print("🛑 Stopping main thread...")
        self.kill_now.set()


def getIPs():
    # TODO: Use public IP checker from config
    urlv4 = "https://checkip.amazonaws.com"
    urlv6 = "https://[2606:4700:4700::1111]/cdn-cgi/trace"
    a = None
    aaaa = None
    global IPV4_ENABLED
    global IPV6_ENABLED
    if IPV4_ENABLED:
        try:
            a = requests.get(urlv4).text
        except Exception:
            global shown_ipv4_warning
            if not shown_ipv4_warning:
                shown_ipv4_warning = True
                print("🧩 IPv4 not detected")
    if IPV6_ENABLED:
        try:
            aaaa = requests.get(urlv6).text.split("\n")
            aaaa.pop()
            aaaa = dict(s.split("=") for s in aaaa)["ip"]
        except Exception:
            global shown_ipv6_warning
            if not shown_ipv6_warning:
                shown_ipv6_warning = True
                print("🧩 IPv6 not detected")
    ips = {}
    if(a is not None):
        ips["ipv4"] = {
            "type": "A",
            "ip": a
        }
    if(aaaa is not None):
        ips["ipv6"] = {
            "type": "AAAA",
            "ip": aaaa
        }
    return ips


def commit_record(ip):
    for option in config["cloudflare"]:
        subdomains = option["subdomains"]
        response = cf_api("zones/" + option['zone_id'], "GET", option)
        if response is None or response["result"]["name"] is None:
            time.sleep(5)
            return
        base_domain_name = response["result"]["name"]
        ttl = 300  # default Cloudflare TTL
        for subdomain in subdomains:
            subdomain = subdomain.lower().strip()
            record = {
                "type": ip["type"],
                "name": subdomain,
                "content": ip["ip"],
                "proxied": option["proxied"],
                "ttl": ttl
            }
            dns_records = cf_api(
                "zones/" + option['zone_id'] +
                "/dns_records?per_page=100&type=" + ip["type"],
                "GET", option)
            fqdn = base_domain_name
            if subdomain:
                fqdn = subdomain + "." + base_domain_name
            identifier = None
            modified = False
            duplicate_ids = []
            if dns_records is not None:
                for r in dns_records["result"]:
                    if (r["name"] == fqdn):
                        if identifier:
                            if r["content"] == ip["ip"]:
                                duplicate_ids.append(identifier)
                                identifier = r["id"]
                            else:
                                duplicate_ids.append(r["id"])
                        else:
                            identifier = r["id"]
                            if r['content'] != record['content'] or \
                                    r['proxied'] != record['proxied']:
                                modified = True
            if identifier:
                if modified:
                    print("📡 Updating record " + str(record))
                    response = cf_api(
                        "zones/" + option['zone_id'] +
                        "/dns_records/" + identifier,
                        "PUT", option, {}, record)
            else:
                print("➕ Adding new record " + str(record))
                response = cf_api(
                    "zones/" + option['zone_id'] + "/dns_records",
                    "POST",
                    option,
                    {},
                    record
                )
            for identifier in duplicate_ids:
                identifier = str(identifier)
                print("🗑️ Deleting stale record " + identifier)
                response = cf_api(
                    "zones/" + option['zone_id'] +
                    "/dns_records/" + identifier,
                    "DELETE", option)
    return response


def cf_api(endpoint, method, config, headers={}, data=False):
    api_token = config['authentication']['api_token']
    if api_token != '' and api_token != 'api_token_here':
        headers = {
            "Authorization": "Bearer " + api_token,
            **headers
        }
    else:
        headers = {
            "X-Auth-Email":
            config['authentication']['api_key']['account_email'],
            "X-Auth-Key":
            config['authentication']['api_key']['api_key'],
        }

    if(data == False):
        response = requests.request(
            method, "https://api.cloudflare.com/client/v4/" + endpoint,
            headers=headers
        )
    else:
        response = requests.request(
            method, "https://api.cloudflare.com/client/v4/" + endpoint,
            headers=headers, json=data)

    if response.ok:
        return response.json()
    else:
        print("📈 Error sending '" + method +
              "' request to '" + response.url + "':")
        print(response.text)
        return None


def updateIPs(ips):
    for ip in ips.values():
        commit_record(ip)


if __name__ == '__main__':
    PATH = os.getcwd() + "/"
    version = float(str(sys.version_info[0]) + "." + str(sys.version_info[1]))
    shown_ipv4_warning = False
    shown_ipv6_warning = False
    IPV4_ENABLED = True
    IPV6_ENABLED = True

    if(version < 3.5):
        raise RuntimeError("🐍 This script requires Python 3.5+")

    config = None
    try:
        with open(PATH + "config.json", encoding="utf8") as config_file:
            config = json.loads(config_file.read())
    except Exception as e:
        raise EnvironmentError("😡 Error reading config.json") from e

    if config is not None:
        try:
            IPV4_ENABLED = config["a"]
            IPV6_ENABLED = config["aaaa"]
        except Exception:
            IPV4_ENABLED = True
            IPV6_ENABLED = True
            print("⚙️ Individually disable IPv4 or IPv6 with new config.json \
            options. Read more about it here: \
            https://github.com/timothymiller/cloudflare-ddns/blob/master/README.md")
        if(len(sys.argv) > 1):
            if(sys.argv[1] == "--repeat"):
                delay = 5*60
                if IPV4_ENABLED and IPV6_ENABLED:
                    print("🕰️ Updating IPv4 (A)& IPv6 (AAAA) records \
                        every 5 minutes")
                elif IPV4_ENABLED and not IPV6_ENABLED:
                    print("🕰️ Updating IPv4 (A) records every 5 minutes")
                elif IPV6_ENABLED and not IPV4_ENABLED:
                    print("🕰️ Updating IPv6 (AAAA) records every 5 minutes")
                next_time = time.time()
                killer = GracefulExit()
                while True:
                    if killer.kill_now.wait(delay):
                        break
                    updateIPs(getIPs())
            else:
                print("❓ Unrecognized parameter '" +
                      sys.argv[1] + "'. Stopping now.")
        else:
            updateIPs(getIPs())

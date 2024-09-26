import sys
import os
import json
import datetime
import sqlite3
import whois
import requests
import dns.resolver
import subprocess

def setup_workspace(workspace_name):
    if not os.path.exists(workspace_name):
        os.makedirs(workspace_name)
    
    db_path = os.path.join(workspace_name, 'recon-ng.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS whois_data (
        domain TEXT PRIMARY KEY,
        registrar TEXT,
        whois_server TEXT,
        creation_date TEXT,
        expiration_date TEXT
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS ip_geolocation (
        ip TEXT PRIMARY KEY,
        country TEXT,
        region TEXT,
        city TEXT,
        latitude REAL,
        longitude REAL
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS dns_lookup (
        domain TEXT,
        record_type TEXT,
        ttl INTEGER,
        address TEXT,
        PRIMARY KEY (domain, record_type, address)
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS recon_ng_data (
        module TEXT,
        domain TEXT,
        data TEXT,
        PRIMARY KEY (module, domain, data)
    )
    ''')

    conn.commit()
    conn.close()

    print(f"Workspace '{workspace_name}' set up with database at {db_path}.")
    return db_path

def write_to_file(filename, content):
    with open(filename, 'a') as f:
        f.write(content + '\n')

def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        data = {
            'domain': domain,
            'registrar': w.registrar,
            'whois_server': w.whois_server,
            'creation_date': str(w.creation_date),
            'expiration_date': str(w.expiration_date)
        }
        return data
    except Exception as e:
        print(f"WHOIS lookup failed for {domain}: {e}")
        return None

def store_whois_data(data, db_path, filename):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
    INSERT OR REPLACE INTO whois_data (domain, registrar, whois_server, creation_date, expiration_date)
    VALUES (?, ?, ?, ?, ?)
    ''', (data['domain'], data['registrar'], data['whois_server'], data['creation_date'], data['expiration_date']))
    conn.commit()
    conn.close()
    
    content = f"WHOIS Data for {data['domain']}:\n" + '\n'.join([f"{key}: {value}" for key, value in data.items()])
    write_to_file(filename, content)

def ip_geolocation(ip):
    response = requests.get(f"http://ip-api.com/json/{ip}")
    if response.status_code == 200:
        data = response.json()
        return {
            'ip': ip,
            'country': data['country'],
            'region': data['regionName'],
            'city': data['city'],
            'latitude': data['lat'],
            'longitude': data['lon']
        }
    else:
        print(f"Failed to get geolocation for IP {ip}: {response.text}")
        return None

def store_ip_geolocation(data, db_path, filename):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
    INSERT OR REPLACE INTO ip_geolocation (ip, country, region, city, latitude, longitude)
    VALUES (?, ?, ?, ?, ?, ?)
    ''', (data['ip'], data['country'], data['region'], data['city'], data['latitude'], data['longitude']))
    conn.commit()
    conn.close()
    
    content = f"IP Geolocation for {data['ip']}:\n" + '\n'.join([f"{key}: {value}" for key, value in data.items()])
    write_to_file(filename, content)

def dns_lookup(domain):
    try:
        result = dns.resolver.resolve(domain, 'A')
        records = []
        for ipval in result:
            records.append({'domain': domain, 'record_type': 'A', 'ttl': result.rrset.ttl, 'address': ipval.to_text()})
        return records
    except Exception as e:
        print(f"DNS lookup failed for {domain}: {e}")
        return None

def store_dns_data(data, db_path, filename):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    for record in data:
        cursor.execute('''
        INSERT OR REPLACE INTO dns_lookup (domain, record_type, ttl, address)
        VALUES (?, ?, ?, ?)
        ''', (record['domain'], record['record_type'], record['ttl'], record['address']))
    conn.commit()
    conn.close()
    
    content = f"DNS Data for {data[0]['domain']}:\n"
    for record in data:
        content += '\n'.join([f"{key}: {value}" for key, value in record.items()]) + '\n'
    write_to_file(filename, content)

def store_recon_ng_data(module, domain, data, db_path, filename):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
    INSERT OR REPLACE INTO recon_ng_data (module, domain, data)
    VALUES (?, ?, ?)
    ''', (module, domain, data))
    conn.commit()
    conn.close()
    
    content = f"Recon-ng Data for {module} on {domain}:\n{data}"
    write_to_file(filename, content)

def run_recon(domain):
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")  # Generate a timestamp
    workspace_name = f"{domain.replace('.', '_')}_results_{timestamp}"  # Include timestamp in workspace name
    db_path = setup_workspace(workspace_name)
    filename = os.path.join(workspace_name, f"{domain.replace('.', '_')}_{timestamp}.txt")  # Include timestamp in file name
    
    whois_data = whois_lookup(domain)
    if whois_data:
        store_whois_data(whois_data, db_path, filename)
    
    dns_data = dns_lookup(domain)
    if dns_data:
        store_dns_data(dns_data, db_path, filename)
        for record in dns_data:
            ip = record['address']
            geo_data = ip_geolocation(ip)
            if geo_data:
                store_ip_geolocation(geo_data, db_path, filename)

    # Perform recon-ng commands
    try:
        print("\nRunning recon-ng commands...\n")

        # Execute recon-ng modules
        recon_commands = [
            f"recon/domains-hosts/whois -d {domain}",
            f"recon/domains-hosts/geoip -t default -d {domain}",
            f"recon/domains-hosts/dns -t default -d {domain}",
            f"recon/domains-hosts/reverse_dns -d {domain}",
            f"recon/domains-hosts/shodan_hostname -d {domain}",
            f"recon/domains-hosts/censys_hosts -d {domain}",
            f"recon/domains-contacts/pgp_search -d {domain}",
            f"recon/domains-contacts/github_commits -d {domain}"
            # Add more Recon-ng modules as needed
        ]

        for command in recon_commands:
            result = subprocess.run(['recon-ng', '-C', command], capture_output=True, text=True)
            print(f"Recon-ng Output for '{command}':\n")
            print(result.stdout)
            store_recon_ng_data(command, domain, result.stdout, db_path, filename)

    except Exception as e:
        print(f"Error running recon-ng commands: {e}")

# Check and install recon-ng if not installed
try:
    subprocess.run(["recon-ng", "-h"], check=True)
except subprocess.CalledProcessError:
    subprocess.run(["sudo", "apt", "install", "recon-ng", "-y"], check=True)

if len(sys.argv) != 2:
    print("Usage: python script_name.py <target_ip_or_website>")
    sys.exit(1)

domain = sys.argv[1]
run_recon(domain)


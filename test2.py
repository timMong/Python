# Регулярные выражения + чтение из файла + scan
import re
import nmap
import json
import socket


count = 0
domain1 = 'leroymerlin.ru'
domain2 = 'lmru.tech'
temp = {domain1: [], domain2: []}


# Функция, которая динамически добавляет новые записи в словарь
def append_to_dict(domain, host, port, service):
    p = [{
        port: service
    }]
    if domain == domain1:
        temp[domain1].append({
            "hostname": host,
            "port": p
    })
    elif domain == domain2:
        temp[domain2].append({
            "hostname": host,
            "port": p
        })
    # print(temp)

# Функция, которая сканирует порты
def scan(host_name):
    global count
    count += 1

    port_begin = 79
    port_end = 82
    if re.finditer(fr'.*{domain1}', host_name):
        domain = domain1
    else:
        domain = domain2
    scanner = nmap.PortScanner()
    try:
        target_ip = socket.gethostbyname(host_name)
        for i in range(port_begin, port_end+1):
            res = scanner.scan(target_ip, str(i), arguments='-sT --top-ports 100')
            try:
                status = res['scan'][target_ip]['tcp'][i]['state']
                service = res['scan'][target_ip]['tcp'][i]['name']
                if status == 'open':
                    append_to_dict(domain, host_name, i, service)
                    # print(f'{match_domain}:{target_ip}:port {i}: status {status}: service {service}')
            except KeyError:
                print(f'Its local IP for domain: {host_name} - {target_ip}')
                break
    except socket.gaierror:
        #...
        print(f'No IP address for: {host_name}')


unique = []
pattern = re.compile('(.*lmru.tech)|(.*leroymerlin.ru)')

# Записываем в новый файл только то, что нам подходит
with open("list_of_hosts.txt", "r") as f1, open("clear.txt", "w") as f2:
    for hostname in f1:
        for match in re.finditer(pattern, hostname):
            if match[0] not in unique:
                unique.append(match[0])
                f2.write(match[0] + '\n')

# Сканируем компы из нового файла
with open("clear.txt", "r") as f2:
    for h in f2:
        n = h.split('\n')
        scan(n[0])


f3 = open("scan_results.json", "w")
json.dump(temp, f3)
f3.close()
print(count)
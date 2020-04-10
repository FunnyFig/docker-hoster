#!/usr/bin/python3
import docker
import argparse
import shutil
import signal
import time
import sys
import os

label_name = "hoster.domains"
enclosing_pattern = "#-----------Docker-Hoster-Domains----------\n"
hosts_path = "/tmp/hosts"
hosts = {}

def signal_handler(signal, frame):
    global hosts
    hosts = {}
    update_hosts_file()
    sys.exit(0)

def main():
    # register the exit signals
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    args = parse_args()
    global hosts_path
    hosts_path = args.file

    dockerClient = docker.APIClient(base_url='unix://%s' % args.socket)
    events = dockerClient.events(decode=True)
    #get running containers
    for c in dockerClient.containers(quiet=True, all=False):
        container_id = c["Id"]
        container = get_container_data(dockerClient, container_id)
        hosts[container_id] = container

    # existing tasks
    for t in dockerClient.tasks():
        handle_task(dockerClient, t)

    update_hosts_file()

    handlers = { 'container': handle_container
               , 'node': handle_node }

    #listen for events to keep the hosts file updated
    for e in events:
        handlers.get(e['Type'], handle_nop)(dockerClient, e)

def handle_nop(client, e):
    pass

def handle_container(dockerClient, e):
    status = e["status"]
    if status =="start":
        container_id = e["id"]
        container = get_container_data(dockerClient, container_id)
        hosts[container_id] = container
        update_hosts_file()

    if status in ("stop", "die", "destroy"):
        container_id = e["id"]
        if container_id in hosts:
            hosts.pop(container_id)
            update_hosts_file()

def handle_node(client, e):
    if e['Action'] != 'update':
        return
    s = e['Actor']['Attributes'].get('state.new')
    if s and s != 'down':
        return
    if not e['Actor']['Attributes']['name']:
        return

    dirty = False
    node_id = e['Actor']['ID']
    for t in client.tasks(filters={'node': node_id}):
        dirty = handle_task(client, t) or dirty

    if dirty:
        update_hosts_file()
    

def handle_task(client, t):
    task_id = t['ID']

    if t['DesiredState'] == 'running':
        hosts[task_id] = get_task_data(t)
        return True
    elif t['DesiredState'] == 'shutdown':
        if task_id in hosts:
            hosts.pop(task_id)
            return True
    return False


def get_task_data(task):
    namespace = task['Spec']['ContainerSpec']['Labels']['com.docker.stack.namespace']

    rv = []

    for n in task['Spec']['Networks']:
        if not n['Aliases']:
            continue
        # overlay network can not be accessed directly
        # we only depend on master port fowarding
        #for na in t['NetworksAttachments']:
        #    if na['Network']['ID'] == n['Aliases']['Target']:
        #        ip_addrs = map(lambda a: a.split('/')[0] ,na['Addresses'])
        #        break
        #for ip in ip_addrs:
        #    rv.append({ 'ip': ip
        #              , 'domains': set(n['Aliases']+[f'{namespace}_{a}' for a in n['Aliases']])}
        rv.append({ 'ip': '127.0.0.1' 
                  , 'domains': set(n['Aliases']+[f'{namespace}_{a}' for a in n['Aliases']])})

    return rv


def get_container_data(dockerClient, container_id):
    #extract all the info with the docker api
    info = dockerClient.inspect_container(container_id)
    container_hostname = info["Config"]["Hostname"]
    container_name = info["Name"].strip("/")
    container_ip = info["NetworkSettings"]["IPAddress"]
    if info["Config"]["Domainname"]:
        container_hostname = container_hostname + "." + info["Config"]["Domainname"]
    
    result = []

    for values in info["NetworkSettings"]["Networks"].values():
        
        if not values["Aliases"]: 
            continue

        result.append({
                "ip": values["IPAddress"] , 
                "name": container_name,
                "domains": set(values["Aliases"] + [container_name, container_hostname])
            })

    if container_ip:
        result.append({"ip": container_ip, "name": container_name, "domains": [container_name, container_hostname ]})

    return result

def test_update_hosts_file():
    if not len(hosts):
        print('Nothing to update')
        return

    print('UPDATE:')
    for id, addresses in hosts.items():
        for addr in addresses:
            print("%s    %s\n"%(addr["ip"],"   ".join(addr["domains"])))

def update_hosts_file():
    if len(hosts)==0:
        print("Removing all hosts before exit...")
    else:
        print("Updating hosts file with:")

    for id,addresses in hosts.items():
        for addr in addresses:
            print("ip: %s domains: %s" % (addr["ip"], addr["domains"]))

    #read all the lines of thge original file
    lines = []
    with open(hosts_path,"r+") as hosts_file:
        lines = hosts_file.readlines()

    #remove all the lines after the known pattern
    for i,line in enumerate(lines):
        if line==enclosing_pattern:
            lines = lines[:i]
            break;

    #remove all the trailing newlines on the line list
    while lines and lines[-1].strip()=="": lines.pop()

    #append all the domain lines
    if len(hosts)>0:
        lines.append("\n\n"+enclosing_pattern)
        
        for id, addresses in hosts.items():
            for addr in addresses:
                lines.append("%s    %s\n"%(addr["ip"],"   ".join(addr["domains"])))
        
        lines.append("#-----Do-not-add-hosts-after-this-line-----\n\n")

    #write it on the auxiliar file
    aux_file_path = hosts_path+".aux"
    with open(aux_file_path,"w") as aux_hosts:
        aux_hosts.writelines(lines)

    #replace etc/hosts with aux file, making it atomic
    shutil.move(aux_file_path, hosts_path)


def parse_args():
    parser = argparse.ArgumentParser(description='Synchronize running docker container IPs with host /etc/hosts file.')
    parser.add_argument('socket', type=str, nargs="?", default="tmp/docker.sock", help='The docker socket to listen for docker events.')
    parser.add_argument('file', type=str, nargs="?", default="/tmp/hosts", help='The /etc/hosts file to sync the containers with.')
    return parser.parse_args()

if __name__ == '__main__':
    main()


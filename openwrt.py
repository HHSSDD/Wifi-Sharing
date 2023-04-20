#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import socket
from multiprocessing import Process
import sys
import re
import os
import fcntl
import time
import sqlite3
import json
import requests
from Cryptodome.Cipher import AES
import base64
#import debugpy


BLOCK_SIZE = 16  # Bytes
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

KEY = base64.b64decode('94ZSDQTvIkSPH/E1pCOVeA==')

      
#debugpy.listen(('0.0.0.0', 5678))

host = "0.0.0.0"  # IP 0.0.0.0 refers to all IP addresses
port = 2222     # The open port is 2222 in Router

server_ip = "wifisharing" # The IP address of server
server_port = 443  # The open port is 443 in server

max_conn = 5   # Maximum number of connections

def router_and_client():
    """
    A server deployed on the router to exchange information with the client
    :return: No return
    """
    processes = []  # A list of processes
    process_ID = 0  # Total number of running processes
    while True:
        print("Smart WiFi Sharing")
        try:
            # These two lines of code prevent the socket server from being occupied after a restart
            # （socket.error: [Errno 98] Address already in use）
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Bind the router IP and port
            s.bind((host, port))
            # Listen for new client connections, set the maximum number of servers to listen to 5
            s.listen(max_conn)

        except socket.error as msg:  # get Error of socket
            print(msg)  # Error display
            sys.exit(1)  # End the program
        
        process2 = Process(target=send_network_data)
        process2.start()

        for i in range(max_conn):  # Allows 5 users to connect simultaneously
            process = Process(target=running, args=(s,))  # Open a process for each user
            process.start()  # Start the process
            processes.append(process)  # Add the started process to the processes list
            process_ID += 1  # Record the number of processes opened
        for p in processes:  # Wait for all processes to finish before adding new ones
            p.join()  # Waiting for the process to finish

        
def send_network_data():


    while(True):

        time.sleep(210)
        with open("/root/users_in_connection", "r") as f:
            users_in_connection = f.readlines()
        if not users_in_connection:
            continue
        print(users_in_connection)
        conn = sqlite3.connect('/tmp/bandwidthd/stats.db')
        c = conn.cursor()
        cursor = c.execute('select ip, sum(total), max(timestamp) from bd_rx_log group by ip')

        data_table = []
        new_data_table = []

        for row in cursor:
            data_table.append(row)
        print(data_table)
        c.execute("delete from bd_rx_log")
        conn.commit()
        conn.close()
        
        masterNetworkData = 0
        x = 0

        for user in users_in_connection: 
            new_data_table.append([])
            spt = user.split(',')
            for data in data_table:
                print(ip_to_string(data[0]))
                if ip_to_string(data[0]) == spt[0]:
                    new_data_table[x].append(spt[0])
                    new_data_table[x].append(spt[1])
                    new_data_table[x].append(spt[2])
                    new_data_table[x].append(data[1])
                    masterNetworkData += data[1]
                    new_data_table[x].append(data[2])
                    x += 1
                    break
        print(new_data_table)
        if not new_data_table[0]:
            continue

        with open("/root/router_info", "r") as f:
            master_info = f.readline()
        
        spt = master_info.split(',')
        masterName = spt[0]
        masterId = spt[1]
        master = {}
        master["masterName"] = masterName
        master["masterId"] = masterId
        master["masterNetworkData"] = masterNetworkData
        users = []
        for userdata in new_data_table:
            user = {}
            user["username"] = userdata[1]
            user["userid"] = userdata[2]
            user["userNetworkData"] = userdata[3]
            users.append(user)

        jsondata = {}
        jsondata["master"] = master
        jsondata["users"] = users
        
        dump_data = json.dumps(jsondata)
        print(dump_data)
        resp = requests.post('https://wifisharing/connect/userNetworkData', json = {"json": dump_data}, verify = '/root/server.pem')
        
        print(resp.text)
        users_access = json.loads(resp.text)
        for user_access in users_access:

            if (str(user_access["access"]) == "False"):
                user_id = str(user_access["userid"])
                for user in new_data_table:
                    if (user[2] == user_id):
                        user_ip = user[0]
                        break
                set_firewall(get_mac(user_ip), 0)



def ip_to_string(ip):

    return str((ip>>24)&0xff) + '.' + str((ip>>16)&0xff) + '.' + str((ip>>8)&0xff) + '.' + str(ip&0xff)

def running(s):
    """
    Managing user-created connections
    :param s: it's a socket created in router_and_client to set a socket connection
    :return: conn
    """
    while True:

        print('Waiting for connection...')
        conn, addr = s.accept()
        print("Connect Successfully")

        deal_client(conn,addr)
        conn.close()
        

def deal_client(conn,addr):
    """
    Processing messages from the client
    :param conn: a socket object which can be considered as a client
    :param addr: the ip address of client
    """

    print("Waiting for messages from the Client")
    # Accepting data from the client

    data = conn.recv(1024)
    client_ip = addr[0]

    print("Received successfully")
    if not data:  # If no data comes in from the client
        print("Client disconnection")
        return
    else:
        # Start processing information from the client data
        info_from_client = aesDecrypt(KEY, data.decode('utf-8'))
        print("Message Received:\n%s" % info_from_client)
    
    info_to_client = handle_info(info_from_client, client_ip)
    print(info_to_client)
    info_to_client = aesEncrypt(KEY, info_to_client)
    conn.send(info_to_client.encode('utf-8'))


def handle_info(info, client_ip):


    if (re.match(r'connectRequest.*', info)):

        spt = info.split(',')
        username = spt[1]
        userid = spt[2]
        token = spt[3]
        userdata = {"username": username, "userid": userid, "token": token}

        resp = requests.post('https://wifisharing/connect/connectRequest', data = userdata, verify = '/root/server.pem')
        
        if resp.text == "Allow WiFi Access":

            mac = get_mac(client_ip)
            with open("/root/users_in_connection", "r") as f:
                users_in_connection = f.readlines()
            user_already_in_access_list = False
            for user in users_in_connection: 
                spt_2 = user.split(',')
                if (spt_2[1] == username):
                    user_already_in_access_list = True
                    break
            if (user_already_in_access_list == False):
                with open("/root/users_in_connection", "a") as f:
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                    f.write(client_ip + ',' + username + ',' + userid)

            set_firewall(mac, 1)

        return resp.text
    
     
    if (re.match(r'logoutManually.*', info)):

        spt = info.split(',')
        userid = spt[1]
        token = spt[2]
        userdata = {"userid": userid, "token": token}

        resp = requests.post('https://wifisharing/login/logoutManually', data = userdata, verify = '/root/server.pem')

        return resp.text
        

    if (re.match(r'registerRouter.*', info)):

        spt = info.split(',')
        username = spt[1]
        userid = spt[2]
        token = spt[3]
        with open("/tmp/sysinfo/board_name", "r") as f:
            routerName = f.readline()
        jsondata = {}
        jsondata["masterName"] = username
        jsondata["masterId"] = userid
        jsondata["masterToken"] = token
        jsondata["routerName"] = routerName
        dump_data = json.dumps(jsondata)

        resp = requests.post('https://wifisharing/login/routerRegister', json = {"json": dump_data}, verify = '/root/server.pem')

        if resp.text == "register successfully":
            with open("/root/router_info", "w") as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                f.write(username + ',' + userid)
        
        return resp.text
        
    
    if (re.match(r'disconnectWifi.*', info)):

        spt = info.split(',')
        username = spt[1]
        userid = spt[2]
        mac = get_mac(client_ip)
        
        with open("/root/users_in_connection", "r") as f:
            users_in_connection = f.readlines()

        new_users_in_connection = []
        for user in users_in_connection: 
            spt_2 = user.split(',')
            if (spt_2[1] == username):
                pass
            else:
                new_users_in_connection.append(user)

        
        with open("/root/users_in_connection", "w") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            f.writelines(new_users_in_connection)

        set_firewall(mac, 0)

        return "successful"
        
    return "Unexpected message"
    

        
def get_mac(ip):
    
    # /proc/net/arp: IP address   HW type   Flags   HW address    Mask     Device
    #                  spt[0]     spt[1]    spt[2]    spt[3]     spt[4]    spt[5]

    with open("/proc/net/arp", "r") as f:
        lines = f.readlines()

    for line in lines:
        spt = line.strip("\n").split()
        if ip == spt[0]:
            return spt[3]
    

def set_firewall(mac, acc):
    """
    Add and modify the original firewall file to control the networking permission of the devices. As we need to write
    to the firewall file, and to ensure that the firewall file is written correctly, this function needs to be locked.
    :param mac: mac address
    :param acc: access right
    :return:
    """

    print("set firewall")
    print("write firewall rules......")

    mac = mac.upper()

    if(acc):
        user_already_in_firewall = False
        with open("/etc/firewall.user", 'r') as f:
            lines = f.readlines()
            for line in lines:
                try:
                    spt = line.strip("\n").split(" ")
                    if(spt[8] == mac):
                        user_already_in_firewall = True
                        break
                except IndexError:
                    pass
        if(user_already_in_firewall == False):
            with open("/etc/firewall.user", 'a') as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                f.write("iptables -I FORWARD -p all -m mac --mac-source " + mac.upper() + " -j ACCEPT\n")
    else:
        with open("/etc/firewall.user", 'r') as f:
            lines = f.readlines()
            newlines = []
            for line in lines:
                try:
                    spt = line.strip("\n").split(" ")
                    if(spt[8] == mac):
                        continue
                    else:
                        newlines.append(line)
                except IndexError:
                    newlines.append(line)
        with open("/etc/firewall.user", 'w') as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            f.writelines(newlines)

    # Needs to restart the firewall to take effect
    os.system("/etc/init.d/firewall restart")

def aesEncrypt(key, data):

    # String padding
    data = pad(data)
    cipher = AES.new(key, AES.MODE_ECB)

    result = cipher.encrypt(data.encode('utf8'))
    encodestrs = base64.b64encode(result)
    return encodestrs.decode('utf8')

def aesDecrypt(key, data):

    data = base64.b64decode(data)
    cipher = AES.new(key, AES.MODE_ECB)

    text_decrypted = unpad(cipher.decrypt(data))
    return text_decrypted.decode('utf8')


if __name__ == '__main__':

    router_and_client()

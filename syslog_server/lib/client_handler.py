from syslog_server.lib import db_handler, data_handler
import paramiko
import datetime
import io

def run_ssh_command(client, command):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if(client[5] == None):
            ssh.connect(client[1], client[2], username=client[3], password=client[4])
        else:
            pkey = paramiko.RSAKey.from_private_key(io.StringIO(client[5]))
            ssh.connect(client[1], client[2], username=client[3], password=client[4], pkey=pkey)
        _, ssh_stdout, _ = ssh.exec_command(command, timeout=5)
        lines = ssh_stdout.readlines()
        ssh.close()
        return(lines)

def process_firewall_rules(client, lines):
    new_rules = 0
    existing_rules = 0
    for line in lines:
        if(line[0] == "@"):
            split = line.split("@", 1)[1].split("(", 1)
            rule_number = split[0]
            description = split[1].split(")", 1)[1].lstrip()
            query_2 = """INSERT INTO pfsense_firewall_rules (pfsense_instance, record_time, rule_number, rule_description) VALUES ({}, '{}', {}, '{}')"""
            query_3 = """SELECT COUNT(*) FROM pfsense_firewall_rules WHERE pfsense_instance = {} AND rule_number = {} AND rule_description = '{}'"""
            now = datetime.datetime.now()
            timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
            query_3 = query_3.format(client[0], rule_number, description)
            results = db_handler.query_db(query_3)
            if(int(results[0][0]) == 0):
                query_2 = query_2.format(client[0], timestamp, rule_number, description)
                new_rules = new_rules + 1
                db_handler.update_db(query_2)
            elif(int(results[0][0]) > 0):
                existing_rules = existing_rules + 1
    print("Instance id: " + str(client[0]))
    print(str(new_rules) + " New rules added")
    print(str(existing_rules) + " Existing rules skipped")

def check_firewall_rules(client):
    lines = run_ssh_command(client, "pfctl -vvsr")
    process_firewall_rules(client, lines)

def check_os_version(client):
    alter_query = "UPDATE pfsense_instances SET freebsd_version = {}, pfsense_release = {} WHERE id = {}"
    lines = run_ssh_command(client, "uname -a")
    lines = lines[0].split(" ")
    freebsd_version = lines[2]
    pfsense_release = lines[5]
    freebsd_version = str(data_handler.single_dimension_index_read(freebsd_version, "freebsd_version", "freebsd_version"))
    pfsense_release = str(data_handler.single_dimension_index_read(pfsense_release, "pfsense_release", "pfsense_release"))
    db_handler.update_db(alter_query.format(freebsd_version, pfsense_release, client[0]))
    print("FreeBSD Version: " + freebsd_version)
    print("PfSense Release: " + pfsense_release)

def check_instance_users(client):
    lines = run_ssh_command(client, "logins")
    count_broad = """SELECT COUNT(*) FROM pfsense_instance_users WHERE user_name = "{}" AND pfsense_instance = {}"""
    count_specific = """SELECT COUNT(*) FROM pfsense_instance_users WHERE user_name = "{}" AND user_group = "{}" AND user_description = "{}" AND pfsense_instance = {}"""
    record_insert = """INSERT INTO pfsense_instance_users (user_name, user_group, user_description, pfsense_instance) VALUES ("{}", "{}", "{}", {})"""
    id_query = """SELECT id FROM pfsense_instance_users WHERE user_name = "{}" AND pfsense_instance = {}"""
    record_update = """UPDATE pfsense_instance_users SET user_group = "{}", user_description = "{}" WHERE id = {}"""
    added = 0
    updated = 0
    skipped = 0
    for line in lines:
        raw_result = line.split()
        count = 0 
        result = []
        descrip = ""
        for item in raw_result:
            if(count < 4):
                result = result + [item]
            else:
                descrip = descrip + " " + str(item)
            count = count + 1
        result = result + [descrip]
        broad_count = db_handler.query_db(count_broad.format(result[0], str(client[0])))[0][0]
        if(broad_count == 0):
            db_handler.update_db(record_insert.format(result[0], result[2], result[4], str(client[0])))
            added = added + 1
        elif(broad_count > 0):
            specific_count = db_handler.query_db(count_specific.format(result[0], result[2], result[4], str(client[0])))[0][0]
            if(specific_count == 0):
                id = db_handler.query_db(id_query.format(result[0], str(client[0])))[0][0]
                db_handler.update_db(record_update.format(result[2], result[4], str(id)))
                updated = updated + 1
            else:
                skipped = skipped + 1
    print("Instance Users Added: " + str(added))
    print("Instance Users Updated: " + str(updated))
    print("Instance Users Skipped: " + str(skipped))

def return_whitelist(client):
    client_id = client[0]
    query = """SELECT ip, destination_port FROM whitelist WHERE pfsense_instance = {}"""
    whitelist_raw = db_handler.query_db(query.format(str(client_id)))
    whitelist = []
    for row in whitelist_raw:
        whitelist = whitelist + [[row[0], row[1]]]
    return(whitelist)
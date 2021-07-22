#----------------------------------------------------
#INITIALISATION
#----------------------------------------------------
#IMPORT LIBRARIES
import logging
import mysql.connector
import os
import datetime
import paramiko
import time
import numpy as np
import pickle
from sklearn.ensemble import IsolationForest

#ADD TO LOG
logging.warning("Program Started")

#SET DB PARAMETERS
db_host = os.environ["DB_IP"]
db_user = os.environ["DB_USER"]
db_password = os.environ["DB_PASS"]
db_schema = os.environ["DB_SCHEMA"]
db_port = os.environ["DB_PORT"]

#SET STORAGE DIRECTORY
dir = "/var/models"

#----------------------------------------------------
#UNDERLYING FUNCTIONS
#----------------------------------------------------
#READ FROM DB
def query_db(query):
    db = mysql.connector.connect(
        host=db_host,
        user=db_user,
        password=db_password,
        database=db_schema,
        port=db_port
    )
    cursor = db.cursor()
    cursor.execute(query)
    result = cursor.fetchall()
    return(result)

#WRITE TO DB
def update_db(query):
    db = mysql.connector.connect(
        host=db_host,
        user=db_user,
        password=db_password,
        database=db_schema,
        port=db_port
    )
    cursor = db.cursor()
    cursor.execute(query)
    db.commit()

def row_sanitize(value, new_row):
    if(value == None):
        value = 0
    elif(value == "NaN"):
        value = 0
    elif(value == "NULL"):
        value = 0
    value = int(value)
    new_row = new_row + [value]
    return(new_row)

#FIND A SUBSTRING WITHIN A STRING
def element_find(start_char_set, end_char_set, data):
    start = data.find(start_char_set) + len(start_char_set)
    end = data.find(end_char_set)
    substring = data[start:end]
    substring = substring.strip()
    end_len = end + len(end_char_set)
    sliced_string = data[end_len:]
    return(substring, sliced_string)

#SPLIT A STRING BASED ON NUMBER OF CHARACTERS
def element_split(no_split, s):
    first_half = s[:no_split]
    second_half = s[no_split:]
    first_half = first_half.strip()
    second_half = second_half.strip()
    return(first_half, second_half)

#REPLACE BLANKS IN TUPLE WITH "NULL"
def iterate_nulls(tup, mode, count):
    new_tup = []
    if(mode == 1):
        while(count > 0):
            for item in tup:
                if(item == ""):
                    new_tup = new_tup + ["NULL"]
                else:
                    new_tup = new_tup + [item]
                count = count - 1
    elif(mode == 2):
        for item in tup:
            if(item == ""):
                new_tup = new_tup + ["NULL"]
            else:
                new_tup = new_tup + [item]
    return(new_tup)

def double_dimension_index_add(results, table, var_names):
    query = """INSERT INTO {} ({}, {}) VALUES ('{}', {})"""
    update_db(query.format(table, var_names[0], var_names[1], results[0], results[1]))

def double_dimension_index_read(results, table, var_names):
    query = """SELECT id FROM {} WHERE {} = '{}' AND {} = {}"""
    query_result = query_db(query.format(table, var_names[0], results[0], var_names[1], var_names[1]))
    if(len(query_result) == 0):
        double_dimension_index_add(results, table, var_names)
        id = query_db(query.format(table, var_names[0], results[0], var_names[1], var_names[1]))[0][0]
    else:
        id = query_result[0][0]
    return(id)  

def single_dimension_index_add(result, table, var_name):
    query = """INSERT INTO {} ({}) VALUES ('{}')"""
    update_db(query.format(table, var_name, result))

def single_dimension_index_read(result, table, var_name):
    query = """SELECT id FROM {} WHERE {} = '{}'"""
    query_result = query_db(query.format(table, var_name, result))
    if(len(query_result) == 0):
        single_dimension_index_add(result, table, var_name)
        id = query_db(query.format(table, var_name, result))[0][0]
    else:
        id = query_result[0][0]
    return(id)

def results_process(results_tup, checks_tup, instance):
    count = 0
    checks_count = 0
    checks_max = len(checks_tup)
    final_tup = []
    for result in results_tup:
        if(checks_count < checks_max):
            if(count == checks_tup[checks_count][0]):
                checks = checks_tup[checks_count]
                if(checks[3] == 2):
                    id = single_dimension_index_read(result, checks[1], checks[2][0])
                elif(checks[3] == 3):
                    checks = checks_tup[checks_count]
                    id = double_dimension_index_read([result, instance], checks[1], checks[2])
                final_tup = final_tup + [id]
                checks_count = checks_count + 1
            else:
                try:
                    final_tup = final_tup + [int(result)]
                except:
                    final_tup = final_tup + [result]
        else:
            try:
                final_tup = final_tup + [int(result)]
            except:
                final_tup = final_tup + [result]
        count = count + 1
    return(final_tup)
    
def vpn_user_process(vpn_user):
    count_query = """SELECT COUNT(*) FROM vpn_user WHERE user_name = {}"""
    select_query = """SELECT id FROM vpn_user WHERE user_name = {}""" 
    count = query_db(count_query.format(vpn_user))[0][0]
    if(count == 0):
        insert_query = """INSERT INTO vpn_user (user_name) VALUES ({})"""
        update_db(insert_query.format(vpn_user))
    id_raw = query_db(select_query.format(vpn_user))
    id = id_raw[0][0]
    return(id)
    
def return_clients():
    query = "SELECT id, reachable_ip, instance_user, instance_password, ssh_port FROM pfsense_instances"
    results = query_db(query)
    clients = []
    for row in results:
        client = [row[0], row[1], row[4], row[2], row[3]]
        clients = clients + [client,]
    return(clients)

def run_ssh_command(client, command):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(client[1], client[2], username=client[3], password=client[4])
        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(command, timeout=5)
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
            results = query_db(query_3)
            if(int(results[0][0]) == 0):
                query_2 = query_2.format(client[0], timestamp, rule_number, description)
                new_rules = new_rules + 1
                update_db(query_2)
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
    freebsd_version = str(single_dimension_index_read(freebsd_version, "freebsd_version", "freebsd_version"))
    pfsense_release = str(single_dimension_index_read(pfsense_release, "pfsense_release", "pfsense_release"))
    update_db(alter_query.format(freebsd_version, pfsense_release, client[0]))
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
        broad_count = query_db(count_broad.format(result[0], str(client[0])))[0][0]
        if(broad_count == 0):
            update_db(record_insert.format(result[0], result[2], result[4], str(client[0])))
            added = added + 1
        elif(broad_count > 0):
            specific_count = query_db(count_specific.format(result[0], result[2], result[4], str(client[0])))[0][0]
            if(specific_count == 0):
                id = query_db(id_query.format(result[0], str(client[0])))[0][0]
                update_db(record_update.format(result[2], result[4], str(id)))
                updated = updated + 1
            else:
                skipped = skipped + 1
    print("Instance Users Added: " + str(added))
    print("Instance Users Updated: " + str(updated))
    print("Instance Users Skipped: " + str(skipped))

def remove_empty_entries(tup):
    new_tup = []
    for item in tup:
        if(item != ''):
            new_tup = new_tup + [item]
    return(new_tup)

def ipsec_range_secondary_subprocess(range):
    new_range = []
    for item in range:
        if(item == ', dpdaction=hold' or ''):
            pass
        else:
            new_entry = item.split("|/0")[0]
            new_range = new_range + [new_entry]
    return(new_range)

def ipsec_range_subprocess(local_ranges, remote_ranges):
    local_ranges = local_ranges.split("|/0 TUNNEL")
    remote_ranges = remote_ranges.split("|/0 TUNNEL")
    local_ranges = ipsec_range_secondary_subprocess(local_ranges)
    remote_ranges = ipsec_range_secondary_subprocess(remote_ranges)
    return([local_ranges, remote_ranges])
#----------------------------------------------------
#PRIMARY FUNCTIONS
#----------------------------------------------------
#PULL DATA FROM PFSENSE INSTANCES IN THE SYSTEM USING SSH
def standard_ssh_checks():
    clients = return_clients()
    for client in clients:
        logging.warning("----------------------------------------")
        logging.warning("Instance: " + str(client[0]))
        logging.warning("----------------------------------------")
        try:
            check_firewall_rules(client) 
        except:
            logging.warning("Firewall Rules Check Failed")
        try:
            check_os_version(client)
        except:
            logging.warning("OS Version Check Failed")
        try:
            check_instance_users(client)
        except:
            logging.warning("User Check Failed")
        try:
            process_ipsec_connections(client)
        except:
            logging.warning("IPSec Connections Check Failed")

#Check results against ML models
def ml_check(results, sub_results, pfsense_instance, filename):
    result = [results[0], pfsense_instance, results[3], sub_results[0], sub_results[1], sub_results[2], sub_results[3], sub_results[4], sub_results[5], sub_results[6], sub_results[7], sub_results[8], sub_results[14], sub_results[16], sub_results[18], sub_results[19], sub_results[21]]
    new_result = []
    for item in result:
        new_result = row_sanitize(item, new_result)
    new_result = np.array([new_result])
    hostname_query = "SELECT hostname FROM pfsense_instances WHERE id = {}"
    hostname = query_db(hostname_query.format(pfsense_instance))[0][0]
    daily_model_location = os.path.join(dir + "/" + hostname)
    model = pickle.load(open(daily_model_location + "/" + filename + ".pickle", 'rb'))
    prediction = model.predict(new_result)[0]
    return(prediction)

def ml_process(results, sub_results, pfsense_instance, filename):
        try:
            ml_result = ml_check(results, sub_results, pfsense_instance, filename)
        except:
            ml_result = "'NULL'"
        return(ml_result)

#Collect filter logs from all clients
def collect_filter_logs():
    clients = return_clients()
    for client in clients:
        parsed = 0
        bucket = 0
        existing = 0
        logging.warning("---------------------------------------")
        logging.warning("PfSense Instance: " + client[1])
        pfsense_instance = client[0]
        lines = run_ssh_command(client, "tail /var/log/filter.log")
        for line in lines:
            result = handle(line, pfsense_instance)
            if(result == "parsed"):
                parsed = parsed + 1
            elif(result == "bucket"):
                bucket = bucket + 1
            elif(result == "Existing"):
                existing = existing + 1
        logging.warning("Logs Parsed: " + str(parsed))
        logging.warning("Logs Skipped: " + str(existing))
        logging.warning("Logs Added to Bucket: " + str(bucket))

#Collect OpenVPN logs from all clients
def collect_OpenVPN_logs():
    clients = return_clients()
    for client in clients:
        pfsense_instance = client[0]
        lines = run_ssh_command(client, "tail /var/log/openvpn.log")
        for line in lines:
            open_vpn_handle(line, pfsense_instance)

#PARSE PFSENSE 2.5.x OPENVPN LOG DATA
def open_vpn_process_25x(data):
    result = element_find("<", ">1 ", data)
    type_code = result[0]
    result_2 = result[1].split()
    timestamp = result_2[0]
    hostname = None
    log_type = result_2[2]
    if(type_code == "37"):
        user_name = result_2[7]
        final_result = ("1", type_code, timestamp, user_name)
    else:
        final_result = ("2", type_code, timestamp, hostname, data)
    return(final_result)

#PARSE PFSENSE 2.5.x LOG DATA
def log_process_25x(data):
    result = element_find("<", ">1 ", data)
    type_code = result[0]
    result_2 = result[1].split()
    timestamp = result_2[0]
    hostname = None
    log_type = result_2[2]
    rset = result_2[6]  
    rset = rset.split(",")
    final_result = (type_code, timestamp, hostname, log_type, rset)
    return(final_result)

#PARSE PFSENSE 2.4.x and 21.05 PFSENSE PLUS LOG DATA
def log_process_24x(data):
    split_1 = data.split(" ", 3)
    timestamp = split_1[0] + " " + split_1[1] + " " + split_1[2]
    rest_1 = split_1[3]
    raw_element_1 = rest_1.split(" ", 1)[1]
    log_type = raw_element_1.split("[")[0]
    rset = raw_element_1.split("]:", 1)[1].strip(" ")
    rset = rset.split(",")
    final_result = ("NULL", timestamp, log_type, rset)
    return(final_result)

def open_vpn_handle(log, pfsense_instance):
    try:
        access_insert_query = """INSERT INTO `open_vpn_access_log` (`type_code`, `record_time`, `vpn_user`, `pfsense_instance`) VALUES ({}, "{}", {}, {});"""
        check_query = """SELECT COUNT(*) FROM open_vpn_access_log WHERE type_code = {} AND record_time = "{}" AND vpn_user = {} AND pfsense_instance = {}"""
        row = open_vpn_process_25x(log)
        raw_time = datetime.datetime.strptime(row[2], '%Y-%m-%dT%H:%M:%S.%f%z')
        timestamp = raw_time.strftime('%Y-%m-%d %H:%M:%S')
        if(row[0] == "1"):
            vpn_user = vpn_user_process(row[3])
            check_count = query_db(check_query.format(row[1], timestamp, vpn_user, str(pfsense_instance)))[0][0]
            if(check_count == 0):
                update_db(access_insert_query.format(row[1], timestamp, vpn_user, str(pfsense_instance)))
                logging.warning("OpenVPN log-on added")
    except:
        logging.warning("OPENVPN PARSING ERROR")

def handle(log, pfsense_instance):
    #Attempt to run data through available parsing functions
    existing_query = """SELECT COUNT(*) FROM `Dashboard_DB`.`pfsense_logs` WHERE `type_code`= {} AND `record_time`= '{}' AND `pfsense_instance`= {} AND `log_type`= {} AND `rule_number`= {} AND `sub_rule_number`= {} AND `anchor`= {} AND `tracker`= {} AND `real_interface`= {} AND `reason`= {} AND `act`= {} AND `direction`= {} AND `ip_version`= {} AND `tos_header`= {} AND `ecn_header`= {} AND `ttl`= {} AND `packet_id`= {} AND `packet_offset`= {} AND `flags`= {} AND `protocol_id`= {} AND `protocol`= {} AND `packet_length`= {} AND `source_ip`= {} AND `destination_ip`= {} AND `source_port`= {} AND `destination_port`= {} AND `data_length`= {}"""
    log_insert_query = """INSERT IGNORE INTO `Dashboard_DB`.`pfsense_logs` (`type_code`, `record_time`, `pfsense_instance`, `log_type`, `rule_number`, `sub_rule_number`, `anchor`, `tracker`, `real_interface`, `reason`, `act`, `direction`, `ip_version`, `tos_header`, `ecn_header`, `ttl`, `packet_id`, `packet_offset`, `flags`, `protocol_id`, `protocol`, `packet_length`, `source_ip`, `destination_ip`, `source_port`, `destination_port`, `data_length`, `previous_day_ml_check`, `previous_week_ml_check`, `combined_ml_check`) VALUES ({}, '{}', {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})"""
    try:
        try:
            #Attempt to parse as PfSense 2.5.x log
            results = log_process_25x(log)
            hostname = results[2]
            sub_results = results[4]
            results = [results[0], results[1], str(pfsense_instance), results[3]]
            #Attempt to parse as PfSense 2.4.x log
        except:
            log = log.strip("\n")
            results = log_process_24x(log)
            timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            sub_results = results[3]
            results = [results[0], timestamp, str(pfsense_instance), results[2]]
        results_checks = [
            [3, "pfsense_log_type", ["log_type"], 2]
            ]
        results = results_process(results, results_checks, pfsense_instance)
        sub_results_checks = [
            [4, "pfsense_real_interface", ["interface", "pfsense_instance"], 3], 
            [5, "pfsense_reason", ["reason"], 2], 
            [6, "pfsense_act", ["act"], 2], 
            [7, "pfsense_direction", ["direction"], 2],
            [9, "pfsense_tos_header", ["tos_header"], 2],
            [10, "pfsense_ecn_header", ["ecn_header"], 2],
            [14, "pfsense_flags", ["flags"], 2],
            [16, "pfsense_protocol", ["protocol"], 2],
            [18, "pfsense_ip", ["ip"], 2],
            [19, "pfsense_ip", ["ip"], 2]
            ]
        sub_results = results_process(sub_results, sub_results_checks, pfsense_instance)
        sub_results = iterate_nulls(sub_results, 2, 99)
        time = datetime.datetime.strptime(results[1], "%Y-%m-%dT%H:%M:%S.%f%z")
        date_time = time.strftime("%Y-%m-%d %H:%M:%S")
        existing = query_db(existing_query.format(results[0], date_time, results[2], results[3], sub_results[0], sub_results[1], sub_results[2], sub_results[3], sub_results[4], sub_results[5], sub_results[6], sub_results[7], sub_results[8], sub_results[9], sub_results[10], sub_results[11], sub_results[12], sub_results[13], sub_results[14], sub_results[15], sub_results[16], sub_results[17], sub_results[18], sub_results[19], sub_results[20], sub_results[21], sub_results[22]))[0][0]
        if(existing == 0):
            daily_ml_result = ml_process(results, sub_results, pfsense_instance, "yesterday")
            weekly_ml_result = ml_process(results, sub_results, pfsense_instance, "last_week")
            if(daily_ml_result == -1 and weekly_ml_result == -1):
                combined_ml_result = "-1"
            else:
                combined_ml_result = "1"
            update_db(log_insert_query.format(results[0], date_time, results[2], results[3], sub_results[0], sub_results[1], sub_results[2], sub_results[3], sub_results[4], sub_results[5], sub_results[6], sub_results[7], sub_results[8], sub_results[9], sub_results[10], sub_results[11], sub_results[12], sub_results[13], sub_results[14], sub_results[15], sub_results[16], sub_results[17], sub_results[18], sub_results[19], sub_results[20], sub_results[21], sub_results[22], daily_ml_result, weekly_ml_result, combined_ml_result))
            return("parsed")
        else:
            return("Existing")
    except:
        query = """INSERT INTO pfsense_log_bucket (log) VALUES ("{}")"""
        update_db(query.format(log))
        return("bucket")

def check_ipsec(client):
    results = run_ssh_command(client, "ipsec statusall")
    listening_ip_addresses = []
    connections = []
    shunted_connections = []
    routed_connections = []
    security_associations = []
    mode = 0
    for row in results:
        row = row.split("\n")[0]
        #Handle Listening IP addresses
        if(mode == 0):
            if(row == "Listening IP addresses:"):
                mode = 1
        if(mode == 1):
            if(row == "Connections:"):
                mode = 2
            else:
                listening_ip_addresses = listening_ip_addresses + [row]
        #Handle Connections
        elif(mode == 2):
            if(row == "Shunted Connections:"):
                mode = 3
            else:
                connections = connections + [row]
        #Handle Shunted Connections
        elif(mode == 3):
            if(row == "Routed Connections:"):
                mode = 4
            else:
                shunted_connections = shunted_connections + [row]
        #Handle Routed Connections        
        elif(mode == 4):
            if(row.split((",", 1)[0]) == "Security Associations "):
                mode = 5
            else:
                routed_connections = routed_connections + [row]
        #Handle Security Associations
        elif(mode == 5):
            security_associations = security_associations + [row]
    return([["listening_ip_addresses", listening_ip_addresses], ["connections", connections], ["shunted_connections", shunted_connections], ["routed_connections", routed_connections], ["security_associations", security_associations]])

def process_ipsec_connections(client):
    connections = check_ipsec(client)[1][1]
    client_id = str(client[0])
    processed_connections = []
    clear_current_connections_query = """DELETE FROM pfsense_ipsec_connections WHERE pfsense_instance = {}"""
    update_db(clear_current_connections_query.format(client_id))
    connection_insert_query = """INSERT IGNORE INTO pfsense_ipsec_connections (pfsense_instance, local_connection, remote_connection, local_ranges, remote_ranges) VALUES ({}, "{}", "{}", "{}", "{}")"""
    connection_check_query = '''SELECT COUNT(*) FROM pfsense_ipsec_connections WHERE pfsense_instance = {} AND local_connection = "{}" AND remote_connection = "{}" AND local_ranges = "{}" AND remote_ranges = "{}"'''
    for row in connections:
        prefix = row.split(":", 1)
        if(prefix[0].strip()[:3] == "con"):
            details = prefix[1]
            intermediary = details.split(":", 1)
            start = intermediary[0].strip()
            try:
                entry = intermediary[1]
                if(start == "local"):
                    local = entry.split("]", 1)[0]
                    local = local.split("[", 1)[1]
                elif(start == "remote"):
                    remote = entry.split("]", 1)[0]
                    remote = remote.split("[", 1)[1]
                elif(start == "child"):
                    child = entry.strip()
                    splits = child.split(" === ")
                    local_ranges = splits[0]
                    remote_ranges = splits[1]
                    local_ranges = local_ranges.split("|/0 TUNNEL")[0]
                    remote_ranges = remote_ranges.split("|/0 TUNNEL")[0]
                    local_ranges = local_ranges.strip().split("|/0")
                    remote_ranges = remote_ranges.strip().split("|/0")
                    local_ranges = remove_empty_entries(local_ranges)
                    remote_ranges = remove_empty_entries(remote_ranges)
                check = query_db(connection_check_query.format(client_id, local, remote, local_ranges, remote_ranges))[0][0]
                if(check == 0):
                    update_db(connection_insert_query.format(client_id, local, remote, local_ranges, remote_ranges))
                    processed_connections = processed_connections + [[local, remote, local_ranges, remote_ranges]]
                else:
                    pass
            except:
                pass

#MAINLOOP
loop = True
while(loop == True):
    try:
        collect_filter_logs()
    except:
        pass
    try:
        collect_OpenVPN_logs()
    except:
        pass
    if(int(datetime.datetime.now().strftime("%M")) % int(os.environ["SSH_POLL_INTERVAL"]) == 0 ):
        try:
            logging.warning("SSH POLL TAKING PLACE")
            standard_ssh_checks()
        except:
            logging.warning("SSH POLL ERROR")
    time.sleep(int(os.environ["SYSLOG_POLL_INTERVAL"]))

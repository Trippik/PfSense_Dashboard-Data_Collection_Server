#----------------------------------------------------
#INITIALISATION
#----------------------------------------------------
#IMPORT LIBRARIES
import logging
import os
import datetime
import paramiko
import time
import numpy as np
import pickle
from sklearn.ensemble import IsolationForest
import io

from lib import db_handler, data_handler

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
def run_ssh_command(client, command):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if(client[5] == None):
            ssh.connect(client[1], client[2], username=client[3], password=client[4])
        else:
            pkey = paramiko.RSAKey.from_private_key(io.StringIO(client[5]))
            ssh.connect(client[1], client[2], username=client[3], password=client[4], pkey=pkey)
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

def interface_sanitize(interfaces):
    new_interfaces = []
    for interface in interfaces:
        if(len(interface) == 9):
            new_interfaces = new_interfaces + [interface]
    return(new_interfaces)

def return_whitelist(client):
    client_id = client[0]
    query = """SELECT ip, destination_port FROM whitelist WHERE pfsense_instance = {}"""
    whitelist_raw = db_handler.query_db(query.format(str(client_id)))
    whitelist = []
    for row in whitelist_raw:
        whitelist = whitelist + [[row[0], row[1]]]
    return(whitelist)

def percent_process(rate, total):
    dec = rate / total
    percent = int(dec * 100)
    percent = str(percent) + "%"
    return(percent)

#----------------------------------------------------
#PRIMARY FUNCTIONS
#----------------------------------------------------
#PULL DATA FROM PFSENSE INSTANCES IN THE SYSTEM USING SSH
def standard_ssh_checks():
    clients = data_handler.return_clients()
    for client in clients:
        logging.warning("----------------------------------------")
        logging.warning("Instance: " + str(client[0]))
        logging.warning("----------------------------------------")
        try:
            error_percent(client)
        except:
            logging.warning("Error Percent Failed")
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
        try:
            interface_process(client)
        except:
            logging.warning("Interface Check Failed")

def error_percent(client):
    last_log_query = """SELECT record_time FROM pfsense_logs WHERE pfsense_instance = {} ORDER BY record_time DESC LIMIT 1"""
    count_days_logs = """SELECT COUNT(*) FROM pfsense_logs WHERE pfsense_instance = {} AND record_time < '{}' AND record_time > '{}'"""
    count_days_errors = """SELECT COUNT(*) FROM pfsense_logs WHERE pfsense_instance = {} AND record_time < '{}' AND record_time > '{}' AND previous_day_ml_check = {}"""
    count_week_errors = """SELECT COUNT(*) FROM pfsense_logs WHERE pfsense_instance = {} AND record_time < '{}' AND record_time > '{}' AND previous_week_ml_check = {}"""
    count_both_errors = """SELECT COUNT(*) FROM pfsense_logs WHERE pfsense_instance = {} AND record_time < '{}' AND record_time > '{}' AND previous_day_ml_check = {} AND previous_week_ml_check = {}"""
    delete_entries = """DELETE FROM error_rates WHERE pfsense_instance = {}"""
    add_entry = """INSERT INTO error_rates (pfsense_instance, daily_error, weekly_error, joint_error) VALUES ({}, '{}', '{}', '{}')"""
    last_time = db_handler.query_db(last_log_query.format(client[0]))[0][0]
    last_time = last_time.strftime('%Y-%m-%d %H:%M:%S')
    now = datetime.datetime.now()
    today = now.strftime('%Y-%m-%d')
    log_count = int(db_handler.query_db(count_days_logs.format(client[0], last_time, today))[0][0])
    daily_error_rate = int(db_handler.query_db(count_days_errors.format(client[0], last_time, today, "-1"))[0][0])
    weekly_error_rate = int(db_handler.query_db(count_week_errors.format(client[0], last_time, today, "-1"))[0][0])
    joint_error_rate = int(db_handler.query_db(count_both_errors.format(client[0], last_time, today, "-1", "-1"))[0][0])
    daily_error_percent = percent_process(daily_error_rate, log_count)
    weekly_error_percent = percent_process(weekly_error_rate, log_count)
    joint_error_percent = percent_process(joint_error_rate, log_count)
    db_handler.update_db(delete_entries.format(str(client[0])))
    db_handler.update_db(add_entry.format(str(client[0]), daily_error_percent, weekly_error_percent, joint_error_percent))

def interface_check(client):
    raw_results = run_ssh_command(client, "ifconfig -a")
    interfaces = []
    new_interface = []
    count = 0
    sys_count = 0
    max_count = len(raw_results)
    for row in raw_results:
        sys_count = sys_count + 1
        if("\n" and not "\t" in row):
            interfaces = interfaces + [new_interface]
            interface = row.split(":", 1)[0]
            new_interface = [interface]
            count = count + 1
        elif("\n" and "\t" in row):
            if('\tdescription' in row):
                result = row.split(":", 1)[1].strip(" ").strip("\n")
            elif('\tether' in row):
                result = row.split(" ", 1)[1].strip(" ").strip("\n")
            elif('\toptions=' in row):
                result = row.split("=", 1)[1].strip(" ").strip("\n")
            elif('\tinet6' in row):
                result = row.split(" ", 1)[1].split("%")[0]
            elif('\tinet' in row):
                result = row.split(" ", 1)[1].split(" netmask")[0]
            elif('\tmedia' in row):
                result = row.split(": ", 1)[1].strip("\n")
            elif('\tstatus' in row):
                result = row.split(": ", 1)[1].strip("\n")
            else:
                pass
            try:
                new_interface = new_interface + [result]
            except:
                pass
        if(sys_count == max_count):
            interfaces = interfaces + [new_interface]
    interfaces = interface_sanitize(interfaces)
    return(interfaces)

def interface_process(client):
    interfaces = interface_check(client)
    clearing_query = "DELETE FROM pfsense_instance_interfaces WHERE pfsense_instance = {}"
    query = """INSERT IGNORE INTO `pfsense_instance_interfaces`
(`pfsense_instance`,
`interface_name`,
`interface_description`,
`interface_attributes`,
`mac_address`,
`ipv6_address`,
`ipv4_address`,
`interface_type`,
`interface_status`)
VALUES
({},
"{}",
"{}",
"{}",
"{}",
"{}",
"{}",
"{}",
"{}")"""
    db_handler.update_db(clearing_query.format(str(client[0])))
    for interface in interfaces:
        db_handler.update_db(query.format(client[0], interface[0], interface[1], interface[2], interface[3], interface[4], interface[5], interface[6], interface[6]))

#Check results against ML models
def ml_check(results, sub_results, pfsense_instance, filename):
    result = [results[0], pfsense_instance, results[3], sub_results[0], sub_results[1], sub_results[2], sub_results[3], sub_results[4], sub_results[5], sub_results[6], sub_results[7], sub_results[8], sub_results[14], sub_results[16], sub_results[18], sub_results[19], sub_results[21]]
    new_result = []
    for item in result:
        new_result = data_handler.row_sanitize(item, new_result)
    new_result = np.array([new_result])
    hostname_query = "SELECT hostname FROM pfsense_instances WHERE id = {}"
    hostname = db_handler.query_db(hostname_query.format(pfsense_instance))[0][0]
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
    clients = data_handler.return_clients()
    for client in clients:
        whitelist = return_whitelist(client)
        parsed = 0
        bucket = 0
        existing = 0
        whitelisted = 0
        logging.warning("---------------------------------------")
        logging.warning("Log Collection")
        logging.warning("PfSense Instance: " + client[1])
        pfsense_instance = client[0]
        lines = run_ssh_command(client, "tail -10 /var/log/filter.log")
        logging.warning("Raw Logs Collected")
        for line in lines:
            result = handle(line, pfsense_instance, whitelist)
            if(result == "parsed"):
                parsed = parsed + 1
            elif(result == "bucket"):
                bucket = bucket + 1
            elif(result == "existing"):
                existing = existing + 1
            elif(result == "whitelisted"):
                whitelisted = whitelisted + 1
        logging.warning("Logs Parsed: " + str(parsed))
        logging.warning("Logs Skipped: " + str(existing))
        logging.warning("Logs Whitelisted: " + str(whitelisted))
        logging.warning("Logs Added to Bucket: " + str(bucket))

#Collect OpenVPN logs from all clients
def collect_OpenVPN_logs():
    clients = data_handler.return_clients()
    for client in clients:
        pfsense_instance = client[0]
        lines = run_ssh_command(client, "tail /var/log/openvpn.log")
        for line in lines:
            open_vpn_handle(line, pfsense_instance)

#PARSE PFSENSE 2.5.x OPENVPN LOG DATA
def open_vpn_process_25x(data):
    result = data_handler.element_find("<", ">1 ", data)
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
    result = data_handler.element_find("<", ">1 ", data)
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
            vpn_user = data_handler.vpn_user_process(row[3])
            check_count = db_handler.query_db(check_query.format(row[1], timestamp, vpn_user, str(pfsense_instance)))[0][0]
            if(check_count == 0):
                db_handler.update_db(access_insert_query.format(row[1], timestamp, vpn_user, str(pfsense_instance)))
                logging.warning("OpenVPN log-on added")
    except:
        logging.warning("OPENVPN PARSING ERROR")

def handle(log, pfsense_instance, whitelist):
    #Attempt to run data through available parsing functions
    existing_query = """SELECT COUNT(*) FROM `Dashboard_DB`.`pfsense_logs` WHERE `type_code`= {} AND `record_time`= '{}' AND `pfsense_instance`= {} AND `log_type`= {} AND `rule_number`= {} AND `sub_rule_number`= {} AND `anchor`= {} AND `tracker`= {} AND `real_interface`= {} AND `reason`= {} AND `act`= {} AND `direction`= {} AND `ip_version`= {} AND `tos_header`= {} AND `ecn_header`= {} AND `ttl`= {} AND `packet_id`= {} AND `packet_offset`= {} AND `flags`= {} AND `protocol_id`= {} AND `protocol`= {} AND `packet_length`= {} AND `source_ip`= {} AND `destination_ip`= {} AND `source_port`= {} AND `destination_port`= {} AND `data_length`= {}"""
    log_insert_query = """INSERT IGNORE INTO `Dashboard_DB`.`pfsense_logs` (`type_code`, `record_time`, `pfsense_instance`, `log_type`, `rule_number`, `sub_rule_number`, `anchor`, `tracker`, `real_interface`, `reason`, `act`, `direction`, `ip_version`, `tos_header`, `ecn_header`, `ttl`, `packet_id`, `packet_offset`, `flags`, `protocol_id`, `protocol`, `packet_length`, `source_ip`, `destination_ip`, `source_port`, `destination_port`, `data_length`, `previous_day_ml_check`, `previous_week_ml_check`, `combined_ml_check`) VALUES ({}, '{}', {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})"""
    try:
        message = None
        #Attempt to parse as PfSense 2.5.x log
        try:
            results = log_process_25x(log)
            hostname = results[2]
            sub_results = results[4]
            results = [results[0], results[1], str(pfsense_instance), results[3]]
        #If Unable to parse as 2.5.x parse as PfSense 2.4.x log
        except:
            log = log.strip("\n")
            results = log_process_24x(log)
            timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            sub_results = results[3]
            results = [results[0], timestamp, str(pfsense_instance), results[2]]
        results_checks = [
            [3, "pfsense_log_type", ["log_type"], 2]
            ]
        results = data_handler.results_process(results, results_checks, pfsense_instance)
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
        sub_results = data_handler.results_process(sub_results, sub_results_checks, pfsense_instance)
        sub_results = data_handler.iterate_nulls(sub_results, 2, 99)
        time = datetime.datetime.strptime(results[1], "%Y-%m-%dT%H:%M:%S.%f%z")
        date_time = time.strftime("%Y-%m-%d %H:%M:%S")
        existing = db_handler.query_db(existing_query.format(results[0], date_time, results[2], results[3], sub_results[0], sub_results[1], sub_results[2], sub_results[3], sub_results[4], sub_results[5], sub_results[6], sub_results[7], sub_results[8], sub_results[9], sub_results[10], sub_results[11], sub_results[12], sub_results[13], sub_results[14], sub_results[15], sub_results[16], sub_results[17], sub_results[18], sub_results[19], sub_results[20], sub_results[21], sub_results[22]))[0][0]
        if(existing == 0):
            target = [sub_results[18], sub_results[20]]
            if((target in whitelist) == True):
                message = "whitelisted"
                daily_ml_result = 1
                weekly_ml_result = 1
            else:
                daily_ml_result = ml_process(results, sub_results, pfsense_instance, "yesterday")
                weekly_ml_result = ml_process(results, sub_results, pfsense_instance, "last_week")
            if(daily_ml_result == -1 and weekly_ml_result == -1):
                combined_ml_result = "-1"
            else:
                combined_ml_result = "1"
            db_handler.update_db(log_insert_query.format(results[0], date_time, results[2], results[3], sub_results[0], sub_results[1], sub_results[2], sub_results[3], sub_results[4], sub_results[5], sub_results[6], sub_results[7], sub_results[8], sub_results[9], sub_results[10], sub_results[11], sub_results[12], sub_results[13], sub_results[14], sub_results[15], sub_results[16], sub_results[17], sub_results[18], sub_results[19], sub_results[20], sub_results[21], sub_results[22], daily_ml_result, weekly_ml_result, combined_ml_result))
            if(message == None):
                message = "parsed"
        else:
            message = "existing"
    except:
        query = """INSERT INTO pfsense_log_bucket (log) VALUES ("{}")"""
        db_handler.update_db(query.format(log))
        message = "bucket"
    return(message)

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
    db_handler.update_db(clear_current_connections_query.format(client_id))
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
                check = db_handler.query_db(connection_check_query.format(client_id, local, remote, local_ranges, remote_ranges))[0][0]
                if(check == 0):
                    db_handler.update_db(connection_insert_query.format(client_id, local, remote, local_ranges, remote_ranges))
                    processed_connections = processed_connections + [[local, remote, local_ranges, remote_ranges]]
                else:
                    pass
            except:
                pass

#MAINLOOP
def main():
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

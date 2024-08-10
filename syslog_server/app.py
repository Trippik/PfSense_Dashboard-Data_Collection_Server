#----------------------------------------------------
#INITIALISATION
#----------------------------------------------------
#IMPORT LIBRARIES
#Third party external libraries
import numpy as np
from sklearn.ensemble import IsolationForest
#Internal libraries
import logging
import os
import datetime
import time
#Custom package libraries
from syslog_server.lib import db_handler, data_handler, client_handler, ml_handler

#ADD TO LOG
logging.warning("Program Started")

#SET STORAGE DIRECTORY
dir = "/var/models"

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
        except Exception:
            logging.exception("Error Percent Failed")
        try:
            client_handler.check_firewall_rules(client) 
        except Exception:
            logging.exception("Firewall Rules Check Failed")
        try:
            client_handler.check_os_version(client)
        except Exception:
            logging.exception("OS Version Check Failed")
        try:
            client_handler.check_instance_users(client)
        except Exception:
            logging.exception("User Check Failed")
        try:
            process_ipsec_connections(client)
        except Exception:
            logging.exception("IPSec Connections Check Failed")
        try:
            interface_process(client)
        except Exception:
            logging.exception("Interface Check Failed")

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
    daily_error_percent = data_handler.percent_process(daily_error_rate, log_count)
    weekly_error_percent = data_handler.percent_process(weekly_error_rate, log_count)
    joint_error_percent = data_handler.percent_process(joint_error_rate, log_count)
    db_handler.update_db(delete_entries.format(str(client[0])))
    db_handler.update_db(add_entry.format(str(client[0]), daily_error_percent, weekly_error_percent, joint_error_percent))

def interface_check(client):
    raw_results = client_handler.run_ssh_command(client, "ifconfig -a")
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
    interfaces = data_handler.interface_sanitize(interfaces)
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

#Collect filter logs from all clients
def collect_filter_logs():
    clients = data_handler.return_clients()
    for client in clients:
        whitelist = client_handler.return_whitelist(client)
        parsed = 0
        bucket = 0
        existing = 0
        whitelisted = 0
        logging.warning("---------------------------------------")
        logging.warning("Log Collection")
        logging.warning("PfSense Instance: " + client[1])
        pfsense_instance = client[0]
        lines = client_handler.run_ssh_command(client, "tail -10 /var/log/filter.log")
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

def handle(log, pfsense_instance, whitelist):
    #Attempt to run data through available parsing functions
    existing_query = """SELECT COUNT(*) FROM `Dashboard_DB`.`pfsense_logs` WHERE `type_code`= {} AND `record_time`= '{}' AND `pfsense_instance`= {} AND `log_type`= {} AND `rule_number`= {} AND `sub_rule_number`= {} AND `anchor`= {} AND `tracker`= {} AND `real_interface`= {} AND `reason`= {} AND `act`= {} AND `direction`= {} AND `ip_version`= {} AND `tos_header`= {} AND `ecn_header`= {} AND `ttl`= {} AND `packet_id`= {} AND `packet_offset`= {} AND `flags`= {} AND `protocol_id`= {} AND `protocol`= {} AND `packet_length`= {} AND `source_ip`= {} AND `destination_ip`= {} AND `source_port`= {} AND `destination_port`= {} AND `data_length`= {}"""
    log_insert_query = """INSERT IGNORE INTO `Dashboard_DB`.`pfsense_logs` (`type_code`, `record_time`, `pfsense_instance`, `log_type`, `rule_number`, `sub_rule_number`, `anchor`, `tracker`, `real_interface`, `reason`, `act`, `direction`, `ip_version`, `tos_header`, `ecn_header`, `ttl`, `packet_id`, `packet_offset`, `flags`, `protocol_id`, `protocol`, `packet_length`, `source_ip`, `destination_ip`, `source_port`, `destination_port`, `data_length`, `previous_day_ml_check`, `previous_week_ml_check`, `combined_ml_check`) VALUES ({}, '{}', {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})"""
    try:
        message = None
        #Attempt to parse as PfSense 2.5.x log
        try:
            results = data_handler.log_process_25x(log)
            hostname = results[2]
            sub_results = results[4]
            results = [results[0], results[1], str(pfsense_instance), results[3]]
        #If Unable to parse as 2.5.x parse as PfSense 2.4.x log
        except:
            log = log.strip("\n")
            results = data_handler.log_process_24x(log)
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
                daily_ml_result = ml_handler.ml_process(results, sub_results, pfsense_instance, "yesterday")
                weekly_ml_result = ml_handler.ml_process(results, sub_results, pfsense_instance, "last_week")
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
    results = client_handler.run_ssh_command(client, "ipsec statusall")
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
                    local_ranges = data_handler.remove_empty_entries(local_ranges)
                    remote_ranges = data_handler.remove_empty_entries(remote_ranges)
                check = db_handler.query_db(connection_check_query.format(client_id, local, remote, local_ranges, remote_ranges))[0][0]
                if(check == 0):
                    db_handler.update_db(connection_insert_query.format(client_id, local, remote, local_ranges, remote_ranges))
                    processed_connections = processed_connections + [[local, remote, local_ranges, remote_ranges]]
                else:
                    pass
            except:
                pass

def run_db_updates():
    logging.warning("Running DDL updates")
    ddl_files = os.listdir("/ddl")
    for file in ddl_files:
        db_handler.process_ddl_file(file_path="/ddl/" + file, file_name=file)

#MAINLOOP
def main():
    loop = True
    run_db_updates()
    while(loop == True):
        try:
            collect_filter_logs()
        except:
            pass
        try:
            data_handler.collect_OpenVPN_logs()
        except:
            pass
        if(int(datetime.datetime.now().strftime("%M")) % int(os.environ["SSH_POLL_INTERVAL"]) == 0 ):
            try:
                logging.warning("SSH POLL TAKING PLACE")
                standard_ssh_checks()
            except:
                logging.warning("SSH POLL ERROR")
        time.sleep(int(os.environ["SYSLOG_POLL_INTERVAL"]))

if __name__ == '__main__':
    main()
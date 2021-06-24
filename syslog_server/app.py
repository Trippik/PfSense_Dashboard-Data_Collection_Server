#----------------------------------------------------
#INITIALISATION
#----------------------------------------------------
#IMPORT LIBRARIES
import logging
import mysql.connector
import os
import re
import datetime
import paramiko
import time

#ADD TO LOG
logging.warning("Program Started")


#SET DB PARAMETERS
db_host = os.environ["DB_IP"]
db_user = os.environ["DB_USER"]
db_password = os.environ["DB_PASS"]
db_schema = os.environ["DB_SCHEMA"]
db_port = os.environ["DB_PORT"]

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
    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(command)
    lines = ssh_stdout.readlines()
    ssh.close()
    return(lines)

#----------------------------------------------------
#PRIMARY FUNCTIONS
#----------------------------------------------------
#PULL DATA FROM PFSENSE INSTANCES IN THE SYSTEM USING SSH
def standard_ssh_checks():
    clients = return_clients()
    for client in clients:
        try:
            lines = run_ssh_command("pfctl -vvsr")
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
                    if(results[0][0] == 0):
                        query_2 = query_2.format(client[0], timestamp, rule_number, description)
                        logging.warning("Rule Added for instance id: " + str(client[0]))
                        update_db(query_2)
        except:
            logging.warning("SSH Error for instance id: " + str(client[0]))

def collect_logs():
    clients = return_clients()
    for client in clients:
        pfsense_instance = client[0]
        lines = run_ssh_command(client, "tail /var/log/filter.log")
        for line in lines:
            handle(line, pfsense_instance)

#PARSE PFSENSE 2.5.x LOG DATA
def log_process_25x(data):
    result = element_find("<", ">1 ", data)
    type_code = result[0]
    result_2 = result[1].split()
    timestamp = result_2[0]
    hostname = result_2[1]
    log_type = result_2[2]
    rset = result_2[6]
    rest = result_2[1].strip()  
    rset = rset.split(",")
    final_result = (type_code, timestamp, hostname, log_type, rset)
    return(final_result)

#PARSE PFSENSE 2.4.x LOG DATA
def log_process_24x(data):
    result = data.split("<", 1)
    rest = result[1]
    type_code, rest = rest.split(">", 1)
    result_2 = element_split(15, rest)
    timestamp = result_2[0]
    rest = result_2[1]
    rest = rest.strip()
    result_4 = rest.split(":", 1)
    log_type = result_4[0]
    rset = result_4[1].strip()
    rset = rset.split(",")
    final_result = (type_code, timestamp, log_type, rset)
    return(final_result)


def handle(log, pfsense_instance):
    #Attempt to run data through available parsing functions
    try:
        #Attempt to parse as PfSense 2.5.x log
        results = log_process_25x(log)
        hostname = results[2]
        sub_results = results[4]
        results = [results[0], results[1], results[2], results[3]]
        results[2] = str(pfsense_instance)
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
        log_insert_query = """INSERT IGNORE INTO `Dashboard_DB`.`pfsense_logs` (`type_code`, `record_time`, `pfsense_instance`, `log_type`, `rule_number`, `sub_rule_number`, `anchor`, `tracker`, `real_interface`, `reason`, `act`, `direction`, `ip_version`, `tos_header`, `ecn_header`, `ttl`, `packet_id`, `packet_offset`, `flags`, `protocol_id`, `protocol`, `packet_length`, `source_ip`, `destination_ip`, `source_port`, `destination_port`, `data_length`) VALUES ({}, '{}', {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})"""
        log_insert_query = log_insert_query.format(results[0], results[1], results[2], results[3], sub_results[0], sub_results[1], sub_results[2], sub_results[3], sub_results[4], sub_results[5], sub_results[6], sub_results[7], sub_results[8], sub_results[9], sub_results[10], sub_results[11], sub_results[12], sub_results[13], sub_results[14], sub_results[15], sub_results[16], sub_results[17], sub_results[18], sub_results[19], sub_results[20], sub_results[21], sub_results[22])
        update_db(log_insert_query)
        logging.warning("Log Parsed")
    except:
        query = """INSERT INTO pfsense_log_bucket (log) VALUES ("{}")"""
        update_db(query.format(log))
        logging.warning("Log added to PfSense Log Bucket")
    if(int(datetime.datetime.now().strftime("%M")) % int(os.environ["SSH_POLL_INTERVAL"]) == 0 ):
        standard_ssh_checks()
        logging.warning("SSH POLL TAKING PLACE")

#MAINLOOP
loop = True
while(loop == True):
    collect_logs()
    time.sleep(int(os.environ["SYSLOG_POLL_INTERVAL"]))

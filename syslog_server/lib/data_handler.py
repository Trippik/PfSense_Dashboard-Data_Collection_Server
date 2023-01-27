import logging
import datetime
from syslog_server.lib import db_handler, client_handler

def row_sanitize(value, new_row:list) -> list:
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
def element_find(start_char_set:str, end_char_set:str, data:str) -> list:
    start = data.find(start_char_set) + len(start_char_set)
    end = data.find(end_char_set)
    substring = data[start:end]
    substring = substring.strip()
    end_len = end + len(end_char_set)
    sliced_string = data[end_len:]
    return(substring, sliced_string)

#SPLIT A STRING BASED ON NUMBER OF CHARACTERS
def element_split(no_split:int, s:str) -> list:
    first_half = s[:no_split]
    second_half = s[no_split:]
    first_half = first_half.strip()
    second_half = second_half.strip()
    return(first_half, second_half)

#REPLACE BLANKS IN TUPLE WITH "NULL"
def iterate_nulls(tup:list, mode:int, count:int) -> list:
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

# --------------------------------
# MOVE THESE INTO DB HANDLER
# --------------------------------
def double_dimension_index_add(results, table, var_names):
    query = """INSERT INTO {} ({}, {}) VALUES ('{}', {})"""
    db_handler.update_db(query.format(table, var_names[0], var_names[1], results[0], results[1]))

def double_dimension_index_read(results, table, var_names):
    query = """SELECT id FROM {} WHERE {} = '{}' AND {} = {}"""
    query_result = db_handler.query_db(query.format(table, var_names[0], results[0], var_names[1], var_names[1]))
    if(len(query_result) == 0):
        double_dimension_index_add(results, table, var_names)
        id = db_handler.query_db(query.format(table, var_names[0], results[0], var_names[1], var_names[1]))[0][0]
    else:
        id = query_result[0][0]
    return(id)  

def single_dimension_index_add(result, table, var_name):
    query = """INSERT INTO {} ({}) VALUES ('{}')"""
    db_handler.update_db(query.format(table, var_name, result))

def single_dimension_index_read(result, table, var_name):
    query = """SELECT id FROM {} WHERE {} = '{}'"""
    query_result = db_handler.query_db(query.format(table, var_name, result))
    if(len(query_result) == 0):
        single_dimension_index_add(result, table, var_name)
        id = db_handler.query_db(query.format(table, var_name, result))[0][0]
    else:
        id = query_result[0][0]
    return(id)

# --------------------------------

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
    count = db_handler.query_db(count_query.format(vpn_user))[0][0]
    if(count == 0):
        insert_query = """INSERT INTO vpn_user (user_name) VALUES ({})"""
        db_handler.update_db(insert_query.format(vpn_user))
    id_raw = db_handler.query_db(select_query.format(vpn_user))
    id = id_raw[0][0]
    return(id)
    
def return_clients():
    query = "SELECT id, reachable_ip, instance_user, instance_password, ssh_port, private_key FROM pfsense_instances"
    results = db_handler.query_db(query)
    clients = []
    for row in results:
        client = [row[0], row[1], row[4], row[2], row[3], row[5]]
        clients = clients + [client,]
    return(clients)

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

def percent_process(rate, total):
    dec = rate / total
    percent = int(dec * 100)
    percent = str(percent) + "%"
    return(percent)

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

#Collect OpenVPN logs from all clients
def collect_OpenVPN_logs():
    clients = return_clients()
    for client in clients:
        pfsense_instance = client[0]
        lines = client_handler.run_ssh_command(client, "tail /var/log/openvpn.log")
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


def open_vpn_handle(log, pfsense_instance):
    try:
        access_insert_query = """INSERT INTO `open_vpn_access_log` (`type_code`, `record_time`, `vpn_user`, `pfsense_instance`) VALUES ({}, "{}", {}, {});"""
        check_query = """SELECT COUNT(*) FROM open_vpn_access_log WHERE type_code = {} AND record_time = "{}" AND vpn_user = {} AND pfsense_instance = {}"""
        row = open_vpn_process_25x(log)
        raw_time = datetime.datetime.strptime(row[2], '%Y-%m-%dT%H:%M:%S.%f%z')
        timestamp = raw_time.strftime('%Y-%m-%d %H:%M:%S')
        if(row[0] == "1"):
            vpn_user = vpn_user_process(row[3])
            check_count = db_handler.query_db(check_query.format(row[1], timestamp, vpn_user, str(pfsense_instance)))[0][0]
            if(check_count == 0):
                db_handler.update_db(access_insert_query.format(row[1], timestamp, vpn_user, str(pfsense_instance)))
                logging.warning("OpenVPN log-on added")
    except:
        logging.warning("OPENVPN PARSING ERROR")
#----------------------------------------------------
#INITIALISATION
#----------------------------------------------------
#IMPORT LIBRARIES
import logging
import socketserver
import mysql.connector
import os
import re
import datetime
import paramiko

#ADD TO LOG
logging.warning("Program Started")

#SET DB PARAMETERS
db_host = os.environ["DB_IP"]
db_user = os.environ["DB_USER"]
db_password = os.environ["DB_PASS"]
db_schema = os.environ["DB_SCHEMA"]
db_port = os.environ["DB_PORT"]

#LISTEN ON PORT 514
HOST, PORT = "0.0.0.0", 514


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

def index_table_add(values, table, elements, mode):
    single_field_insert_query = "INSERT INTO {} ({}) VALUES ('{}')"
    double_field_insert_query = "INSERT INTO {} ({}, {}) VALUES ('{}', {})"
    read_query = "SELECT id FROM {} WHERE {}"
    single_element_where = "{} = '{}'"
    double_element_where = "{} = '{}' AND {} = {}"
    if(mode == 2):
        query = single_field_insert_query.format(table, elements[0], values)
        update_db(query)
        read_query = read_query.format(table, single_element_where.format(elements[0], values))
        result = query_db(read_query)
        id = result[0][0]
    return(id)

def index_table_process(values, table, elements, mode):
    read_query = "SELECT id FROM {} WHERE {} LIMIT 1"
    count_query = "SELECT COUNT(*) FROM {} WHERE {}"
    single_element_where = "{} = '{}'"
    double_element_where = "{} = '{}' AND {} = {}"
    if(mode == 1):
        read_query = read_query.format(table, single_element_where.format(elements[0], values))
        results = query_db(read_query)
        for row in results:
            id = row[0]
    elif(mode == 2):
        count_query = count_query.format(table, single_element_where.format(elements[0], values))
        count = int(query_db(count_query)[0][0])
        if(count > 0):
            read_query = read_query.format(table, single_element_where.format(elements[0], values))
            results = query_db(read_query)
            id = results[0][0]
        else:
            id = index_table_add(values, table, elements, mode)
    return(id)


def results_process(results_tup, checks_tup):
    count = 0
    checks_count = 0
    checks_max = len(checks_tup)
    final_tup = []
    for result in results_tup:
        if(checks_count < checks_max):
            if(count == checks_tup[checks_count][0]):
                logging.warning(result)
                logging.warning(str(checks_tup[checks_count]))
                checks_count = checks_count + 1
        final_tup = final_tup + [result]
        count = count + 1

#----------------------------------------------------
#PRIMARY FUNCTIONS
#----------------------------------------------------
#PULL DATA FROM PFSENSE INSTANCES IN THE SYSTEM USING SSH
def standard_ssh_checks():
    query = "SELECT id, reachable_ip, instance_user, instance_password, ssh_port FROM pfsense_instances"
    results = query_db(query)
    clients = []
    for row in results:
        client = [row[0], row[1], row[4], row[2], row[3]]
        clients = clients + [client,]
    for client in clients:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(client[1], client[2], username=client[3], password=client[4])
            ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("pfctl -vvsr")
            lines = ssh_stdout.readlines()
            ssh.close()
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

#CLASS TO HANDLE INCOMING UDP PACKETS
class SyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = bytes.decode(self.request[0].strip())
        log = str(data)
        #Attempt to run data through available parsing functions
        #try:
        #Attempt to parse as PfSense 2.5.x log
        results = log_process_25x(log)
        results = iterate_nulls(results, 1, 4)
        hostname = results[2]
        sub_results = iterate_nulls(results[4], 2, 99)
        results = [results[0], results[1], results[2], results[3]]
        query_1 = "SELECT COUNT(*) FROM pfsense_instances WHERE hostname = '{}'"
        query_1.format(hostname)
        query_results = query_db(query_1)
        if(query_results[0][0] == "0"):
            query_2 = "INSERT INTO pfsense_instances (hostname) VALUES ('{}')"
            query_2 = query_2.format(hostname)
            update_db(query_2)
        results_checks = [[2, "pfsense_instances", ["hostname"], 1], [3, "pfsense_log_type", ["log_type"], 2]]
        results_process(results, results_checks)
        if(int(datetime.datetime.now().strftime("%M")) % int(os.environ["SSH_POLL_INTERVAL"]) == 0 ):
            standard_ssh_checks()
            logging.warning("SSH POLL TAKING PLACE")

#MAINLOOP
if __name__ == "__main__":
	try:
		server = socketserver.UDPServer((HOST,PORT), SyslogUDPHandler)
		server.serve_forever(poll_interval=float(os.environ["SYSLOG_POLL_INTERVAL"]))
	except (IOError, SystemExit):
		raise

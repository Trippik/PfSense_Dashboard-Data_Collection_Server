import logging
import socketserver
import mysql.connector
import os
import re

logging.warning("Program Started")

db_host = os.environ["DB_IP"]
db_user = os.environ["DB_USER"]
db_password = os.environ["DB_PASS"]
db_schema = os.environ["DB_SCHEMA"]
db_port = os.environ["DB_PORT"]

LOG_FILE = 'youlogfile.log'
HOST, PORT = "0.0.0.0", 514

#Functions to interact with db
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

#Functions to handle string manipulation
def element_find(start_char_set, end_char_set, data):
    start = data.find(start_char_set) + len(start_char_set)
    end = data.find(end_char_set)
    substring = data[start:end]
    logging.warning(substring)
    substring = substring.strip()
    end_len = end + len(end_char_set)
    logging.warning(str(end_len))
    sliced_string = data[end_len:]
    return(substring, sliced_string)

def element_split(no_split, s):
    first_half = s[:no_split]
    second_half = s[no_split:]
    first_half = first_half.strip()
    second_half = second_half.strip()
    return(first_half, second_half)

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

def log_process_24x(data):
    result = data.split("<", 1)
    result_1 = result[1].split("> ", 1)
    type_code = result_1[0]
    logging.warning("TYPE CODE:")
    logging.warning(type_code)
    logging.warning("POST TYPE CODE SPLIT:")
    logging.warning(result_1[1])
    result_2 = element_split(15, result_1[1])
    timestamp = result_2[0]
    logging.warning("TIMESTAMP:")
    logging.warning(timestamp)
    result_3 = result_2[1].split(" ", 2)
    result_4 = result_3[3].split(":")
    log_type = result_4[0]
    rset = result_4[1].strip()
    rset = rset.split(",")
    final_result = (type_code, timestamp, log_type, rset)
    return(final_result)

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

#Class to handle UDP packets
class SyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        addr = self.client_address[0]
        data = bytes.decode(self.request[0].strip())
        socket = self.request[1]
        log = str(data)
        try:
            try:
                logging.warning("PfSense 2.5.x Attempted")
                results = log_process_25x(log)
                results = iterate_nulls(results, 1, 4)
                sub_results = iterate_nulls(results[4], 2, 99)
                query = "INSERT INTO pfsense_logs (type_code, record_time, hostname, log_type, rule_number, sub_rule_number, anchor, tracker, real_interface, reason, act, direction, ip_version, tos_header, ecn_header, ttl, packet_id, packet_offset, flags, protocol_id, protocol, packet_length, source_ip, destination_ip, source_port, destination_port, data_length) VALUES ({}, '{}', '{}', '{}', {}, {}, {}, {}, '{}', '{}', '{}', '{}', {}, '{}', '{}', {}, {}, {}, '{}', {}, '{}', {}, '{}', '{}', {}, {}, {})"
                query = query.format(results[0], results[1], results[2], results[3], sub_results[0], sub_results[1], sub_results[2], sub_results[3], sub_results[4], sub_results[5], sub_results[6], sub_results[7], sub_results[8], sub_results[9], sub_results[10], sub_results[11], sub_results[12], sub_results[13], sub_results[14], sub_results[15], sub_results[16], sub_results[17], sub_results[18], sub_results[19], sub_results[20], sub_results[21], sub_results[22])
                update_db(query)
            except:
                logging.warning("PfSense 2.4.x Attempted")
                results = log_process_24x(log)
                logging.warning("RESULTS:")
                logging.warning(results)
                results = iterate_nulls(results, 1, 4)
                sub_results = iterate_nulls(results[4], 2, 99)
                query = "INSERT INTO pfsense_logs (type_code, record_time, log_type, rule_number, sub_rule_number, anchor, tracker, real_interface, reason, act, direction, ip_version, tos_header, ecn_header, ttl, packet_id, packet_offset, flags, protocol_id, protocol, packet_length, source_ip, destination_ip, source_port, destination_port, data_length) VALUES ({}, '{}', '{}', '{}', {}, {}, {}, {}, '{}', '{}', '{}', '{}', {}, '{}', '{}', {}, {}, {}, '{}', {}, '{}', {}, '{}', '{}', {}, {}, {})"
                query = query.format(results[0], results[1], results[2], sub_results[0], sub_results[1], sub_results[2], sub_results[3], sub_results[4], sub_results[5], sub_results[6], sub_results[7], sub_results[8], sub_results[9], sub_results[10], sub_results[11], sub_results[12], sub_results[13], sub_results[14], sub_results[15], sub_results[16], sub_results[17], sub_results[18], sub_results[19], sub_results[20], sub_results[21], sub_results[22])
                logging.warning("QUERY:")
                logging.warning(query)
                logging.warning("")
                update_db(query)
        except:
            logging.warning("Parsing failed")

if __name__ == "__main__":
	try:
		server = socketserver.UDPServer((HOST,PORT), SyslogUDPHandler)
		server.serve_forever(poll_interval=float(os.environ["POLL_INTERVAL"]))
	except (IOError, SystemExit):
		raise
	except KeyboardInterrupt:
		print ("Crtl+C Pressed. Shutting down.")

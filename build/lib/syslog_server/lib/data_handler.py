import syslog_server.lib.db_handler

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

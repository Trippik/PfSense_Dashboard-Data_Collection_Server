import mysql.connector
import os
from datetime import datetime
import logging
import time

def pull_db_details():
    return (os.environ["DB_IP"],os.environ["DB_USER"],os.environ["DB_PASS"],os.environ["DB_SCHEMA"],os.environ["DB_PORT"])

def create_db_connection():
    db_details = pull_db_details()
    return mysql.connector.connect(
        host=db_details[0],
        user=db_details[1],
        password=db_details[2],
        database=db_details[3],
        port=db_details[4]
    )

#READ FROM DB
def query_db(query):
    with create_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query)
        result = cursor.fetchall()
        return(result)

#WRITE TO DB
def update_db(query):
    with create_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query)
        conn.commit()

# EXECUTE SQL FILE
def execute_sql_file(file_path):
    with open(file_path, 'r') as file:
        sql_commands = file.read()
    
    with create_db_connection() as conn:
        cursor = conn.cursor()
        for command in sql_commands.split(';'):
            command = command.strip()
            if command:
                cursor.execute(command)
        conn.commit()

def process_ddl_file(file_path: str, file_name: str):
    file_name.lower()
    file_name_split = file_name.split(".")
    if file_name_split[-1] == "sql":
        try:
            schema_exists = False
            latest_rev = 0
            for result in query_db("SELECT table_name FROM information_schema.tables WHERE table_schema = 'Dashboard_DB';"):
                if result[0] == "db_versioning":
                    schema_exists = True
            if schema_exists:
                query_resp = query_db("SELECT rev_number FROM db_versioning ORDER BY rev_number DESC LIMIT 1;")
                if len(query_resp) > 0:
                    latest_rev = query_db("SELECT rev_number FROM db_versioning ORDER BY rev_number DESC LIMIT 1;")[0][0]
            if (int(latest_rev) < int(file_name_split[0])) or latest_rev == "NULL":
                logging.warning(f"Running DDL {file_name}")
                execute_sql_file(file_path)
                update_db(f"INSERT INTO db_versioning (rev_number, run_date) VALUES ({file_name_split[0]}, '{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}')")
        except Exception:
            logging.exception("Error when trying to process ddl")

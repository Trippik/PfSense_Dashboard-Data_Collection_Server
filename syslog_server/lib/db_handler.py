import mysql.connector
import os

def pull_db_details():
    return (os.environ["DB_IP"],os.environ["DB_USER"],os.environ["DB_PASS"],os.environ["DB_SCHEMA"],os.environ["DB_PORT"])

def create_db_connection(db_host, db_user, db_password, db_schema, db_port):
    db_details = pull_db_details()
    db = mysql.connector.connect(
        host=db_details[0],
        user=db_details[1],
        password=db_details[2],
        database=db_details[3],
        port=db_details[4]
    )
    yield db

#READ FROM DB
def query_db(query):
    cursor = create_db_connection().cursor()
    cursor.execute(query)
    result = cursor.fetchall()
    return(result)

#WRITE TO DB
def update_db(query):
    db = create_db_connection()
    db.cursor.execute(query)
    db.commit()
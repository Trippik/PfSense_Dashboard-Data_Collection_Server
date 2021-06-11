# PfSense_Dashboard-Syslog_Server
Syslog server component of the PfSense Monitoring dashboard, formatted as a docker container it acts as a Syslog server processing incoming data from PfSense instances and storing them in an underlying MySQL database used by all containers making up the PfSense Dashboard
  
## ENV Variables  
DB_IP = IP that MySQL is accessible on  
DB_USER = User credential for DB access  
DB_PASS = Password for DB access  
DB_SCHEMA = Name of target Schema in DB  
DB_PORT = Port that DB is accessible on  
POLL_INTERVAL = Interval in seconds at which to poll client instances  
  
## Network Requirements
Container needs to be accessible to all remote PfSense instances, and needs an open UDP connection on port 514

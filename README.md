# PfSense_Dashboard-Syslog_Server
Syslog server component of the PfSense Monitoring dashboard, formatted as a docker container it acts as a Syslog server processing incoming data from PfSense instances and storing them in an underlying MySQL database used by all containers making up the PfSense Dashboard
  
## ENV Variables  
DB_IP = IP that MySQL is accessible on  
DB_USER = User credential for DB access  
DB_PASS = Password for DB access  
DB_SCHEMA = Name of target Schema in DB  
DB_PORT = Port that DB is accessible on  
SYSLOG_POLL_INTERVAL = Interval in seconds at which to poll client instances for new syslog data  
SSH_POLL_INTERVAL = Interval in mins at which to poll client instances for SSH derived info  
  
*NB - The SYSLOG_POLL_INTERVAL must always be smaller than SSH_POLL_INTERVAL due to the method by which their functions are called*
  
## Network Requirements
Container needs to be accessible to all remote PfSense instances, and needs an open UDP connection on port 514
  
## Client Configuration
In it's current state the syslog server is fully compatible with 2.5.x versions of PfSense, with only limited support for 2.4.x version of PfSense due to a hostname log bug in this software version (https://redmine.pfsense.org/issues/7020).
In order to add a new PfSense instance, firstly begin remote syslog sending to the system using the relevant instructions below. 
Once syslog records from the remote instance begin being transmitted to the system, a new record for this instance will be automatically added to the underlying database.
IP Connection details and SSH credentials can then be added to this instance record to allow the system to pull data from the remote instance in order to maintain records for all datapoints.
*NB - 2.4.x PfSense versions are only capable of limited syslog transmission within the system, and there is little to no utility in using the more advanced SSH data pulling with them*
  
### PfSense 2.5.x - Syslog Setup
Within the System Log Settings (Status > System Logs > Settings) set the logging format to "SYSLOG RFC5424" and set the system to:  
  - Log packets matched from the default block rules 
  - Log packets matched from the default pass rules
  - Log packets blocked by 'Block Bogon Networks' rules
  - Log packets blocked by 'Block Private Networks' rules
  - Web Server Log
  - Log errors from the web server process
Finally, configure remote logging with appropriate source addresses and syslog server addressing for your setup, and then set the "Remote Syslog Contents" to "Everything"  
### PfSense 2.4.x - Syslog Setup
Due to a Syslog bug in this version of PfSense the hostname of the PfSense instance is not recorded in it's syslog entries, this means it is not possible to link a log entry with a specific 2.4.x PfSense instance, greatly limiting the monitoring capabilites for them within the system.
However if you do wish to add these to the system, within the System Log Settings (Status > System Logs > Settings) set the system to:  
  - Log packets matched from the default block rules 
  - Log packets matched from the default pass rules
  - Log packets blocked by 'Block Bogon Networks' rules
  - Log packets blocked by 'Block Private Networks' rules
  - Log errors from the web server process
Finally, configure remote logging with appropriate source addresses and syslog server addressing for your setup, and then set the "Remote Syslog Contents" to "Everything"  

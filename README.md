# PfSense_Dashboard-Syslog_Server
Syslog server component of the PfSense Monitoring dashboard, formatted as a docker container it acts as a Syslog server retrieving and processing log data from PfSense instances and storing them in an underlying MySQL database used by all containers making up the PfSense Dashboard
  
## ENV Variables  
DB_IP = IP that MySQL is accessible on  
DB_USER = User credential for DB access  
DB_PASS = Password for DB access  
DB_SCHEMA = Name of target Schema in DB  
DB_PORT = Port that DB is accessible on  
SYSLOG_POLL_INTERVAL = Interval in seconds at which to poll client instances for new syslog data  
SSH_POLL_INTERVAL = Interval in mins at which to poll client instances for SSH derived info  
  
*NB - The SYSLOG_POLL_INTERVAL must always be smaller than SSH_POLL_INTERVAL due to the method by which their functions are called, both of these variables must be integers*

## Container Volumes
The container will need a volume attached to it that is shared with the Data Processing container for the dashboard (https://github.com/Trippik/PfSense_Dashboard-Data_Processing_Server) mapped to /var/models to share ML models between the two containers.
  
## Network Requirements
Container needs to be accessible to all remote PfSense instances.
  
## Client Configuration
In it's current state the syslog server is fully compatible and tested with 2.5.x PfSense CE and 21.05 PfSense Plus.  
The system should also be compatible with earlier 2.4.x versions of PfSense, however this is not tested. 
In order to add a new PfSense instance, there are three key steps.  
Firstly begin syslogs need to be properly configured using the instructions below. 
Secondly you will need to ensure that SSH access to your client PfSense instance is enabled.  
Finally you will need to enter the details of your client PfSense instance into the system, including the original admin/root account setup for the PfSense client.
  
*NB - By default only the root/admin account has access to the required /var/log directory on PfSense client machines. If you do not wish to put the admin user into the system, you can use another user but you will have to ensure that read and execute permissions have been given to the alternate user you put into the system in order for it to function properly*
  
### PfSense CE 2.5.x/PfSense Plus 21.05 - Syslog Setup
Within the System Log Settings (Status > System Logs > Settings) set the logging format to "SYSLOG RFC5424" and set the system to:  
  - Log packets matched from the default block rules 
  - Log packets matched from the default pass rules
  - Log packets blocked by 'Block Bogon Networks' rules
  - Log packets blocked by 'Block Private Networks' rules
  - Web Server Log
  - Log errors from the web server process

### Installation Notes
Although the system is intended to be deployed as a Docker Container, the software repo is within itself a standard Python Package, and as such can be installed using the setup.py file and run by using the "PfSense_Dashboard-Data_Collection_Server" command from the command line of your host server (assuming the correct ENV variables are set)

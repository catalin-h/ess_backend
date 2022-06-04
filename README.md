## ESS Backend Service
TOTP basic authentication service and Docker integration

### Summary
* use Rust async/await runtime from async_std
* scripts for generating self-signed server/client pairs for admin and pam services
* docker file for building service container image
* docker compose file for running the ESS app composed of postgres (DB) service and TOTP service
* the DB service stores the user secret key used later for authentication

## Building and running the service in Docker
All commands should be run from root directory.

### How to building the ESS Docker service image
Assuming docker engine/desktop is installed run the following command
```
 docker image build -t ess_backend:v0
```
Note that the version is `v0` and in order to use this version must update the _ESS_BACKEND_IMG_TAG_ envar from `.env` file.

### How to run the ESS service in Docker
Assuming docker engine/desktop is installed run the following command
```
docker-compose up -d
```
Note:
* custom health check is implemented by ess service and checked by command from Dockerfile
* entrypoint and service envars are embedded in docker image or in `.env` file
* the ess service handles SIGINT, SIGTERM and SIGUP signals in order to gracefully shutdown from Docker
* the postgres service details like user or database name can be configured via `.env` file

### Getting the admin/pam client service root CA and client certificates
Assuming the ess image was generated or is running under the name _ess_backend-ess_backend_ws-1_ must run the following Docker command(s) for copying the root CA files:
For admin client:
```
docker cp ess_backend-ess_backend_ws-1:/opt/ess_backend/certs/admin/admin-root-ca.crt ./
```
For pam client:
```
docker cp ess_backend-ess_backend_ws-1:/opt/ess_backend/certs/pam/pam-root-ca.crt ./
```
Note:
* The web service client needs to be authenticated by the server so must copy 3 files: the root CA, signed client certificate and the client key. To download all from a running `ess service` container one can use the script file `download_all_client_certs_from_container.sh <container name>`
* The server certificate is bounded to the following host names and IPs:
```
*.ess.local                                                                                                                                                                                              *.ess.net                                                                                                                                                                                                *.ess.local                                                                                                                                                                                              127.0.0.1           
```
To use another host name must update the _scripts/openssl.cnf_ and add a new entry in `[ my_subject_alt_names ]` section and regenerate the docker container image.

## Web Service Utilities
The _ess_backend_ binary provides some utilities. The available sub-command are:
* _db_        Database actions. Run '<EXE> db help' for more details
* _health_    Checks the health of an existing ess_backend service
* _start_     Starts the ess service
* _stop_      Stop an already running service

Usage: ess_backend <SUBCOMMAND>

### Using the database _db_ subcommand
```
SUBCOMMANDS:
connect     Verify database connection
delete      Delete user
get-all     Get all users
get-user    Get user data by username
init        Initialize the ess database and client table
insert      Insert user
update      Update user info & secret except the username
verify      Verify secret for username
```
#### connect
Verify database connection

USAGE:
ess_backend db connect [OPTIONS]

 OPTIONS:

 --database <DATABASE>    Database name to connect [default: ess]  
 --pg-default             Use default database name; e.g. postgres

#### init
Initialize the ess database and client table

USAGE:

ess_backend db init [OPTIONS]

   OPTIONS:
 
   -r, --reset    Delete and recreate the clients table

#### insert
Insert user

USAGE:

 ess_backend db insert [OPTIONS] --username <USERNAME>
 
 OPTIONS:
 
 -f, --first-name <FIRST_NAME>    The user's first name [default: noname]

 -l, --last-name <LAST_NAME>      The user's last name [default: noname]

 -s, --secret <SECRET>            A secret key is a unique random string generated when creating the employee record for the first time

 -u, --username <USERNAME>        The unique user name
 
 #### update
 Update user info

USAGE:
    ess_backend db update [OPTIONS] <USERNAME>

ARGS:
    <USERNAME>    The unique user name

OPTIONS:

    -f, --first-name <FIRST_NAME>    The user's first name

    -l, --last-name <LAST_NAME>      The user's last name

#### get-user
Get user data by username

USAGE:

    ess_backend db get-user <USERNAME>

ARGS:

    <USERNAME>    The unique username

#### get-all
Get all users

USAGE:

    ess_backend db get-all

#### delete
Delete user

USAGE:

    ess_backend db delete <USERNAME>

ARGS:

    <USERNAME>    The unique username

#### verify
Verify secret for username

USAGE:

    ess_backend db verify [OPTIONS] <USERNAME> [ONE_TIME_PASSWORD]

ARGS:

    <USERNAME>             The unique user name

    <ONE_TIME_PASSWORD>    If present then check the against this code, otherwise generate the
                           otp code

OPTIONS:

    -d, --discrepancy <DISCREPANCY>    On verify otp it controls how many intervals of timeslice
                                       length to check around current timestamp. Default is 1. E.g.
                                       if discrepancy = 2 and t is the current timestamp then it
                                       will check every code generate by timeslices:
                                       (t-2*expire_interval), (t-1*expire_interval),
                                       (t-0*expire_interval), (t-1*expire_interval) and
                                       (t-2*expire_interval)

    -l, --length <LENGTH>              The code length, default 6

    -t, --timeslice <TIMESLICE>        The default expire interval in seconds, default is 60s

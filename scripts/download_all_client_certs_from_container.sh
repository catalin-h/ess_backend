#!/bin/sh
echo "downloading certs from container : $1 .."

docker cp $1:/opt/ess_backend/certs/pam/pam-root-ca.crt ./
docker cp $1:/opt/ess_backend/certs/pam/pam-server-crt.pem ./
docker cp $1:/opt/ess_backend/certs/pam/pam-server-key.pem ./

docker cp $1:/opt/ess_backend/certs/admin/admin-root-ca.crt ./
docker cp $1:/opt/ess_backend/certs/admin/admin-server-crt.pem ./
docker cp $1:/opt/ess_backend/certs/admin/admin-server-key.pem ./


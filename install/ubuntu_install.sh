#!/bin/bash
## 20180910 1.0 GA - Ubuntu EZ-Button Phoenix installer
########################################################################
#
#                                             ....
#.                                        ,,,,.
#.                                   .,,,,,
#..                              .,,,,,.
# ..                         ,,,,,,,.
# ...                   .,,,,,,,.
#  ...              ,,,,,,,,,.
#  ....        .,,,,,,,,,,
#   ....      .,,,,,,,.
#   .....     ,,,,,
#    .....    ,,,,,         SparkIT Solutions
#              ,,,,
#   ,,,,        ,,,.
# ,,,,,    ..   .,,.
#,,       ....   .,.
#        .....    .,
#       .....      .
#      ....
#     ....
#    ...
#  ....
# ...
#
########################################################################
###################### THIS IS IMPORTANT ###############################
##### Our test builds had their OS mount, and also an SSD mounted at /ssd and a RAID 5 HDD array mounted at /data.
##### You can get creative here, or leave it all on one disk, but keep that in mind when you see what the following default mounts are (we put things in certain places for various reasons)
##### Please take some time to actually read and set these variables and passwords
##### Most importantly... Have fun...
#####
# The user you'll run cuckoo services as
CUCKOO_USER="cuckoo"
# email for....
EMAIL="default@beastmode.tools"
# VM network , used for detonations
SANDNET="10.200.0.0/24"
# IP For the physical host, on the virtual network.
# This will have to be the default gateway of the virtualbox machines you intend to use for detonations
SANDIP="10.200.0.254"
# The interface you want your VMs to be using to get to the internet
SANDINT="vboxnet0"
# Certificate information for the self signed, multi CN cert
ORG_NAME="SparkIT Solutions"
PHOENIX_HOSTNAME=$HOSTNAME
COUNTRY="US"
STATE="GA"
LOCALE="Atlanta"
BUSINESSUNIT="Beastmode"

# Right now we use Cyberchef that's built into moloch.  Not sure if we need a full instance by itself
#DOCKER_CYBERCHEF_IP="172.18.1.248"

# Docker specific details
# See line  160 if you want to separate the networks per container
# MongoDB
DOCKER_MONGO_IP="172.18.1.254"
DOCKER_MONGO_NET="172.18.1.0/24"
DOCKER_MONGO_DIR="/ssd/mongo"

# Kibana
DOCKER_KIBANA_IP="172.18.1.250"

# Grafana
DOCKER_GRAFANA_IP="172.18.1.249"
DOCKER_GRAFANA_DIR="/ssd/grafana"

# Elasticsearch
DOCKER_ELASTIC_IP="172.18.1.253"
#DOCKER_ELASTIC_NET="172.18.2.0/24"
DOCKER_ELASTIC_DIR="/ssd/elastic"
DOCKER_ELASTIC_BACKUP_DIR="/esbackup"

# MySQL
DOCKER_MYSQL_IP="172.18.1.252"
DOCKER_MYSQL_PASSWORD="cuckoo"
DOCKER_MYSQL_DIR="/ssd/mysql/data"
DOCKER_MYSQL_CONF="/ssd/mysql/etc"
DOCKER_MYSQL_DATABASE="cuckoo"
DOCKER_MYSQL_ROOT_PASSWORD="Root123"
MYSQL_CONN_STR="mysql://${CUCKOO_USER}:${DOCKER_MYSQL_PASSWORD}@${DOCKER_MYSQL_IP}/${DOCKER_MYSQL_DATABASE}"

# MISP
DOCKER_MISP_IP="172.18.1.251"
DOCKER_MISP_FQDN="misp.$PHOENIX_HOSTNAME"
DOCKER_MISP_EMAIL="blackhole.em@gmail.com"
DOCKER_MISP_DIR="/ssd/misp/db"
DOCKER_MISP_BACKUP_DIR="/ssd/misp/backup"
# This might need to remain hardcoded for installs
DOCKER_MISP_API="6OkrVL8vHZHfOdY08h6lLYXHQK4cox1ymfHkQ4s4"
DOCKER_POSTFIX_HOST="23.31.159.194"
DOCKER_MISP_MYSQL_USER="phoenix"
DOCKER_MISP_MYSQL_PASSWORD="password"

# Apache2
APACHE2_ADMIN_USER="admin"
APACHE2_ADMIN_PASS="admin"

# Moloch
# TODO: migrate moloch to docker
export MOLOCH_USER="admin"
export MOLOCH_PASSWORD="admin"
export MOLOCH_INTERFACE=$SANDINT
export MOLOCH_ELASTICSEARCH="http://$DOCKER_ELASTIC_IP:9200"
export MOLOCH_INET="yes"
export MOLOCH_LOCALELASTICSEARCH="no"


DJANGO_USER="admin"
DJANGO_PASSWORD="admin"

# Openvpn configuration location.  This will have to match with systemd or whatever you use
OPENVPN="/etc/openvpn"
# Running this from install/ would mean the root cuckoo folder is in the parent directory
CWD=$(pwd)
CUCKOODIR=$(dirname "$CWD")
#I know this is greasy, but requires no interaction
MOLOCHS2SPW=$(date|sha256sum|awk '{ print $1 }')
## $VMSTORAGE is for if you want to put your VMs somewhere else, like on SSDs
## If people don't read the variables and set them, they'll end up with their VMs in a folder named /ssd/vbox
## Imagine how embarrassing it would be to be running VMs from a folder named '/ssd' and have it not be an SSD!!
VMSTORAGE="/ssd/vbox"

# If you have a big data slice, put your storage mount in there
PHOENIXSTORAGE="/data/phoenix_storage"

MLOCATE_DIRECTORIES_TO_IGNORE="\/data \/home\/cuckoo"
#make installer not ask us any questions.  If you're troubleshooting bad installs remove this and see if you get asked something important
export DEBIAN_FRONTEND=noninteractive

### EDIT PAST THIS AT YOUR PERIL
## Who the !@#$ is Joe Blow?!
## OMNIPOTENTLY IDEMPOTENT BASH SCRIPT >> THIS SCRIPT STOMPS ON EVERYTHING BUT ITSELF, INSTALL IT ON A FRESH SYSTEM OR CAVEAT EMPTOR!

if [[ ${EUID} -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi


edit_crontab() {
    cron_file=$1
    user=$2

    crontab -u ${user} -l 2> /dev/null > cuckoocron
    sed -i '/#CUCKOOCRONS/,/#ENDCUCKOOCRONS/d' cuckoocron
    /bin/cp -f ${cron_file} cuckoocron
    replace_templates "cuckoocron"
    crontab -u ${user} cuckoocron
    rm cuckoocron
}

replace_templates() {
    sed -i "s:CUCKOODIR:$(realpath ${CUCKOODIR}):g" $1
    sed -i "s/CUCKOO_USER/${CUCKOO_USER}/g" $1
    sed -i "s/PHOENIX_HOSTNAME/${PHOENIX_HOSTNAME}/g" $1
    sed -i "s/SANDIP/${SANDIP}/g" $1
    sed -i "s/SANDINT/${SANDINT}/g" $1
    sed -i "s#MYSQL_CONN_STR#${MYSQL_CONN_STR}#g" $1

    sed -i "s/DOCKER_MONGO_IP/${DOCKER_MONGO_IP}/g" $1
    sed -i "s:DOCKER_MONGO_DIR:$(realpath ${DOCKER_MONGO_DIR}):g" $1
    sed -i "s#DOCKER_MONGO_NET#${DOCKER_MONGO_NET}#g" $1

    sed -i "s/DOCKER_KIBANA_IP/${DOCKER_KIBANA_IP}/g" $1
    sed -i "s/DOCKER_GRAFANA_IP/${DOCKER_GRAFANA_IP}/g" $1
    sed -i "s:DOCKER_GRAFANA_DIR:${DOCKER_GRAFANA_DIR}:g" $1

    sed -i "s/DOCKER_MYSQL_DATABASE/${DOCKER_MYSQL_DATABASE}/g" $1
    sed -i "s/DOCKER_MYSQL_PASSWORD/${DOCKER_MYSQL_PASSWORD}/g" $1
    sed -i "s/DOCKER_MYSQL_IP/${DOCKER_MYSQL_IP}/g" $1
    sed -i "s/DOCKER_MYSQL_ROOT_PASSWORD/${DOCKER_MYSQL_ROOT_PASSWORD}/g" $1
    sed -i "s:DOCKER_MYSQL_DIR:$(realpath ${DOCKER_MYSQL_DIR}):g" $1
    sed -i "s:DOCKER_MYSQL_CONF:$(realpath ${DOCKER_MYSQL_CONF}):g" $1

    sed -i "s:DOCKER_ELASTIC_DIR:$(realpath ${DOCKER_ELASTIC_DIR}):g" $1
    sed -i "s:DOCKER_ELASTIC_BACKUP_DIR:$(realpath ${DOCKER_ELASTIC_BACKUP_DIR}):g" $1
    sed -i "s/DOCKER_ELASTIC_IP/${DOCKER_ELASTIC_IP}/g" $1

    sed -i "s/DOCKER_POSTFIX_HOST/${DOCKER_POSTFIX_HOST}/g" $1
    sed -i "s#DOCKER_MISP_FQDN#${DOCKER_MISP_FQDN}#g" $1
    sed -i "s#DOCKER_MISP_EMAIL#${DOCKER_MISP_EMAIL}#g" $1
    sed -i "s/DOCKER_MISP_IP/${DOCKER_MISP_IP}/g" $1
    sed -i "s:DOCKER_MISP_DIR:${DOCKER_MISP_DIR}:g" $1
    sed -i "s:DOCKER_MISP_API:${DOCKER_MISP_API}:g" $1
    sed -i "s:DOCKER_MISP_BACKUP_DIR:${DOCKER_MISP_BACKUP_DIR}:g" $1
    sed -i "s:DOCKER_MISP_MYSQL_USER:${DOCKER_MISP_MYSQL_USER}:g" $1
    sed -i "s:DOCKER_MISP_MYSQL_PASSWORD:${DOCKER_MISP_MYSQL_PASSWORD}:g" $1


}

update_packages() {
## We don't want interaction from the iptables install, so let's fix that
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

# This is where the magic happens
## Set our timezone
timedatectl set-timezone Etc/UTC
# Modify for different locales
locale-gen en_US en_US.UTF-8

echo "Updating packages"
## Check for Suricata and liblognormalize
SURICHECK=$(dpkg -l|grep suricata)
if [ -z "$SURICHECK" ]; then
    add-apt-repository -y ppa:oisf/suricata-stable
fi
RSYSLOGCHECK=$(dpkg -l|grep rsyslog-mmnormalize)
if [ -z "$RSYSLOGCHECK" ]; then
    add-apt-repository -y ppa:adiscon/v8-stable
    add-apt-repository -y ppa:ubuntu-sdk-team/ppa
fi

## Add mongodb repository for the client
apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 0C49F3730359A14518585931BC711F9BA15703C6
echo "deb [ arch=amd64,arm64 ] http://repo.mongodb.org/apt/ubuntu xenial/mongodb-org/3.4 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-3.4.list
 add-apt-repository -y "deb http://security.ubuntu.com/ubuntu xenial-security main"
## Update and upgrade
apt-get update -y
apt-get upgrade -y

## Check your version dependencies... once or twice...
echo "Installing dependencies"

apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confnew" install -y git fail2ban openvpn apache2 wget curl uuid-dev libmagic-dev pkg-config g++ flex bison zlib1g-dev libffi-dev gettext libgeoip-dev make libjson-perl libbz2-dev libwww-perl libpng-dev xz-utils libffi-dev iptables-persistent build-essential libssl-dev python-dev libxml2-dev libxslt-dev libtiff5-dev libjpeg8-dev zlib1g-dev libfreetype6-dev liblcms2-dev libwebp-dev tcl8.6-dev tk8.6-dev python-tk libmysqlclient-dev libpcre3-dbg libpcre3-dev autoconf automake libtool libpcap-dev libnet1-dev libyaml-dev zlib1g-dev libcap-ng-dev libmagic-dev libjansson-dev libjansson4 python-pip suricata yara htop nmon apparmor-utils tcpdump volatility mysql-client python python-yaml python-mysqldb python-psycopg2 lm-sensors netcat zlib1g-dev uuid-dev libmnl-dev gcc make autoconf autoconf-archive autogen automake pkg-config sysfsutils unzip rsyslog rsyslog-mmnormalize liblognorm-dev rsyslog-elasticsearch sqlite3 mongodb-clients curl python python-pip apt-transport-https libseccomp2 aufs-tools cgroupfs-mount cgroup-lite pigz ethtool uuid-runtime tesseract-ocr lsof libfuzzy-dev libuv1-dev

echo "Grabbing python requirements"
pip install --upgrade pip
pip2.7 install -r ../requirements.txt
}

setup_rsyslog() {

# Setup RSyslog logging
mkdir /var/log/cuckoo
/bin/cp -f rsyslog/10-phoenix.conf /etc/rsyslog.d
replace_templates "/etc/rsyslog.d/10-phoenix.conf"
/bin/cp -f rsyslog/*.rules /etc/rsyslog.d
# Rsyslog seg faults if this stanza is put in 10-phoenix.conf, so we grab the newly installed config, remove the last line, which is an include, and then manually add the include back
head -n -4 /etc/rsyslog.conf > /tmp/rsyslog.conf
## The template has way too many backslashes and double quotes for me to bother escaping, just decode and append it
echo "dGVtcGxhdGUobmFtZT0iZG9ja2VyLWluZGV4IgogIHR5cGU9Imxpc3QiKSB7CiAgICBjb25zdGFu
dCh2YWx1ZT0iZG9ja2VyLSIpCiAgICBwcm9wZXJ0eShuYW1lPSJ0aW1lcmVwb3J0ZWQiIGRhdGVG
b3JtYXQ9InJmYzMzMzkiIHBvc2l0aW9uLmZyb209IjEiIHBvc2l0aW9uLnRvPSI0IikKICAgIHBy
b3BlcnR5KG5hbWU9InRpbWVyZXBvcnRlZCIgZGF0ZUZvcm1hdD0icmZjMzMzOSIgcG9zaXRpb24u
ZnJvbT0iNiIgcG9zaXRpb24udG89IjciKQogICAgcHJvcGVydHkobmFtZT0idGltZXJlcG9ydGVk
IiBkYXRlRm9ybWF0PSJyZmMzMzM5IiBwb3NpdGlvbi5mcm9tPSI5IiBwb3NpdGlvbi50bz0iMTAi
KQp9CnRlbXBsYXRlKG5hbWU9Impzb25fc3lzbG9nIgogIHR5cGU9Imxpc3QiKSB7CiAgICBjb25z
dGFudCh2YWx1ZT0ieyIpCiAgICAgIGNvbnN0YW50KHZhbHVlPSJcIkB0aW1lc3RhbXBcIjpcIiIp
ICAgICAgIHByb3BlcnR5KG5hbWU9InRpbWVyZXBvcnRlZCIgZGF0ZUZvcm1hdD0icmZjMzMzOSIp
CiAgICAgIGNvbnN0YW50KHZhbHVlPSJcIixcInR5cGVcIjpcInN5c2xvZ19qc29uIikKICAgICAg
Y29uc3RhbnQodmFsdWU9IlwiLFwidGFnXCI6XCIiKSAgICAgICAgICAgcHJvcGVydHkobmFtZT0i
c3lzbG9ndGFnIiBmb3JtYXQ9Impzb24iKQogICAgICBjb25zdGFudCh2YWx1ZT0iXCIsXCJyZWxh
eWhvc3RcIjpcIiIpICAgICBwcm9wZXJ0eShuYW1lPSJmcm9taG9zdCIpCiAgICAgIGNvbnN0YW50
KHZhbHVlPSJcIixcInJlbGF5aXBcIjpcIiIpICAgICAgIHByb3BlcnR5KG5hbWU9ImZyb21ob3N0
LWlwIikKICAgICAgY29uc3RhbnQodmFsdWU9IlwiLFwibG9nc291cmNlXCI6XCIiKSAgICAgcHJv
cGVydHkobmFtZT0ic291cmNlIikKICAgICAgY29uc3RhbnQodmFsdWU9IlwiLFwiaG9zdG5hbWVc
IjpcIiIpICAgICAgcHJvcGVydHkobmFtZT0iaG9zdG5hbWUiIGNhc2Vjb252ZXJzaW9uPSJsb3dl
ciIpCiAgICAgIGNvbnN0YW50KHZhbHVlPSJcIixcInByb2dyYW1cIjpcIiIpICAgICAgcHJvcGVy
dHkobmFtZT0icHJvZ3JhbW5hbWUiKQogICAgICBjb25zdGFudCh2YWx1ZT0iXCIsXCJwcmlvcml0
eVwiOlwiIikgICAgICBwcm9wZXJ0eShuYW1lPSJwcmkiKQogICAgICBjb25zdGFudCh2YWx1ZT0i
XCIsXCJzZXZlcml0eVwiOlwiIikgICAgICBwcm9wZXJ0eShuYW1lPSJzeXNsb2dzZXZlcml0eSIp
CiAgICAgIGNvbnN0YW50KHZhbHVlPSJcIixcImZhY2lsaXR5XCI6XCIiKSAgICAgIHByb3BlcnR5
KG5hbWU9InN5c2xvZ2ZhY2lsaXR5IikKICAgICAgY29uc3RhbnQodmFsdWU9IlwiLFwic2V2ZXJp
dHlfbGFiZWxcIjpcIiIpICAgcHJvcGVydHkobmFtZT0ic3lzbG9nc2V2ZXJpdHktdGV4dCIpCiAg
ICAgIGNvbnN0YW50KHZhbHVlPSJcIixcImZhY2lsaXR5X2xhYmVsXCI6XCIiKSAgIHByb3BlcnR5
KG5hbWU9InN5c2xvZ2ZhY2lsaXR5LXRleHQiKQogICAgICBjb25zdGFudCh2YWx1ZT0iXCIsXCJt
ZXNzYWdlXCI6XCIiKSAgICAgICBwcm9wZXJ0eShuYW1lPSJyYXdtc2ciIGZvcm1hdD0ianNvbiIp
CiAgICAgIGNvbnN0YW50KHZhbHVlPSJcIixcImVuZF9tc2dcIjpcIiIpCiAgICBjb25zdGFudCh2
YWx1ZT0iXCJ9XG4iKQp9Cg=="|base64 -d >> /tmp/rsyslog.conf
echo "module(load=\"omelasticsearch\")
module(load=\"imtcp\" MaxSessions=\"65535\")
input(type=\"imtcp\" port=\"5514\" address=\"127.0.0.1\" ruleset=\"docker\")

ruleset(name=\"docker\") {
        action(type=\"omelasticsearch\"
                        name=\"docker_es\"
                        server=\"${DOCKER_ELASTIC_IP}\"
                        serverport=\"9200\"
                        template=\"json_syslog\"
                        searchIndex=\"docker-index\"
                        dynSearchIndex=\"on\"
                        bulkmode=\"on\"
                        queue.type=\"linkedlist\"
                        queue.filename=\"docker.rsysq\"
                        queue.maxdiskspace=\"20g\"
                        queue.maxfilesize=\"2048m\"
                        queue.saveonshutdown=\"on\"
                        action.resumeretrycount=\"-1\"
                        )


}

# Include all config files in /etc/rsyslog.d/
#
\$IncludeConfig /etc/rsyslog.d/*.conf
" >> /tmp/rsyslog.conf

/bin/cp -f /tmp/rsyslog.conf /etc/
service rsyslog restart
}

tune_mongo() {

## Disable hugepage for better mongo performance
HUGEPAGECHECK=$(grep 'kernel/mm/transparent_hugepage/enabled = never' /etc/sysfs.conf)
if [ -z  "$HUGEPAGECHECK" ]; then
	echo -e 'kernel/mm/transparent_hugepage/enabled = never\nkernel/mm/transparent_hugepage/defrag = never' >> /etc/sysfs.conf
	echo 'never' > /sys/kernel/mm/transparent_hugepage/enabled
	echo 'never' > /sys/kernel/mm/transparent_hugepage/defrag
fi

}

install_docker() {
#Docker won't install if openvpn is running with VPNs.  Shutting it off to avoid issues
service openvpn stop

# Check if docker is installed, if not install it
DOCKERCHECK=$(dpkg -l|grep docker-ce)
if [ -z "$DOCKERCHECK" ]; then
    echo "Installing Docker-CE"
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
    sudo add-apt-repository \
   "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
   $(lsb_release -cs) \
   stable"
    apt-get update -y
    apt-get install -y docker-ce
    curl -L https://github.com/docker/compose/releases/download/1.19.0/docker-compose-`uname -s`-`uname -m` -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
fi

## Docker containers for DBs is probably a bad idea, don't use this for prod deployments?
echo "Setting up Docker networks and containers if they don't already exist"
mkdir -p "${DOCKER_MONGO_DIR}/db"
mkdir -p "${DOCKER_MONGO_DIR}/etc"
mkdir -p "${DOCKER_ELASTIC_DIR}"
mkdir -p "${DOCKER_MISP_DIR}"
mkdir -p "${DOCKER_MISP_BACKUP_DIR}"
mkdir -p "${DOCKER_MYSQL_DIR}"
mkdir -p "${DOCKER_MYSQL_CONF}"
/bin/cp -f "mysql/mysqld.cnf" "${DOCKER_MYSQL_CONF}"
chown -R 999.999 ${DOCKER_MYSQL_CONF}
chown -R 999.999 ${DOCKER_MYSQL_DIR}
chown -R 1000.1000 ${DOCKER_ELASTIC_DIR}

## pre-make Grafana folder - change this to named volume later
mkdir -p $DOCKER_GRAFANA_DIR
chown -R 472.472 $DOCKER_GRAFANA_DIR

## Stage your mongo config and stats
/bin/cp -f "mongodb/mongod.conf" "${DOCKER_MONGO_DIR}/etc"
replace_templates "../utils/mongo_stats.sh"
chmod +x ../utils/mongo_stats.sh

# You could put these on a network if you want to later
# [ ! "$(docker network ls | grep mongo)" ] && docker network create --subnet=${DOCKER_MONGO_NET} mongo
# Right now we're putting all the docker containers in the same network, but you can separate that out if you'd like
#[ ! "$(docker network ls | grep es)" ] && docker network create --subnet=${DOCKER_ELASTIC_NET} es
# check if docker images have already been created, if not it creates them
#sudo [ ! "$(docker ps -a | grep cuckoo-mongo)" ] && docker run --restart always -d --name cuckoo-mongo --net mongo --ip ${DOCKER_MONGO_IP} -p 27017 -v ${DOCKER_MONGO_DIR}/db:/data/db -v ${DOCKER_MONGO_DIR}/etc/mongod.conf:/etc/mongod.conf mongo
#sudo [ ! "$(docker ps -a | grep cuckoo-elastic)" ] && docker run --restart always -d --name cuckoo-elastic --net mongo --ip ${DOCKER_ELASTIC_IP} -p 9200 -p 9300 -v ${DOCKER_ELASTIC_DIR}:/data/elastic -e "discovery.type=single-node" -e "xpack.security.enabled=false" docker.elastic.co/elasticsearch/elasticsearch:5.6.6
#sudo [ ! "$(docker ps -a | grep cuckoo-mysql)" ] && docker run --restart always -d --name cuckoo-mysql --net mongo --ip ${DOCKER_MYSQL_IP} -p 3306 -e MYSQL_USER=${CUCKOO_USER} -e MYSQL_PASSWORD=${DOCKER_MYSQL_PASSWORD} -e MYSQL_DATABASE=${DOCKER_MYSQL_DATABASE} -e MYSQL_ROOT_PASSWORD=${DOCKER_MYSQL_ROOT_PASSWORD} -v ${DOCKER_MYSQL_DIR}:/data/mysql  mysql:5.7

#sudo [ ! "$(docker ps -a | grep cuckoo-mongo)" ] && docker run --restart always -d --name cuckoo-mongo -p ${DOCKER_MONGO_IP}:27017:27017 -v ${DOCKER_MONGO_DIR}/db:/data/db -v ${DOCKER_MONGO_DIR}/etc/mongod.conf:/etc/mongod.conf mongo
#sudo [ ! "$(docker ps -a | grep cuckoo-elastic)" ] && docker run --restart always -d --name cuckoo-elastic -p ${DOCKER_ELASTIC_IP}:9200:9200 -p ${DOCKER_ELASTIC_IP}:9300:9300 -v ${DOCKER_ELASTIC_DIR}:/data/elastic -e "discovery.type=single-node" -e "xpack.security.enabled=false" docker.elastic.co/elasticsearch/elasticsearch:5.6.6
#sudo [ ! "$(docker ps -a | grep cuckoo-mysql)" ] && docker run --restart always -d --name cuckoo-mysql -p ${DOCKER_MYSQL_IP}:3306:3306 -e MYSQL_USER=${CUCKOO_USER} -e MYSQL_PASSWORD=${DOCKER_MYSQL_PASSWORD} -e MYSQL_DATABASE=${DOCKER_MYSQL_DATABASE} -e MYSQL_ROOT_PASSWORD=${DOCKER_MYSQL_ROOT_PASSWORD} -v ${DOCKER_MYSQL_DIR}:/data/mysql  mysql:5.7

## Setup the MISP docker container
LOCALDIR=$PWD
#git clone https://github.com/harvard-itsecurity/docker-misp.git
cd docker-misp
docker rmi harvarditsecurity/misp
docker build \
    --rm=true --force-rm=true \
    --build-arg MYSQL_MISP_PASSWORD=sdiofj09wej09fwjef9020932j0 \
    --build-arg POSTFIX_RELAY_HOST=$DOCKER_POSTFIX_HOST \
    --build-arg MISP_FQDN=$DOCKER_MISP_FQDN \
    --build-arg MISP_EMAIL=$EMAIL \
    -t harvarditsecurity/misp container
cd $LOCALDIR

/bin/cp -f docker/docker-compose.yml ../docker/
replace_templates "../docker/docker-compose.yml"
docker run --rm -v $DOCKER_MISP_DIR:/var/lib/mysql harvarditsecurity/misp /init-db
docker-compose  -f ../docker/docker-compose.yml up -d
}

configure_es() {
## Wait for ES to come up
sleep 30

## Start DB monitoring
touch /var/log/cuckoo/rooter.log

## Adding elasticsearch templates
echo "Adding elasticsearch templates"
ESTEMPLATECHECK=$(curl ${DOCKER_ELASTIC_IP}:9200/_template/hunt 2>/dev/null|grep '\"template\":\"hunt-\*\"')
if [ -z "${ESTEMPLATECHECK}" ]; then
    ls docker/elastic/*.template|awk -F '/' '{print $NF}'|while read line; do
        TN=$(echo $line|awk -F '.template' '{print $1}')
        curl -XPUT "${DOCKER_ELASTIC_IP}:9200/_template/$TN" -d "$(cat docker/elastic/$TN.template)"
    done
fi

/bin/cp -f elasticsearch2elastic.py ../utils
replace_templates "../utils/elasticsearch2elastic.py"

}

import_kibana() {
## Check for node, used to import kibana dashboards
NODECHECK=$(dpkg -l|grep npm)
if [ -z "$NODECHECK" ]; then
    curl -sL https://deb.nodesource.com/setup_10.x | sudo -E bash -
    apt-get install -y nodejs
    npm install elasticdump -g

## Note to self, if you ever want to create elaborate dashboards and then package them up for initial boot, this would be how
    elasticdump \
  --input=kibana/kibana_mapping.json \
  --output=http://$DOCKER_ELASTIC_IP:9200/.kibana \
  --type=mapping
    elasticdump \
  --input=kibana/kibana_data.json \
  --output=http://$DOCKER_ELASTIC_IP:9200/.kibana \
  --type=data

## I thought i might have needed to manually make kibana recognize the indexes again.  The dump from a running kibana works perfectly though
#curl -XPUT http://$DOCKER_ELASTIC_IP:9200/.kibana/index-pattern/cuckoo-* -d '{"title" : "cuckoo-*",  "timeFieldName": "time"}'
#sleep 5
#curl -XPUT http://$DOCKER_ELASTIC_IP:9200/.kibana/index-pattern/docker-* -d '{"title" : "docker-*",  "timeFieldName": #"@timestamp"}'
#sleep 5
#curl -XPUT http://$DOCKER_ELASTIC_IP:9200/.kibana/index-pattern/fail2ban-* -d '{"title" : "fail2ban-*",  "timeFieldName": #"@timestamp"}'
#sleep 5
#curl -XPUT http://$DOCKER_ELASTIC_IP:9200/.kibana/index-pattern/apache2-* -d '{"title" : "apache2-*",  "timeFieldName": "Timestamp"}'
#sleep 5
#curl -XPUT http://$DOCKER_ELASTIC_IP:9200/.kibana/index-pattern/linux-* -d '{"title" : "linux-*",  "timeFieldName": "@timestamp"}'
fi
}

setup_iptables() {
# Setup iptables
if [ -z $(iptables -nL|grep 'IPTABLES-INPUT-CHAIN') ]; then
    service netfilter-persistent start
    iptables -I INPUT -i vboxnet0 -p tcp -m state --state NEW -m tcp --dport 2042 -j ACCEPT
    iptables -I INPUT -s 127.0.0.1 -d 127.0.0.1 -p tcp -m state --state NEW -m tcp --dport 8090 -j ACCEPT
    iptables -I INPUT -s 127.0.0.1 -d 127.0.0.1 -p tcp -m state --state NEW -m tcp --dport 8000 -j ACCEPT
    iptables -I INPUT -i lo -j ACCEPT
    iptables -I INPUT -p tcp -m state --state NEW -m tcp --dport 8005 -j ACCEPT
    iptables -I INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
    iptables -I INPUT -p tcp -m state --state NEW -m tcp --dport 80 -j ACCEPT
    iptables -I INPUT -p tcp -m state --state NEW -m tcp --dport 443 -j ACCEPT
    iptables -I INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -I INPUT -m limit --limit 1/sec -j LOG --log-prefix "IPTABLES-INPUT-CHAIN-TOP|" --log-level 7
    iptables -A INPUT -m limit --limit 1/sec -j LOG --log-prefix "IPTABLES-INPUT-CHAIN-DROPPED|" --log-level 7
    iptables -A INPUT -j DROP
## Even... more... grease...
## This stops the DBs from listening on external interfaces
    grep iface /etc/network/interfaces|grep -v 'lo'|awk '{print $2}'|while read myint; do
        for i in 9200 9300 3306 27017; do
	        iptables -I FORWARD -i "$myint" -p tcp -m state --state NEW -m tcp --dport "$i" -j DROP
        done
    done
## Only allow your docker bridge interfaces to hit the DBs
    iptables -I FORWARD ! -s $DOCKER_MONGO_NET -p tcp -m tcp --dport 3306 -j DROP
    iptables -I FORWARD ! -s $DOCKER_MONGO_NET -p tcp -m tcp --dport 9200 -j DROP
    iptables -I FORWARD ! -s $DOCKER_MONGO_NET -p tcp -m tcp --dport 9300 -j DROP
    iptables -I FORWARD ! -s $DOCKER_MONGO_NET -p tcp -m tcp --dport 27017 -j DROP
    iptables -I FORWARD -m limit --limit 1/sec -j LOG --log-prefix "IPTABLES-FORWARD-CHAIN-TOP|" --log-level 7
    iptables -A FORWARD -m limit --limit 1/sec -j LOG --log-prefix "IPTABLES-FORWARD-CHAIN-DROPPED|" --log-level 7
    iptables -A FORWARD -j DROP
    invoke-rc.d netfilter-persistent save
fi
}

import_grafana() {
## Stop grafana to load dashboards
## TODO: make this idempotent
docker-compose -f  ../docker/docker-compose.yml stop phoenix-grafana
echo "INSERT INTO 'api_key' (id, org_id, name, key, role, created, updated) VALUES(2,1,'adminkey','fccbfcdb23dc238ea6c62697ffe214fe2e628d639f339ea70169df1f430ad0c32353cf90883e64ee5b1dae488ce3d2ba9261','Admin','2018-07-28 18:41:42','2018-07-28 18:41:42');" | sqlite3 ${DOCKER_GRAFANA_DIR}/grafana.db
docker-compose -f ../docker/docker-compose.yml start phoenix-grafana
echo "Waiting 45 s for Grafana to settle"
sleep 45
python2.7 docker/grafana/configure_grafana.py $DOCKER_GRAFANA_IP $DOCKER_ELASTIC_IP
}

setup_virtualbox() {
## Get VirtualBox and set it up
VBOXCHECK=$(dpkg -l|grep virtualbox-5.2)
if [ -z "$VBOXCHECK" ]; then
    echo "Installing VirtualBox"
    echo 'deb http://download.virtualbox.org/virtualbox/debian xenial contrib' >> /etc/apt/sources.list
    wget -q https://www.virtualbox.org/download/oracle_vbox_2016.asc -O- | sudo apt-key add -
    wget -q https://www.virtualbox.org/download/oracle_vbox.asc -O- | sudo apt-key add -
    sudo apt-get update -y
    sudo apt-get install -y virtualbox-6.0
    ##TODO - don't greasily hard code virtualbox extension packs in an installer you infantile pillock
    wget "https://download.virtualbox.org/virtualbox/6.0.8/Oracle_VM_VirtualBox_Extension_Pack-6.0.8.vbox-extpack"
    echo y | vboxmanage extpack install Oracle_VM_VirtualBox_Extension_Pack-6.0.8.vbox-extpack
fi

# Setup the VM network, where your host will act as a default gateway for the guest VMs
VMINTCHECK=$(ifconfig -a|grep ${SANDINT})
if [ -z ${VMINTCHECK} ]; then
    echo "Adding host interface"
    vboxmanage hostonlyif create
# If you set the IP for your SANDINT as root, then every time your box runs 'vboxheadless' your vboxnet0 IP will revert back to 192.168.56.1
## Many, many hours lost here
    su - $CUCKOO_USER -c "vboxmanage hostonlyif ipconfig $SANDINT --ip $SANDIP --netmask 255.255.255.0"
fi
}

setup_rclocal() {
## BUG - This didn't work sed-fu no good
## Greasy... Setup your rc.local...
cp /etc/rc.local temp.local
sed -i '/#CUCKOOLOCALS/,/#ENDCUCKOOLOCALS/d' temp.local
cat rc.local_template >> temp.local
replace_templates "temp.local"
/bin/cp -f temp.local /etc/rc.local
sed -i 's/exit 0//g' /etc/rc.local
tail -n 2 /etc/rc.local|head -n 1 > /tmp/start_es_monitoring.sh
bash /tmp/start_es_monitoring.sh && rm -f /tmp/start_es_monitoring.sh
}

add_cuckoo_user() {
## Add the cuckoo user
id -u ${CUCKOO_USER}
if [ $? -eq 1 ]; then
    echo "##### Adding local *NIX user to run Phoenix - ${CUCKOO_USER} #####"+${CUCKOO_USER}
    adduser "${CUCKOO_USER}" --gecos "" --disabled-password
    if [ ! -d "$VMSTORAGE" ]; then
        mkdir -p $VMSTORAGE
        chown -R $CUCKOO_USER.$CUCKOO_USER $VMSTORAGE
    fi
fi
chown -R "${CUCKOO_USER}.${CUCKOO_USER}" "${CUCKOODIR}"
}

setup_fail2ban() {
## Setup Fail2Ban
echo "##### Setting Fail2Ban to drop #####"
sed -i 's/blocktype =.*/blocktype = DROP/g' /etc/fail2ban/action.d/iptables-common.conf
}

setup_certificates() {
## It's certificate time
if [ ! -f /etc/pki/tls/private/$HOSTNAME.key ]; then
    echo "##### Setting up certificates #####"
    openssl genrsa -out ca.key 8192

## Generate CSR
    openssl req -new -key ca.key -out ca.csr -subj "/C=$COUNTRY/ST=$STATE/L=$LOCALE/O=$ORG_NAME/OU=$BUSINESSUNIT/CN=$PHOENIX_HOSTNAME" -config <(
    cat <<-EOF
[req]
default_bits = 8192
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[ dn ]
C=$COUNTRY
ST=$STATE
L=$LOCALE
O=$ORG_NAME
OU=$BUSINESSUNIT
emailAddress=$EMAIL
CN=$PHOENIX_HOSTNAME

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = misp.$PHOENIX_HOSTNAME
DNS.2 = moloch.$PHOENIX_HOSTNAME
DNS.3 = grafana.$PHOENIX_HOSTNAME
DNS.4 = kibana.$PHOENIX_HOSTNAME
EOF
)

## Generate Self Signed Key
    openssl x509 -req -days 730 -in ca.csr -signkey ca.key -out ca.crt

## Copy the files to the correct locations
    mkdir -p /etc/pki/tls/certs
    mkdir -p /etc/pki/tls/private
    cp ca.crt /etc/pki/tls/certs
    cp ca.key /etc/pki/tls/private/$HOSTNAME.key
    cp ca.csr /etc/pki/tls/private/$HOSTNAME.csr
fi
}

setup_apache2() {
## Add admin apache2 account
htpasswd -b -c /etc/apache2/.admin_htpasswd "$APACHE2_ADMIN_USER" "$APACHE2_ADMIN_PASS"
htpasswd -b -c /etc/apache2/.cuckoo "$APACHE2_ADMIN_USER" "$APACHE2_ADMIN_PASS"

##TODO this is not tested yet
## If you use our configuration you have to maintain your backend cuckooweb port in httpd/cuckoo.conf
## Default is 127.0.0.1:8000
echo "##### Setting up apache2 #####"
/bin/cp -f httpd/*.* /etc/apache2/conf-enabled/
sed -i "s/EMAIL_REPLACE/${EMAIL}/g" /etc/apache2/conf-enabled/cuckoo.conf
sed -i "s/HOSTNAME_REPLACE/${HOSTNAME}/g" /etc/apache2/conf-enabled/cuckoo.conf

sed -i "s/HOSTNAME_REPLACE/${HOSTNAME}/g" /etc/apache2/conf-enabled/rev_proxy.conf
sed -i "s/HOSTPATH/${PHOENIX_HOSTNAME}/g" /etc/apache2/conf-enabled/rev_proxy.conf

## Disable standard http
sed -i "s/Listen 80/#Listen 80/g" /etc/apache2/ports.conf
mkdir -p /var/log/apache2/cuckoo
sudo a2enmod rewrite
sudo a2enmod proxy
service apache2 restart
touch /etc/apache2/.cuckoo
}

setup_cuckoo_daemons() {
echo "##### Setting up cuckoo daemons #####"
## Adding init.d scripts to start cuckoo at system start
cp init.d/* /etc/init.d/
chmod +x /etc/init.d/cuckoo*
## Replace initd scripts with build details
replace_templates "/etc/init.d/cuckoo*"

## Push cuckoo config files
/bin/cp -rf ${CUCKOODIR}/install/conf/* ${CUCKOODIR}/conf
replace_templates "${CUCKOODIR}/conf/*"

##TODO remove /etc/init.d/functions from init.d scripts
touch /etc/init.d/functions
}

setup_mongo(){
docker-compose -f ../docker/docker-compose.yml exec -T phoenix-mongo sh -c "mongo cuckoo --eval \"db.analysis.createIndex({'info.ended':-1})\""
docker-compose -f ../docker/docker-compose.yml exec -T phoenix-mongo sh -c "mongo cuckoo --eval \"db.analysis.createIndex({'info.id':1})\""
docker-compose -f ../docker/docker-compose.yml exec -T phoenix-mongo sh -c "mongo cuckoo --eval \"db.analysis.createIndex({'info.started':1})\""
docker-compose -f ../docker/docker-compose.yml exec -T phoenix-mongo sh -c "mongo cuckoo --eval \"db.analysis.createIndex({'target.category':1})\""
docker-compose -f ../docker/docker-compose.yml exec -T phoenix-mongo sh -c "mongo cuckoo --eval \"db.analysis.createIndex({'procmemory.extracted.sha1':-1})\""
docker-compose -f ../docker/docker-compose.yml exec -T phoenix-mongo sh -c "mongo cuckoo --eval \"db.analysis.createIndex({'procmemory.extracted.sha1':1})\""
docker-compose -f ../docker/docker-compose.yml exec -T phoenix-mongo sh -c "mongo cuckoo --eval \"db.analysis.createIndex({'network.http_ex.sha1':1})\""
docker-compose -f ../docker/docker-compose.yml exec -T phoenix-mongo sh -c "mongo cuckoo --eval \"db.analysis.createIndex({'network.https_ex.sha1':1})\""
docker-compose -f ../docker/docker-compose.yml exec -T phoenix-mongo sh -c "mongo cuckoo --eval \"db.analysis.createIndex({'network.http_ex.md5':1})\""
docker-compose -f ../docker/docker-compose.yml exec -T phoenix-mongo sh -c "mongo cuckoo --eval \"db.analysis.createIndex({'network.https_ex.md5':1})\""
docker-compose -f ../docker/docker-compose.yml exec -T phoenix-mongo sh -c "mongo cuckoo --eval \"db.analysis.createIndex({'procmemory.extracted.sha256':1})\""
docker-compose -f ../docker/docker-compose.yml exec -T phoenix-mongo sh -c "mongo cuckoo --eval \"db.analysis.createIndex({'target.file.sha256':1})\""
docker-compose -f ../docker/docker-compose.yml exec -T phoenix-mongo sh -c "mongo cuckoo --eval \"db.analysis.createIndex({'dropped.sha256':1})\""
docker-compose -f ../docker/docker-compose.yml exec -T phoenix-mongo sh -c "mongo cuckoo --eval \"db.analysis.createIndex({'info.tlp':1})\""
docker-compose -f ../docker/docker-compose.yml exec -T phoenix-mongo sh -c "mongo cuckoo --eval \"db.analysis.createIndex({'info.owner':1})\""
docker-compose -f ../docker/docker-compose.yml exec -T phoenix-mongo sh -c "mongo cuckoo --eval \"db.analysis.createIndex({'info.started':1})\""
docker-compose -f ../docker/docker-compose.yml exec -T phoenix-mongo sh -c "mongo cuckoo --eval \"db.analysis.createIndex({'network.dns.request':1})\""
docker-compose -f ../docker/docker-compose.yml exec -T phoenix-mongo sh -c "mongo cuckoo --eval \"db.analysis.createIndex({'network.http_ex.host':1})\""
docker-compose -f ../docker/docker-compose.yml exec -T phoenix-mongo sh -c "mongo cuckoo --eval \"db.analysis.createIndex({'network.https_ex.host':1})\""
docker-compose -f ../docker/docker-compose.yml exec -T phoenix-mongo sh -c "mongo cuckoo --eval \"db.analysis.createIndex({'target.file.sha1':1})\""
docker-compose -f ../docker/docker-compose.yml exec -T phoenix-mongo sh -c "mongo cuckoo --eval \"db.analysis.createIndex({'network.domains.domain':1})\""
}

setup_moloch() {
echo "##### Setting up Moloch #####"
## Download and install moloch
MOLOCHCHECK=$(dpkg -l|grep moloch)
if [ -z "$MOLOCHCHECK" ]; then
    echo "##### Downloading Moloch ######"
    wget "https://files.molo.ch/builds/ubuntu-16.04/moloch_0.50.0-1_amd64.deb"
    dpkg -i moloch_0.50.0-1_amd64.deb

## Install certificates
    sed -i 's/MOLOCH_LOCALELASTICSEARCH=not-set//' /data/moloch/bin/Configure
    /data/moloch/bin/Configure
    /bin/cp -f moloch/config.ini /data/moloch/etc/config.ini
    /bin/cp -f /etc/pki/tls/private/$HOSTNAME.key /data/moloch/etc/c.key
    /bin/cp -f /etc/pki/tls/certs/ca.crt /data/moloch/etc/c.crt
    /bin/cp -f moloch/viewer.js /data/moloch/viewer/viewer.js
    wget https://s3-us-west-2.amazonaws.com/phoenix-geoip/GeoIP.dat -P /data/moloch/etc
    wget https://s3-us-west-2.amazonaws.com/phoenix-geoip/GeoIPv6.dat -P /data/moloch/etc
    wget https://s3-us-west-2.amazonaws.com/phoenix-geoip/GeoIPASNumv6.dat -P /data/moloch/etc
    wget https://s3-us-west-2.amazonaws.com/phoenix-geoip/GeoIPASNum.dat -P /data/moloch/etc
    replace_templates "/data/moloch/etc/config.ini"
##TODO - degrease this...
    sed -i "s/REPLACE_MOLOCH_PASSWORD/${MOLOCHS2SPW}/g" /data/moloch/etc/config.ini
    sed -i 's/# certFile.*/certFile=\/data\/moloch\/etc\/c.crt/g' /data/moloch/etc/config.ini
    sed -i 's/# keyFile.*/keyFile=\/data\/moloch\/etc\/c.key/g' /data/moloch/etc/config.ini
    sed -i 's/\[default\]/\[default\]\nreadTruncatedPackets = true/g' /data/moloch/etc/config.ini
## Initialize moloch ES db & update geo
    perl /data/moloch/db/db.pl ${DOCKER_ELASTIC_IP}:9200 init

##TODO: Supersede with setup_user.py
    /data/moloch/bin/moloch_add_user.sh ${MOLOCH_USER} "Admin User" ${MOLOCH_PASSWORD} --admin

## Grease...Grease everywhere
    LOCALDIR=$PWD
    cd /data/moloch/viewer
    ../bin/node ../bin/npm install request
    ../bin/node ../bin/npm install sync-promise
    cd $LOCALDIR
fi
}

setup_misp() {
##TODO migrate this to a localhost socket
echo "##### Setting up MISP #####"
MISP_COMMAND_1="mysql misp -se \"GRANT ALL PRIVILEGES on misp.* to \\\"$DOCKER_MISP_MYSQL_USER\\\"@\\\"172.18.1.1\\\"  IDENTIFIED BY \\\"$DOCKER_MISP_MYSQL_PASSWORD\\\";\""
MISP_COMMAND_2="sed -i 's/127.0.0.1/0.0.0.0/g' /etc/mysql/mariadb.conf.d/50-server.cnf"
docker-compose -f ../docker/docker-compose.yml exec -T phoenix-misp sh -c "$MISP_COMMAND_1"
docker-compose -f ../docker/docker-compose.yml exec -T phoenix-misp sh -c "$MISP_COMMAND_2"
docker-compose -f ../docker/docker-compose.yml restart phoenix-misp
}

install_vms() {
echo "##### Installing OVAs/VMs #####"
## Setting up VirtualBox VMs
## If set, move where you keep the VMs (for IOPS)
if [ -d "$VMSTORAGE" ]; then
    VBOXDIR="$VMSTORAGE"
    su - $CUCKOO_USER -c "vboxmanage setproperty machinefolder $VMSTORAGE"
    chown -R $CUCKOO_USER.$CUCKOO_USER $VMSTORAGE
else
    VBOXDIR=$(su - $CUCKOO_USER -c "vboxmanage list systemproperties|grep \"Default machine folder:\"|awk -F 'Default machine folder:' '{print $2}'|sed -e 's/^          //g'")
fi
MYDIR=$PWD
## This tarball should be created by going to a vbox parent directory and doing 'tar -cpzf VirtualBox\ VMs'
TARBALL=$(ls $MYDIR/virtualbox/*.tar.gz 2>/dev/null|wc -l)
if [ "$TARBALL" == 1 ]; then
    echo "##### Found a tarball in the vbox_templates directory. Untarring... #####"
    ls $MYDIR/virtualbox/*.tar.gz|head -n 1 | while read mytar; do cd $VBOXDIR ; tar -xvzf "$mytar"; done
    chown -R $CUCKOO_USER.$CUCKOO_USER $VBOXDIR
    find $VBOXDIR|grep "\.vbox$"|while read vbox; do echo "vboxmanage registervm \"${vbox}\"" >> /home/$CUCKOO_USER/register_vms.sh ; done
    su - $CUCKOO_USER -c "bash /home/$CUCKOO_USER/register_vms.sh"
    cd $MYDIR
fi

}

setup_crontab() {
echo "##### Setting up crontab #####"
## Editing Crontab
/bin/cp -rf ${CUCKOODIR}/install/crontab/scripts/ ${CUCKOODIR}/utils/crontab/
chmod +x ${CUCKOODIR}/utils/crontab/*/*.sh

## Replacing variables in crontab files for both users
for file in  $(find ${CUCKOODIR}/utils/crontab/*|grep sh); do
    replace_templates "${file}"
done

## Ensuring cuckoo can't put jobs in root's cron
chown -R root.root ${CUCKOODIR}/utils/crontab/root

## More templating and adding crons
edit_crontab "crontab/crontab_root.template" "root"
edit_crontab "crontab/crontab.template" "${CUCKOO_USER}"
}

setup_openvpn() {
echo "##### Setting up OpenVPN #####"
## Copy openvpn configs to openvpn folder
if ! ls "${OPENVPN}/*.conf" >> /dev/null 2>&1; then
    cp openvpn/* "${OPENVPN}"/
    update-rc.d openvpn defaults
    echo -e "[vpn]\nenabled = no\n" > $CUCKOODIR/conf/vpn.conf
    echo "vpns = $(ls openvpn/*.conf|sed 's/\.conf//g'|tr '\n' ','|sed 's/openvpn\///g'|sed 's/.$//g')" >> $CUCKOODIR/conf/vpn.conf
    VPNARRAY=$(grep dev openvpn/*.conf|awk '{print $NF}'|tr '\n' ' '|sed 's/.$//g')
    sed -i "s/REPLACEVPNS/\"$VPNARRAY\"/g" "$CUCKOODIR/utils/crontab/root/openvpn_route.sh"
    echo '#
# reserved values
#
255     local
254     main
253     default
0       unspec' > /etc/iproute2/rt_tables
    VPNCOUNTER=2
    ls openvpn/*.conf|while read vpnfile; do
        VPNNAME=$(echo $vpnfile|sed 's/\.conf//g'|sed 's/openvpn\///g')
        VPNDEV=$(grep dev $vpnfile|awk '{print $NF}')
        # Assign your VPN adapter to cuckoo's VPN config file
        echo "[${VPNNAME}]" >> $CUCKOODIR/conf/vpn.conf
        echo "name = ${VPNNAME}" >> $CUCKOODIR/conf/vpn.conf
        echo "description = ${VPNNAME}" >> $CUCKOODIR/conf/vpn.conf
        echo "interface = ${VPNDEV}" >> $CUCKOODIR/conf/vpn.conf
        echo "rt_table = ${VPNDEV}" >> $CUCKOODIR/conf/vpn.conf
        # Build your routing table files for iproute2
        echo "$VPNCOUNTER   ${VPNDEV}" >> /etc/iproute2/rt_tables
        VPNCOUNTER=$((VPNCOUNTER + 1))
    done
fi

## Start up openvpn
service openvpn start
echo "##### Waiting for openvpn tunnels to be up for sure... #####"
echo "##### A lot of stuff that follows is dependent on it   #####"
echo "##### (cuckooweb, cuckoorooter, cuckood, etc.          #####"
sleep 30
}

configure_cuckoo() {

echo "##### Configuring Cuckoo #####"
/etc/init.d/cuckoorooter start
sleep 10

## Make logging dir
mkdir -p /var/log/cuckoo
chown -R $CUCKOO_USER.$CUCKOO_USER /var/log/cuckoo

## Update cuckoo bins and sigs
python ../utils/community.py -waf

## Update cuckoo web db
/etc/init.d/cuckoorooter restart
#try and apply auth first
python ../web/manage.py migrate auth
python ../web/manage.py makemigrations auth
python ../web/manage.py migrate auth
python ../web/manage.py makemigrations
python ../web/manage.py migrate

## Superseded by setup_user.py
## echo "Create Django superuser"
#python ../web/manage.py createsuperuser
echo "from django.contrib.auth import get_user_model; User = get_user_model(); User.objects.create_superuser('$DJANGO_USER', '$EMAIL', '$DJANGO_PASSWORD')" | python ../web/manage.py shell
# TODO: Future
#python ../utils/setup_user.py -e ${EMAIL} > pw.txt

echo "##### Initialize Yara rules #####"
if [ ! -d "${CUCKOODIR}/data/yara/rules/external" ];then
    mkdir -p "${CUCKOODIR}/data/yara/rules/external"
    git clone https://github.com/Yara-Rules/rules.git ${CUCKOODIR}/data/yara/rules/external
else
    git -C ${CUCKOODIR}/data/yara/rules/external pull
fi

## Chown yara rules after pulling them
chown -R $CUCKOO_USER.$CUCKOO_USER ${CUCKOODIR}/data/yara
}

setup_tcpdump() {
echo "##### Configuring tcpdump #####"
service molochviewer start
systemctl enable molochviewer
#aa-disable /usr/sbin/tcpdump
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
#../utils/crontab/cuckoo_full_restart.sh
## If you end up running your root filesystem on something that doesn't have extended attributes, you can do this insecurely like:
chmod +s /usr/sbin/tcpdump
## Not recommended...
}

configure_hunt_containers() {
# Add cuckoo user to docker group
if [ -z $(getent group docker|grep $CUCKOO_USER) ]; then
    usermod -aG docker $CUCKOO_USER
fi

#Build the hunting containers
if [ -z $(docker ps -a|grep prodyara) ]; then
    mkdir -p $CUCKOODIR/docker/yara  && docker build -t prodyara $CUCKOODIR/docker/yara
fi
if [ -z $(docker ps -a|grep prodsuri) ]; then
    mkdir -p $CUCKOODIR/docker/suricata  && docker build -t prodsuricata $CUCKOODIR/docker/suricata
fi

}

setup_netdata() {
## Install netdata
echo "##### Installing netdata for system monitoring #####"

git clone https://github.com/firehol/netdata.git --depth=1 /tmp/netdata
LOCALDIR=$PWD
cd /tmp/netdata
bash netdata-installer.sh --dont-wait --install /opt
sed -i 's/.*# bind to = .*/\tbind to = 127.0.0.1/g' /opt/netdata/etc/netdata/netdata.conf
systemctl enable netdata
service netdata restart
cd ${LOCALDIR}
}

start_es_monitoring() {
## Install es monitoring
echo "##### Starting ES Monitoring #####"
    if [ -z "$(ps -ef|grep elasticsearch2elastic.py|grep -v grep)" ]; then
    ## We were waiting until the user was created to start monitoring ES
        su - $CUCKOO_USER -c "python2.7 $CUCKOODIR/utils/elasticsearch2elastic.py > /dev/null &"
    fi
}

setup_storage() {
## Setup spinning disk storage
echo "##### Setting up storage #####"
    if [ -n "$PHOENIXSTORAGE" ]; then
        if [ ! -d "$PHOENIXSTORAGE" ]; then
            mkdir -p "$PHOENIXSTORAGE"
        fi
            mv "$CUCKOODIR/storage" "$PHOENIXSTORAGE"
            if [ ! -d "$PHOENIXSTORAGE/storage" ]; then
                mkdir -p "$PHOENIXSTORAGE/storage"
            fi
            ln -s "$PHOENIXSTORAGE/storage" "$CUCKOODIR/storage"
            chown -R $CUCKOO_USER.$CUCKOO_USER "$PHOENIXSTORAGE"
            chown -R $CUCKOO_USER.$CUCKOO_USER "$CUCKOODIR"
    fi
}

hosts_file() {
    OUTSIDE_INT=$(route | grep '^default'|grep 0.0.0.0|awk '{print $NF}')
}

update_db_check(){
UPDATEDBCHECK=$(grep cuckoo /etc/updatedb.conf)
echo $UPDATEDBCHECK
if [ -z "$UPDATEDBCHECK" ]; then
        sed -i "s/\(PRUNEPATHS.*\).$/\1 $MLOCATE_DIRECTORIES_TO_IGNORE \"/g" /etc/updatedb.conf
fi
}
## Sometimes you don't know how much work goes into a system until you actually document how it works...
## This is essentially how the install script breaks everything down:

update_packages
setup_rsyslog
tune_mongo
install_docker
configure_es
import_kibana
setup_iptables
import_grafana
setup_virtualbox
setup_rclocal
add_cuckoo_user
setup_fail2ban
setup_certificates
setup_apache2
setup_cuckoo_daemons
setup_mongo
setup_moloch
setup_misp
install_vms
setup_crontab
setup_openvpn
configure_cuckoo
setup_tcpdump
configure_hunt_containers
setup_netdata
start_es_monitoring
setup_storage
hosts_file
update_db_check

echo "########################## FINISHED INSTALLING #########################"
echo "########################################################################"
echo "#"
echo "#                                             ...."
echo "#.                                        ,,,,."
echo "#.                                   .,,,,,"
echo "#..                              .,,,,,."
echo "# ..                         ,,,,,,,."
echo "# ...                   .,,,,,,,."
echo "#  ...              ,,,,,,,,,."
echo "#  ....        .,,,,,,,,,,       Follow the Post-Install instructions  "
echo "#   ....      .,,,,,,,.          in the README.md. "
echo "#   .....     ,,,,,              The following services are setup: "
echo "#    .....    ,,,,,              https://$PHOENIX_HOSTNAME "
echo "#              ,,,,              https://netdata.$PHOENIX_HOSTNAME"
echo "#   ,,,,        ,,,.             https://grafana.$PHOENIX_HOSTNAME"
echo "# ,,,,,    ..   .,,.             https://kibana.$PHOENIX_HOSTNAME"
echo "#,,       ....   .,.             https://misp.$PHOENIX_HOSTNAME"
echo "#        .....    .,             https://moloch.$PHOENIX_HOSTNAME"
echo "#       .....      ."
echo "#      ...."
echo "#     ....    /etc/hosts hack:"
echo "#    ...  < $OUTSIDE_INT    $PHOENIX_HOSTNAME netdata.$PHOENIX_HOSTNAME \\"
echo "#  ....     grafana.$PHOENIX_HOSTNAME kibana.$PHOENIX_HOSTNAME \\"
echo "# ...       misp.$PHOENIX_HOSTNAME moloch.$PHOENIX_HOSTNAME >"
echo "#"
echo "########################################################################"

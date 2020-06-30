#!/bin/bash
# syntax: $0 <node> <ip> <port> <service-id> <service>
# 1) deploy service on $NODE
# 2) add $SERVICE_IP to loopback of $NODE
# 3) start http server on $NODE listening on $SERVICE_IP:$SERVICE_PORT (tcp)

NODE=$1
IP=$2
PORT=$3
SERVICE_ID=$4
SERVICE=$5

#VERBOSE="1"

if [ "${VERBOSE}" ]; then
    echo -e "\nSERVICE(${SERVICE_ID}).START : NODE='${NODE}' IP='${IP}' PORT='${PORT}' SERVICE_ID='${SERVICE_ID}' SERVICE='${SERVICE}'"
fi

STEPS=5

. common.cfg

echo -e "\n==============================================="
echo "# SERVICE(${SERVICE_ID}).START[1/${STEPS}] : Check input"

CHECK=`sudo docker ps | awk '{print $NF}' | grep "${NODE}"`
if [ ! "${CHECK}" ] ; then
    echo "Docker '${NODE}' : NOT running!"
    exit 1
else
    echo "Docker '${NODE}' : OK"
fi

if [ ! -x "./${SERVICE}_start.sh" ] ; then
    echo "./${SERVICE}_start.sh : NOT available."
    exit 1
else
    echo "./${SERVICE}_start.sh : OK"
fi

echo -e "\n==============================================="
echo "# SERVICE(${SERVICE_ID}).START [2/${STEPS}] : Check service is available on '${NODE}'"

# check basic structure
CHECK=`docker exec -it ${NODE} bash -c "ls ${SERVICE_DIR}" | grep -v "No such file or directory"`
if [ ! "${CHECK}" ] ; then
##if [ -d "${SERVICE_DIR}" ] ; then
    echo "# Creating '${SERVICE_DIR}'"
    docker exec -it ${NODE} bash -c "mkdir -p ${SERVICE_DIR}"
fi
#docker exec -it ${NODE} bash -c "if [ -d "${SERVICE_DIR}" ] ; then mkdir -p ${SERVICE_DIR} ; fi"

CHECK=`docker exec -it ${NODE} bash -c "ls ${ADDR_DIR}" | grep -v "No such file or directory"`
if [ ! "${CHECK}" ] ; then
#if [ -d "${ADDR_DIR}" ] ; then
    echo "# Creating '${ADDR_DIR}'"
    docker exec -it ${NODE} bash -c "mkdir -p ${ADDR_DIR}"
fi
#docker exec -it ${NODE} bash -c "if [ -d "${ADDR_DIR}" ] ; then mkdir -p ${ADDR_DIR} ; fi"

# check service id
CHECK=`docker exec -it ${NODE} bash -c "ls ${SERVICE_DIR}/${SERVICE_ID}" | grep -v "No such file or directory"`
if [ "${CHECK}" ] ; then
#if [ -d "${SERVICE_DIR}/${SERVICE_ID}" ] ; then
    echo "ERROR: Service ID '${SERVICE_ID}' already exists."
    exit 1
fi

# check ip:port
CHECK=`docker exec -it ${NODE} bash -c "ls ${ADDR_DIR}/${IP}/${PORT}" | grep -v "No such file or directory"`
if [ "${CHECK}" ] ; then
#if [ -f "${ADDR_DIR}/${IP}/${PORT}" ] ; then
    echo "ERROR: Combination '${IP}:${PORT}' is already used."
    exit 1
fi

echo -e "\n==============================================="
echo "# SERVICE(${SERVICE_ID}).START [3/${STEPS}] : Create service on '${NODE}'"
# create service record
docker exec -it ${NODE} bash -c "mkdir -p ${SERVICE_DIR}/${SERVICE_ID}"

#docker exec -it ${NODE} bash -c "echo -e \"ID=${SERVICE_ID}\nPROTO=tcp\nIP=${IP}\nPORT=${PORT}\nLOG=${SERVICE_DIR}/${SERVICE_ID}/log\" > ${SERVICE_DIR}/${SERVICE_ID}/info"

# assign IP if not used yet
CHECK=`docker exec -it ${NODE} bash -c "ls ${ADDR_DIR}/${IP}" | grep -v "No such file or directory"`
if [ ! "${CHECK}" ] ; then
#if [ ! -d "${ADDR_DIR}/${IP}" ] ; then
    docker exec -it ${NODE} bash -c "mkdir -p ${ADDR_DIR}/${IP}"
    echo "# Setup service IP ${IP}"
    docker exec -it ${NODE} bash -c "ip addr add ${IP} dev lo"
    docker exec -it ${NODE} bash -c "ip addr"
fi

# create $PORT record
docker exec -it ${NODE} bash -c "touch ${ADDR_DIR}/${IP}/${PORT}"

# check
if [ "${VERBOSE}" ]; then
    echo ""
    docker exec -it ${NODE} bash -c "ls -R ${BASE_DIR}"
fi

echo -e "\n==============================================="
echo "# SERVICE(${SERVICE_ID}).START [4/${STEPS}] : Start service on '${NODE}'"

#                      <node>  <ip>  <port>  <service-id>  <home-dir>
./${SERVICE}_start.sh ${NODE} ${IP} ${PORT} ${SERVICE_ID} ${SERVICE_DIR}/${SERVICE_ID}

if [ -x "./${SERVICE}_check.sh" ] ; then
    echo -e "\n==============================================="
    echo "# SERVICE(${SERVICE_ID}).START [5/${STEPS}] : Check service is running"

    #echo -e "\n==============================================="
    #echo -e "\n### CURL from '${NODE}' to ${IP}:${PORT}"
    # syntax: $0     <docker>  <ip>        <port>
    ./${SERVICE}_check.sh ${NODE} ${IP} ${PORT} ${SERVICE_ID}
    #./test_curl.sh ${IP} ${PORT} ${NODE}
else
    echo "./${SERVICE}_check.sh not awailable for check."
fi

echo -e "\n==============================================="
echo "# SERVICE(${SERVICE_ID}).START : DONE"
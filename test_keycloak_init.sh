#!/usr/bin/env bash

CMD_ARGS=$1
KEYCLOAK_DOCKER_IMAGE="quay.io/keycloak/keycloak:latest"

function keycloak_stop() {
    docker stop unittest_keycloak &> /dev/null
    docker rm unittest_keycloak &> /dev/null
}

function keycloak_start() {
    echo "Starting keycloak docker container"
    docker run -d --name unittest_keycloak -e KEYCLOAK_ADMIN="${KEYCLOAK_ADMIN}" -e KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD}" -p "${KEYCLOAK_PORT}:8080" "${KEYCLOAK_DOCKER_IMAGE}" start-dev
    SECONDS=0
    until curl --silent --output /dev/null localhost:$KEYCLOAK_PORT; do
      sleep 5;
      if [ ${SECONDS} -gt 180 ]; then
        echo "Timeout exceeded";
        exit 1;
      fi
    done
}

# Ensuring that keycloak is stopped in case of CTRL-C
trap keycloak_stop err exit

keycloak_stop # In case it did not shut down correctly last time.
keycloak_start

eval ${CMD_ARGS}
docker logs unittest_keycloak > keycloak_test_logs.txt
RETURN_VALUE=$?

exit ${RETURN_VALUE}

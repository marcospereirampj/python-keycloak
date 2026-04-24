#!/usr/bin/env bash

CMD_ARGS=$1
KEYCLOAK_ADMIN="${KEYCLOAK_ADMIN:-admin}"
KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-admin}"
KEYCLOAK_HOST="${KEYCLOAK_HOST:-localhost}"
KEYCLOAK_PORT="${KEYCLOAK_PORT:-8081}"
KEYCLOAK_DOCKER_IMAGE_TAG="${KEYCLOAK_DOCKER_IMAGE_TAG:-latest}"
KEYCLOAK_DOCKER_IMAGE="quay.io/keycloak/keycloak:$KEYCLOAK_DOCKER_IMAGE_TAG"
KEYCLOAK_USE_HTTPS="${KEYCLOAK_USE_HTTPS:-true}"
KEYCLOAK_STARTUP_TIMEOUT="${KEYCLOAK_STARTUP_TIMEOUT:-300}"
KEYCLOAK_CERT_DIR="${KEYCLOAK_CERT_DIR:-.keycloak-certs}"
KEYCLOAK_CERT_FILE="${KEYCLOAK_CERT_DIR}/tls.crt"
KEYCLOAK_KEY_FILE="${KEYCLOAK_CERT_DIR}/tls.key"
export KEYCLOAK_ADMIN KEYCLOAK_ADMIN_PASSWORD KEYCLOAK_HOST KEYCLOAK_PORT
export KEYCLOAK_DOCKER_IMAGE_TAG KEYCLOAK_USE_HTTPS KEYCLOAK_CERT_DIR

function keycloak_stop() {
    if [ "$(docker ps -aq -f name=unittest_keycloak)" ]; then
        docker logs unittest_keycloak >keycloak_test_logs.txt || true
        docker stop unittest_keycloak &>/dev/null || true
        docker rm unittest_keycloak &>/dev/null || true
    fi
}

function keycloak_prepare_tls() {
    if [[ "${KEYCLOAK_USE_HTTPS}" != "true" ]]; then
        return
    fi

    mkdir -p "${KEYCLOAK_CERT_DIR}"
    if [[ ! -f "${KEYCLOAK_CERT_FILE}" || ! -f "${KEYCLOAK_KEY_FILE}" ]]; then
        openssl req -x509 -newkey rsa:2048 -sha256 -days 7 -nodes \
            -subj "/CN=localhost" \
            -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
            -keyout "${KEYCLOAK_KEY_FILE}" \
            -out "${KEYCLOAK_CERT_FILE}"
    fi

    # Keycloak runs as a non-root user in the container, so ensure mounted TLS files
    # are world-readable in CI and local environments.
    chmod 644 "${KEYCLOAK_CERT_FILE}" "${KEYCLOAK_KEY_FILE}"
}

function keycloak_start() {
    echo "Starting keycloak docker container"
    PWD=$(pwd)
    keycloak_prepare_tls
    if [[ "$KEYCLOAK_DOCKER_IMAGE_TAG" == "22.0" || "$KEYCLOAK_DOCKER_IMAGE_TAG" == "23.0" ]]; then
        KEYCLOAK_FEATURES="admin-fine-grained-authz,token-exchange"
    else
        KEYCLOAK_FEATURES="admin-fine-grained-authz:v1,token-exchange:v1"
    fi
    DOCKER_ARGS=(
        -d --name unittest_keycloak
        -e KEYCLOAK_ADMIN="${KEYCLOAK_ADMIN}"
        -e KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD}"
        -e KC_HTTP_ENABLED=true
        -e KC_HOSTNAME=localhost
        -e KC_HOSTNAME_STRICT=false
        -e KC_HOSTNAME_STRICT_HTTPS=false
        -v "${PWD}/tests/providers:/opt/keycloak/providers"
    )
    KEYCLOAK_ARGS=(start-dev --features="${KEYCLOAK_FEATURES}")
    if [[ "${KEYCLOAK_USE_HTTPS}" == "true" ]]; then
        DOCKER_ARGS+=(
            -p "${KEYCLOAK_PORT}:8443"
            -v "${PWD}/${KEYCLOAK_CERT_DIR}:/opt/keycloak/conf/tls"
        )
        KEYCLOAK_ARGS+=(
            --https-certificate-file=/opt/keycloak/conf/tls/tls.crt
            --https-certificate-key-file=/opt/keycloak/conf/tls/tls.key
        )
    else
        DOCKER_ARGS+=(-p "${KEYCLOAK_PORT}:8080")
    fi

    docker run "${DOCKER_ARGS[@]}" "${KEYCLOAK_DOCKER_IMAGE}" "${KEYCLOAK_ARGS[@]}"
    SECONDS=0
    until \
        if [[ "${KEYCLOAK_USE_HTTPS}" == "true" ]]; then
            curl --silent --insecure --output /dev/null "https://localhost:${KEYCLOAK_PORT}"
        else
            curl --silent --output /dev/null "http://localhost:${KEYCLOAK_PORT}"
        fi; do
        if [[ -z "$(docker ps -q -f name=unittest_keycloak)" ]]; then
            echo "Keycloak container exited before readiness check passed"
            docker logs unittest_keycloak | tee keycloak_test_logs.txt || true
            docker ps -a --filter name=unittest_keycloak
            exit 1
        fi
        sleep 5
        if [ ${SECONDS} -gt "${KEYCLOAK_STARTUP_TIMEOUT}" ]; then
            echo "Timeout exceeded"
            docker logs unittest_keycloak | tee keycloak_test_logs.txt || true
            docker ps -a --filter name=unittest_keycloak
            exit 1
        fi
    done
}

# Ensuring that keycloak is stopped in case of CTRL-C
trap keycloak_stop err exit

keycloak_stop # In case it did not shut down correctly last time.
keycloak_start

eval ${CMD_ARGS}
RETURN_VALUE=$?

exit ${RETURN_VALUE}

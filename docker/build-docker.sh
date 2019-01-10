#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR/..

DOCKER_IMAGE=${DOCKER_IMAGE:-wolfcoinpay/wolfcoind-develop}
DOCKER_TAG=${DOCKER_TAG:-latest}

BUILD_DIR=${BUILD_DIR:-.}

rm docker/bin/*
mkdir docker/bin
cp $BUILD_DIR/src/wolfcoind docker/bin/
cp $BUILD_DIR/src/wolfcoin-cli docker/bin/
cp $BUILD_DIR/src/wolfcoin-tx docker/bin/
strip docker/bin/wolfcoind
strip docker/bin/wolfcoin-cli
strip docker/bin/wolfcoin-tx

docker build --pull -t $DOCKER_IMAGE:$DOCKER_TAG -f docker/Dockerfile docker

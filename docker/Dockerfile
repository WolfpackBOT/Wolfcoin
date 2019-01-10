FROM debian:stretch
LABEL maintainer="Wolfcoin Developers <dev@wolfcoin.org>"
LABEL description="Dockerised WolfcoinCore, built from Travis"

RUN apt-get update && apt-get -y upgrade && apt-get clean && rm -fr /var/cache/apt/*

COPY bin/* /usr/bin/

#!/bin/bash
GO_VERSION="1.22.2"
ARCH="arm64"
wget https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-${ARCH}.tar.gz
rm go${GO_VERSION}.linux-${ARCH}.tar.gz
echo "export GOROOT=/usr/local/go" >> ~/.profile
echo "export GOPATH=\$HOME/go" >> ~/.profile
echo "export PATH=\$PATH:/usr/local/go/bin:\$GOPATH/bin" >> ~/.profile
source ~/.profile
go version

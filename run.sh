#!/bin/bash

cp "$(pwd)/injectme.so" "/tmp/inject.so"
./monitor $1

#!/bin/bash

apt update \
&& apt install gcc g++ git curl make -y

# Define build variables
# HARDENED_MALLOC_VERSION is set to the latest tag available on GitHub
# https://github.com/GrapheneOS/hardened_malloc
HARDENED_MALLOC_VERSION="2024080600"
CONFIG_NATIVE=false
VARIANT=default

# Clone and build hardened_malloc
cd /tmp \
&& git clone --depth 1 --branch ${HARDENED_MALLOC_VERSION} https://github.com/GrapheneOS/hardened_malloc \
&& cd hardened_malloc \
&& wget -q https://grapheneos.org/allowed_signers -O grapheneos_allowed_signers \
&& git config gpg.ssh.allowedSignersFile grapheneos_allowed_signers \
&& git verify-tag $(git describe --tags) \
&& make CONFIG_NATIVE=${CONFIG_NATIVE} VARIANT=${VARIANT}

# Move hardened_malloc to the correct directory
cp /tmp/hardened_malloc/out/libhardened_malloc.so /usr/local/lib/

# Cleanup
rm -rf /tmp/hardened_malloc

# Add hardened_malloc to our path if it's not already present in ~/.bashrc
if ! grep -q "LD_PRELOAD=\"/usr/local/lib/libhardened_malloc.so\"" ~/.bashrc; then
    echo 'export LD_PRELOAD="/usr/local/lib/libhardened_malloc.so"' >> ~/.bashrc
fi

echo 'source ~/.bashrc'

echo "Hardened Malloc build and setup completed."
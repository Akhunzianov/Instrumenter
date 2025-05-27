FROM --platform=linux/amd64 ubuntu:22.04

# Install the necessary packages
RUN apt update
RUN apt install -y --no-install-recommends \
    build-essential \
    gcc \
    g++ \
    wget \
    ca-certificates \
    git \
    make \
    cmake \
    ninja-build \
    python3 \
    openocd \
    picocom \
    zsh \
    curl \
    file \
    libcapstone-dev \
    capstone-tool \
    && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/keystone-engine/keystone.git /opt/keystone && \
    cd /opt/keystone && \
    mkdir build && cd build && \
    cmake .. && \
    make -j$(nproc) && \
    make install && \
    ldconfig

ENV GIT_SSL_NO_VERIFY=true

# Disable printing "Entering directory" message in GNU Make
ENV GNUMAKEFLAGS=--no-print-directory

# Install Oh My Zsh
RUN sh -c "$(wget --no-check-certificate -O- https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended && \
    git clone https://github.com/zsh-users/zsh-autosuggestions ~/.oh-my-zsh/custom/plugins/zsh-autosuggestions
ENV SHELL=/bin/zsh

# Config git for ignore file mode and line endings (otherwise there will be a lot of false changes in the files)
RUN git config --global core.filemode false && \
    git config --global core.autocrlf true

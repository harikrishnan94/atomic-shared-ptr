# See here for image contents: https://github.com/microsoft/vscode-dev-containers/tree/v0.195.0/containers/cpp/.devcontainer/base.Dockerfile
# [Choice] Debian / Ubuntu version (use Debian 11/9, Ubuntu 18.04/21.04 on local arm64/Apple Silicon): debian-11, debian-10, debian-9, ubuntu-21.04, ubuntu-20.04, ubuntu-18.04
ARG VARIANT=debian-11
FROM mcr.microsoft.com/vscode/devcontainers/cpp:0-${VARIANT}

# [Optional] Uncomment this section to install additional packages.
# RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
#     && apt-get -y install --no-install-recommends <your-package-list-here>

# Install clangd
RUN wget -q -c https://github.com/clangd/clangd/releases/download/14.0.3/clangd-linux-14.0.3.zip && \
    unzip -q clangd-linux-14.0.3.zip && \
    sudo cp -r clangd_14.0.3/* /usr/local/ && \
    rm -r clangd_14.0.3 clangd-linux-14.0.3.zip

# Install gcc-11
RUN (echo deb http://deb.debian.org/debian testing main contrib non-free; \
    echo deb-src http://deb.debian.org/debian testing main contrib non-free) | sudo tee /etc/apt/sources.list.d/gcc-11.list
RUN sudo apt update
RUN sudo apt install -y gcc-11 g++-11 -t testing
RUN sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-11 11
RUN sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-11 11

# Install cmake 3.23
RUN wget -q -c https://github.com/Kitware/CMake/releases/download/v3.23.2/cmake-3.23.2-linux-x86_64.sh && \
    chmod +x cmake-3.23.2-linux-x86_64.sh && \
    sudo ./cmake-3.23.2-linux-x86_64.sh --skip-license --prefix=/usr/local && \
    rm cmake-3.23.2-linux-x86_64.sh
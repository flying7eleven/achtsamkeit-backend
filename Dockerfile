# use the same platform for building as we use for running the server
FROM debian:bullseye-slim AS build

# ensure we have rust installed in the appropiate version
RUN apt update && \
    apt install -y curl build-essential libpq-dev && \
    curl https://sh.rustup.rs -sSf | \
    sh -s -- --default-toolchain stable -y
ENV PATH=/root/.cargo/bin:$PATH

# copy the source files and build the backend in release-mode
COPY . /usr/src/app
WORKDIR /usr/src/app
RUN cargo build --release

# configure the acutal container for running the backend
FROM debian:bullseye-slim

# install the required dependencies
RUN apt update && \
    apt install -y libpq5 curl

# copy the files for running the container
COPY --from=build --chown=1001 /usr/src/app/target/release/achtsamkeit-backend /usr/local/achtsamkeit/server

#
WORKDIR /usr/local/achtsamkeit

# configure the user(-id) for the running process
USER 1001

# expose the backend port
EXPOSE 5432/tcp

# startup the backend
CMD exec /usr/local/achtsamkeit/server
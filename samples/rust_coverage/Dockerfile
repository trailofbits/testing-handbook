FROM rust:1.74.0-slim-bullseye

RUN apt update
RUN apt install -y pkg-config libssl-dev lcov
RUN cargo install cargo-tarpaulin
RUN cargo install cargo-llvm-cov --locked
RUN cargo install llvm-cov-pretty
RUN rustup component add llvm-tools-preview
RUN cargo install grcov

WORKDIR /home/test

COPY ./Cargo.toml /home/test/
COPY ./src /home/test/src
COPY ./get_coverage.sh /home/test/
RUN mkdir /home/test/outputs

RUN /bin/bash ./get_coverage.sh

CMD /bin/bash
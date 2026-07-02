# Rust coverage

A simple Rust project and a script for generating HTML coverage reports using various tools.

Build and run the Docker container:

```sh
docker build --build-arg CACHEBUST=$(date +%s) -t tob_cov_test .
mkdir -p outputs
docker run -it --rm -v "$PWD/outputs:/home/test/outputs" tob_cov_test
```

The coverage reports are written to the local `outputs` directory.

```sh
find outputs -name 'index.html' -o -name 'tarpaulin-report.html'
```

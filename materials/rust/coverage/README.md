# Rust coverage

A simple Rust project and a script for generating HTML coverage reports using various tools.

Build and run docker container:
```sh
docker build --build-arg CACHEBUST=$(date +%s) -t tob_cov_test .
docker run -it --rm tob_cov_test
```

Copy content from the container:
```sh
docker cp tob_cov_test:/home/test/outputs .
```

Review results opening relevant HTML files:
```sh
find . -not -path '*/src/*' -name 'index.html' -or -name tarpaulin-report.htm
```

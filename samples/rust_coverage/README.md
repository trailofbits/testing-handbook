# Rust coverage

A simple Rust project and a script for generating HTML coverage reports using various tools.

Build and run docker container:
```sh
docker build -t tob_cov_test .
docker run -it --name tob_cov_test tob_cov_test bash
```

Copy content from the container:
```sh
docker cp tob_cov_test:/home/test/outputs .
```

Review results opening relevant HTML files:
```sh
find . -name 'index.html' -or -name tarpaulin-report.html
```

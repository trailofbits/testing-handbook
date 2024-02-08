Before we can compile libpng, we have to install dependencies for it:

```shell
apt install zlib1g-dev
```

Next, we configure and compile libpng as a static library without linking libFuzzer.
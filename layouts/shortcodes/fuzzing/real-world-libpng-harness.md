Next, we download a harness from GitHub. Usually, you would have to write a harness yourself. However, for this example, an existing one suffices.


```shell
curl -O https://raw.githubusercontent.com/glennrp/libpng/f8e5fa92b0e37ab597616f554bee254157998227/contrib/oss-fuzz/libpng_read_fuzzer.cc
```


Finally, we link together the instrumented libpng, the harness, and the libFuzzer runtime.
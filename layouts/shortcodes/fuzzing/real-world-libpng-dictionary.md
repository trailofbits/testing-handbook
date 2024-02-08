```shell
curl -o seeds/input.png https://raw.githubusercontent.com/glennrp/libpng/acfd50ae0ba3198ad734e5d4dec2b05341e50924/contrib/pngsuite/iftp1n3p08.png
```


We also download a [dictionary]({{ (.Get 0) }}) for the PNG format to better guide the fuzzer. A dictionary provides the fuzzer with some initial clues about the file format, such as which magic bytes PNG uses.


```shell
curl -O https://raw.githubusercontent.com/glennrp/libpng/2fff013a6935967960a5ae626fc21432807933dd/contrib/oss-fuzz/png.dict
```


The fuzzing campaign can be launched by running:
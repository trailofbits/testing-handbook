---
title: "Dudect"
weight: 45
# bookFlatSection: false
# bookToc: true
# bookHidden: false
# bookCollapseSection: false
# bookComments: false
# bookSearchExclude: false
---
{{< math >}}
# Dudect 
## Overview

[Dudect](https://github.com/oreparaz/dudect/) is a [statistical constant-time analysis tool]({{<ref "/docs/crypto/constant_time_tool/index#statistical-tools" >}}) that measures the execution time of a specific *code section* for two different *input classes* and aims to find the statical difference between the measurements of the two classes.
If the timing measurements for the two input classes deviate from one another, it would suggest that the code is dependent on the input and, therefore, not constant time. 
The two most commonly used input classes are:
1. **Fixed input class**: \(\mathbf{A}=\{a,a,\cdots,a\}, |A|=n\)
2. **Random input class**: \(\mathbf{B}=\{b_1,b_2,\cdots,b_n\},|B|=n\)

The code section under analysis receives an input \(i \in \{\mathbf{A}, \mathbf{B}\}\), chosen randomly.
Dudect performs multiple timing measurements, grouping them based on the input class \(\{\mathbf{A},\mathbf{B}\}\) of the input \(i\).
After collecting a user-specified number of measurements, a [Welch's t-test](https://en.wikipedia.org/wiki/Welch%27s_t-test) evaluates the differences between the two measurement sets.
If there is a significant difference, the t-value will reflect this, indicating that the code's execution time varies based on the input.

## Setup 

Currently, Dudect supports x86 architecture and there is a [pull request](https://github.com/oreparaz/dudect/pull/36) for ARM-based architectures. 
To get started using Dudect, include the header file `dudect.h`, which defines all internal functions.

```c
#define DUDECT_IMPLEMENTATION
#include "dudect.h"
```

Since Dudect uses the C math library `<math.h>`, the compiler must link the library with the `-lm` flag.

{{< tabs "beyond" >}}
{{< tab "gcc" >}}
```bash
gcc -lm ct_test.c -o ct_test
```

{{< /tab >}}
{{< tab "clang" >}}
```bash
clang -lm ct_test.c -o ct_test
```
{{< /tab >}}
{{< /tabs >}}

Now the compiler will link all the required files but will fail due to two functions that need to be implemented by the user. 
In the following, we explain what these two functions do and how to configure Dudect. 

## Working with Dudect

Dudect measures the execution time of a specific code section using different inputs.
It requires two main pieces of information:
1. What code section should be measured?  \(\rightarrow\) `do_one_computation`
2. What input should be provided to the code? \(\rightarrow\) `prepare_inputs`

### Do One Computation


All code specified inside the `do_one_computation` function is timed by Dudect.

```c
uint8_t do_one_computation(uint8_t *data) {
    ...
}
```

Dudect executes this function multiple times with input data from one of the input classes, chosen at random.


### Prepare Inputs

The input provided to the computation function is implemented inside the `prepare_inputs` function and is precomputed in bulk instead of calling it every time before timing `do_one_computation`.


```c
void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes){
    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = randombit();
        uint8_t *input = input_data + (size_t)i * c->chunk_size;
        if (classes[i] == 0) {
            ... // Input class A
        } else {
            ... // Input class B
        }
    }
}
```

All input data is stored sequentially in the `input_data` array, and the class of each input is randomly determined. 
Dudect uses this data as input for the `do_one_computation` function.
During the Welch's t-test, Dudect needs to know which input belongs to which input class. 
Therefore, the `classes` array contains 1 or 0 to indicate the input class, aiding in the t-test analysis.

Lastly, configure Dudect with the size required of each individual input and the number of measurements performed per iteration. 

```c
dudect_config_t config = {
    .chunk_size = /* Size of a single input */,
    .number_measurements = ...,
};
dudect_ctx_t ctx;
dudect_init(&ctx, &config);
```

The `dudect_init(&ctx, &config);` function allocates all necessary memory regions for storing input data, timing measurements, etc.

### Dudect Loop

To capture timing measurements, `dudect_main(&ctx)` is called, which:
1. Precomputes all inputs by calling `prepare_inputs` and storing them in the continuous `ctx->input_data` array.
2. Executes and times the `do_one_computation` function `number_measurements` number of times.
3. Continuously updates and prints statistics of the collected measurements.

The function `dudect_main` must be called at least twice to calibrate the thresholds. 
It can be run in an endless loop until significant differences are detected.
```c
int run_test(void) {
    ...
    dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
    while (state == DUDECT_NO_LEAKAGE_EVIDENCE_YET) {
        state = dudect_main(&ctx);
    }
    dudect_free(&ctx);
    return (int)state;
}
```

Use the `timeout` command to run the process for a specified time.

```bash
timeout <NumberOfSeconds> ./ct_test
```

Dudect calculates new statistics using the t-test after each iteration and reports them, e.g.:
```
meas:    1.20 M, max t:   +1.61, max tau: 1.47e-03, (5/tau)^2: 1.16e+07. For the moment, maybe constant time.
```

A high absolute `t-value` suggests possible timing variance, which implies data-dependent execution paths. 
If Dudect consistently reports that the measurements are `maybe constant time`, it means that the timing differences detected are not statistically significant. 

## Improving Measurement Accuracy
To ensure Dudect detects potential timing leakages, it is crucial to reduce noise that might overshadow timing differences between the input classes.
Dudect statically removes outlier measurements, but a large number of measurements may still be necessary.
Precise measurements can help reduce the time needed to detect leakages.
To improve the accuracy of the collected measurements, it is recommended to:

**Reduce Code Noise**:
Only run the specific function you want to test, avoiding operations that may add overhead, such as *key generation* or *cipher initialization*.

**Reduce Operating System Noise**: 
For precise measurements, especially in short code sections, reduce noise from the operating system.
One can **pin the process to a CPU core** and **isolate this core** to reduce the noise. 
Doing so will reduce the number of context switches performed during the execution, providing more consistent and accurate measurements. 

Use the `taskset` command to pin the process to a core:

```bash
taskset -c 2 ./ct_test
```

Avoid using cores 0 and 1 as they are often used by the OS for other tasks. 
Pinning a task prevents performance costs associated with cache invalidation during process execution on different CPUs.
For further noise reduction, consider setting specific kernel boot parameters. 
More information can be found in this [guide](https://manuel.bernhardt.io/posts/2023-11-16-core-pinning/).


## Template
Dudect provides [example code](https://github.com/oreparaz/dudect/tree/master/examples) for AES and other ciphers, which is a good starting point.
The following is a simple template that can be used to start:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DUDECT_IMPLEMENTATION
#include "dudect.h"

/* this will be called over and over */
uint8_t do_one_computation(uint8_t *data)
{
    // ToDo: Implement the code you want to test
    <CODE TO MEASURE>
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes)
{
    for (size_t i = 0; i < c->number_measurements; i++)
    {
        classes[i] = randombit();
        uint8_t *input = input_data + (size_t)i * c->chunk_size;
        if (classes[i] == 0)
        {
            // ToDo: Specify the input data for the first input class
            <INPUT CLASS A>
        }
        else
        {
            // ToDo: Specify the input data for the second input class
            <INPUT CLASS B>
        }
    }
}

int run_test(void)
{
    dudect_config_t config = {
        // ToDo: Set the required size for a singular input
        .chunk_size = <INPUT SIZE NEED FOR ONE COMPUTATION>,
        // ToDo: Set the number of measurements that should be performed per iteration
        .number_measurements = <MEASUREMENTS PER ITERATION>,
    };
    dudect_ctx_t ctx;

    dudect_init(&ctx, &config);

    dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
    while (state == DUDECT_NO_LEAKAGE_EVIDENCE_YET)
    {
        state = dudect_main(&ctx);
    }
    dudect_free(&ctx);
    return (int)state;
}

int main(int argc, char **argv)
{
    run_test();
}
```

The template code above will run in an endless loop until the measurements are significantly different and the code is deemed not constant-time.

### CI Setup

Constant monitoring is essential to detect any timing leakages introduced by new changes. 
Continuous testing ensures the assumption of constant-time is not violated when new code is introduced. 

The following bash script can be used as a template to get started. 
It assumes the following file structure:

```
├── tests
│   ├── ct_test.c // Contains the dudect loop
│   └── dudect.h
```

Running the bash script automatically compiles the `ct_test.c` file using `clang` and executes the binary on the second core using `taskset -c 2` and stops execution after 5 minutes.
For real-world production, one should ideally execute the test for longer than 5 minutes, as more measurements ensure a higher probability of dudect detecting timing differences. 

```bash
#!/bin/bash

# Set the path to the test folder
TEST_DIR="tests"
TEST_FILENAME="ct_test.c"
TEST_DURATION="300s"
CT_TEST="$TEST_DIR/$TEST_FILENAME"
DUDECT_HEADER="$TEST_DIR/dudect.h"

OUTPUT_BINARY="ct_test_bin"
clang -lm -DDUDECT_IMPLEMENTATION -o $OUTPUT_BINARY $CT_TEST

if [ $? -ne 0 ]; then
  echo "Compilation failed."
  exit 1
fi

# Run the compiled binary with taskset on core 2 and timeout
TASKSET_CMD="taskset -c 2"
TIMEOUT_CMD="timeout $TEST_DURATION"
$TASKSET_CMD $TIMEOUT_CMD ./$OUTPUT_BINARY

# Capture the return status of the binary
RETURN_STATUS=$?

# Analyze the return status
if [ $RETURN_STATUS -eq 0 ]; then
  echo "No timing vulnerability detected within the specified time."
  exit 0
elif [ $RETURN_STATUS -eq 124 ]; then
  echo "No timing vulnerability detected within the specified time."
  exit 0
else
  echo "Test failed. Timing vulnerability detected."
  exit 1
fi
```

Running this script periodically ensures that new changes introduced to a library do not violate the constant time assumption. 

## Limitations
1. **No Guarantees**:
Dudect's time measurements are as reliable as the conditions allow. 
Non-security-relevant code in `do_one_computation` can create noise, masking the leakage signal.
Even if Dudect finds no leakages, it doesn't guarantee that the code is free from timing vulnerabilities.

2. **System Dependency**:
Results can vary based on architecture and system conditions.
Machines with many concurrent processes may fail to detect leakage signals, and results may not be reproducible on different machines. 

3. **Further Investigation Needed**:
If Dudect detects a leakage, it doesn't pinpoint the source.
Other tools, like TimeCop, can help identify the leakage.

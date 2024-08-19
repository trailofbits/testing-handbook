---
title: "Constant time analysis tooling"
weight: 4
summary: "Constant time tooling aims to verify that there do not exist any timing side channels in a implementation."
bookCollapseSection: true
math: true
# bookFlatSection: false
# bookToc: true
# bookHidden: false
# bookComments: false
# bookSearchExclude: false
---
# Constant time analysis tooling

{{< math >}}
Timing attacks are side channels that exploit variations in execution time to extract secret information. Unlike cryptanalysis, which seeks to find weaknesses and break the theoretical security guarantees of a cryptographic protocol, timing attacks leverage implementation flaws in specific protocols.  
While specific cryptographic constructions, such as asymmetric cryptography, may be more vulnerable to timing attacks, this attack vector can potentially affect any cryptographic implementation. To mitigate timing attacks, it is best practice to ensure implementations are constant time, meaning the execution time of cryptographic functions should remain constant regardless of the input. In practice, one should ensure that **the code path and any memory accesses are independent of secret data**. Not all timing differences are exploitable, but removing any differences ensures the security of the implementation. To ensure that an implementation is constant time, cryptography practitioners have developed various tools to detect non-constant time code.  

This entry is divided into two sections.
The first provides [background](#background) information on timing attacks and a concrete [example](#example-modular-exponentiation-timing-attacks).
The second section focuses on different [tools](#constant-time-tooling) practitioners can use to check if an implementation is constant time and categorizes them into four distinct classes, each with its advantages and limitations.

## Background

Timing attacks on cryptographic implementations were introduced by [Kocher](https://paulkocher.com/doc/TimingAttacks.pdf) in 1996\. Over the years, various researchers expanded on these attacks. Notably, [Schindler](https://www.torsten-schuetze.de/sommerakademie2009/papers-sekundaer/Schindler\_Timing\_2000.pdf) demonstrated attacks on RSA implementations which used a specific optimization improvement, and in 2005, Brumley and Boneh published [Remote Timing Attacks are Practical](https://crypto.stanford.edu/\~dabo/papers/ssl-timing.pdf), successfully extracting secret keys from OpenSSL. Also, symmetric ciphers like AES can be vulnerable to timing attacks, as shown in [Cache-timing attacks on AES](https://mimoza.marmara.edu.tr/\~msakalli/cse466\_09/cache%20timing-20050414.pdf).  
More recently, the post-quantum algorithm Kyber was found to have timing vulnerabilities in its official implementation, dubbed [KyberSlash](https://eprint.iacr.org/2024/1049.pdf). The [CWE-385](https://cwe.mitre.org/data/definitions/385.html) catalog tracks timing vulnerabilities found in implementations.  

Generally, to exploit a timing attack, two key prerequisites must be met:

1. Access to an oracle allowing sufficient queries.  
2. A timing dependency between the secret and attacker-controlled data

The number of queries needed depends on the severity of the timing leakage. If the timing leakage signal is strong relative to the noise introduced by all other instructions or network latency, a few measurements may suffice; otherwise, millions might be needed. Timing dependencies occur due to differences in execution traces or instruction timings.

### Common constant time violation patterns

The four most common patterns that violate the constant time property stem from these four patterns, which are all dependent on secret data:

```c
// 1. Conditional jumps
if(secret == 1):
{
...
}
while(secret > 0)
{
...
}

// 2. Array access 
lookup_table[secret];

// 3. Integer division (processor dependent) 
data = secret / m;

// 4. Shift operation (processor dependent)
data = a << secret;
```

When writing code that performs any operation using secret data one should keep these four patterns in mind and aim to avoid them.

**Conditional jumps** result in executing different instructions and generally lead to the most significant time differences out of the four patterns. Making the execution flow of the program dependent on secret data is going to lead to vast timing differences depending on how different the two branches are.  

**Array access** and more general memory access, dependent on secret data, can be used to extract the indexing value due to timing differences when accessing memory locations. These timing differences primarily stem from the utilization of caches and whether or not a given value is inside the cache. Ciphers like AES, which use substitution tables dependent on secret data, are suitable for this attack even over the network, as demonstrated here [Cache-timing attacks on AES](https://mimoza.marmara.edu.tr/~msakalli/cse466_09/cache%20timing-20050414.pdf).

**Integer division and shift operations** can leak the secret if the divisor or the amount by which the value is shifted depends on secret data.  
These operations can leak the secret data depending on the CPU architecture or compiler used.

In cases where it is impossible to avoid these patterns because the cryptographic algorithm requires them, one should employ [masking techniques](https://link.springer.com/chapter/10.1007/978-3-642-38348-9_9) to remove or reduce any correlation between the execution time and the secret data.

In the next section, we will illustrate how timing attacks on modular exponentiation exploit conditional jumps.

### Example: Modular Exponentiation Timing Attacks

[Kocher](https://paulkocher.com/doc/TimingAttacks.pdf) showed that algorithms used to calculate modular exponentiation are susceptible to timing attacks.
Given that popular cryptographic systems like **RSA** and **Diffie-Hellman** use modular exponentiation, this vulnerability poses a significant security risk.
In RSA, for example, decryption involves raising the ciphertext \(ct\) to the secret exponent \(d\) modulo the public modulus \(N\):

$$
ct^{d} \mod{N}
$$

If an attacker can query the decryption function with different values for \(ct\) under the same secret exponent \(d\), they may deduce the value of \(d\) based on the time taken for the computations.
Since modular exponentiation is computationally intensive and widely used, optimizing this operation can greatly enhance performance.
One such optimization, known as *exponentiation by squaring* or the *right-to-left binary method*, reduces the number of multiplications to \(\log{d}\).

$$
\begin{flalign}
& \textbf{Input: } \text{base }y,\text{exponent } d=\{d_n,\cdots,d_0\}_2,\text{modulus } N \\
&r = 1 \\
&\textbf{for } i=|n| \text{ downto } 0: \\
&\quad\textbf{if } d_i == 1: \\
&\quad\quad r = r * y \mod{N} \\
&\quad y = y * y \mod{N} \\
&\textbf{return }r
\end{flalign}
$$

The resulting code branches depending on the exponent bit \(d_i\) violating the *conditional jump* principle described in the previous section.
If the exponent bit \(d_i = 1\), an additional multiplication \(r = r * y\) is performed, resulting in a longer execution time and, therefore, leaking the number of 1 and 0 bits present in \(d\).
Furthermore, a commonly used technique for modular multiplication called *Montgomery multiplication* is not constant time and performs an additional computation depending on the modulus and the multiplication result.  
If an intermediate value of the multiplication exceeds the modulus \(N\), a reduction step needs to be performed.
The additional reduction step will lead to an observable difference in timings.

To exploit these variations, an attacker can construct two inputs, \(y\) and \(y'\), such that:

$$
\begin{align*}
y^2 < y^3 < N \\
y'^2 < N \leq y'^3
\end{align*}
$$

A modular multiplication without reduction may take \(t_1\) time, and one where the reduction step is required will take \(t_2\) time steps.
For \(y\), both Montgomery multiplications will not require a reduction step, resulting in time \(t_1+t_1\).
For \(y'\), the first multiplication \(r=r*r\) will not require a reduction, but the second \(r=r*y \) might, causing an additional time \(t_2\).

$$
\begin{flalign}
& \color{gray} \textbf{Input: } \text{base }y,\text{exponent } d=\{d_n,\cdots,d_0\}_2,\text{modulus } N \\
&\color{gray}r = 1 \\
&\color{gray}\textbf{for } i=|n| \text{ downto } 0: \\
&\color{gray}\quad\textbf{if } d_i == 1: \\
&\quad\quad r = r * y \mod{N}
\begin{cases}
    t_1,& \text{if } r * y < N\\
    t_2,& \text{if } r * y \geq N
\end{cases} \\
&\quad y = y * y \mod{N} \begin{cases}
    t_1,& \text{if } r * r < N\end{cases} \\
&\color{gray}\textbf{return }r
\end{flalign}
$$

The branching behavior reveals timing differences:

|    | \(d_i = 0\)           | \(d_i = 1 \)                  |
|----|-----------------------|-------------------------------|
| \(y \) | \(t_1\) | \(t_1 + t_1\) |
| \(y'\) | \(t_1\) | \(t_1 + t_2\) |

By analyzing these timing differences, an attacker can infer whether a specific bit \(d_i\) is 0 or 1. While a single execution might not yield sufficient information, multiple measurements combined with statistical analysis can help recover the private key \(d\).

## Constant Time Tooling

To mitigate the risk of timing attacks, it is best practice to implement cryptographic algorithms in a *constant time* manner, meaning the execution time remains uniform regardless of the input.
To ensure the absence of such timing differences, the cryptographic community has created various timing tools that aim to detect potential timing differences.  
These tools differentiate themselves by the programming language they target (most often C) and the fundamental approach of timing analysis.
We can group the different approaches into four distinct categories:

1. **Formal**
2. **Symbolic**
3. **Dynamic**
4. **Statistical**

Each approach has its benefits and downsides compared to others.

### Formal Tools

Formal verification tools aim to mathematically prove that a given model adheres to specified timing leakage properties.
To achieve this, these tools first create an abstraction of the source code or binary, known as a model.
The next step involves specifying properties that the model must not violate, often by annotating variables or memory regions that should remain secret.
These tools are classified as static tools because they do not execute the underlying code.

Popular formal tools include:

- [SideTrail](https://github.com/aws/s2n-tls/tree/main/tests/sidetrail)
- [ct-verif](https://github.com/imdea-software/verifying-constant-time)
- [FaCT](https://github.com/plsyssec/fact)

| Pros | Cons |
| :---- | :---- |
| **Guarantee**: Formal verification proves the absence of timing leaks under the analyzed model. | Complexity: These tools tend to require more expertise in both cryptography and formal methods, making them less accessible to general developers. |
| **Flexibility**: Many tools utilize LLVM bytecode, allowing for use with various languages. | Modeling and restrictions: Assumptions made during formalization may not perfectly reflect reality, potentially leading to incomplete verification. For example, any changes introduced during the compilation stage may lead to a binary that is different from the analyzed model. |

### Symbolic tools

Symbolic tools use symbolic execution to find timing leakages by analyzing how different execution paths and memory accesses depend on symbolic variables, particularly secret data.
Symbolic execution can also provide concrete values for which a certain property is violated, which can be useful for understanding the underlying issue.  
Most symbolic execution tools focus on cache timing attacks, making them a useful tool for threat models involving an attacker who shares the same cache.

Popular symbolic tools include:

- [Binsec](https://github.com/binsec/binsec)
- [pitchfork](https://github.com/PLSysSec/haybale-pitchfork)

| Pros | Cons |
| :---- | :---- |
| **Counterexamples**: Symbolic execution can provide concrete counterexamples or test cases that demonstrate the existence of a vulnerability, making it easier to understand and reproduce the issue. | **Time intensive**: Symbolic execution will explore all possible paths, which results in long execution times.     |

### Dynamic Tools

Dynamic tools, alongside formal tools, are among the most common methods for ensuring constant time execution. These approaches typically involve marking specific memory regions as sensitive, ensuring they do not reveal timing information, or by tracing the execution flow to detect differences in execution traces for different inputs.

Popular dynamic tools include:

- [Memsan](https://clang.llvm.org/docs/MemorySanitizer.html): [Tutorial](https://crocs-muni.github.io/ct-tools/tutorials/memsan)
- [TimeCop](https://www.post-apocalyptic-crypto.org/timecop/) / [Valgrind](https://neuromancer.sk/article/29)

| Pros | Cons |
| :---- | :---- |
| Granular Analysis: Allows specification of sensitive memory regions, making them effective for targeted analysis. | Limited Coverage: Can only track execution paths encountered during testing, potentially missing some vulnerabilities. |
| Flexibility: Can be adapted to various contexts by annotating different codebase parts. |  |

### Statistical Tools

Statistical tools analyze a program by executing it with various inputs and measuring the elapsed time.
If the time measurements are consistent across all inputs, it suggests the absence of timing vulnerabilities.
Since these tools measure the actual code being executed, they are close to practical implementation and account for potential variables, making them great as an initial check for potential timing issues.

Popular statistical tools include:

- [dudect](https://github.com/oreparaz/dudect)
- [tlsfuzzer](https://github.com/tlsfuzzer/tlsfuzzer)

| Pros | Cons |
| -------- | ------- |
| **Setup**: Setting up statistical tests can be quite straightforward and, in some cases, can be done without needing access to source code.  | **Debugging**: When a timing difference is detected, statistical tools typically do not provide information about the cause or location of the issue within the code. |
| **Practical**: Statistical tools measure real-time leakage, providing real-world results that include all potential variables (for example, compiler optimizations, architecture differences). | **Noise**: The quality of the recorded measurements is only as precise as the testing harness allows. If other parts of the code take significantly more time, a timing vulnerability might go undetected. |

## Further Reading

[“These results must be false”: A usability evaluation of constant-time analysis tools](https://www.usenix.org/system/files/sec24fall-prepub-760-fourne.pdf)

[List of constant time tools](https://crocs-muni.github.io/ct-tools/)

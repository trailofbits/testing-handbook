---
title: "C/C++"
slug: c-cpp
summary: "TODO"
weight: 1
bookCollapseSection: true
---

# C/C++ {#c-c}

In this section, we will discuss how to fuzz C/C++ projects, including how to set up a fuzzer in your project. While there are many options for fuzzing C/C++ projects, we will ground this tutorial in the practical use of libFuzzer and AFL++: two of the most prominent fuzzing tools in use today that can be applied to any C/C++ project.

For a general introduction about fuzzing and fuzzing setup (e.g., the harness, fuzzer runtime, instrumentation, and SUT), refer to the [introduction](#introduction-to-fuzzers). 


## When should I use which fuzzer? {#when-should-i-use-which-fuzzer}


{{< rawHtml >}}
<table>
  <tr>
   <td><strong>libFuzzer</strong>
   </td>
   <td>Simple; well-tested; basic fuzzing features; limited multi-core fuzzing; libFuzzer is in maintenance-only mode
   </td>
  </tr>
  <tr>
   <td><strong>AFL++</strong>
   </td>
   <td>Well-tested; industry-standard; sufficient for most fuzzing needs; supported multi-core fuzzing
   </td>
  </tr>
</table>
{{< /rawHtml >}}
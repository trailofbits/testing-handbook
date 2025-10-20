---
weight: 2
bookFlatSection: true
title: "Static analysis"
---

# Static analysis

This section presents several static analysis tools. For each tool, we cover topics such as:

- Installation and basic use
- Advanced configuration
- Usage in continuous integration pipelines

{{< section >}}


## Basic theory

Below is an overview of techniques implemented in static analysis tools.

Usually tools support only a subset of the following analyses, with varying degree of precision and completeness. Knowing what are a tool's capabilities is useful in determining it's usefulness.

### Views on a code

* Abstract Syntax Tree (AST)
* Control Flow Graph (CFG)
* Data Flow Graph (DFG)
* Call Graph
* Intermediate Representation (IR)
* Single Static Assignment Form (SSA)
* Use-Definition Chain (use-def)

### Analyses

* AST traversal
* Abstract Interpretation
    * Constant Propagation
    * Value Range analysis
* Data-Flow analysis
* Train Tracking
* Control-Flow analysis
    * Domination relationship
    * Reachability
* Hoare logic
* Model checking
* Symbolic execution
    * Concolic execution
* Type analysis
* Alias/Pointer/points-to analysis
* Program slicing
* Global value numbering
* Hash consing

### Precision

* Intraprocedural
    * Flow-sensitivity (order of statements)
    * Path-sensitivity (conditional branches)

* Interprocedural
    * Context-sensitivity (Polyvariance)
        * Call-site
        * Type
        * Object
    * Context-insensitive


### Properties

* Soundness
* Precision
* Completness
* Execution time

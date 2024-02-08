---
title: "Rule-based models"
slug: rule-based-models
summary: "This section describes how to define a Tamarin model using multiset rewrite rules."
weight: 10
---

# Rule-based models

A Tamarin model can be defined either using multiset rewrite rules, or as processes using Sapic+. This section will
introduce the rewrite rule-based approach.

Rewrite rules are defined using the following syntax:

```js
rule Rule_name:
  [ input facts ] --[ action facts ]-> [ output facts ]
```

This should be interpreted as follows: if we have the given input facts, we can execute the rule to emit the action
facts and produce the corresponding output facts.

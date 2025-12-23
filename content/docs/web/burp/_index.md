---
title: "Burp Suite Professional"
weight: 2
summary: "Burp Suite Professional is an HTTP interception proxy with numerous security testing features."
bookCollapseSection: true
---

# Introduction to Burp Suite Professional

## 1. What is it?

Burp Suite Professional is an HTTP interception proxy with numerous security testing features. It allows you to view and manipulate
the HTTP requests and responses flowing between a client (usually a web application loaded in a browser) and a server.

With the increased traffic of today's websites, Burp stands out for its ability to handle parallel requests.
Its interactive tools allow you to formulate and test hypotheses about how the site will behave, even when there is a lot of
traffic to sort through—a feat that is difficult for most browser development tools. In addition, Burp includes advanced search
and filtering mechanisms that greatly increase user productivity when dealing with high traffic.
Burp's UI also significantly outperforms browser development tools when it comes to editing requests.

{{< hint info >}}🎥 Watch the Trail of Bits Webinar on
[Mastering Web Research with Burp Suite](https://www.youtube.com/watch?v=0PV5QEQTmPg).
In this session, we dive into advanced web research techniques using Burp Suite with James Kettle, including how to discover ideas and targets,
optimize your setup, and utilize Burp tools in various scenarios. We also explore the future of Burp with the introduction of BChecks
and compare dynamic and static analysis through real-world examples.
{{< /hint >}}

Burp contains four major features:

1. **Burp Proxy**. The **Proxy** tab lets you view, sort, and filter proxied requests and responses.
2. **Burp Scanner (both active and passive)**. The passive Burp Scanner analyzes requests and responses and informs users
   about potential issues. The active Burp Scanner generates requests to send to the server, testing it for potential
   vulnerabilities, and displays the results.
3. **Burp Repeater**. Burp Repeater allows you to edit and conveniently send requests.
4. **Burp Intruder**. Burp Intruder allows you to populate portions of requests (e.g., query strings, POST parameters, URL paths,
   headers) with sets of predefined fuzzing payloads and send them to a target server automatically. Burp Intruder then displays
   the server’s responses to help you identify bugs or vulnerabilities resulting from unexpected input.

In short, Burp lets you capture HTTP traffic, interact with it conveniently, and conduct security testing by
using Burp's embedded logic (predefined rules) or manual methods.

## 2. Where can Burp support you?

Through extensive experience in white box security auditing at Trail of Bits, we've learned that identifying security
vulnerabilities isn't always straightforward. Here are some of the challenges:

* Some security vulnerabilities can originate from the large number of third-party libraries or their configurations.
* Large products contain various components spread over complicated infrastructure, making the system’s real-world behavior hard
  to predict.
* The presence of bugs varies depending on the configuration of the deployment environment (e.g., staging vs. production).

Burp addresses these challenges by providing a practical suite of tools that help you do the following:

* Identify server-side issues and unexpected behaviors.
* Identify client-side vulnerabilities (with the assistance of Burp's DOM Invader Chromium extension).
* Make sense of the data sent to the front end, uncovering its purpose and how it affects the application's behavior in instances
  where the code is obfuscated using libraries such as React or Webpack.
* Understand what data the client is expected to provide, such as cookies or headers, and whether the timeframes for client-side
  data storage comply with local regulations.
* Learn how a web application behaves under different scenarios, such as when traffic is coming from various geographical
  locations or when different user preferences are set or unset.
* Use comprehensive built-in tools to efficiently fuzz multiple query parameters or header values simultaneously, without
  extensive scripting. For example, using the Intruder tool, you can fuzz various parts of a request, helping unearth issues
  that may manifest only when certain input combinations exist.

Regardless of your application's complexities and challenges, Burp Suite offers a comprehensive toolkit that can
significantly enhance your ability to uncover potential security vulnerabilities.

## 3. What this Testing Handbook will give you

This handbook provides the answers: what you can precisely do to enhance the security of a product with minimal time and effort.
We give you strategic ideas with links to the [official documentation](https://portswigger.net/burp/documentation).
At this point in the Testing Handbook, we recommend that you do the following:

* Reach out for free to [PortSwigger Web Security Academy](https://portswigger.net/web-security) to obtain
  knowledge of web vulnerabilities.
* Go to the [PortSwigger website](https://portswigger.net/burp/pro) to request a trial or buy a license
  (we mostly work on the paid Burp Suite Professional version).

Next, you may follow our [step-by-step guide](stepbystep/_index.md) to test your app using Burp.

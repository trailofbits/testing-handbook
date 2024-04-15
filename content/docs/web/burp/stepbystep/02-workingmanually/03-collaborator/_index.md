---
title: "Burp Collaborator"
slug: collaborator
summary: "Burp Collaborator is a Burp Suite Professional ecosystem tool that helps uncover hidden security vulnerabilities in your web applications. By allowing your testing to span more than just the immediate interaction with a target, Burp Collaborator opens the door to identifying out-of-band (OOB) vulnerabilities."
weight: 3
bookToc: true
---

# Burp Collaborator

Burp Collaborator is a Burp Suite Professional ecosystem tool that helps uncover hidden security vulnerabilities in your
web applications. By allowing your testing to span more than just the immediate interaction with a target, Burp Collaborator
opens the door to identifying out-of-band (OOB) vulnerabilities.

## What is it?

Simply put, Burp Collaborator is a server that can receive requests over numerous protocols (e.g., HTTP, HTTPS, DNS, or SMTP).
It enables the detection of vulnerabilities that don't manifest in the direct responses received from a target application but
rather appear in the connections initiated by the application to other systems, which is why they are called out-of-band vulnerabilities.

Burp Collaborator generates unique identifiers (subdomains for the Burp Collaborator server) that you can use in the payloads
sent to the target application. If the application interacts unexpectedly with the unique location based on your payload, Burp
Collaborator captures the interaction, letting you know about potential vulnerabilities.

## Significant usage scenarios

Burp Collaborator's ability to reveal OOB vulnerabilities is a powerful addition to your security testing toolkit.
It helps you discover flaws that other testing methods may miss.

Burp Collaborator is integrated into various parts of Burp Suite, including Burp Scanner, which automatically tests for various
Burp Collaborator–based vulnerabilities, and tools like Burp Intruder and Burp Repeater, where you can manually leverage
Burp Collaborator capabilities. You can also use third-party extensions like [Collaborator Everywhere](https://portswigger.net/bappstore/2495f6fb364d48c3b6c984e226c02968)
that automatically add Burp Collaborator payloads to certain parts of requests.

Here are notable examples of security issues that Burp Collaborator helps uncover:

1. **Server-side request forgery (SSRF)**. If an application can retrieve content from arbitrary URLs supplied by the user,
it can be tricked into hitting the Burp Collaborator server, indicating a potential SSRF vulnerability. For more information,
see [Server-side request forgery (SSRF)](https://portswigger.net/web-security/ssrf).

2. **Blind XML external entity (XXE) processing**. If your XML payload with a DOCTYPE containing a reference to the Burp
Collaborator server is processed by the application and initiates a call to the Burp Collaborator server, this often signifies
an XXE vulnerability. For more information, see [XML external entity (XXE) injection](https://portswigger.net/web-security/xxe).

3. **DNS interaction**. If payloads injected into the application result in the server making unexpected DNS lookups to the
Burp Collaborator server, this could indicate a wide variety of issues, including insecure data processing or server-side template
injection. Usually, DNS interaction is a basis for deeper investigation to uncover a security issue.

## Burp Collaborator client

Burp Suite includes a Burp Collaborator client that queries the Burp Collaborator server for any interactions detected.
Whenever you use a Collaborator payload (a unique URL, DNS subdomain, or email address) within Burp Suite, the application
automatically polls the Burp Collaborator server for interactions involving that payload.

In manual testing, you can generate your Collaborator payloads by using the **Collaborator** tab and copying the payloads.
If an OOB interaction occurs, you'll be alerted.

{{< resourceFigure "collaborator-tab.png" >}}
The example **Collaborator** tab in Burp
{{< / resourceFigure >}}

- In Burp Repeater, you can right-click on the request and choose **Insert Collaborator payload** or use the `$collabplz` placeholder
with the Taborator extension enabled. For more information, see the
[Burp Repeater]() section.

- In Burp Intruder, you can use the [Collaborator payloads](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types#:~:text=processing%20rule.-,Collaborator%20payloads,-This%20generates%20and)
type or the `$collabplz` placeholder with the Taborator extension enabled.
See more in the [Burp Intruder]()
section.

{{< hint warning >}}
Remember to generate Burp Collaborator payloads only in the context of the [Burp project](https://portswigger.net/burp/documentation/desktop/projects)
stored on your disk. If you generate them in the temporary Burp project, you will lose access to them when you restart Burp.
{{< /hint >}}

## Disabling Burp Collaborator

Some applications you test should not be exposed to third-party servers, even a Burp Collaborator server.
It's essential to be aware of these scenarios, but deactivating Burp Collaborator should be carefully considered
as it may limit your ability to identify certain vulnerabilities.

You can turn off any of the Burp Collaborator–related capabilities in the **Collaborator** settings tab:

{{< resourceFigure "collaborator-settings.png" >}}
The **Settings** panel of Burp Collaborator
{{< / resourceFigure >}}

Consider deploying your private instance of a Burp Collaborator server in highly sensitive environments.
We find that having a private Burp Collaborator server is fruitful even when you have limited capability to assign the server
to the specific domain name and can rely only on the IP address in the internal network.

## Setting up your private Burp Collaborator server

By default, Burp Suite Professional uses the Burp Collaborator server hosted by PortSwigger (e.g., under the `oastify.com` domain).
However, some security testing scenarios may necessitate setting up a private instance of the Burp Collaborator server.
Reasons for this could be to test internal, non-routable systems or for privacy.

To run your own Burp Collaborator server, you'll need to follow the instructions in [Deploying a private Burp Collaborator server](https://portswigger.net/burp/documentation/collaborator/server/private).

## Pingbacks do not have to use the Burp Collaborator domain name

You can use any domain name as long as it points to the original Burp Collaborator server IP address and uses the unique
identifier for your custom domain elsewhere in the HTTP request. This allows you to easily bypass the restriction where
the `oastify.com` domain would be denylisted.

For example, you can have the `8oxo34j107g7kxk2ais46459u00sojc8.oastify.com` Burp Collaborator payload point
to the IP address `54.77.139.23`, which means you can set up your own domain that points to this IP address—for example,
`tobbytest.com`. You can send a request to tobbytest.com and set the User-Agent header to `8oxo34j107g7kxk2ais46459u00sojc8`.
Burp Collaborator will still tell you that it received an HTTP request.

{{< customFigure "The curl command to send a request to the tobbytest.com server with a customized User-Agent header" >}}

```sh {linenos=false}
curl -A 8oxo34j107g7kxk2ais46459u00sojc8 tobbytest.com     
```

{{< /customFigure >}}

{{< resourceFigure "burp-collaborator-ua.png" >}}
The request to Burp Collaborator with a payload placed in the `User-Agent` header
{{< / resourceFigure >}}

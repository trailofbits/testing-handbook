---
title: "Burp Intruder"
slug: intruder
summary: "Burp Intruder is a tool for automating customized attacks against web applications and serves as an HTTP request fuzzer."
weight: 2
bookToc: true
---

# Burp Intruder

Burp Intruder is a tool for automating customized attacks against web applications and serves as an HTTP request fuzzer.
It provides the functionality to configure attacks involving numerous iterations of a base request.
Burp Intruder can change the base request by inserting various payloads into predefined positions, making it a versatile
tool for discovering vulnerabilities that particularly rely on unexpected or malicious input.

To send a request to Burp Intruder, right-click on the request and select **Send to Intruder**.

For basic information on using Burp Intruder, refer to the official documentation: [Getting started with Burp Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder/getting-started).
Specifically, familiarize yourself with attack types when you have more than one place to attack in the request:

{{< resourceFigure "intruder-attack-type.png" >}}
Example Burp Intruder attack types
{{< / resourceFigure >}}

## Wordlists

A wordlist is a file containing a collection of payloads (i.e., input strings) that Burp populates requests with during an attack.
Wordlists allow you to test how a web application handles unexpected and malformed input.

**Prepare your wordlist(s).** Burp contains simple built-in lists, but you should prepare your own for more coverage. For example,
the following are popular public wordlists:

- [SecLists](https://github.com/danielmiessler/SecLists)
- [Payloads All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings)

The following is an example of multiple aggregated wordlists:

- [`payloads.txt`](https://gist.github.com/ahpaleus/e80654d82e718731e8b5385d5df56f2b)
  
Depending on your target, the effectiveness of various wordlists can vary significantly.
Your choice of wordlist should correspond to the specifics of the application and the type of vulnerabilities you are hunting for.
Here are some scenarios:

1. **Language-specific lists**. If you are testing an application predominantly in a particular language, using a language-specific
wordlist could yield more fruitful results. For instance, the SecLists [big English wordlist](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/raft-large-words-lowercase.txt) is useful when looking for hidden
or undocumented POST, GET, or JSON parameters.
2. **Vulnerability-specific lists**. Some wordlists are designed to detect specific vulnerabilities.
If you want to test for SQL injection, you would use a wordlist packed with SQL injection payloads.
Similarly, if you are looking for file or directory enumeration vulnerabilities, wordlists with common
file and directory names could help uncover them.
3. **Technology stack lists**. Depending on the application's underlying technology, some wordlists might be better suited
than others. For example, if the application is built on Adobe Experience Manager, the [`aem2.txt`](https://github.com/danielmiessler/SecLists/blob/3ff9658de5742e4ebb73aff996d6a1170e0a256e/Discovery/Web-Content/aem2.txt)
 list could uncover hidden files and vulnerabilities.

It’s a good habit to extend your list(s) with payloads based on your experience, new research, or the specifics of your targets.

{{< hint info >}}
**Configure a custom wordlist location.** Burp Intruder comes with basic [predefined payload lists](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-lists).
You can load your own directory of custom wordlists in the [Intruder settings](https://portswigger.net/burp/documentation/desktop/settings/tools/intruder#payload-list-location:~:text=Saving%20attacks.-,Payload%20list%20location,-These%20settings%20enable).
This allows your custom wordlists to be easily accessible.
{{< /hint >}}

{{< resourceFigure "custom-wordlists.png" >}}
Example custom payload list in Burp Intruder
{{< / resourceFigure >}}

{{< hint info >}}
Use the [Taborator](https://portswigger.net/bappstore/c9c37e424a744aa08866652f63ee9e0f) extension and add the `$collabplz`
placeholder to a wordlist.
When processing the request, Taborator will automatically change it to a valid <mandy>[Burp Collaborator]() payload.
For example, `?url=http://$collabplz` will be changed to `?url=http://p6abcw7n8g5z5uw332mv6r3rhin9bzzo.oastify.com`.
You will see the output in the **Taborator** tab when the interaction with the host is observed.
{{< /hint >}}

## Where to §attack§?

You tell Burp Intruder where to attack by placing payloads between `§§` characters. But where are the exact places
to attack in your HTTP request? Well, bugs can be anywhere, so choose placeholders anywhere you can think of
(e.g., path, middle of path, parameter, parameter name, header values, additional headers, etc.).
Your success depends on the target, the bugs you are looking for, the wordlists you use, your creativity, and your experience.

<mandy>Also, you can add payload markers (`§§`) to the target to parameterize the different URLs that the request is sent (figure 3).

{{< resourceFigure "target-payload-markers.png" >}}
Adding payload markers in Burp Intruder to the target
{{< / resourceFigure >}}

{{< hint info >}}
You can use the [Auto feature](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/positions#:~:text=Apply%20automatic%20payload%20markers%20%2D%20click%20Auto%20%C2%A7)
in Burp Intruder to automatically place payload markers in common positions within the request, such as query parameters,
body parameters, etc.
{{< /hint >}}
</mandy>

## What to look for?

Successfully executing a Burp Intruder attack is only the first step. The critical part is thoroughly analyzing
the results for potential vulnerabilities. Beyond obvious attack results (such as a sensitive `/etc/passwd`
file returned in the response), remember to consider the following:

1. **Observe results**. Observe error messages, stack traces, and unexpected response bodies.
These may indicate that the input payload has triggered anomalies in the application behavior,
hinting at potential vulnerabilities that need further investigation

2. **Extract from the response**. Right-click on the request and click on [**Define extract grep from response**](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/settings#grep-extract)
to create a response extraction rule. This will create a separate column and extract the contents of a specific location within
each response. For example, extracting a value between certain HTML tags can allow you to identify cross-site scripting (XSS),
or extracting the value from the `Location` header can help you detect an open redirection vulnerability.

3. **Watch Burp Collaborator interactions**. Using Burp Collaborator payloads in your Burp Intruder attack can help identify
out-of-band vulnerabilities. When you inject any Burp Collaborator payload (or use `$collabplz` from the Taborator extension
in the request), watch for interactions in the **Collaborator** tab.
When using Taborator, interactions will be displayed in the **Taborator** tab instead.
4. **Sort specific columns**. Properly sorting the result columns can provide better insights:

   a. **Length**: Check for unusual response lengths. If most are similar lengths but a few deviate significantly,
   the payloads leading to these differences might have triggered unexpected behavior in the application.
   For example, each response length is typically 1565, but one returns a length of 1337. That could indicate a different
   behavior based on the injected input.

   b. **HTTP response codes**: Codes like 500 or 502 could indicate potential denial-of-service (DoS) vulnerabilities.
   A 302 response could also be a clue to open redirection vulnerabilities. If you're testing authentication-related parts
   of the request, unexpected 200 or 201 status codes may signify a potential authorization bypass vulnerability.

   c. **Response time**: Unusually long or distinctly short response times may indicate DoS attacks or sleep-related injection
   flaws, such as time-based blind SQL injection attacks. To configure the results table, click on the **Columns** menu and select
   **Response received** or **Response completed**.

## Various Burp Intruder tips

1. <mandy>[Create a specific resource pool](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/resource-pool)
for Intruder attacks so that the scanner and Intruder are not competing against each other for workers to issue the requests.</mandy>

2. By default, a Burp Intruder URL encodes specific characters within the final payload.
Consider running the attack twice—with enabled and disabled payload encoding. Refer to [Burp Intruder payload processing](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/processing#:~:text=Configuring%20payload%20encoding)
to see how to configure payload encoding.

3. The [Hackvertor](https://portswigger.net/bappstore/65033cbd2c344fbabe57ac060b5dd100) extension allows you to use tags that
will escape and encode input in various ways. You can place `§§` characters inside a Hackvertor tag—for example,
`<@jwt('HS256','secret')>§payload§<@/jwt>`

4. Extension-generated payload types exist
(e.g., from [Freddy, Deserialization Bug Finder](https://portswigger.net/bappstore/ae1cce0c6d6c47528b4af35faebc3ab3)). You can
choose them in the **Payloads** tab in Burp Intruder by selecting **Extension-generated** in the **Payload type** drop-down menu
and then choosing the specific payload setting, as shown in figure 4:

   {{< resourceFigure "extension-generated.png" >}}
   The **Payloads** tab when configuring an attack in Burp Intruder.
   {{< / resourceFigure >}}

5. You can use the [Recursive grep](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types#:~:text=WIENER%0APeter%20wiener-,Recursive%20grep,-This%20enables%20you)
payload type to extract text from the response to the previous request and use that text as the payload for the current request.
See the [NahamCon2023: Bug Bounty Village workshop](https://youtu.be/rM61brpBV48?t=9199) (starts at 2:33:19) for an example configuration.
<mandy>
6. Always run attacks in temporary project mode (do not click [save attack in the attack configuration](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/settings#:~:text=Intruder%20settings.-,Save%20attack,-Professional)),
and then [save the attack to the project file](https://portswigger.net/burp/documentation/desktop/tools/intruder/results/saving-attacks)
if you want to preserve the results afterward.

7. [Intruder can automatically generate collaborator payloads](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types#:~:text=processing%20rule.-,Collaborator%20payloads,-This%20generates%20and)
in both a payload source and post-payload processing. If interactions are found after the attack has finished,
it will update the results with the interaction count and raise the issue in the Event log,
providing that the attack has not been deleted.

{{< resourceFigure "collabo-event-log.png" >}}
An issue raised in the Event log upon a collaborator payload interaction
{{< / resourceFigure >}}

{{< resourceFigure "collabo-interaction-column.png" >}}
The Interactions column in Burp Intruder attack upon a collaborator payload interaction
{{< / resourceFigure >}}

</mandy>
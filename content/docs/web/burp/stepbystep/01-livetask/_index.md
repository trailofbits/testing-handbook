---
title: "Live task"
slug: livetask
summary: "Live tasks process traffic from specific Burp Suite tools and perform defined actions."
weight: 10
url: docs/web/burp/guide/livetask
---
<!-- markdownlint-disable first-line-h1 -->
## First run with a live task
<!-- markdownlint-restore -->
{{< hint info >}}
Ensure you have enabled extensions from the [Enabling extensions]({{% relref "docs/web/burp/stepbystep/#enabling-extensions" %}}) step.
{{< /hint >}}

[Live tasks](https://portswigger.net/burp/documentation/desktop/tutorials/using-live-tasks) process traffic from specific
Burp Suite tools (e.g., Burp Proxy, Burp Repeater, Burp Intruder) and perform
defined actions. In the live task strategy, we set up the live active Burp Scanner task to grab the proxied traffic
when we visit the website and automatically send it to Burp Scanner. Follow these steps to set up Burp to automatically
scan proxied requests:

1. Open **Dashboard** and click **New live task**.
2. Under **Tools scope**, select **Proxy**.
3. In **URL scope**, select **Suite scope**.
4. Check the **Ignore duplicate items based on URL and parameter names** box. This option ensures that Burp Suite avoids scanning
the same request multiple times. More specifically, it prevents Burp Suite from repeatedly scanning requests that share the same
URL and parameter names, regardless of their parameter values.

    Here's an example to illustrate:

    * Consider a scenario where your application has a profile page for a user, accessed via the URL
    `http://example.com/profile?id=1234`. When browsing the application, you might visit this URL multiple times with different
    `id` values (e.g., `?id=1234`, `?id=2345`, etc.).

    With **Ignore duplicate items based on URL and parameter names** checked, Burp Suite will scan this URL only once,
    regardless of the different `id` values you use. It treats all these requests (`http://example.com/profile?id=1234`,
    `http://example.com/profile?id=2345`, etc.) as duplicates based on their common URL `/profile` and the `id` parameter name.
    This helps prevent unnecessary redundancy in the scanning process, which in turn can save valuable time.

5. Go to **Scan configuration**, click on the **Select from library** button, and select **Audit coverage - maximum** to
have the most comprehensive scan possible. For more information, see [Built-in configurations](https://portswigger.net/burp/documentation/scanner/scan-configurations/burp-scanner-built-in-configs).
6. Optionally, you can adjust the number of concurrent requests on the target at any time.
For more information, see [Managing resource pools for scans](https://portswigger.net/burp/documentation/desktop/automated-scanning/managing-resource-pools).

Then, open the embedded Burp browser and go through your website carefully; try to visit every nook and cranny of your website.
You can see detailed information and specific requests in **Tasks** > **Live audit from Proxy (suite)**.

Use the [**Logger**](https://portswigger.net/burp/documentation/desktop/tools/logger/getting-started) tab and observe how
the scanning works under the hood and how your application reacts to potentially malicious requests. Be cautious where the
application scans the sign-out API calls (e.g., `/logout`) to ensure your session will not be terminated and result in many of
your requests ending in HTTP “401 Unauthorized” errors. Also, take care that the web application firewall (WAF) does not block you
out or Burp does not send too many requests in a given time, which may result in the HTTP “429 Too Many Requests” response
status code. To prevent issues with excessive traffic from Burp, see [automatic throttling](https://portswigger.net/burp/documentation/desktop/settings/project/tasks#:~:text=requests%20are%20sent.-,Automatic%20throttling,-%2D%20Specify%20the%20response).

{{< hint danger >}}
Remember that using an active Burp Scanner can have disruptive effects on the website, such as data loss.
{{< /hint >}}

Also, check whether Burp accurately processes the application’s requests. For example, some applications need
the HMAC SHA-256 signature of the current request in a custom header—otherwise, the server responds with an error.
Other web applications are scrupulous in handling CSRF tokens (e.g., via the `X-CSRF-Token` header)—otherwise,
they respond with an error too. If the application’s requests are not handled correctly, you can miss the accuracy
of testing. See more in the
[Ensure your app handling works correctly section]({{% relref "docs/web/burp/stepbystep/03-ensure-working-correctly/" %}}).

## Where are the results?

Mainly, you will find identified issues raised by the live scans in the **Dashboard** > **Tasks** activity.
Review reported issues carefully and pay particular attention to high-severity and certain confidence issues.

Also, it’s crucial to look at nonstandard responses when using different Burp tools—in particular, the following:

   1. Check the **Logger** tab (consider extending the limit of the memory used—see [Working with Burp Logger entries](https://portswigger.net/burp/documentation/desktop/tools/logger/settings#:~:text=were%20actually%20captured.-,Capture%20limit,-You%20can%20specify)).

      a. Nonstandard error HTTP responses (e.g., 500, 502) that can indicate the need for further digging

      b. Potential error messages and stack traces

      c. Success status responses (e.g., “200 OK”) for requests that should not pass the authorization mechanism

      d. 302 and 301 status responses for any potential [open redirection](https://portswigger.net/kb/issues/00500100_open-redirection-reflected)
      issues

   2. When you work from the white-box perspective, look at the application logs and try to identify any potential crashes,
   panics, or log injections (see [CRLF injection](https://book.hacktricks.xyz/pentesting-web/crlf-0d-0a) and [IP spoofing](https://portswigger.net/kb/issues/00400110_spoofable-client-ip-address)).

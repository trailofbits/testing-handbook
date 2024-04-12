---
title: "Step-by-step guide: rapidly mastering Burp to test your app"
slug: rapidlymaster
summary: "This section gives you a step-by-step guide to rapidly mastering Burp to test your app."
weight: 10
---

# Step-by-step guide: rapidly mastering Burp to test your app

## Installation and first steps

For the first steps, refer to the official documentation on
[installing and licensing Burp Suite Professional](https://portswigger.net/burp/documentation/desktop/getting-started/download-and-install)
on your system.

## Preparing the proxy

To launch Burp's embedded browser based on Chromium, select the **Proxy** > **Intercept** tab and click the **Open browser** button.
Before proceeding, get familiar with [Proxy intercept](https://portswigger.net/burp/documentation/desktop/tools/proxy/intercept-messages).

If you want to configure an external browser other than Chromium (e.g., Firefox or Safari), refer to the **official documentation**.

## First run of your target web application in Burp

1. Open your web application using the embedded Burp browser. Go through the largest number of functionalities you want to cover,
   such as logging in, signing up, and visiting possible features and panels.
2. [Add your targets to your scope](https://portswigger.net/burp/documentation/desktop/getting-started/setting-target-scope#:~:text=Step%204%3A%20Set%20the%20target%20scope).
   Narrowing down specific domains in the **Target tab** allows you to control what’s tested.

   a. Consider stopping Burp from sending out-of-scope items to the history. A pop-up will be shown with the text,
   “‘Do you want Burp Proxy to stop sending out-of-scope items to the history or other Burp tools?” Choose one of the following options:

   * Click **Yes** if you are sure you have chosen all possible domains. This will help you avoid sending potentially malicious requests
     to unforeseen hosts. This way, you can configure Burp Scanner to actively attack targets only from the configured scope.
   * Click **No** if it’s your first run and you are unsure about potential underlying requests to the specific domains.
     This will help you gain a more thorough overview of what’s going on in your application.

    b. For more information on configuring the scope, see [Scope](https://portswigger.net/burp/documentation/desktop/tools/target/scope).

3. Once you configure the scope, briefly look at Burp Proxy and what’s happening in the intercepted traffic.

   a. When you go through the application with Burp attached, many unwanted requests (e.g., to fonts.googleapis.com)
   can crop up in the **Intercept** tab.

   b. To turn off intercepting the uninteresting host, click on the intercepted request in the **Interception** tab, right-click,
   and then choose **Don’t intercept requests** > **To this host**. Burp will then automatically forward requests to the marked host.

   c. Keep in mind that if you selected **No** when asked in the previous step (“Do you want Burp Proxy to stop sending out-of-scope
   items to the history or other Burp tools?”), you could see a lot of out-of-scope (“unwanted”) items.

{{< hint info >}}
Important hot key: By default, **Ctrl+F** forwards the current HTTP request in the Burp Intercept feature.
{{< /hint >}}

## Enabling extensions

Extensions can be added to Burp to enhance its capabilities in finding bugs and automating
various tasks. For in-depth information on installing the Burp extensions that we will cover in this section,
refer to [Installing extensions](https://portswigger.net/burp/documentation/desktop/extensions/installing-extensions).

Some extensions fall under the category of “turn on and forget.” They are mostly designed to automatically run on each
Burp Scanner task without user interaction, with results appearing in the **Issue activity** pane of the **Dashboard** tab.
We generally recommend the following extensions, which should apply to most web applications:

1. [**ActiveScan++**](https://portswigger.net/bappstore/3123d5b5f25c4128894d97ea1acc4976) enhances the default active and
passive scanning capabilities of Burp Suite.
It adds checks for vulnerabilities that the default Burp Scanner might miss.
2. [**Backslash Powered Scanner**](https://portswigger.net/bappstore/9cff8c55432a45808432e26dbb2b41d8) extends the active
scanning capability by trying to identify known and unknown classes
of server-side injection vulnerabilities.
3. [**Software Vulnerability Scanner**](https://portswigger.net/bappstore/c9fb79369b56407792a7104e3c4352fb) integrates with
Burp Suite to automatically identify known software vulnerabilities in web applications.
4. [**Freddy, Deserialization Bug Finder**](https://portswigger.net/bappstore/ae1cce0c6d6c47528b4af35faebc3ab3) helps detect
and exploit serialization issues in libraries and APIs (e.g., .NET and Java).
5. [**J2EEScan**](https://portswigger.net/bappstore/7ec6d429fed04cdcb6243d8ba7358880) improves the test coverage during
web application penetration tests on J2EE applications.
6. [**403 Bypasser**](https://portswigger.net/bappstore/444407b96d9c4de0adb7aed89e826122) attempts to bypass HTTP 403 Forbidden
responses by changing request methods and altering headers.

Some of the above extensions need
[Jython or JRuby](https://portswigger.net/burp/documentation/desktop/extensions/installing-extensions#:~:text=Installing%20Jython%20or%20JRuby)
configured in Burp.

{{< hint warning >}}
<mandy>Because of the performance impact of enabling too many extensions, you should only enable extensions that you are actively
using. We encourage you to periodically review your currently enabled extensions and unload any that you don't currently use.
{{< /hint >}}

## First run with a live task

{{< hint info >}}
Ensure you have enabled extensions from the [Enabling extensions](#enabling-extensions) step.
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
    `http://example.com/profile?id=2345`, etc.) as duplicates based on their common URL /profile and the id parameter name.
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

{{< hint warning >}}
Remember that using an active Burp Scanner can have disruptive effects on the website, such as data loss.
{{< /hint >}}

Also, check whether Burp accurately processes the application’s requests. For example, some applications need
the HMAC SHA-256 signature of the current request in a custom header—otherwise, the server responds with an error.
Other web applications are scrupulous in handling CSRF tokens (e.g., via the `X-CSRF-Token` header)—otherwise,
they respond with an error too. If the application’s requests are not handled correctly, you can miss the accuracy
of testing. See more in the <mandy>[Ensure your app handling works correctly section]().

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

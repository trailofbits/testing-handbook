---
title: "Step-by-step guide: rapidly mastering Burp to test your app"
slug: guide
summary: "This section gives you a step-by-step guide to rapidly mastering Burp to test your app."
weight: 10
url: docs/web/burp/guide
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

1. [**Active Scan++**](https://portswigger.net/bappstore/3123d5b5f25c4128894d97ea1acc4976) enhances the default active and
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
Because of the performance impact of enabling too many extensions,
you should enable only extensions that you are actively using.
We encourage you to periodically review your enabled extensions and unload any that you don't currently use.
{{< /hint >}}

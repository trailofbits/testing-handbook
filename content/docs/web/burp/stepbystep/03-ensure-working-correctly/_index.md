---
title: "Ensure your app handling works correctly"
slug: app-handling
summary: "It’s essential to prepare Burp to handle your target application if you want the best results when using Burp’s automatic scanning capabilities. This way, you will not miss proper functionality testing because of application errors, which will allow you to find more bugs."
weight: 30
---

# Ensure your app handling works correctly

It’s essential to prepare Burp to handle your target application if you want the best results when using Burp’s automatic scanning
capabilities. This way, you will not miss proper functionality testing because of application errors,
which will allow you to find more bugs.

Remember these aspects when using Burp’s automated tools (such as Burp Scanner):

1. **Session handling**. Ensure that Burp handles sessions properly, refreshes cookies if needed,
and updates any necessary headers per request (e.g., some web applications require requests to be signed).
Also, ensure that Burp does not silently invalidate sessions during active scanning by sending a request to sign out.
To address these cases, you may need to configure session handling rules. For more information, refer to the following resources:

    - [Maintaining an authenticated session](https://portswigger.net/burp/documentation/desktop/testing-workflow/session-management/maintaining-authenticated-session)

    - [Session handling rule editor](https://portswigger.net/burp/documentation/desktop/settings/sessions/session-handling-rules)

2. **Anti-CSRF tokens**. Using Burp against a web application that uses [anti-CSRF tokens](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#token-based-mitigation)
can cause problems because the application should not allow a request to be resent without updating the anti-CSRF token.
Usually, you should be able to update anti-CSRF tokens with session handling rules; for more information,
see [Using Burp's Session Handling Rules with anti-CSRF Tokens](https://portswigger.net/support/using-burp-suites-session-handling-rules-with-anti-csrf-tokens).

3. **Throttling**. Ensure that using Burp does not return an HTTP “429 Too Many Requests” status code or similar.
Generally, Burp has a feature to [handle automatic throttling](https://portswigger.net/burp/documentation/desktop/settings/project/tasks#:~:text=Automatic%20throttling%20%2D%20Specify%20the%20response,429%20(Too%20many%20requests))
when tackling a specific status code. However, there may be other ways the application informs you about exceeded traffic.
If possible, turn off throttling on the server side for the duration of the tests and adjust throttling accordingly.
Still, if you need to bypass throttling, you can use the [IP Rotate](https://portswigger.net/bappstore/2eb2b1cb1cf34cc79cda36f0f9019874)
extension.

4. **WAF**. Ensure that a WAF does not block your requests if one is in place.
If it does, try to allowlist your IP address or bypass it using the [Bypass WAF](https://portswigger.net/bappstore/ae2611da3bbc4687953a1f4ba6a4e04c)
extension.

Sometimes there are edge cases where standard Burp features (like macros) or existing extensions do not solve the above problems.
In those cases, you need to create a custom extension. You can find more information on developing custom extensions in
[Creating Burp extensions](https://portswigger.net/burp/documentation/desktop/extensions/creating).

Although the initial investment in setting up Burp Suite, including configuring standard features, handling macros,
and creating custom extensions, may seem time-consuming, the payoff is often substantial. From our experience at Trail of Bits,
the teams that put in the effort to fully customize and orchestrate Burp Suite to navigate complex applications tend to uncover
significantly more security vulnerabilities.

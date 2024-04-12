---
title: "Additional Burp Best Practices and Tips"
slug: tips
weight: 20
---

# Additional Burp Best Practices and Tips

## Searching for a specific string in all of Burp Suite

Let’s say you need to find a certain value or error string, but you can’t remember where you saw it (i.e., in which Burp tool).
Was it in Burp Repeater, Burp Scanner, Burp Target? To find it, use the global search in Burp Suite (accessible via **Burp** > **Search**):

{{< resourceFigure "burp-search.png" >}}
The context menu to invoke the Burp Suite **Search** function
{{< / resourceFigure >}}

{{< resourceFigure "global-search.png" >}}
The global **Search** function in Burp
{{< / resourceFigure >}}

## Testing for race condition issues

Race conditions occur when the timing or ordering of events affects a system's behavior. In the context of web applications,
a race condition could occur if the application's security decisions depend on the sequence or timing of processed requests.
You can learn more about race condition issues on the [PortSwigger website](https://portswigger.net/web-security/race-conditions).

### Using Burp Repeater to test for race conditions

To conveniently detect race conditions, Burp allows you to group multiple requests and send them in a short time window.
So you can prepare multiple requests in Burp Repeater, send them almost simultaneously, and observe the system's behavior.
To group multiple requests in Burp Repeater, click the **+** sign and select **Add tab**:


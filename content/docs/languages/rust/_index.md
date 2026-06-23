---
title: "Rust"
slug: lang-rust
weight: 1
bookCollapseSection: true
---

# Rust security

Rust is a multi-paradigm, general-purpose, memory-safe programming language.

{{< rawHtml >}}
<!-- markdownlint-disable-next-line MD033 -->
<div id="rust-banner-code">
{{< highlight rust >}}
fn main(){unsafe{(|f:&dyn Fn(u128)->Box<dyn Iterator<Item=char>+'static>|f(0x315214c3639feaf55946ee9e32u128).for_each(|c|print!("{c}")))(Box::leak(Box::new(|mut n|Box::new((0..0xD).map(move|_|{let c=char::from_u32_unchecked(((n%251)^0x1F)as _);n/=251;c}))as _)))}}
{{< /highlight >}}
</div>
{{< /rawHtml >}}

Start your review with our [rust-review](https://github.com/trailofbits/skills/tree/main/plugins/rust-review) skill. It covers basic issues.

{{< section >}}

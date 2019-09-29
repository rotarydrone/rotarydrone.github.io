---
layout: page
title: CTF Writeups
---

<section>
<h3>CTF Writeups</h3>
{% for post in site.categories.ctf %}
 <li><span>{{ post.date | date_to_string }}</span> &nbsp; <a href="{{ post.url }}">{{ post.title }}</a></li>
{% endfor %}
</section>
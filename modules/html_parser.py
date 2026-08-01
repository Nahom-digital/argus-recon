"""
Module 4 · HTML / DOM parser.

Built on BeautifulSoup + lxml but goes further than a plain link scrape. Per
page it extracts:

  * every <form> (absolute action, method, enctype) with its input/select/
    textarea fields, defaults, and whether the field is hidden
  * every <button>/<input>/<a role=button> with name, id, value, text,
    onclick and all data-* attributes (feeds button->request mapping)
  * every <a href>
  * favicon and every <img> (src, srcset, alt, name)
  * meta tags (name/property -> content) and generator
  * HTML comments (kept verbatim; also mined for URLs)
  * inline event-handler URLs and inline <script> bodies (handed to js_parser)

Returned as a plain dict so the crawler and graph loader can consume it without
importing bs4.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

from bs4 import BeautifulSoup, Comment

from .util import normalize_url

# URLs embedded in attribute values / comments / handlers.
_URL_RX = re.compile(r"""(?:(?:https?:)?//[^\s'"<>()]+|/[A-Za-z0-9_\-./]+(?:\?[^\s'"<>()]*)?)""")
_FORM_FIELD_TAGS = ("input", "select", "textarea")


def _abs(base: str, val: str | None) -> str | None:
    if not val:
        return None
    return normalize_url(val, base)


def _data_attrs(tag) -> dict:
    return {k: v for k, v in tag.attrs.items()
            if k.startswith("data-") and isinstance(v, str)}


def _field_from_tag(tag) -> dict:
    name = tag.get("name") or tag.get("id") or ""
    ftype = (tag.get("type") or ("select" if tag.name == "select"
             else "textarea" if tag.name == "textarea" else "text")).lower()
    return {
        "name": name,
        "id": tag.get("id"),
        "type": ftype,
        "value": (tag.get("value") or "")[:120],
        "placeholder": tag.get("placeholder"),
        "required": tag.has_attr("required"),
        "hidden": ftype == "hidden" or tag.get("type") == "hidden",
        "autocomplete": tag.get("autocomplete"),
    }


def parse(html: str, base_url: str) -> dict:
    soup = BeautifulSoup(html or "", "lxml")

    out = {
        "forms": [], "buttons": [], "links": [], "resources": [],
        "images": [], "favicon": None, "meta": [], "comments": [],
        "inline_scripts": [], "handler_urls": [],
    }

    # ---- forms ----------------------------------------------------------- #
    for form in soup.find_all("form"):
        action = _abs(base_url, form.get("action")) or base_url
        fields = [_field_from_tag(t) for t in form.find_all(_FORM_FIELD_TAGS)
                  if (t.get("name") or t.get("id"))]
        # buttons inside the form also count as interaction points
        for b in form.find_all("button"):
            if b.get("name"):
                fields.append(_field_from_tag(b) if b.name in _FORM_FIELD_TAGS
                              else {"name": b.get("name"), "type": "button",
                                    "value": (b.get("value") or "")[:120],
                                    "hidden": False})
        out["forms"].append({
            "action": action,
            "method": (form.get("method") or "GET").upper(),
            "enctype": form.get("enctype") or "application/x-www-form-urlencoded",
            "id": form.get("id"),
            "name": form.get("name"),
            "fields": fields,
        })

    # ---- buttons & clickables ------------------------------------------- #
    for tag in soup.find_all(["button", "a", "input"]):
        is_button = (tag.name == "button"
                     or (tag.name == "input" and (tag.get("type") or "").lower()
                         in ("button", "submit", "image", "reset"))
                     or (tag.name == "a" and tag.get("role") == "button")
                     or tag.get("onclick"))
        if not is_button:
            continue
        out["buttons"].append({
            "tag": tag.name,
            "type": (tag.get("type") or "").lower() or None,
            "name": tag.get("name"),
            "id": tag.get("id"),
            "value": (tag.get("value") or "")[:120],
            "text": tag.get_text(strip=True)[:80] if tag.name != "input" else None,
            "onclick": tag.get("onclick"),
            "href": _abs(base_url, tag.get("href")) if tag.name == "a" else None,
            "data": _data_attrs(tag),
        })

    # ---- anchors --------------------------------------------------------- #
    for a in soup.find_all("a", href=True):
        u = _abs(base_url, a["href"])
        if u:
            out["links"].append(u)

    # ---- scripts & stylesheets & other src'd resources ------------------ #
    for s in soup.find_all("script"):
        src = s.get("src")
        if src:
            u = _abs(base_url, src)
            if u:
                out["resources"].append({"url": u, "kind": "script"})
        elif s.string and s.string.strip():
            out["inline_scripts"].append(s.string)
    for link in soup.find_all("link", href=True):
        rel = " ".join(link.get("rel", [])).lower()
        u = _abs(base_url, link["href"])
        if not u:
            continue
        if "icon" in rel:
            out["favicon"] = out["favicon"] or u
        else:
            out["resources"].append({"url": u, "kind": "stylesheet" if "stylesheet" in rel else "link"})
    for tag in soup.find_all(src=True):
        if tag.name in ("script", "img"):
            continue
        u = _abs(base_url, tag.get("src"))
        if u:
            out["resources"].append({"url": u, "kind": tag.name})

    # ---- images ---------------------------------------------------------- #
    for img in soup.find_all("img"):
        src = _abs(base_url, img.get("src"))
        srcset = []
        if img.get("srcset"):
            for part in img["srcset"].split(","):
                cand = _abs(base_url, part.strip().split(" ")[0])
                if cand:
                    srcset.append(cand)
        if src or srcset:
            out["images"].append({
                "src": src, "srcset": srcset,
                "alt": img.get("alt"), "name": img.get("name") or img.get("id"),
            })

    if not out["favicon"]:
        out["favicon"] = normalize_url("/favicon.ico", base_url)

    # ---- meta tags ------------------------------------------------------- #
    for m in soup.find_all("meta"):
        key = m.get("name") or m.get("property") or m.get("http-equiv")
        if key and m.get("content"):
            out["meta"].append({"key": key, "content": m.get("content")[:300]})

    # ---- comments (+ URLs inside them) ----------------------------------- #
    for c in soup.find_all(string=lambda t: isinstance(t, Comment)):
        text = str(c).strip()
        if text:
            out["comments"].append(text[:500])

    # ---- inline event-handler URLs -------------------------------------- #
    handler_attrs = ("onclick", "onsubmit", "onload", "onchange", "onmouseover")
    for tag in soup.find_all(True):
        for ha in handler_attrs:
            if tag.get(ha):
                for u in _URL_RX.findall(tag[ha]):
                    au = normalize_url(u, base_url)
                    if au:
                        out["handler_urls"].append(au)

    # de-dup lists that can repeat
    out["links"] = list(dict.fromkeys(out["links"]))
    out["handler_urls"] = list(dict.fromkeys(out["handler_urls"]))
    seen = set()
    res = []
    for r in out["resources"]:
        if r["url"] not in seen:
            seen.add(r["url"])
            res.append(r)
    out["resources"] = res
    return out

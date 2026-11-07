"""Build a labelled sample dataset of URLs for training/testing.

    python ml/build_dataset.py            -> ml/data/urls.csv

IMPORTANT: the phishing URLs produced here are *synthetic* - they are generated
from patterns documented in phishing research (look-alike domains, brand in
subdomain, '@' tricks, IP hosts, free hosting, etc.). They do not point to real
live phishing sites. Legitimate URLs use real, well-known domains with
realistic paths, including tricky legitimate cases (hyphenated brands, login
pages, country domains) to measure false positives.

For a stronger evaluation, download a public dataset (e.g. PhiUSIIL from the UCI
repository, PhishTank / OpenPhish exports, or Tranco top sites) and save it as a
CSV with columns ``url,label`` (label 1 = phishing, 0 = legitimate). The
training and evaluation scripts accept any such file via ``--data``.
"""
from __future__ import annotations

import argparse
import csv
import os
import random
import string

HERE = os.path.dirname(os.path.abspath(__file__))

LEGIT_DOMAINS = [
    # global sites
    "www.google.com", "mail.google.com", "drive.google.com", "www.youtube.com",
    "www.facebook.com", "www.instagram.com", "web.whatsapp.com", "twitter.com",
    "www.linkedin.com", "www.microsoft.com", "login.microsoftonline.com",
    "outlook.live.com", "www.apple.com", "support.apple.com", "www.icloud.com",
    "www.amazon.com", "www.amazon.co.uk", "www.netflix.com", "www.paypal.com",
    "en.wikipedia.org", "github.com", "gist.github.com", "stackoverflow.com",
    "www.reddit.com", "news.ycombinator.com", "www.bbc.co.uk", "www.bbc.com",
    "edition.cnn.com", "www.nytimes.com", "www.theguardian.com", "docs.python.org",
    "pypi.org", "developer.mozilla.org", "www.w3schools.com", "www.coursera.org",
    "www.khanacademy.org", "www.udemy.com", "medium.com", "dev.to",
    "www.dropbox.com", "zoom.us", "slack.com", "open.spotify.com",
    "www.ebay.com", "www.etsy.com", "www.walmart.com", "www.target.com",
    "www.bestbuy.com", "www.ikea.com", "www.booking.com", "www.airbnb.com",
    "www.tripadvisor.com", "www.imdb.com", "www.twitch.tv", "www.tiktok.com",
    "www.pinterest.com", "www.quora.com", "www.chase.com", "www.wellsfargo.com",
    "www.bankofamerica.com", "www.hsbc.co.uk", "www.binance.com", "www.coinbase.com",
    "store.steampowered.com", "steamcommunity.com", "www.adobe.com", "www.canva.com",
    "www.figma.com", "www.notion.so", "trello.com", "www.atlassian.com",
    "www.salesforce.com", "www.oracle.com", "www.ibm.com", "www.intel.com",
    "www.nvidia.com", "www.samsung.com", "www.dell.com", "www.hp.com",
    "www.lenovo.com", "www.cloudflare.com", "aws.amazon.com", "azure.microsoft.com",
    "cloud.google.com", "www.digitalocean.com", "www.heroku.com", "vercel.com",
    "www.nasa.gov", "www.irs.gov", "www.usa.gov", "www.gov.uk", "www.who.int",
    "www.un.org", "www.harvard.edu", "web.mit.edu", "www.stanford.edu",
    "www.ox.ac.uk", "www.cam.ac.uk",
    # Pakistan / regional
    "www.daraz.pk", "www.dawn.com", "www.geo.tv", "www.hbl.com", "www.meezanbank.com",
    "www.easypaisa.com.pk", "www.jazzcash.com.pk", "www.nadra.gov.pk", "www.hec.gov.pk",
    "nust.edu.pk", "www.comsats.edu.pk", "pu.edu.pk", "www.lums.edu.pk",
    "www.fbr.gov.pk", "www.pta.gov.pk", "www.olx.com.pk", "www.zameen.com",
    "www.rozee.pk", "www.foodpanda.pk", "www.ufone.com", "www.jazz.com.pk",
    "www.telenor.com.pk", "www.ptcl.com.pk", "www.ubldigital.com", "www.bankalfalah.com",
    # tricky legitimate: hyphens, digits, country TLDs, uncommon names
    "www.coca-cola.com", "www.t-mobile.com", "www.mercedes-benz.com",
    "www.rolls-royce.com", "www.harley-davidson.com", "www.7-eleven.com",
    "www.3m.com", "www.123rf.com", "www.office.com", "www.google.de",
    "www.amazon.de", "www.amazon.in", "www.bbc.co.uk", "www.sky.com",
    "www.weather.com", "www.accuweather.com", "www.timeanddate.com",
    "www.speedtest.net", "www.archive.org", "www.gutenberg.org", "www.arxiv.org",
    "www.nature.com", "www.sciencedirect.com", "scholar.google.com",
    "www.researchgate.net", "www.ieee.org", "dl.acm.org", "www.springer.com",
    "www.kaggle.com", "huggingface.co", "www.tensorflow.org", "pytorch.org",
    "scikit-learn.org", "flask.palletsprojects.com", "www.djangoproject.com",
    "nodejs.org", "react.dev", "angular.dev", "vuejs.org", "getbootstrap.com",
    "www.mysql.com", "www.postgresql.org", "www.mongodb.com", "redis.io",
    "www.docker.com", "kubernetes.io", "www.jetbrains.com", "code.visualstudio.com",
]

LEGIT_PATHS = [
    "/", "/", "/", "/about", "/contact", "/help", "/login", "/signin", "/account",
    "/search?q=python+tutorial", "/news/technology", "/products", "/blog/2024/05/update",
    "/en-us/", "/docs/getting-started", "/wiki/Computer_security", "/careers",
    "/pricing", "/support/article/12345", "/watch?v=dQw4w9WgXcQ", "/settings/security",
    "/privacy", "/terms", "/cart", "/orders", "/user/profile", "/courses/cs50",
    "/questions/231767/what-does-the-yield-keyword-do", "/r/cybersecurity/",
    "/download", "/en/latest/", "/3/library/urllib.parse.html", "/pulls",
    "/category/electronics?page=2", "/gp/your-account/order-history",
    "/myaccount/summary", "/accounts/login/?next=/dashboard/",
]

BRANDS = [
    ("paypal", "paypal.com"), ("apple", "apple.com"), ("microsoft", "microsoft.com"),
    ("office365", "office.com"), ("outlook", "outlook.com"), ("google", "google.com"),
    ("gmail", "gmail.com"), ("amazon", "amazon.com"), ("facebook", "facebook.com"),
    ("instagram", "instagram.com"), ("whatsapp", "whatsapp.com"), ("netflix", "netflix.com"),
    ("linkedin", "linkedin.com"), ("dropbox", "dropbox.com"), ("docusign", "docusign.com"),
    ("dhl", "dhl.com"), ("fedex", "fedex.com"), ("usps", "usps.com"), ("chase", "chase.com"),
    ("wellsfargo", "wellsfargo.com"), ("bankofamerica", "bankofamerica.com"),
    ("hsbc", "hsbc.com"), ("binance", "binance.com"), ("coinbase", "coinbase.com"),
    ("metamask", "metamask.io"), ("steam", "steampowered.com"), ("ebay", "ebay.com"),
    ("yahoo", "yahoo.com"), ("easypaisa", "easypaisa.com.pk"), ("jazzcash", "jazzcash.com.pk"),
    ("hbl", "hbl.com"), ("meezan", "meezanbank.com"), ("icloud", "icloud.com"),
    ("adobe", "adobe.com"), ("telegram", "telegram.org"),
]

LURE_WORDS = ["login", "signin", "verify", "secure", "account", "update", "confirm",
              "support", "billing", "unlock", "recovery", "auth", "wallet", "security",
              "service", "online", "portal", "help", "alert", "id", "web", "my"]
BAD_TLDS = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "online", "site",
            "live", "click", "info", "icu", "cyou", "shop", "support", "vip", "buzz"]
OK_TLDS = ["com", "net", "org", "co", "info", "us", "io"]
FREE_HOSTS = ["000webhostapp.com", "weebly.com", "wixsite.com", "firebaseapp.com",
              "web.app", "netlify.app", "vercel.app", "glitch.me", "herokuapp.com",
              "blogspot.com", "github.io", "pages.dev", "repl.co", "ngrok-free.app",
              "azurewebsites.net", "square.site", "godaddysites.com", "webflow.io"]
PHISH_PATHS = ["/login", "/signin.php", "/verify/account", "/secure/update.html",
               "/webscr?cmd=_login-run", "/account/confirm", "/billing/update",
               "/auth/session", "/wp-content/plugins/login/index.php", "/recovery",
               "/unlock-account", "/kyc/verify", "/otp", "/claim/prize", "/index.html",
               "/support/ticket", "/password/reset", "/payment/failed", "/"]
HOMOGLYPH_SWAPS = [("o", "0"), ("l", "1"), ("i", "1"), ("e", "3"), ("a", "4"),
                   ("s", "5"), ("m", "rn"), ("w", "vv")]


def rand_str(rng, n, alphabet=string.ascii_lowercase + string.digits):
    return "".join(rng.choice(alphabet) for _ in range(n))


def typo(rng, brand):
    """Produce a look-alike spelling of ``brand``."""
    choice = rng.random()
    if choice < 0.45:
        swaps = [(a, b) for a, b in HOMOGLYPH_SWAPS if a in brand]
        if swaps:
            a, b = rng.choice(swaps)
            idx = [i for i, ch in enumerate(brand) if brand.startswith(a, i)]
            i = rng.choice(idx)
            return brand[:i] + b + brand[i + len(a):]
    if choice < 0.65 and len(brand) > 4:  # drop a letter
        i = rng.randrange(1, len(brand) - 1)
        return brand[:i] + brand[i + 1:]
    if choice < 0.85:  # double a letter
        i = rng.randrange(len(brand))
        return brand[:i] + brand[i] + brand[i:]
    i = rng.randrange(len(brand) - 1)  # swap adjacent letters
    return brand[:i] + brand[i + 1] + brand[i] + brand[i + 2:]


def phishing_url(rng) -> str:
    brand, real = rng.choice(BRANDS)
    lure = rng.choice(LURE_WORDS)
    lure2 = rng.choice(LURE_WORDS)
    scheme = "https" if rng.random() < 0.55 else "http"
    path = rng.choice(PHISH_PATHS)
    technique = rng.randrange(11)
    if technique == 0:      # brand in subdomain of attacker domain
        host = f"{brand}.com.{lure}-{rand_str(rng, 5)}.{rng.choice(BAD_TLDS + OK_TLDS)}"
    elif technique == 1:    # hyphenated brand + lure words
        host = f"{rng.choice(['', 'www.'])}{brand}-{lure}-{lure2}.{rng.choice(BAD_TLDS + OK_TLDS)}"
    elif technique == 2:    # typosquatting
        host = f"{rng.choice(['', 'www.', lure + '.'])}{typo(rng, brand)}.{rng.choice(OK_TLDS + BAD_TLDS)}"
    elif technique == 3:    # IP address host
        ip = ".".join(str(rng.randint(1, 254)) for _ in range(4))
        host = ip + (f":{rng.choice([8080, 8443, 8000, 2083])}" if rng.random() < 0.3 else "")
        path = f"/{brand}/{lure}" + path
    elif technique == 4:    # '@' credential trick
        host = f"{rng.choice(['www.', ''])}{real}@{rand_str(rng, 7, string.ascii_lowercase)}.{rng.choice(BAD_TLDS)}"
    elif technique == 5:    # free hosting with brand in subdomain or path
        if rng.random() < 0.5:
            host = f"{brand}-{lure}-{rand_str(rng, 4)}.{rng.choice(FREE_HOSTS)}"
        else:
            host = f"{rand_str(rng, 8, string.ascii_lowercase)}.{rng.choice(FREE_HOSTS)}"
            path = f"/{brand}/{lure}" + path
    elif technique == 6:    # many subdomains
        host = f"{lure}.{brand}.{lure2}.{rand_str(rng, 6, string.ascii_lowercase)}.{rng.choice(BAD_TLDS + OK_TLDS)}"
    elif technique == 7:    # brand glued with lure, cheap TLD
        host = f"{brand}{lure}{rng.choice(['', str(rng.randint(1, 99))])}.{rng.choice(BAD_TLDS)}"
    elif technique == 8:    # random-looking domain with brand in path
        host = f"{rand_str(rng, rng.randint(10, 16))}.{rng.choice(BAD_TLDS + OK_TLDS)}"
        path = f"/{brand}/{lure}{path}"
    elif technique == 9:    # open redirect on a generic site
        host = f"{rand_str(rng, 6, string.ascii_lowercase)}-{lure}.{rng.choice(OK_TLDS)}"
        path = f"/redirect?url=http://{typo(rng, brand)}.{rng.choice(BAD_TLDS)}/{lure}"
    else:                   # generic credential-harvest domain, no brand
        host = f"{lure}-{lure2}-{rng.choice(['center', 'portal', 'service', 'team', 'desk'])}.{rng.choice(BAD_TLDS + OK_TLDS)}"
    if rng.random() < 0.25:
        path += f"?session={rand_str(rng, 24)}&id={rng.randint(1000, 99999)}"
    return f"{scheme}://{host}{path}"


def legit_url(rng) -> str:
    host = rng.choice(LEGIT_DOMAINS)
    path = rng.choice(LEGIT_PATHS)
    scheme = "https" if rng.random() < 0.95 else "http"
    if rng.random() < 0.1:
        path += ("&" if "?" in path else "?") + f"utm_source=newsletter&utm_medium=email&ref={rng.randint(1, 999)}"
    return f"{scheme}://{host}{path}"


def build(n_each: int, seed: int) -> list[tuple[str, int]]:
    rng = random.Random(seed)
    rows: set[tuple[str, int]] = set()
    while sum(1 for _, y in rows if y == 0) < n_each:
        rows.add((legit_url(rng), 0))
    while sum(1 for _, y in rows if y == 1) < n_each:
        rows.add((phishing_url(rng), 1))
    out = sorted(rows)
    rng.shuffle(out)
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--n", type=int, default=1500, help="URLs per class")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--out", default=os.path.join(HERE, "data", "urls.csv"))
    args = parser.parse_args()
    rows = build(args.n, args.seed)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["url", "label"])
        writer.writerows(rows)
    print(f"Wrote {len(rows)} rows to {args.out}")


if __name__ == "__main__":
    main()

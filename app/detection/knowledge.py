"""Static knowledge used by the feature extractor.

These lists are deliberately small and readable so they can be explained in
the project report and extended by the administrator/developer.
"""

# Public-suffix entries made of two labels. Used to find the *registered*
# domain (e.g. "bank.com.pk" -> registered domain "bank.com.pk", not "com.pk").
MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk",
    "com.pk", "net.pk", "org.pk", "edu.pk", "gov.pk", "gob.pk", "web.pk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.in", "net.in", "org.in", "ac.in", "gov.in",
    "com.br", "net.br", "org.br", "gov.br",
    "co.jp", "ne.jp", "or.jp", "ac.jp",
    "co.nz", "org.nz", "co.za", "org.za", "gov.za",
    "com.cn", "net.cn", "org.cn", "com.sg", "com.my", "com.tr", "com.mx",
    "com.ar", "com.sa", "com.eg", "com.ng", "co.ke", "com.bd", "com.hk",
    "co.id", "co.kr", "com.tw", "com.ua", "co.il", "com.ph", "com.vn",
}

# TLDs that are cheap/free and statistically over-represented in phishing
# feeds. Being on this list is a weak signal, never proof.
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "online", "site",
    "website", "space", "live", "click", "link", "work", "buzz", "rest",
    "fit", "cyou", "icu", "monster", "quest", "sbs", "cfd", "zip", "mov",
    "country", "kim", "loan", "men", "date", "download", "review", "win",
    "bid", "stream", "racing", "party", "trade", "accountant", "science",
    "gdn", "support", "help", "shop", "vip",
}

# Words frequently used to create urgency or imitate login/payment flows.
SUSPICIOUS_KEYWORDS = [
    "login", "log-in", "signin", "sign-in", "logon", "verify", "verification",
    "validate", "secure", "security", "account", "update", "confirm",
    "banking", "password", "passwd", "credential", "wallet", "suspend",
    "suspended", "locked", "unlock", "restore", "recover", "billing",
    "invoice", "payment", "webscr", "cmd=_login", "ebayisapi", "auth",
    "authenticate", "reset", "unusual", "alert", "limited", "support",
    "helpdesk", "refund", "claim", "prize", "winner", "free-gift", "bonus",
    "kyc", "otp", "2fa",
]

# Brands that attackers commonly impersonate, mapped to the registered domains
# they actually own. A brand name appearing anywhere else is suspicious.
BRANDS = {
    "paypal": {"paypal.com", "paypal.me", "paypalobjects.com"},
    "apple": {"apple.com", "icloud.com", "apple.co"},
    "icloud": {"icloud.com", "apple.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "microsoftonline.com", "outlook.com", "azure.com", "bing.com", "msn.com"},
    "office365": {"office.com", "microsoft.com", "office365.com"},
    "outlook": {"outlook.com", "live.com", "microsoft.com"},
    "google": {"google.com", "google.com.pk", "google.co.uk", "googleapis.com", "gstatic.com", "youtube.com", "gmail.com", "goo.gl", "googleusercontent.com"},
    "gmail": {"gmail.com", "google.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.in", "amazon.de", "amazonaws.com", "amazon.ae", "amzn.to"},
    "facebook": {"facebook.com", "fb.com", "fb.me", "facebook.net"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net", "wa.me"},
    "netflix": {"netflix.com"},
    "linkedin": {"linkedin.com", "lnkd.in"},
    "twitter": {"twitter.com", "x.com", "t.co"},
    "dropbox": {"dropbox.com", "dropboxusercontent.com"},
    "adobe": {"adobe.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "dhl": {"dhl.com", "dhl.de"},
    "fedex": {"fedex.com"},
    "usps": {"usps.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "citibank": {"citibank.com", "citi.com"},
    "hsbc": {"hsbc.com", "hsbc.co.uk", "hsbc.com.pk"},
    "binance": {"binance.com"},
    "coinbase": {"coinbase.com"},
    "metamask": {"metamask.io"},
    "steam": {"steampowered.com", "steamcommunity.com"},
    "ebay": {"ebay.com", "ebay.co.uk"},
    "yahoo": {"yahoo.com"},
    "github": {"github.com", "github.io", "githubusercontent.com"},
    "easypaisa": {"easypaisa.com.pk"},
    "jazzcash": {"jazzcash.com.pk"},
    "hbl": {"hbl.com"},
    "meezan": {"meezanbank.com"},
    "telegram": {"telegram.org", "t.me"},
}

# Registered domains of well-known legitimate sites. Matching one lowers the
# score, but tricks such as "@" credentials or IP hosts are still detected.
TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "gmail.com", "facebook.com", "instagram.com",
    "whatsapp.com", "twitter.com", "x.com", "linkedin.com", "microsoft.com",
    "live.com", "office.com", "outlook.com", "apple.com", "icloud.com",
    "amazon.com", "amazon.co.uk", "netflix.com", "paypal.com", "wikipedia.org",
    "github.com", "stackoverflow.com", "reddit.com", "yahoo.com", "bing.com",
    "dropbox.com", "adobe.com", "zoom.us", "slack.com", "spotify.com",
    "ebay.com", "chase.com", "wellsfargo.com", "bankofamerica.com",
    "nytimes.com", "bbc.co.uk", "bbc.com", "cnn.com", "python.org",
    "mozilla.org", "cloudflare.com", "w3schools.com", "coursera.org",
    "edx.org", "khanacademy.org", "hec.gov.pk", "nadra.gov.pk",
    "daraz.pk", "dawn.com", "geo.tv", "hbl.com", "meezanbank.com",
    "easypaisa.com.pk", "jazzcash.com.pk", "binance.com", "coinbase.com",
    "openai.com", "anthropic.com", "medium.com", "quora.com", "twitch.tv",
    "tiktok.com", "pinterest.com", "imdb.com", "booking.com", "airbnb.com",
    "salesforce.com", "oracle.com", "ibm.com", "intel.com", "nvidia.com",
    "samsung.com", "dell.com", "hp.com", "lenovo.com", "steampowered.com",
    "steamcommunity.com", "telegram.org", "docusign.com", "dhl.com",
    "fedex.com", "usps.com", "ups.com", "gov.uk", "irs.gov", "who.int",
    "un.org", "harvard.edu", "mit.edu", "stanford.edu", "nust.edu.pk",
    "comsats.edu.pk", "pu.edu.pk", "fast.edu.pk", "lums.edu.pk",
}

# Every domain a listed brand owns is also considered trusted.
for _owned in BRANDS.values():
    TRUSTED_DOMAINS |= _owned

# Link shorteners hide the real destination.
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "cutt.ly", "shorturl.at", "rebrand.ly", "tiny.cc",
    "rb.gy", "t.ly", "s.id", "v.gd", "qr.ae", "lnkd.in", "trib.al", "shorte.st",
    "clck.ru", "u.to", "soo.gd", "bl.ink", "short.io", "tinyurl.is",
}

# Platforms that host user content. Legitimate, but heavily abused to host
# phishing pages because they come with a free, trusted-looking domain + HTTPS.
FREE_HOSTING_DOMAINS = {
    "000webhostapp.com", "weebly.com", "wixsite.com", "wix.com",
    "firebaseapp.com", "web.app", "netlify.app", "vercel.app", "glitch.me",
    "herokuapp.com", "blogspot.com", "wordpress.com", "github.io",
    "pages.dev", "workers.dev", "repl.co", "replit.app", "ngrok.io",
    "ngrok-free.app", "trycloudflare.com", "azurewebsites.net",
    "appspot.com", "square.site", "godaddysites.com", "webflow.io",
    "carrd.co", "sites.google.com", "forms.gle", "duckdns.org", "no-ip.org",
    "ddns.net", "surge.sh", "framer.website", "notion.site", "jimdosite.com",
    "yolasite.com", "mystrikingly.com", "ipfs.io", "dweb.link",
}

# File types that should never be downloaded from an unexpected link.
RISKY_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".msi", ".apk", ".jar", ".vbs", ".js",
    ".ps1", ".hta", ".dll", ".iso", ".img", ".zip", ".rar", ".7z", ".docm",
    ".xlsm", ".pptm", ".lnk",
}

# Query parameter names that commonly carry an open-redirect target.
REDIRECT_PARAMS = {
    "url", "redirect", "redirect_url", "redirect_uri", "redir", "next",
    "return", "returnurl", "return_url", "goto", "target", "dest",
    "destination", "continue", "out", "link", "to", "r", "u",
}

# Look-alike character substitutions used in typosquatting.
HOMOGLYPHS = [
    ("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"),
    ("4", "a"), ("5", "s"), ("7", "t"), ("8", "b"), ("@", "a"), ("$", "s"),
    ("!", "i"), ("|", "l"),
]

# Endings that only verified organisations can register (government,
# education, military, international bodies). A weak positive signal: such
# sites can still be compromised.
RESTRICTED_TLDS = {
    "gov", "edu", "mil", "int", "gov.pk", "edu.pk", "gov.uk", "ac.uk",
    "gov.au", "edu.au", "gov.in", "ac.in", "gov.br", "ac.jp", "gov.za",
}

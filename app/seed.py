"""Default cybersecurity awareness content, inserted on first start."""
from .extensions import db
from .models import AwarenessArticle

ARTICLES = [
    {
        "title": "What is Phishing?",
        "category": "Basics",
        "icon": "envelope-exclamation",
        "summary": "Phishing is a trick where attackers pretend to be someone you trust "
                   "to steal passwords, money or personal information.",
        "content": """Phishing is a type of **social engineering** attack. Instead of hacking a computer directly, the attacker tricks a person into handing over sensitive information or installing malware.

A phishing message usually pretends to come from a trusted source such as a bank, a delivery company, a university, an employer or a popular website. It then pushes you to click a link, open an attachment or reply with details.

## What attackers want
- Usernames and passwords (email, banking, social media)
- Banking, card or mobile-wallet details
- One-time passwords (OTP) and verification codes
- Personal data such as CNIC/ID numbers and addresses
- Access to your device by getting you to install malware

## Why it works
Phishing relies on emotion rather than technology: **urgency** ("your account will be closed today"), **fear** ("unusual login detected"), **curiosity** ("see who viewed your profile") or **greed** ("you have won a prize").

## The golden rule
If a message asks you to act quickly and enter personal information, stop. Go to the official website or app yourself instead of using the link in the message.""",
    },
    {
        "title": "Common Phishing Techniques",
        "category": "Techniques",
        "icon": "bug",
        "summary": "Email phishing, smishing, vishing, spear phishing, fake login pages "
                   "and QR-code phishing explained.",
        "content": """Attackers use many channels. Knowing the patterns makes them much easier to spot.

## Types of phishing
- **Email phishing** - mass emails that copy the look of real companies.
- **Spear phishing** - targeted messages that use your name, job or recent activity to look convincing.
- **Whaling** - spear phishing aimed at managers and executives.
- **Smishing** - phishing by SMS or WhatsApp, for example fake parcel-delivery or prize messages.
- **Vishing** - phone calls pretending to be your bank or a government office asking for an OTP.
- **Quishing** - QR codes that open a fake website.
- **Clone phishing** - a copy of a real email you received earlier, with the link swapped for a malicious one.

## Tricks used in links
- **Look-alike domains** such as `paypa1.com` or `arnazon.com` (letters swapped for similar ones).
- **Brand in the subdomain** such as `paypal.com.secure-login.xyz` - the real domain is `secure-login.xyz`.
- **The @ trick** such as `https://bank.com@evil.site` - the browser actually opens `evil.site`.
- **Link shorteners** that hide the real destination.
- **Free hosting** pages on site builders that come with HTTPS and a trusted-looking address.
- **Unicode look-alike letters** (homograph attacks) that look identical to normal letters.""",
    },
    {
        "title": "How to Identify Suspicious URLs",
        "category": "Detection",
        "icon": "search",
        "summary": "A step-by-step method to read a web address and find the real "
                   "domain before you click.",
        "content": """The most important skill is finding the **real domain** of a link. Hover over a link (or long-press on mobile) to see the full address before opening it.

## Read the address from right to left
1. Find the first single "/" after "https://". Everything before it is the host name.
2. In the host name, look at the last two parts, for example `example.com` (or three for addresses like `example.com.pk`). That is the real domain owner.
3. Everything to the left of the real domain is a subdomain, which the owner can set to anything - including "paypal" or "your-bank".

## Warning signs
- An IP address instead of a name, such as `http://192.168.4.20/login`
- Misspelled brand names or swapped characters (0 for o, 1 for l, rn for m)
- Many hyphens or many subdomains
- Unusual endings such as .tk, .xyz, .top used for a "bank"
- Words like login, verify, secure, update, suspended in an unknown domain
- An "@" symbol inside the address
- Very long addresses full of random characters
- Shortened links from people you do not know

## Remember
HTTPS and the padlock only mean the connection is encrypted. **Phishing sites use HTTPS too.** The padlock does not tell you who owns the website.""",
    },
    {
        "title": "Safe Browsing Practices",
        "category": "Safe Browsing",
        "icon": "globe",
        "summary": "Everyday habits that keep you safe online on computers and phones.",
        "content": """Good habits stop most attacks before they start.

## Everyday habits
- Type important addresses (bank, university portal, email) yourself or use saved bookmarks.
- Keep your operating system, browser and apps updated - updates fix security holes.
- Only install apps from official stores and check the developer name and reviews.
- Do not download attachments you were not expecting, especially .exe, .apk, .zip or Office files that ask you to "enable macros".
- Be careful on public Wi-Fi; avoid logging into banking on open networks.
- Use the browser's built-in protection (Safe Browsing / SmartScreen) and keep it switched on.
- Log out of shared or public computers and never let the browser save passwords there.

## On social media and messaging apps
- Be careful with "too good to be true" offers, giveaways and job offers.
- A message from a friend can still be fake if their account was hacked - confirm by calling them.
- Never share verification codes with anyone. Real companies will never ask for them.""",
    },
    {
        "title": "Password Security",
        "category": "Passwords",
        "icon": "key",
        "summary": "How to create strong passwords, why reuse is dangerous and how "
                   "password managers help.",
        "content": """A strong, unique password for every account limits the damage if one website is breached or you are phished.

## Creating strong passwords
- Use **long passphrases** of 12+ characters, e.g. four random words with a number.
- Avoid names, birthdays, phone numbers and common words such as "password123".
- Never reuse the same password on different websites.

## Password managers
A password manager generates and remembers unique passwords for you. It also helps against phishing: it will **not auto-fill** your password on a fake look-alike domain, which is a useful warning sign.

## If you think a password was stolen
1. Change it immediately from the official website or app.
2. Change it anywhere else you used the same password.
3. Turn on multi-factor authentication.
4. Check the account for unknown logins, forwarding rules or changed recovery details.""",
    },
    {
        "title": "Multi-Factor Authentication (MFA)",
        "category": "Authentication",
        "icon": "phone",
        "summary": "Why a second step at login protects you even when a password is "
                   "stolen, and which methods are strongest.",
        "content": """Multi-factor authentication (also called 2FA or two-step verification) asks for something **in addition to your password** when you log in.

## Factors
- Something you **know** - a password or PIN
- Something you **have** - your phone, an authenticator app or a security key
- Something you **are** - fingerprint or face recognition

## Which methods are strongest?
1. **Security keys and passkeys** - resist phishing because they only work on the real website.
2. **Authenticator apps** (time-based codes) - much better than SMS.
3. **SMS codes** - better than nothing, but can be intercepted or stolen with SIM-swap fraud.

## Important warning
Attackers now try to steal your MFA code too. **Never type or tell an OTP to anyone** who calls or messages you, and never approve a login prompt that you did not start yourself.""",
    },
    {
        "title": "How to Report Suspicious Links",
        "category": "Reporting",
        "icon": "flag",
        "summary": "What to do if you receive a phishing message or think you fell for "
                   "one.",
        "content": """Reporting phishing protects other people and helps take malicious sites down.

## If you receive a suspicious message
- Do not click links, open attachments or reply.
- Use the **Report phishing / Report spam** button in your email app (Gmail, Outlook) or messaging app.
- At work or university, forward it to your IT/security team as instructed by them.
- Report fake websites to Google Safe Browsing (safebrowsing.google.com/safebrowsing/report_phish) and Microsoft (microsoft.com/wdsi/support/report-unsafe-site).
- Forward phishing emails to the impersonated organisation; many have a dedicated address such as phishing@ or abuse@ on their official website.
- In Pakistan, cyber-crime can be reported to the National Cyber Crime Investigation Agency (NCCIA, formerly FIA Cyber Crime Wing); spam SMS can be reported to PTA.

## If you already clicked or entered details
1. Disconnect and do not enter any more information.
2. Change the affected passwords immediately from the official site.
3. Call your bank using the number on your card if financial details were shared.
4. Turn on MFA and check for unknown activity.
5. Run a security scan if you downloaded a file.
6. Report the incident - acting quickly limits the damage.""",
    },
]


def seed_awareness_content() -> int:
    """Insert default articles when the table is empty. Returns rows added."""
    if AwarenessArticle.query.first() is not None:
        return 0
    for position, data in enumerate(ARTICLES):
        db.session.add(AwarenessArticle(slug=AwarenessArticle.slugify(data["title"]),
                                        position=position, **data))
    db.session.commit()
    return len(ARTICLES)

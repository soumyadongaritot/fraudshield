import re
import math
from collections import Counter

# ── Suspicious Keywords ───────────────────────────────────────────────
SUSPICIOUS_KEYWORDS = [
    'login','secure','verify','update','free','win','prize','claim',
    'urgent','alert','suspended','confirm','banking','password','signin',
    'wallet','recover','blocked','unusual','immediate','refund',
    'validate','authenticate','authorize','action','needed','expire',
    'restrict','limited','locked','disabled','compromised','account',
    'billing','payment','credit','debit','card','bank','otp','cvv',
    'ssn','social','security','number','mother','maiden','dob',
    'giveaway','lucky','selected','winner','congratulations','bonus',
    'reward','promo','coupon','discount','click','here','now','today'
]

# ── Bad TLDs (genuinely high-risk) ───────────────────────────────────
BAD_TLDS = [
    '.tk','.ml','.ga','.cf','.gq','.pw','.cc','.su','.buzz','.fit',
    '.xyz','.top','.win','.bid','.click','.link','.loan','.work',
    '.party','.racing','.review','.science','.date','.faith','.trade',
    '.webcam','.cricket','.accountant','.download','.stream','.gdn',
    '.icu','.cyou','.cfd','.sbs','.monster'
]

# ── Trusted TLDs ─────────────────────────────────────────────────────
TRUSTED_TLDS = [
    '.com','.org','.edu','.gov','.net','.io','.ai','.app','.dev',
    '.co.uk','.ac.in','.co.in','.ac.uk','.gov.in','.gov.uk',
    '.edu.in','.org.in','.co','.us','.ca','.au','.de','.fr',
    '.jp','.uk','.in','.eu','.nz','.sg','.me','.tv',
    '.tech','.online','.site','.store','.shop','.blog','.page'
]

# ── Trusted Domains ───────────────────────────────────────────────────
TRUSTED_DOMAINS = [
    'google.com','gmail.com','youtube.com','drive.google.com',
    'docs.google.com','maps.google.com','accounts.google.com',
    'mail.google.com','cloud.google.com','google.co.in',
    'microsoft.com','office.com','outlook.com','live.com',
    'hotmail.com','azure.microsoft.com','onedrive.live.com',
    'xbox.com','bing.com','account.microsoft.com',
    'apple.com','icloud.com','developer.apple.com','appleid.apple.com',
    'amazon.com','amazon.in','amazon.co.uk','aws.amazon.com',
    'facebook.com','instagram.com','whatsapp.com','meta.com',
    'twitter.com','x.com','linkedin.com','reddit.com',
    'pinterest.com','snapchat.com','tiktok.com','discord.com',
    'twitch.tv','telegram.org','signal.org',
    'netflix.com','spotify.com','hulu.com','disneyplus.com',
    'primevideo.com','youtube.com','soundcloud.com',
    'github.com','gitlab.com','stackoverflow.com',
    'cloudflare.com','digitalocean.com','vercel.com',
    'netlify.com','render.com','notion.so','figma.com',
    'slack.com','zoom.us','dropbox.com','adobe.com',
    'shopify.com','stripe.com','paypal.com','wordpress.com',
    'claude.ai','anthropic.com','openai.com','huggingface.co',
    'chase.com','bankofamerica.com','wellsfargo.com',
    'coinbase.com','binance.com','robinhood.com',
    'sbi.co.in','hdfcbank.com','icicibank.com','axisbank.com',
    'kotakbank.com','paytm.com','phonepe.com','razorpay.com',
    'zerodha.com','groww.in','upstox.com',
    'flipkart.com','myntra.com','snapdeal.com','meesho.com',
    'nykaa.com','bigbasket.com','swiggy.com','zomato.com',
    'irctc.co.in','makemytrip.com','goibibo.com',
    'ndtv.com','timesofindia.com','thehindu.com',
    'gov.in','nic.in','india.gov.in','uidai.gov.in',
    'incometax.gov.in','gst.gov.in','rbi.org.in',
    'wikipedia.org','coursera.org','udemy.com','khanacademy.org',
    'who.int','cdc.gov','mayoclinic.org','webmd.com',
    'bbc.com','cnn.com','reuters.com','bloomberg.com',
    'techcrunch.com','theverge.com','medium.com','archive.org',
    'naukri.com','indeed.com','glassdoor.com',
    'booking.com','airbnb.com','expedia.com','tripadvisor.com',
    'virustotal.com','kaspersky.com','norton.com','malwarebytes.com',
    'ebay.com','etsy.com','walmart.com','alibaba.com',
]

# ── URL Shorteners ────────────────────────────────────────────────────
SHORTENERS = [
    'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','short.link',
    'buff.ly','ift.tt','dlvr.it','soo.gd','clicky.me','budurl.com',
    'bc.vc','u.to','is.gd','v.gd','tiny.cc','tny.im','tr.im'
]

# ── Brand names to detect spoofing ────────────────────────────────────
BRANDS = [
    'paypal','amazon','google','apple','microsoft','facebook','netflix',
    'spotify','instagram','twitter','linkedin','sbi','hdfc','icici',
    'axis','paytm','phonepe','flipkart','whatsapp','discord','binance',
    'coinbase','robinhood','chase','wellsfargo','bankofamerica'
]


def extract_domain(url: str) -> str:
    try:
        domain = url.split('/')[2] if '//' in url else url.split('/')[0]
        return domain.lower().replace('www.', '')
    except Exception:
        return url.lower()


def get_features(url: str) -> list:
    url = str(url).strip()
    domain = extract_domain(url)
    parts = url.split('/')
    path = '/'.join(parts[3:]) if len(parts) > 3 else ''
    url_lower = url.lower()
    domain_lower = domain.lower()

    # ── Basic length features ─────────────────────────────────────────
    url_len         = len(url)
    domain_len      = len(domain)
    path_len        = len(path)

    # ── Character counts ──────────────────────────────────────────────
    num_dots        = url.count('.')
    num_hyphens     = url.count('-')
    num_underscores = url.count('_')
    num_slashes     = url.count('/')
    num_at          = url.count('@')
    num_question    = url.count('?')
    num_equals      = url.count('=')
    num_ampersand   = url.count('&')
    num_percent     = url.count('%')
    num_digits      = sum(c.isdigit() for c in url)
    num_special     = sum(1 for c in url if not c.isalnum() and c not in '/:.-_?=&%@#')

    # ── Domain-specific ───────────────────────────────────────────────
    domain_parts    = domain.split('.')
    domain_dots     = domain.count('.')
    domain_hyphens  = domain.count('-')
    subdomain_count = max(0, len(domain_parts) - 2)
    domain_digits   = sum(c.isdigit() for c in domain)
    domain_len_ratio = domain_len / max(url_len, 1)

    # ── Protocol & security ───────────────────────────────────────────
    has_https       = 1 if url.startswith('https://') else 0
    has_ip          = 1 if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', url) else 0
    has_at          = 1 if '@' in url else 0
    has_double_slash= 1 if url.count('//') > 1 else 0
    has_port        = 1 if re.search(r':\d{2,5}(/|$)', url) else 0

    # ── Suspicious content ────────────────────────────────────────────
    suspicious_count = sum(1 for k in SUSPICIOUS_KEYWORDS if k in url_lower)
    has_bad_tld     = 1 if any(domain_lower.endswith(t) for t in BAD_TLDS) else 0
    has_trusted_tld = 1 if any(domain_lower.endswith(t) for t in TRUSTED_TLDS) else 0
    is_trusted      = 1 if any(
        domain_lower == d or domain_lower.endswith('.' + d)
        for d in TRUSTED_DOMAINS
    ) else 0
    is_shortener    = 1 if any(s in url_lower for s in SHORTENERS) else 0

    # ── Entropy (randomness of domain) ───────────────────────────────
    counts  = Counter(domain_lower)
    entropy = -sum((c / len(domain_lower)) * math.log2(c / len(domain_lower))
                   for c in counts.values()) if domain_lower else 0

    # ── Brand spoofing detection ──────────────────────────────────────
    brand_in_domain     = sum(1 for b in BRANDS if b in domain_lower)
    brand_in_path       = sum(1 for b in BRANDS if b in path.lower())
    # Brand in domain but NOT a trusted domain = spoofing
    brand_spoof         = 1 if (brand_in_domain > 0 and not is_trusted) else 0

    # ── Lookalike / homoglyph detection ──────────────────────────────
    has_lookalike   = 1 if re.search(r'[0o][a-z]|[a-z][0o]|1[li]|[li]1', domain_lower) else 0

    # ── Punycode (internationalized domain spoofing) ──────────────────
    has_punycode    = 1 if 'xn--' in domain_lower else 0

    # ── Excessive subdomains ──────────────────────────────────────────
    many_subdomains = 1 if subdomain_count >= 3 else 0

    # ── Long domain name ─────────────────────────────────────────────
    long_domain     = 1 if domain_len > 30 else 0

    # ── Digit ratio in domain ────────────────────────────────────────
    digit_ratio     = domain_digits / max(domain_len, 1)

    # ── Hyphen ratio ─────────────────────────────────────────────────
    hyphen_ratio    = num_hyphens / max(url_len, 1)

    # ── Query string length ───────────────────────────────────────────
    query_len       = len(url.split('?')[1]) if '?' in url else 0

    # ── Number of path segments ───────────────────────────────────────
    path_segments   = len([p for p in path.split('/') if p])

    # ── Redirect indicators ───────────────────────────────────────────
    has_redirect    = 1 if any(r in url_lower for r in ['redirect', 'redir', 'url=', 'goto=', 'link=']) else 0

    return [
        url_len, domain_len, path_len,
        num_dots, num_hyphens, num_underscores, num_slashes,
        num_at, num_question, num_equals, num_ampersand,
        num_percent, num_digits, num_special,
        domain_dots, domain_hyphens, subdomain_count,
        domain_digits, domain_len_ratio,
        has_https, has_ip, has_at, has_double_slash, has_port,
        suspicious_count, has_bad_tld, has_trusted_tld, is_trusted,
        is_shortener, entropy,
        brand_in_domain, brand_in_path, brand_spoof,
        has_lookalike, has_punycode, many_subdomains,
        long_domain, digit_ratio, hyphen_ratio,
        query_len, path_segments, has_redirect
    ]

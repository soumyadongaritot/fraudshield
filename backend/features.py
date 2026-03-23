import re
import math
from collections import Counter

# ── Suspicious Keywords ───────────────────────────────────────────────
SUSPICIOUS_KEYWORDS = [
    'login','secure','verify','update','free','win','prize','claim',
    'urgent','alert','suspended','confirm','banking','password','signin',
    'wallet','recover','blocked','unusual','immediate','refund',
    'validate','authenticate','authorize','action','needed','expire',
    'suspended','restrict','limited','locked','disabled','compromised'
]

# ── Bad TLDs (genuinely high-risk) ───────────────────────────────────
BAD_TLDS = ['.tk','.ml','.ga','.cf','.gq','.pw','.cc','.su','.buzz','.fit']

# ── Trusted TLDs (legitimate extensions) ─────────────────────────────
TRUSTED_TLDS = [
    '.com','.org','.edu','.gov','.net','.io','.ai','.app','.dev',
    '.co.uk','.ac.in','.co.in','.ac.uk','.gov.in','.gov.uk',
    '.edu.in','.org.in','.co','.us','.ca','.au','.de','.fr',
    '.jp','.uk','.in','.eu','.nz','.sg','.me','.tv','.studio',
    '.tech','.online','.site','.store','.shop','.blog','.page'
]

# ── Trusted Domains (verified safe) ──────────────────────────────────
TRUSTED_DOMAINS = [
    # Google
    'google.com','gmail.com','youtube.com','drive.google.com',
    'docs.google.com','maps.google.com','play.google.com',
    'accounts.google.com','mail.google.com','cloud.google.com',
    'scholar.google.com','google.co.in','google.co.uk',

    # Microsoft
    'microsoft.com','office.com','outlook.com','live.com',
    'hotmail.com','teams.microsoft.com','azure.microsoft.com',
    'onedrive.live.com','xbox.com','bing.com','msn.com',
    'account.microsoft.com','login.microsoftonline.com',

    # Apple
    'apple.com','icloud.com','developer.apple.com',
    'support.apple.com','store.apple.com','appleid.apple.com',

    # Amazon
    'amazon.com','amazon.in','amazon.co.uk','aws.amazon.com',
    'prime.amazon.com','kindle.amazon.com','payments.amazon.com',

    # Meta
    'facebook.com','instagram.com','whatsapp.com',
    'messenger.com','meta.com','workplace.com',

    # Social
    'twitter.com','x.com','linkedin.com','reddit.com',
    'pinterest.com','tumblr.com','snapchat.com','tiktok.com',
    'discord.com','twitch.tv','telegram.org','signal.org',

    # Entertainment
    'netflix.com','spotify.com','hulu.com','disneyplus.com',
    'primevideo.com','youtube.com','vimeo.com','soundcloud.com',
    'pandora.com','deezer.com','tidal.com',

    # Tech
    'github.com','gitlab.com','bitbucket.org','stackoverflow.com',
    'cloudflare.com','digitalocean.com','heroku.com','vercel.com',
    'netlify.com','railway.app','render.com','supabase.com',
    'firebase.google.com','notion.so','figma.com','canva.com',
    'slack.com','zoom.us','dropbox.com','box.com','adobe.com',
    'shopify.com','stripe.com','paypal.com','wordpress.com',

    # AI
    'claude.ai','anthropic.com','openai.com','chatgpt.com',
    'chat.openai.com','bard.google.com','gemini.google.com',
    'huggingface.co','midjourney.com','perplexity.ai',
    'copilot.microsoft.com','stability.ai','runwayml.com',

    # Finance
    'chase.com','bankofamerica.com','wellsfargo.com','citibank.com',
    'capitalone.com','discover.com','americanexpress.com',
    'goldmansachs.com','morganstanley.com','fidelity.com',
    'schwab.com','vanguard.com','robinhood.com','coinbase.com',
    'binance.com','kraken.com','paypal.com','stripe.com',
    'venmo.com','cashapp.com','zelle.com',

    # Indian Finance
    'sbi.co.in','hdfcbank.com','icicibank.com','axisbank.com',
    'kotakbank.com','yesbank.in','pnbindia.in','canarabank.com',
    'paytm.com','phonepe.com','gpay.com','razorpay.com',
    'zerodha.com','groww.in','upstox.com','angelone.in',
    'policybazaar.com','coverfox.com','acko.com',

    # Indian Shopping
    'flipkart.com','amazon.in','myntra.com','snapdeal.com',
    'meesho.com','nykaa.com','bigbasket.com','grofers.com',
    'swiggy.com','zomato.com','dunzo.com','blinkit.com',
    'indiamart.com','tradeindia.com','justdial.com',

    # Indian Travel
    'irctc.co.in','makemytrip.com','goibibo.com','yatra.com',
    'cleartrip.com','ola.com','rapido.bike','redbus.in',

    # Indian News
    'ndtv.com','timesofindia.com','thehindu.com','hindustantimes.com',
    'indianexpress.com','livemint.com','businessstandard.com',
    'economictimes.indiatimes.com','indiatimes.com','news18.com',

    # Indian Govt
    'gov.in','nic.in','india.gov.in','mca.gov.in','incometax.gov.in',
    'gst.gov.in','epfindia.gov.in','uidai.gov.in','digilocker.gov.in',

    # Shopping
    'ebay.com','etsy.com','walmart.com','target.com','bestbuy.com',
    'costco.com','homedepot.com','lowes.com','ikea.com','wayfair.com',

    # Travel
    'booking.com','airbnb.com','expedia.com','tripadvisor.com',
    'hotels.com','kayak.com','skyscanner.com','uber.com','lyft.com',

    # News
    'nytimes.com','bbc.com','cnn.com','reuters.com','theguardian.com',
    'forbes.com','bloomberg.com','wsj.com','washingtonpost.com',
    'techcrunch.com','wired.com','theverge.com','arstechnica.com',

    # Education
    'harvard.edu','mit.edu','stanford.edu','coursera.org','udemy.com',
    'edx.org','khanacademy.org','duolingo.com','quizlet.com',
    'wikipedia.org','britannica.com','academia.edu',

    # Health & Govt
    'nasa.gov','nih.gov','cdc.gov','who.int','un.org',
    'worldbank.org','medicare.gov','usa.gov','europa.eu',
    'mayoclinic.org','webmd.com','healthline.com','medlineplus.gov',

    # Other
    'medium.com','quora.com','wikipedia.org','archive.org',
    'wolframalpha.com','duckduckgo.com','ecosia.org','brave.com',
    'mozilla.org','firefox.com','opera.com','vivaldi.com',
]

def extract_domain(url):
    try:
        domain = url.split('/')[2] if '//' in url else url.split('/')[0]
        return domain.lower().replace('www.', '')
    except:
        return url.lower()

def get_features(url):
    domain = extract_domain(url)
    path = '/'.join(url.split('/')[3:]) if len(url.split('/')) > 3 else ''

    url_len = len(url)
    domain_len = len(domain)
    path_len = len(path)
    num_dots = url.count('.')
    num_hyphens = url.count('-')
    num_underscores = url.count('_')
    num_slashes = url.count('/')
    num_at = url.count('@')
    num_question = url.count('?')
    num_equals = url.count('=')
    num_ampersand = url.count('&')
    num_percent = url.count('%')
    num_digits = sum(c.isdigit() for c in url)
    domain_dots = domain.count('.')
    domain_hyphens = domain.count('-')
    subdomain_count = max(0, len(domain.split('.')) - 2)
    domain_digits = sum(c.isdigit() for c in domain)
    has_https = 1 if url.startswith('https://') else 0
    has_ip = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0
    has_at = 1 if '@' in url else 0
    has_double_slash = 1 if url.count('//') > 1 else 0
    has_port = 1 if re.search(r':\d{2,5}', url) else 0
    url_lower = url.lower()
    suspicious_count = sum(1 for k in SUSPICIOUS_KEYWORDS if k in url_lower)
    has_bad_tld = 1 if any(domain.endswith(t) for t in BAD_TLDS) else 0
    has_trusted_tld = 1 if any(domain.endswith(t) for t in TRUSTED_TLDS) else 0
    is_trusted = 1 if any(domain == d or domain.endswith('.'+d) for d in TRUSTED_DOMAINS) else 0
    counts = Counter(domain)
    entropy = -sum((c/len(domain)) * math.log2(c/len(domain))
                   for c in counts.values()) if domain else 0
    brands = ['paypal','amazon','google','apple','microsoft','facebook',
              'netflix','spotify','instagram','twitter','linkedin',
              'sbi','hdfc','icici','axis','paytm','phonepe','flipkart']
    brand_in_domain = sum(1 for b in brands if b in domain.lower())
    brand_in_path = sum(1 for b in brands if b in path.lower())
    has_lookalike = 1 if re.search(r'[0-9][a-z]|[a-z][0-9]', domain.split('.')[0]) else 0
    shorteners = ['bit.ly','tinyurl','t.co','goo.gl','ow.ly','short.link']
    is_shortener = 1 if any(s in url for s in shorteners) else 0

    return [
        url_len, domain_len, path_len, num_dots, num_hyphens,
        num_underscores, num_slashes, num_at, num_question, num_equals,
        num_ampersand, num_percent, num_digits, domain_dots, domain_hyphens,
        subdomain_count, domain_digits, has_https, has_ip, has_at,
        has_double_slash, has_port, suspicious_count, has_bad_tld,
        has_trusted_tld, is_trusted, entropy, brand_in_domain,
        brand_in_path, has_lookalike, is_shortener
    ]
# make_url_labels.py

import pandas as pd

def main():
    # 1) Load phishing URLs
    #    (assumes Phishing.csv has a column 'url')
    phish = pd.read_csv('Phishing.csv')
    phish = phish.rename(columns={phish.columns[0]: 'url'})
    phish['label'] = 'phishing'

    # 2) Define ~100 top domains
    top_domains = [
        'google.com','youtube.com','facebook.com','baidu.com','wikipedia.org',
        'reddit.com','yahoo.com','google.co.in','qq.com','taobao.com',
        'tmall.com','amazon.com','sohu.com','linkedin.com','live.com',
        'vk.com','zoom.us','instagram.com','microsoft.com','office.com',
        'tiktok.com','yandex.ru','netflix.com','twitch.tv','pinterest.com',
        'wordpress.com','mail.ru','ok.ru','stackoverflow.com','adobe.com',
        'apple.com','dropbox.com','salesforce.com','paypal.com','stripe.com',
        'cnn.com','nytimes.com','bbc.co.uk','msn.com','aliexpress.com',
        'indeed.com','whatsapp.com','spotify.com','weibo.com','github.com',
        'slack.com','uber.com','airbnb.com','tumblr.com','ebay.com',
        'walmart.com','target.com','booking.com','expedia.com','tripadvisor.com',
        'kayak.com','ikea.com','moma.org','nih.gov','cdc.gov',
        'gov.uk','usa.gov','un.org','harvard.edu','mit.edu',
        'ox.ac.uk','stanford.edu','cam.ac.uk','ethz.ch','utoronto.ca',
        'apple.com','oracle.com','ibm.com','nvidia.com','intel.com',
        'mozilla.org','gitlab.com','sourceforge.net','shopify.com','snapchat.com',
        'quora.com','tumblr.com','pinterest.com','cnn.com','forbes.com'
    ]

    # 3) Patterns to apply per domain (8 each → ~800 benign URLs)
    patterns = [
        ('https://',        ''       ),
        ('http://',         ''       ),
        ('https://www.',    ''       ),
        ('http://www.',     ''       ),
        ('https://',        '/login' ),
        ('https://',        '/about' ),
        ('https://',        '/contact'),
        ('https://',        '/help'  )
    ]

    # 4) Build benign list
    benign_urls = []
    for d in top_domains:
        for pre, suf in patterns:
            benign_urls.append(f"{pre}{d}{suf}")

    benign = pd.DataFrame({
        'url': benign_urls,
        'label': 'legit'
    })

    # 5) Combine & shuffle
    df = pd.concat([phish, benign], ignore_index=True)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    # 6) Save
    df.to_csv('urls_and_labels.csv', index=False)
    print(f"✅ urls_and_labels.csv created with {len(df)} rows "
          f"({len(benign)} legit, {len(phish)} phishing)")

if __name__ == '__main__':
    main()

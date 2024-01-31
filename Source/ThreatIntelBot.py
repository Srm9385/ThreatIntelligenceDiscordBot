from threading import Lock
import feedparser
import requests
import time
import json
import os
from dateutil import parser
from concurrent.futures import ThreadPoolExecutor

lock = Lock()

private_rss_feed_list = [
    ['https://grahamcluley.com/feed/', 'Graham Cluley'],
    ['https://threatpost.com/feed/', 'Threatpost'],
    ['https://krebsonsecurity.com/feed/', 'Krebs on Security'],
    ['https://www.darkreading.com/rss.xml', 'Dark Reading'],
    ['http://feeds.feedburner.com/eset/blog', 'We Live Security'],
    ['https://davinciforensics.co.za/cybersecurity/feed/', 'DaVinci Forensics'],
    ['https://blogs.cisco.com/security/feed', 'Cisco'],
    ['https://www.infosecurity-magazine.com/rss/news/', 'Information Security Magazine'],
    ['http://feeds.feedburner.com/GoogleOnlineSecurityBlog', 'Google'],
    ['http://feeds.trendmicro.com/TrendMicroResearch', 'Trend Micro'],
    ['https://www.bleepingcomputer.com/feed/', 'Bleeping Computer'],
    ['https://www.proofpoint.com/us/rss.xml', 'Proof Point'],
    ['http://feeds.feedburner.com/TheHackersNews?format=xml', 'Hacker News'],
    ['https://www.schneier.com/feed/atom/', 'Schneier on Security'],
    ['https://www.binarydefense.com/feed/', 'Binary Defense'],
    ['https://securelist.com/feed/', 'Securelist'],
    ['https://research.checkpoint.com/feed/', 'Checkpoint Research'],
    ['https://www.virusbulletin.com/rss', 'VirusBulletin'],
    ['https://modexp.wordpress.com/feed/', 'Modexp'],
    ['https://www.tiraniddo.dev/feeds/posts/default', 'James Forshaw'],
    ['https://blog.xpnsec.com/rss.xml', 'Adam Chester'],
    ['https://msrc-blog.microsoft.com/feed/', 'Microsoft Security'],
    ['https://www.recordedfuture.com/feed', 'Recorded Future'],
    ['https://www.sentinelone.com/feed/', 'SentinelOne'],
    ['https://redcanary.com/feed/', 'RedCanary'],
    ['https://cybersecurity.att.com/site/blog-all-rss', 'ATT'],
    ["https://www.cisa.gov/uscert/ncas/alerts.xml", "US-CERT CISA"],
    ["https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml", "NCSC"],
    ["https://www.cisecurity.org/feed/advisories", "Center of Internet Security"]
]

json_feed_url = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"

teams_webhook_url = "REDACTED"

def get_articles(feed_url):
    try:
        feed = feedparser.parse(feed_url)
        return feed.entries
    except Exception as e:
        print(f"An error occurred when getting articles: {str(e)}")
        return []

def get_articles_from_json(json_url):
    try:
        response = requests.get(json_url)
        if response.status_code == 200:
            data = response.json()
            return data
        else:
            print(f"Failed to fetch JSON feed at {json_url}")
            return []
    except Exception as e:
        print(f"An error occurred when getting articles from JSON: {str(e)}")
        return []



def send_to_teams(teams_card):
    headers = {
        "Content-Type": "application/json"
    }
    response = requests.post(
        teams_webhook_url, headers=headers, data=json.dumps(teams_card))
    print(response.status_code)
    print(response.text)


article_identifiers = []

def format_article(article, source, color):
    try:
        published_date = parser.parse(article.get('published', ''))
        published_date = published_date.strftime('%Y-%m-%d %H:%M:%S')
    except ValueError:
        published_date = "Unknown date"

    text = article.get('summary', article.get('description', ''))

    return {
        "@context": "https://schema.org/extensions",
        "@type": "MessageCard",
        "themeColor": color,
        "title": article.title,
        "text": text,
        "sections": [
            {
                "facts": [
                    {
                        "name": "Source",
                        "value": source
                    },
                    {
                        "name": "Date",
                        "value": published_date
                    }
                ]
            }
        ],
        "potentialAction": [
            {
                "@type": "OpenUri",
                "name": "Read More",
                "targets": [
                    {
                        "os": "default",
                        "uri": article.link
                    }
                ]
            }
        ]
    }

def format_json_article(article, color):
    try:
        published_date = parser.parse(article["discovered"])
        published_date = published_date.strftime('%Y-%m-%d %H:%M:%S')
    except ValueError:
        published_date = "Unknown date"

    return {
        "@context": "https://schema.org/extensions",
        "@type": "MessageCard",
        "themeColor": color,
        "title": "Victim: " + article["post_title"],
        "text": "New extortion case has been reported on Ransomwatch.",
        "sections": [
            {
                "facts": [
                    {
                        "name": "Source",
                        "value": article["group_name"]
                    },
                    {
                        "name": "Date",
                        "value": published_date
                    }
                ]
            }
        ]
    }

def process_feed(feed, source):
    global article_identifiers
    articles = get_articles(feed)
    edu_keywords = ["university", "college", "higher education", "academic", ".edu", "campus", "universities", "student", "faculty", "tuition", "scholarship", "professor"]
    security_keywords = ["ransomware", "vulnerabilities", "exploit", "vulnerability", "malware", "breach", "zero day", "zero-day", "security patch", "hack", "apt"]

    for article in articles:
        color = None  # No default color
        if source in ["CISA", "Center of Internet Security", "NCSC"]:
            color = "0000FF"  # Blue
        elif any(keyword in article.title.lower() or keyword in article.summary.lower() for keyword in security_keywords):
            color = "008000"  # Green
        elif any(keyword in article.title.lower() or keyword in article.summary.lower() for keyword in edu_keywords):
            color = "FFA500"  # Orange

        # If no color has been assigned, skip this article
        if color is None:
            continue

        article_identifier = article.link.strip()  # Using URL as identifier
        with lock:
            if article_identifier not in article_identifiers:
                article_identifiers.append(article_identifier)
                teams_card = format_article(article, source, color)
                print(teams_card)
                #send_to_teams(teams_card)

                with open("article_identifiers.txt", "a") as f:
                    f.write(article_identifier + "\n")


def process_json_feed(json_articles):
    global article_identifiers
    for article in json_articles:
        color = None  # No default color
        if '.edu' in article["post_title"].lower():
            color = "FFA500"  # Orange

        # If no color has been assigned, skip this article
        if color is None:
            continue

        article_identifier = (article["post_title"] + "|" + article["discovered"]).strip()  # Using post title and date as identifier
        with lock:
            if article_identifier not in article_identifiers:
                article_identifiers.append(article_identifier)
                teams_card = format_json_article(article, color)
                print(teams_card)
                #send_to_teams(teams_card)

                with open("article_identifiers.txt", "a") as f:
                    f.write(article_identifier + "\n")


def main():
    global article_identifiers
    if os.path.exists("article_identifiers.txt"):
        with open("article_identifiers.txt", "r") as f:
            article_identifiers = [line.strip() for line in f.readlines()]

    # Define a ThreadPoolExecutor
    executor = ThreadPoolExecutor(max_workers=10)

    while True:
        for feed, source in private_rss_feed_list:
            # Submit a new task to the executor
            executor.submit(process_feed, feed, source)

        json_articles = get_articles_from_json(json_feed_url)
        executor.submit(process_json_feed, json_articles)

        time.sleep(60)

if __name__ == '__main__':
    main()
import re
import time
import lxml
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from collections import Counter

blacklist = set()
visited = set()
last_access = {}

unique_pages = set() 
longest_page_url = None
longest_page_word_count = 0
subdomains = {}
word_counter = Counter()

URL_MAXLEN = 250
SEGMENTS_MAXLEN = 10
QUERY_PARAMS_MAXLEN = 5

with open("stop_words.txt") as f:
    stop_words = set(f.read().split())

def scraper(url, resp):
    links = []
    if resp.status == 200:
        links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]

def extract_next_links(url, resp):
    global longest_page_url, longest_page_word_count, word_counter, unique_pages, subdomains
    links = []
    
    if resp.status != 200:
        blacklist.add(url)
    elif "text/html" not in resp.raw_response.headers.get("Content-Type", ""):
        print(f"{url} is not an HTML page")
    elif len(resp.raw_response.content) == 0:
        blacklist.add(url)
    else:
        cleaned_url = url.split("#")[0]
        visited.add(cleaned_url)
        unique_pages.add(cleaned_url)

        try:
            soup = BeautifulSoup(resp.raw_response.content, "lxml")
            words = re.findall(r'\w+', soup.get_text(separator=' ').lower())

            filtered_words = [w for w in words if w not in stop_words]

            word_counter.update(filtered_words)

            word_count = len(words)
            if word_count > longest_page_word_count:
                longest_page_word_count = word_count
                longest_page_url = cleaned_url

            parsed_cleaned = urlparse(cleaned_url)
            hostname = parsed_cleaned.netloc.lower()

            if hostname.endswith("ics.uci.edu"):
                if hostname not in subdomains:
                    subdomains[hostname] = set()
                subdomains[hostname].add(cleaned_url)

            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            for anchor in soup.find_all("a", href=True):
                absolute_url = urljoin(base_url, anchor["href"])
                link = absolute_url.split("#")[0]
                if link not in links:
                    links.append(link)
        except Exception as e:
            print(f"ERROR ON {url}: {e}")
    return links


def is_valid(url):
    try:
        if url in visited:
            return False
        if url in blacklist:
            return False
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False
        if len(url) > URL_MAXLEN:
            return False
        path_segments = parsed.path.split('/')
        if len(path_segments) > SEGMENTS_MAXLEN:
            return False
        query_params = parsed.query.split('&') if parsed.query else []
        if len(query_params) > QUERY_PARAMS_MAXLEN:
            return False
        # hardcode any links that have a date in them, any links from wordpress, 
        # example: https://wiki.ics.uci.edu/doku.php/projects:maint-spring-2021?tab_details=edit&do=media&tab_files=upload&image=virtual_environments%3Ajupyterhub%3Avscode.jpg&ns=services%3Apurchases, status <200>, using cache ('styx.ics.uci.edu', 9002).
        # idk how to filter dis bro
        if re.search(r'wiki', parsed.netloc, re.IGNORECASE):
            return False
        if re.search(r'wordpress', parsed.netloc, re.IGNORECASE) or re.search(r'wordpress', parsed.path, re.IGNORECASE):
            return False

        hostname = parsed.netloc

        now = time.time()
        if hostname in last_access:
            elapsed = now - last_access[hostname]
            if elapsed < 0.5:
                time.sleep(0.5 - elapsed)
        last_access[hostname] = time.time()

        return re.match(r'^(.+\.)?(ics\.uci\.edu|cs\.uci\.edu|informatics\.uci\.edu|stat\.uci\.edu)$', parsed.netloc) and \
            not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())

    except TypeError:
        print ("TypeError for ", parsed)
        # TODO: raise a specific error

def output_report():
    unique_count = len(unique_pages)
    print(f"Total unique pages: {unique_count}")

    print(f"Longest page: {longest_page_url} with {longest_page_word_count} words")

    common_words = word_counter.most_common(50)
    print("50 Most common words (word, frequency):")
    for word, freq in common_words:
        print(f"{word}, {freq}")

    print("Subdomains in ics.uci.edu:")
    for subdomain in sorted(ics_subdomains.keys()):
        count = len(ics_subdomains[subdomain])
        print(f"{subdomain}, {count}")

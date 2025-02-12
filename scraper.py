import re
import lxml
from urllib.parse import urlparse, urljoin, parse_qs
from bs4 import BeautifulSoup
from collections import Counter

blacklist = set()
visited = set()
trap_check = {}

longest_page_url = None
longest_page_word_count = 0
subdomains = {}
word_counter = Counter()

URL_MAXLEN = 225
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
    global blacklist, visited, trap_check
    global longest_page_url, longest_page_word_count, subdomains, word_counter
    
    links = []
    
    if resp.status != 200:
        blacklist.add(url)
    elif "text/html" not in resp.raw_response.headers.get("Content-Type", ""):
        blacklist.add(url)
    elif len(resp.raw_response.content) == 0:
        blacklist.add(url)
    else:
        # cleaned_url is the url with the fragment cut off (so scheme to query)
        cleaned_url = url.split("#")[0]
        visited.add(cleaned_url)

        try:
            soup = BeautifulSoup(resp.raw_response.content, "lxml")
            words = re.findall(r'\w+', soup.get_text(separator=' ').lower())

            filtered_words = [w for w in words if w not in stop_words]

            word_counter.update(filtered_words)
            word_count = len(words)
            if word_count > longest_page_word_count:
                longest_page_word_count = word_count
                longest_page_url = cleaned_url

            # parsed_cleaned is a Parse Object from scheme to query
            parsed_cleaned = urlparse(cleaned_url)
            hostname = parsed_cleaned.netloc.lower()

            if hostname.endswith("ics.uci.edu") or hostname.endswith("cs.uci.edu") or hostname.endswith("informatics.uci.edu") or hostname.endswith("stat.uci.edu"):
                if hostname not in subdomains:
                    subdomains[hostname] = set()
                subdomains[hostname].add(cleaned_url)

            base_url = f"{parsed_cleaned.scheme}://{parsed_cleaned.netloc}"

            for anchor in soup.find_all("a", href=True):
                absolute_url = urljoin(base_url, anchor["href"])
                link = absolute_url.split("#")[0]
                if link not in links:
                    links.append(link)
        
        except Exception as e:
            print(f"ERROR ON {url}: {e}")
        
    return links


def is_valid(url):
    global blacklist, visited, trap_check
    global longest_page_url, longest_page_word_count, subdomains, word_counter
    global URL_MAXLEN, SEGMENTS_MAXLEN, QUERY_PARAMS_MAXLEN

    try:
        if url in visited or urlparse(url).hostname in visited:
            return False
        if url in blacklist:
            return False
        if len(url) > URL_MAXLEN:
            return False

        base_url = url.split("?")[0]
        if (base_url in trap_check):
            trap_check[base_url] += 1
        else:
            trap_check = dict()
            trap_check[base_url] = 1

        if trap_check[base_url] > 175:
            return False

        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False

        path_segments = parsed.path.split('/')
        if len(path_segments) > SEGMENTS_MAXLEN:
            return False

        query_params = parsed.query.split('&') if parsed.query else []

        if len(query_params) > QUERY_PARAMS_MAXLEN:
            return False
        if re.search(r'\b\d{4}-\d{2}-\d{2}\b', url):
            blacklist.add(url)
            return False

        # unwanted file extensions
        pattern = (
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            r"|png|tiff?|mid|mp2|mp3|mp4"
            r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            r"|epub|dll|cnf|tgz|sha1"
            r"|thmx|mso|arff|rtf|jar|csv"
            r"|rm|smil|wmv|swf|wma|zip|rar|gz)$"
        )
        # check that queries do not have unwanted file extensions
        queries = parse_qs(parsed.query)
        for values in queries.values():
            for value in values:
                if re.match(pattern, value.lower()):
                    return False

        return re.match(r'^(.+\.)?(ics\.uci\.edu|cs\.uci\.edu|informatics\.uci\.edu|stat\.uci\.edu)$', parsed.netloc) and \
            not re.match(pattern, parsed.path.lower())

    except TypeError:
        print ("TypeError for ", parsed)

def output_report():
    print(f"Total unique pages: {len(visited)}")

    print(f"Longest page: {longest_page_url} with {longest_page_word_count} words")

    common_words = word_counter.most_common(50)
    print("50 Most common words (word, frequency):")
    for word, freq in common_words:
        print(f"{word}, {freq}")

    print("Subdomains in ics.uci.edu:")
    for subdomain in sorted(subdomains.keys()):
        count = len(subdomains[subdomain])
        print(f"{subdomain}, {count}")

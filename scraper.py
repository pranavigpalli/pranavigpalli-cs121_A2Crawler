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

MIN_FILE_SIZE = 100              # 100 bytes (approx. 20 words)
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
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
    global blacklist, visited, last_access, trap_check
    global longest_page_url, longest_page_word_count, subdomains, word_counter
    
    links = []
    cleaned_url = url.split("#")[0]  # the url without the fragment (i.e. scheme to query)
    
    if resp.status != 200:
        blacklist.add(cleaned_url)
    elif resp.raw_response and ("text/html" not in resp.raw_response.headers.get("Content-Type", "")):
        blacklist.add(cleaned_url)
    elif len(resp.raw_response.content) < MIN_FILE_SIZE:
        blacklist.add(cleaned_url)
    elif len(resp.raw_response.content) > MAX_FILE_SIZE:
        blacklist.add(cleaned_url)
    else:
        visited.add(cleaned_url)

        try:
            soup = BeautifulSoup(resp.raw_response.content, "lxml")
            words = re.findall(r'\w+', soup.get_text(separator=' ').lower())

            if len(words) < 20:
                blacklist.add(cleaned_url)
                return []

            filtered_words = [word for word in words if word not in stop_words]

            word_counter.update(filtered_words)
            word_count = len(words)
            if word_count > longest_page_word_count:
                longest_page_word_count = word_count
                longest_page_url = cleaned_url

            # parsed_cleaned is a ParseResult object from scheme to query
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
    global blacklist, visited, last_access, trap_check
    global longest_page_url, longest_page_word_count, subdomains, word_counter
    global URL_MAXLEN, SEGMENTS_MAXLEN, QUERY_PARAMS_MAXLEN

    try:
        if url in visited:
            return False
        if url in blacklist:
            return False
        if len(url) > URL_MAXLEN:
            return False

        base_url = url.split("?")[0]
        trap_check[base_url] = trap_check.get(base_url, 0) + 1
        if trap_check[base_url] > 175:
            return False

        if trap_check[base_url] > 175:
            return False

        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False
        
        if (url in visited) or (url in blacklist):
            return False
        
        if len(url) > URL_MAXLEN:
            return False
        
        path_segments = parsed.path.split('/')
        if len(path_segments) > SEGMENTS_MAXLEN:
            return False
        
        query_params = parsed.query.split('&')
        if len(query_params) > QUERY_PARAMS_MAXLEN:
            return False

        if re.search(r'\b\d{4}[-/]\d{2}[-/]\d{2}\b|\b\d{2}[-/]\d{2}[-/]\d{4}\b', url):
            return False
        if re.search(r'[?&](date|year|month|day|view|do|tab_files)=[^&]*', url, re.IGNORECASE):
            return False
        if re.search(r'gitlab\.ics\.uci\.edu.*(/-/|/users/|/blob/|/commits/|/tree/|/compare|/explore/|\.git$|/[^/]+/[^/]+)', url):
            return False
        if re.search(r'sli\.ics\.uci\.edu.*\?action=download&upname=', url):
            return False

        if (re.search(r'\b\d{4}[-/]\d{2}[-/]\d{2}\b|\b\d{2}[-/]\d{2}[-/]\d{4}\b', url) or 
            re.search(r'\b\d{4}[-/]\d{2}(-\d{2})?\b', url) or 
            re.search(r'[?&](date|year|month|day|view|do|tab_files|ical)=[^&]*', url, re.IGNORECASE)):
            return False
        if re.search(r'gitlab\.ics\.uci\.edu.*(/-/|/users/|/blob/|/commits/|/tree/|/compare|/explore/|\.git$|/[^/]+/[^/]+)', url):
            return False
        if re.search(r'sli\.ics\.uci\.edu.*\?action=download&upname=', url):
            return False
        if re.search(r'wp-login\.php\?redirect_to=[^&]+', url):
            return False
        if re.search(r'/page/\d+', url):
            return False
        if re.search(r'[\?&]version=\d+', url) or re.search(r'[\?&]action=diff&version=\d+', url) or re.search(r'[\?&]format=txt', url):
            return False
        if re.search(r'\b\d{4}-(spring|summer|fall|winter)\b', parsed.path, re.IGNORECASE):
            return False

        # unwanted file extensions
        pattern = r".*\.(css|js|bmp|gif|jpe?g|ico"
        + r"|png|tiff?|mid|mp2|mp3|mp4"
        + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
        + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
        + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
        + r"|epub|dll|cnf|tgz|sha1"
        + r"|thmx|mso|arff|rtf|jar|csv"
        + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$" 
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
        raise

def output_report():
    with open("report.txt", "w", encoding="utf-8") as file:
        unique_count = len(visited)
        file.write(f"Total unique pages: {unique_count}\n\n")

        file.write(f"Longest page: {longest_page_url} with {longest_page_word_count} words\n\n")

        common_words = word_counter.most_common(50)
        file.write("50 Most common words (word, frequency):\n")
        for word, freq in common_words:
            file.write(f"{word}, {freq}\n")
        file.write("\n")

        file.write("Subdomains in ics.uci.edu:\n")
        for subdomain in sorted(subdomains.keys()):
            count = len(subdomains[subdomain])
            file.write(f"{subdomain}, {count}\n")
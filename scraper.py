# re is for the regex filteration
# lxml is for the BeautifulSoup
# urlib was used for parsing the url
# BeautifulSoup is used for retrieving all page content
# Counter is used for generating the report, specifically for counting the amt of words on a page. 
import re
import lxml
from urllib.parse import urlparse, urljoin, parse_qs
from bs4 import BeautifulSoup
from collections import Counter

# These are data structures that store URLs. 
blacklist = set()
# blacklist stores URLs that don’t have the response code of 200, contain too much or too little content, and aren’t text or html files.
visited = set()
# Visited stores all valid URLs that were scraped. These are sets since they cannot contain duplicate objects
trap_check = {}
# Trap_check keeps track of all URLs’ subdomain and their frequency. Every subdomain has a maximum amount, and if exceeded, are then ignored

longest_page_url = None
# longest_page_url is the longest url page found yet
longest_page_word_count = 0
# longest_page_word_count is the length of the longest url page
subdomains = {}
# subdomains is a dictionary that stores all subdomains & links them to a set that contains all specific subdomain URLs within it
word_counter = Counter()
# word_counter is a Counter() object that stores all words found from scraping pages

# These hard-coded variables are set limits we have for when we crawl.
# The file size MUST be between 100 bytes and 5 MB, and the URL cannot be too long.  
MIN_FILE_SIZE = 100              # 100 bytes (approx. 20 words)
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
URL_MAXLEN = 225
SEGMENTS_MAXLEN = 10
QUERY_PARAMS_MAXLEN = 5

# This is meant to create our stop words list.
# We use a file we created prior to running the crawler and create a set containing all the stop words
with open("stop_words.txt") as f:
    stop_words = set(f.read().split())

# scraper() takes in both a URL and its response, and determines if the URL’s response code is valid for it to be crawled.
# If so, then the URL and its response are sent to extract_next_links().
# This gives a list of valid links scraped from the page. Returns a list of links from that link list that are valid. 
# Time complexity: 
def scraper(url, resp):
    links = []
    if resp.status == 200:
        links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]

# extract_next_links() takes in a URL and its response code, and scrapes the webpage for its content and other URLs within itself. 
# Time complexity: 
def extract_next_links(url, resp):
    global blacklist, visited, last_access, trap_check
    global longest_page_url, longest_page_word_count, subdomains, word_counter
    
    links = [] # list for all links found on webpage
    cleaned_url = url.split("#")[0]  # the url without the fragment (i.e. scheme to query)
    
    # if any of the following are true, the URL is added to the blacklist and is not scrapped. Otherwise, URL is added to visited
    if resp.status != 200: # if the response status is valid
        blacklist.add(cleaned_url)
    elif resp.raw_response and ("text/html" not in resp.raw_response.headers.get("Content-Type", "")): # if the URL isn’t a text or html file
        blacklist.add(cleaned_url)
    elif len(resp.raw_response.content) < MIN_FILE_SIZE: # if the webpage is bigger than 100 bytes
        blacklist.add(cleaned_url)
    elif len(resp.raw_response.content) > MAX_FILE_SIZE: # if the webpage is smaller than 5 MB
        blacklist.add(cleaned_url)
    else:
        visited.add(cleaned_url)

        try:
            soup = BeautifulSoup(resp.raw_response.content, "lxml") # Turning URL contents into a soup object
            words = re.findall(r'\w+', soup.get_text(separator=' ').lower()) # Retrieving text content from webpage

            if len(words) < 20: # If the webpage is too small, add it to the blacklist and return an empty list
                blacklist.add(cleaned_url)
                return []

            filtered_words = [word for word in words if word not in stop_words] # List of all of the words from the webpage that ARE NOT stop words

            # Adds words to the word counter object, and finds the length of all valid words on the webpage.
            # If the current longest page is longer than the previous longest page, it is reassigned as that
            word_counter.update(filtered_words)
            word_count = len(words)
            if word_count > longest_page_word_count:
                longest_page_word_count = word_count
                longest_page_url = cleaned_url

            # parsed_cleaned is a ParseResult object from scheme to query
            parsed_cleaned = urlparse(cleaned_url)
            hostname = parsed_cleaned.netloc.lower()

            # If the URL is under the domains of “ics.uci.edu”, “cs.uci.edu”, “informatics.uci.edu”, or “stat.uci.edu”,
            # it is added as a key within subdomains, with its ‘cleaned’ URL part of its set.
            # If the hostname is not already in subdomains, it is added first. 
            if hostname.endswith("ics.uci.edu") or hostname.endswith("cs.uci.edu") or hostname.endswith("informatics.uci.edu") or hostname.endswith("stat.uci.edu"):
                if hostname not in subdomains:
                    subdomains[hostname] = set()
                subdomains[hostname].add(cleaned_url)

            # making the base URL from the ‘cleaned’ URL (scheme and netloc), going through all links within the URL and adding href to the link.
            # adding the link to the link list. 
            base_url = f"{parsed_cleaned.scheme}://{parsed_cleaned.netloc}"
            for anchor in soup.find_all("a", href=True):
                absolute_url = urljoin(base_url, anchor["href"])
                link = absolute_url.split("#")[0]
                if link not in links:
                    links.append(link)

        # If an exception or error occurs, print error
        except Exception as e:
            print(f"ERROR ON {url}: {e}")
        
    return links # Returning all links found on current URL

# is_valid() takes in a URL string and verifies whether it is a valid URL to scrape or not, depending on specific criteria. Returns True if the URL is verified, False otherwise
# Time complexity: O(L + k + m)
# Where:
# L is the length of the URL,
# k is the number of path segments,
# m is the number of query parameters.
def is_valid(url):
    global blacklist, visited, last_access, trap_check
    global longest_page_url, longest_page_word_count, subdomains, word_counter
    global URL_MAXLEN, SEGMENTS_MAXLEN, QUERY_PARAMS_MAXLEN
    # We are changing the global variables within this function, so we must
    # declare them here to make sure that we change the globals rather than creating
    # new local variables.

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
        if url in blacklist:
            return False
        if len(url) > URL_MAXLEN:
            return False

        if re.search(r'\b\d{4}[-/]\d{2}[-/]\d{2}\b|\b\d{2}[-/]\d{2}[-/]\d{4}\b', url):
            return False
        if re.search(r'[?&](date|year|month|day|view|do|tab_files)=[^&]*', url, re.IGNORECASE):
            return False
        if re.search(r'gitlab\.ics\.uci\.edu.*(/-/|/users/|/blob/|/commits/|/tree/|/compare|/explore/|\.git$|/[^/]+/[^/]+)', url):
            return False
        if re.search(r'sli\.ics\.uci\.edu.*\?action=download&upname=', url):
            return False
        
        path_segments = parsed.path.split('/')
        if len(path_segments) > SEGMENTS_MAXLEN:
            return False
        
        query_params = parsed.query.split('&')
        if len(query_params) > QUERY_PARAMS_MAXLEN:
            return False

        base_url = url.split("?")[0]  # without query or fragment
        trap_check[base_url] = trap_check.get(base_url, 0) + 1
        if trap_check[base_url] > 175:
            return False
        
        subdomain = parsed.netloc
        trap_check[subdomain] = trap_check.get(subdomain, 0) + 1
        if trap_check[subdomain] > 500:
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
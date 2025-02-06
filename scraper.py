import re
import time
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import lxml

blacklist = set()
visited = set()

def scraper(url, resp):
    links = []
    if resp.status == 200:
        links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]

def extract_next_links(url, resp):
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content
    links = []
    if resp.status != 200:
        blacklist.add(url)
    elif "text/html" not in resp.raw_response.headers.get("Content-Type", ""):
        print(f"{url} is not an HTML page")
    elif len(resp.raw_response.content) == 0:
        blacklist.add(url)
    else:
        visited.add(url)
        try:
            soup = BeautifulSoup(resp.raw_response.content, "lxml")
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            for anchor in soup.find_all("a", href=True):
                absolute_url = urljoin(base_url, anchor["href"])
                cleaned_url = absolute_url.split("#")[0]
                links.append(cleaned_url)
        except Exception as e:
            print(f"ERROR ON {url}: {e}")
    return links

def is_valid(url):
    # Make sure to return only URLs that are within the domains and paths mentioned above! (see is_valid function in scraper.py -- you need to change it)
    # 
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        if url in visited:
            return False
        if url in blacklist:
            return False
            
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False
        return re.match(r'^(\w*\.)?(ics\.uci\.edu|cs\.uci\.edu|informatics\.uci\.edu|stat\.uci\.edu)$', parsed.netloc) and \
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
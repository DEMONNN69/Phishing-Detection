import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date
from urllib.parse import urlparse


class FeatureExtraction:
    def __init__(self, url):
        self.url = url
        self.features = []
        self.domain = ""
        self.whois_response = ""
        self.urlparse = ""
        self.response = ""
        self.soup = ""

        self._init_request()
        self._init_parsers()

        self.features = [
            self.using_ip(),
            self.long_url(),
            self.short_url(),
            self.contains_symbol(),
            self.redirecting(),
            self.prefix_suffix(),
            self.sub_domains(),
            self.https_check(),
            self.domain_reg_length(),
            self.favicon(),
            self.non_std_port(),
            self.https_domain_url(),
            self.request_url(),
            self.anchor_url(),
            self.links_in_script_tags(),
            self.server_form_handler(),
            self.info_email(),
            self.abnormal_url(),
            self.website_forwarding(),
            self.status_bar_cust(),
            self.disable_right_click(),
            self.using_popup_window(),
            self.iframe_redirection(),
            self.age_of_domain(),
            self.dns_recording(),
            self.website_traffic(),
            self.page_rank(),
            self.google_index(),
            self.links_pointing_to_page(),
            self.stats_report()
        ]

    def _init_request(self):
        try:
            self.response = requests.get(self.url)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except requests.RequestException:
            pass

    def _init_parsers(self):
        try:
            self.urlparse = urlparse(self.url)
            self.domain = self.urlparse.netloc
        except Exception:
            pass

        try:
            self.whois_response = whois.whois(self.domain)
        except Exception:
            pass

    def using_ip(self):
        try:
            ipaddress.ip_address(self.url)
            return -1
        except ValueError:
            return 1

    def long_url(self):
        url_length = len(self.url)
        if url_length < 54:
            return 1
        elif 54 <= url_length <= 75:
            return 0
        return -1

    def short_url(self):
        match = re.search(r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net', self.url)
        return -1 if match else 1

    def contains_symbol(self):
        return -1 if "@" in self.url else 1

    def redirecting(self):
        return -1 if self.url.rfind('//') > 6 else 1

    def prefix_suffix(self):
        return -1 if '-' in self.domain else 1

    def sub_domains(self):
        dot_count = self.url.count('.')
        if dot_count == 1:
            return 1
        elif dot_count == 2:
            return 0
        return -1

    def https_check(self):
        return 1 if self.urlparse.scheme == 'https' else -1

    def domain_reg_length(self):
        try:
            expiration_date = self._get_date(self.whois_response.expiration_date)
            creation_date = self._get_date(self.whois_response.creation_date)
            age = (expiration_date.year - creation_date.year) * 12 + (expiration_date.month - creation_date.month)
            return 1 if age >= 12 else -1
        except Exception:
            return -1

    def _get_date(self, date_field):
        if isinstance(date_field, list):
            return date_field[0]
        return date_field

    def favicon(self):
        try:
            for head in self.soup.find_all('head'):
                for link in head.find_all('link', href=True):
                    dots = link['href'].count('.')
                    if self.url in link['href'] or dots == 1 or self.domain in link['href']:
                        return 1
            return -1
        except Exception:
            return -1

    def non_std_port(self):
        return -1 if ':' in self.domain else 1

    def https_domain_url(self):
        return -1 if 'https' in self.domain else 1

    def request_url(self):
        try:
            total_elements = 0
            success_elements = 0
            elements = ['img', 'audio', 'embed', 'iframe']
            for element in elements:
                for tag in self.soup.find_all(element, src=True):
                    dots = tag['src'].count('.')
                    if self.url in tag['src'] or self.domain in tag['src'] or dots == 1:
                        success_elements += 1
                    total_elements += 1

            percentage = self._calculate_percentage(success_elements, total_elements)
            return self._evaluate_percentage(percentage, [22.0, 61.0])
        except Exception:
            return -1

    def anchor_url(self):
        try:
            total_elements = 0
            unsafe_elements = 0
            for a in self.soup.find_all('a', href=True):
                if any(x in a['href'].lower() for x in ["#", "javascript", "mailto"]) or (self.url not in a['href'] and self.domain not in a['href']):
                    unsafe_elements += 1
                total_elements += 1

            percentage = self._calculate_percentage(unsafe_elements, total_elements)
            return self._evaluate_percentage(percentage, [31.0, 67.0])
        except Exception:
            return -1

    def links_in_script_tags(self):
        try:
            total_elements = 0
            success_elements = 0
            elements = ['link', 'script']
            for element in elements:
                for tag in self.soup.find_all(element, href=True if element == 'link' else 'src'):
                    dots = tag[element].count('.')
                    if self.url in tag[element] or self.domain in tag[element] or dots == 1:
                        success_elements += 1
                    total_elements += 1

            percentage = self._calculate_percentage(success_elements, total_elements)
            return self._evaluate_percentage(percentage, [17.0, 81.0])
        except Exception:
            return -1

    def server_form_handler(self):
        try:
            forms = self.soup.find_all('form', action=True)
            if not forms:
                return 1
            for form in forms:
                if form['action'] in ["", "about:blank"]:
                    return -1
                elif self.url not in form['action'] and self.domain not in form['action']:
                    return 0
            return 1
        except Exception:
            return -1

    def info_email(self):
        return -1 if re.search(r"[mail\(\)|mailto:?]", str(self.soup)) else 1

    def abnormal_url(self):
        try:
            return 1 if self.response.text == self.whois_response else -1
        except Exception:
            return -1

    def website_forwarding(self):
        try:
            history_len = len(self.response.history)
            if history_len <= 1:
                return 1
            elif history_len <= 4:
                return 0
            return -1
        except Exception:
            return -1

    def status_bar_cust(self):
        return -1 if re.search("<script>.+onmouseover.+</script>", self.response.text) else 1

    def disable_right_click(self):
        return -1 if re.search(r"event.button ?== ?2", self.response.text) else 1

    def using_popup_window(self):
        return -1 if re.search(r"alert\(", self.response.text) else 1

    def iframe_redirection(self):
        return -1 if re.search(r"<iframe>|<frameBorder>", self.response.text) else 1

    def age_of_domain(self):
        try:
            creation_date = self._get_date(self.whois_response.creation_date)
            today = date.today()
            age = (today.year - creation_date.year) * 12 + (today.month - creation_date.month)
            return 1 if age >= 6 else -1
        except Exception:
            return -1

    def dns_recording(self):
        try:
            return 1 if self.whois_response else -1
        except Exception:
            return -1

    def website_traffic(self):
        try:
            rank = BeautifulSoup(urllib.request.urlopen(f"http://data.alexa.com/data?cli=10&dat=s&url={self.url}"), 'xml').find("REACH")['RANK']
            return 1 if int(rank) < 100000 else 0
        except Exception:
            return -1

    def page_rank(self):
        try:
            rank_checker_response = requests.post("https://www.checkpagerank.net/index.php", {"name": self.url})
            global_rank = int(re.search(r"Global Rank: ([0-9]+)", rank_checker_response.text).group(1))
            return 1 if 0 < global_rank < 100000 else 0
        except Exception:
            return -1

    def google_index(self):
        try:
            site = search(self.url, 5)
            return 1 if site else -1
        except Exception:
            return -1

    def links_pointing_to_page(self):
        try:
            num_links = len(re.findall(r"<a href=", self.response.text))
            return 1 if num_links == 0 else 0 if num_links <= 2 else -1
        except Exception:
            return -1

    def stats_report(self):
        try:
            url_match = re.search(r"google.com/safebrowsing/diagnostic\?site=", self.url)
            return -1 if url_match else 1
        except Exception:
            return 1

    def _calculate_percentage(self, success, total):
        return (success / total) * 100 if total > 0 else 0

    def _evaluate_percentage(self, percentage, thresholds):
        if percentage < thresholds[0]:
            return 1
        elif thresholds[0] <= percentage < thresholds[1]:
            return 0
        return -1

import requests
import json
import urllib
from linkify_it import LinkifyIt

def analyze_link(text):
    linkify = LinkifyIt()
    link_result = linkify.match(text)

    # If no URL is found in the text
    if not link_result:
        return {'Link': False}

    # Extract the URL from the first match
    url = link_result[0].url

    # Analyze the URL
    API_KEY = ''
    encoded_url = urllib.parse.quote(url, safe='')
    api_url = f"https://ipqualityscore.com/api/json/url/{API_KEY}/"
    response = requests.get(api_url + encoded_url)
    data = response.json()

    # Extract specific fields
    required_fields = {
        "Link" : True,
        "link_malware": data.get("malware", False),
        "link_phishing": data.get("phishing", False),
        "link_suspicious": data.get("suspicious", False),
        "link_adult": data.get("adult", False),
        "link_risk_score": data.get("risk_score", 0)
    }

    return required_fields

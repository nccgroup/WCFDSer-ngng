#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup

url='https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-nbfs/9268bb11-94bf-451a-8827-955495e99c7b'
# Download page
response = requests.get(url)
# Parse the HTML of the response
soup = BeautifulSoup(response.content, 'html.parser')

# Extract table rows
table = soup.find_all("table")[1]
rows = table.find_all("tr")

for ind, row in enumerate(rows):
    if ind == 0:  # Skip the header row
        continue
    # Print in an easy to diff format
    print(
        'dict.Add("{}");'.format(
            str(row.find_all('p')[1].string).strip()
        )
    )

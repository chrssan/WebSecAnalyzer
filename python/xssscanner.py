import requests
from pprint import pprint
from bs4 import BeautifulSoup as soup
from urllib.parse import urljoin
from datetime import datetime

url = input("Please enter a URL you want to scan: ")


# function to download the website of the url we want to scan
def get_url(url):
    dlwebsite = soup(requests.get(url).content, "html.parser")
    return dlwebsite.find_all("form")


def get_website_info(form):
    #grabs methods from website
    websitedet = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get")

    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})

    # stores grabbed info into new variables
    websitedet["action"] = action
    websitedet["method"] = method
    websitedet["inputs"] = inputs

    return websitedet

def add_info(form_details, url, value):
    #grabs the URL and gets any form that has an action attribute
    target_url = urljoin(url, form_details["action"])

    # gets inputs from the page
    inputs = form_details["inputs"]
    data = {}

    for input in inputs:
        if input["type"] == "text":
            input["value"] = value
        input_name = input.get("name")
        input_value = input.get("value")

        if input_name and input_value:
            # if input name and value are not available, add them to the data form submission
            data[input_name] = input_value

        if form_details["method"] == "post":  # return what method is being used
            return requests.post(target_url, params=data)
        else:
            return requests.get(target_url, params=data)




def scan_xss(url):
    """
    This method allows the application to do its job - the function below inserts javascript code onto a detected input field and if the javascript code is accepted,
    the script returns true, xss vulnerability is avilable for the site.
    """

    # collects all forms from the url
    forms = get_url(url)
    print(f"Detected {len(forms)} forms on {url}.")
    #puts javascript code in form
    js_script = "<script> alert ('test vulnerability')</script>"

    #prints false if code above is not accepted
    is_vulnerable = False

    # print all inputs that the code above was able to push and get a result out of
    for form in forms:
        form_details = get_website_info(form)
        now = datetime.now()
        content = add_info(form_details, url, js_script).content.decode()
        if js_script in content:
            print("Scan completed", now )
            print(f"Vulnerability Detected on {url}")
            print(f" Scan Info:")
            pprint(form_details)
            is_vulnerable = True
            return is_vulnerable

if __name__ == "__main__":
    import sys
print(scan_xss(url))

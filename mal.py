import modelbit
mb = modelbit.login()
import pandas as pd
import xgboost as xgb
from urllib.parse import urlparse


model = xgb.XGBClassifier(tree_method='hist')
model.load_model('xgboost_model.model')  


def predict_malicious_url(url):
 
    parsed_url = urlparse(url)
    url_length = len(url)
    hostname_length = len(parsed_url.hostname) if parsed_url.hostname else 0
    path_length = len(parsed_url.path)
    fd_length = url.count('/')
    count_dash = url.count('-')
    count_at = url.count('@')
    count_question = url.count('?')
    count_percent = url.count('%')
    count_dot = url.count('.')
    count_equal = url.count('=')
    count_http = url.count('http')
    count_https = url.count('https')
    count_www = url.count('www')
    count_digits = sum(c.isdigit() for c in url)
    count_letters = sum(c.isalpha() for c in url)
    count_dir = url.count('//')
    use_of_ip = 1 if parsed_url.hostname and parsed_url.hostname.replace('.', '').isdigit() else 0
    short_url = 1 if len(parsed_url.path) < 20 else 0

    input_data = pd.DataFrame({
        'url_length': [url_length],
        'hostname_length': [hostname_length],
        'path_length': [path_length],
        'fd_length': [fd_length],
        'count-': [count_dash],
        'count@': [count_at],
        'count?': [count_question],
        'count%': [count_percent],
        'count.': [count_dot],
        'count=': [count_equal],
        'count-http': [count_http],
        'count-https': [count_https],
        'count-www': [count_www],
        'count-digits': [count_digits],
        'count-letters': [count_letters],
        'count_dir': [count_dir],
        'use_of_ip': [use_of_ip],
        'short_url': [short_url],
    })

    prediction = model.predict(input_data)[0]
    return prediction


input_url = input()
prediction = predict_malicious_url(input_url)
print("Prediction for", input_url, ":", prediction)
mb.deploy(predict_malicious_url)

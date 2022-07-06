# Overview
py-shodan-notifier collects host information from Shodan and send it to slack.

# Requirements

* python3 ( >= 3.8)

* python-dotenv [https://pypi.org/project/python-dotenv/](https://pypi.org/project/python-dotenv/)

* Shodan CLI [https://cli.shodan.io/](https://cli.shodan.io/)

* python-slack-sdk [https://github.com/slackapi/python-slack-sdk](https://github.com/slackapi/python-slack-sdk)

* TinyDB [https://pypi.org/project/tinydb/](https://pypi.org/project/tinydb/)

# Support
Linux

# Usage
```
Usage: python3 py-shodan-notifier2.py
```

# Install
```
git clone
cd py-shodan-notifier2
vi .env
 - enter your Shodan API key to SHODAN_API
 - enter your slack bot token to SLACK_BOT_TOKEN
 - enter your slack channel id to SLACK_CHANNEL
vi iplist.txt
 - enter your target IP addresses
python3 py-shodan-notifier2.py
```


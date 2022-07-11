import os
import shodan
import time
import datetime
from tinydb import TinyDB, Query
from dotenv import load_dotenv
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

abs_dirpath = os.path.dirname(os.path.abspath(__file__))
dotenv_path = os.path.join(abs_dirpath, ".env")
load_dotenv(dotenv_path)
# to compare timestamp with shodan, get timestamp as UTC
now = datetime.datetime.utcnow()

pending_days = 10
close_days = 30
# threshold hours. days * hours
reopen_threshold = close_days * 24
pending_threshold = pending_days * 24
close_threshold = close_days * 24

SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN")
SLACK_CHANNEL = os.environ.get("SLACK_CHANNEL")
SHODAN_API = os.environ.get("SHODAN_API")

client = WebClient(token=SLACK_BOT_TOKEN)
api = shodan.Shodan(SHODAN_API)

def fetch_scan_result(ip):
    print(f'trying to fetch scan results for {ip}...')
    try:
        host_result = []
        host = api.host(ip)
        ip_address = host['ip_str']
        host_os = host.get('os', 'None')
        if host_os is None:
            host_os = '-'

        data = host['data']

        for item in data:
            port = item['port']
            transport = item['transport']
            if not item['hostnames']:
                hostnames = '-'
            else:
                hostnames = '|'.join(item['hostnames'])
            if not item['domains']:
                domains = '-'
            else:
                domains = '|'.join(item['domains'])
            product = item.get('product', '-')
            version = item.get('version', '-')
            vulns = item.get('vulns', '-')
            if vulns != '-':
                keys = list(vulns.keys())
                vulns = '|'.join(sorted(keys))
            timestamp = item['timestamp']
            # port is default open
            status = 'open'

            dict_item = {'ip': ip_address, 'port': port, 'transport': transport, 'os': host_os, 'hostnames': hostnames, 'domains': domains, 'product': product, 'version': version, 'vulns': vulns, 'timestamp': timestamp, 'status': status}
            host_result.append(dict_item)

        return host_result

    except shodan.APIError as e:
        print('Error: {}'.format(e))

def get_diffs(db, results):
    new_documents = []
    new_header = f'''\
##### New
ID, IP, Port, Transport, OS, Hostnames, Domains, Product, Version, Vulns, Timestamp
'''
    new_contents = ''
    reopen_header = f'''\
##### Updated re-open
ID, IP, Port, Transport, Status
'''
    reopen_contents = ''

    if not db.all():
        # print('Database or documents do not exist. Initializing database.')
        db.insert_multiple(results)
    else:
        # print('Checking increments from past results...')
        for host_result in results:
            # timestamp is used for comparison later
            timestamp = host_result['timestamp']
            # current timestamp string
            current_timestamp = timestamp

            # define query fragments
            query_fragment = {
                'ip': host_result['ip'],
                'port': host_result['port'],
                'transport': host_result['transport'],
                'os': host_result['os'],
                'hostnames': host_result['hostnames'],
                'domains': host_result['domains'],
                'product': host_result['product'],
                'version': host_result['version'],
                'vulns': host_result['vulns']
                }
            # create new dictionary which is combined query_fragment with timestamp
            query_fragment_all = {**query_fragment, **{'timestamp': timestamp}}

            # search documents with fragment filter
            search_results = db.search(Query().fragment(query_fragment))

            # when target documents don't exist
            if not search_results:
                query_document = [query_fragment]
                open_status, open_docs = check_open_status_and_documents(db, query_document, current_timestamp)
                open_ids = list(map(get_document_ids, open_docs))

                # when no other combinations exist
                if not open_ids:
                    document_id = db.insert(host_result)
                # when other combinations exist
                else:
                    # when open_status is open
                    if open_status == 'open':
                        document_id = db.insert(host_result)
                        db.update({'status': open_status}, doc_ids = open_ids)
                    # when open_status is re-open
                    else:
                        host_result['status'] = 're-open'
                        document_id = db.insert(host_result)

                        # preparing output
                        for open_doc in open_docs:
                            open_doc_id = open_doc.doc_id
                            reopen_contents += f"{open_doc_id},{open_doc['ip']},{open_doc['port']},{open_doc['transport']},{open_doc['status']}\n"
                        reopen_contents += f"{document_id},{host_result['ip']},{host_result['port']},{host_result['transport']},{host_result['status']}\n"

                        db.update({'status': open_status}, doc_ids = open_ids)

                # print(f'New document inserted.')

                host_result['id'] = document_id
                new_documents.append(host_result)
            # when target documents exist
            else:
                if search_results[0]['timestamp'] == current_timestamp:
                    # print(f'No update.')
                    continue
                else:
                    open_status, open_docs = check_open_status_and_documents(db, search_results, current_timestamp)
                    open_ids = list(map(get_document_ids, open_docs))

                    if open_status == 're-open':
                        host_result['status'] = 're-open'
                        # preparing output
                        for open_doc in open_docs:
                            open_doc_id = open_doc.doc_id
                            reopen_contents += f"{open_doc_id},{open_doc['ip']},{open_doc['port']},{open_doc['transport']},{open_doc['status']}\n"
                        reopen_contents += f"{document_id},{host_result['ip']},{host_result['port']},{host_result['transport']},{host_result['status']}\n"

                    # update status
                    db.update({'status': open_status}, doc_ids = open_ids)

                    # update timestamp. MUST update timestamp after check_open_status_and_ids()
                    db.update({'timestamp': timestamp}, Query().fragment(query_fragment))

                    # print(f'Only timestamp is updated.')

    if not new_documents:
        new_contents += f'No results.\n'
    else:
        for document in new_documents:
            new_contents += f"{document['id']},{document['ip']},{document['port']},{document['transport']},"
            new_contents += f"{document['os']},{document['hostnames']},{document['domains']},{document['product']},"
            new_contents += f"{document['version']},{document['vulns']},{document['timestamp']}\n"

    if not reopen_contents:
        reopen_contents += f'No results.\n'

    diff_contents = new_header + new_contents + reopen_header + reopen_contents
    return diff_contents

def get_document_ids(document):
    return document.doc_id

def get_latest_timestamp(documents):
    timestamps = [document.get('timestamp') for document in documents]
    return max(timestamps)

def compare_reopen_threshold(latest_timestamp, current_timestamp):
    latest_datetime = datetime.datetime.strptime(latest_timestamp, '%Y-%m-%dT%H:%M:%S.%f')
    current_datetime = datetime.datetime.strptime(current_timestamp, '%Y-%m-%dT%H:%M:%S.%f')

    delta = current_datetime - latest_datetime
    delta_hours = delta / datetime.timedelta(hours=1)

    # whent delta is over reopen threshold , return true
    if delta_hours > reopen_threshold:
        return True
    else:
        return False

# TinyDB custom test function. Used for pending threshold comparison
def compare_pending_threshold(value):
    last_datetime = datetime.datetime.strptime(value, '%Y-%m-%dT%H:%M:%S.%f')

    delta = now - last_datetime
    delta_hours = delta / datetime.timedelta(hours=1)

    # whent delta is over pending threshold but under close, return true
    if pending_threshold < delta_hours < close_threshold:
        return True
    else:
        return False

# TinyDB custom test function. Used for close threshold comparison
def compare_close_threshold(value):
    last_datetime = datetime.datetime.strptime(value, '%Y-%m-%dT%H:%M:%S.%f')

    delta = now - last_datetime
    delta_hours = delta / datetime.timedelta(hours=1)

    # whent delta is over close threshold, return true
    if delta_hours > close_threshold:
        return True
    else:
        return False

def check_open_status_and_documents(db, documents, current_timestamp):
    # in this case, documents always have only one item
    document = documents[0]
    service_combinations = db.search((Query().fragment({'ip': document['ip'], 'port': document['port'], 'transport': document['transport']})))

    # when noting match (means this combination is new)
    if not service_combinations:
        return 'open', []

    # doc_ids = list(map(get_document_ids, service_combinations))

    # get latest timestamp among service_combinations
    latest_timestamp = get_latest_timestamp(service_combinations)

    # whent latest_timestamp is over threshold
    if compare_reopen_threshold(latest_timestamp, current_timestamp):
        # return 're-open', doc_ids
        return 're-open', service_combinations
    else:
        # return 'open', doc_ids
        return 'open', service_combinations

def get_status_update_documents(db, documents, status):
    # check timestamp for documents which have same IP,Port,Transport combination
    ids = []
    target_documents = []

    for document in documents:
        # if document id is already in list, skip.
        # if document.doc_id in ids:
        if document in target_documents:
            continue

        service_combinations = db.search((Query().fragment({'ip': document['ip'], 'port': document['port'], 'transport': document['transport']})))
        # get latest timestamp among service_combinations
        latest_timestamp = get_latest_timestamp(service_combinations)

        if status == 'pending':
            if compare_pending_threshold(latest_timestamp):
                # doc_ids = list(map(get_document_ids, service_combinations))
                # ids.extend(doc_ids)
                target_documents.extend(service_combinations)
        elif status == 'close':
            if compare_close_threshold(latest_timestamp):
                # doc_ids = list(map(get_document_ids, service_combinations))
                # ids.extend(doc_ids)
                target_documents.extend(service_combinations)

    return target_documents

def update_status(db):
    Scan = Query()

    pending_contents = ""
    close_contents = ""
    pending_header = f'''##### Updated pending (threshold: {pending_days} days.)
ID, IP, Port, Transport, Status
'''
    close_header = f'''##### Updated close (threshold: {close_days} days.)
ID, IP, Port, Transport, Status
'''

    # search documents which are possibly needed to be updated status to pending
    pending_candidate_docs = db.search((Scan.timestamp.test(compare_pending_threshold)) & ~ (Scan.status == 'pending'))

    # check timestamp for documents which have same IP,Port,Transport combination
    pending_docs = get_status_update_documents(db, pending_candidate_docs, 'pending')
    pending_ids = list(map(get_document_ids, pending_docs))
    # print(f'pending update target ids = {pending_ids}')

    db.update({'status': 'pending'}, doc_ids = pending_ids)

    if not pending_ids:
        pending_contents += f'No results.\n'
    else:
        for pending_doc in pending_docs:
            pending_doc_id = pending_doc.doc_id
            pending_contents += f"{pending_doc_id},{pending_doc['ip']},{pending_doc['port']},{pending_doc['transport']},pending\n"

    # search documents needed to update status to close
    close_candidate_docs = db.search((Scan.timestamp.test(compare_close_threshold)) & ~ (Scan.status == 'close'))

    # check timestamp for documents which have same IP,Port,Transport combination
    close_docs = get_status_update_documents(db, close_candidate_docs, 'close')
    close_ids = list(map(get_document_ids, close_docs))
    # print(f'close update target ids = {close_ids}')

    db.update({'status': 'close'}, doc_ids = close_ids)

    if not close_ids:
        close_contents += f'No results.\n'
    else:
        for close_doc in close_docs:
            close_doc_id = close_doc.doc_id
            close_contents += f"{close_doc_id},{close_doc['ip']},{close_doc['port']},{close_doc['transport']},close\n"

    update_contents = pending_header + pending_contents + close_header + close_contents
    return update_contents

def get_csv_result(results):
    csv_header = f'No, IP, Port, OS, Hostnames, Domains, Product, Version, Vulns, Timestamp\n'
    csv_result = ''
    count = 1
    for result in results:
        csv_result += f"{count},{result['ip']},{result['port']},{result['transport']},{result['os']},{result['hostnames']},"
        csv_result += f"{result['domains']},{result['product']},{result['version']},{result['vulns']},{result['timestamp']}\n"
        count += 1
    return csv_header + csv_result

def main():
    db = TinyDB(os.path.join(abs_dirpath, 'shodan.json'))
    today = datetime.date.today()
    report = ""

    header = f'[Shodan Notifier Report on {today}]\n'
    update_part_header = f"""\
================Update Report==============
"""
    today_part_header = f"""\
===========Results on {today}===========
"""
    footer = f"""\
========================================
Have a good day!"""

    # list for holding shodan results
    results = []
    with open(os.path.join(abs_dirpath, "iplist.txt"), "r") as f:
        lines = f.read().splitlines()
        unique_lines = sorted(list(set(lines)))
        for line in unique_lines:
            host_result = fetch_scan_result(line)

            # respect shodan API rate limit
            time.sleep(1)

            if not host_result:
                continue

            results.extend(host_result)

    # get update report contents
    diff_contents = get_diffs(db, results)
    update_contents = update_status(db)

    # get today's report contents
    today_results = get_csv_result(results)

    report = header + update_part_header + diff_contents + update_contents + today_part_header + today_results + footer
    print(report)

    with open(os.path.join(abs_dirpath, f'logs/{today}_report.txt'), 'w') as f:
        f.writelines(report)

    try: 
        # response = client.chat_postMessage(channel=SLACK_CHANNEL, text=report)
        response = client.files_upload(channels=SLACK_CHANNEL, content=report, title="Shodan_Notifier")
    except SlackApiError as e:
        assert e.response["ok"] is False
        assert e.response["error"]
        print(f"Got an error: {e.response['error']}")

if __name__ == "__main__":
    main()

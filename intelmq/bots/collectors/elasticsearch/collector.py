# -*- coding: utf-8 -*-

"""
Elasticsearch query collector bot
Queries ElasticSearch to get events from stored data. Query 

Parameters:
    elk_url: string. URL to the ElasticSearch interface
    query_file: string. Query to be sent to elastic to get aggregated data. 
                Query supposed to return 2-dimensional array (e.g. stacked bar chart data) 
                with IP address as a key
    period_to_query: int. For how many hours to query the elastic
    hit_count: int. How many buckets should hit the IP to be collected
    hit_sum: int. what is total amount of hits for IP in order to be collected
    classification: string
"""

import requests, json
from intelmq.lib.bot import CollectorBot


class ELKCollectorBot(CollectorBot):

    def process(self):
        elk_url = self.parameters.elk_url
        query_file = self.parameters.query_file
        period_to_query = self.parameters.period_to_query
        hit_count = self.parameters.hit_count
        hit_sum = self.parameters.hit_sum
        classification = self.parameters.classification

        headers = {'Content-Type': 'application/json'}

        # Adding period_to_query value as a timestamp value into ELK query
        elk_query = json.load(open(query_file))
        for item in elk_query['query']['bool']['must']:
            if 'range' in item:
                for key, value in item.items():
                    for k, v in value.items():
                        v['gte'] = 'now-' + str(period_to_query) + 'h'
                        v['lte'] = 'now'

        self.logger.info('ELK to IntelMQ processing started')
        response = requests.get(elk_url, data=json.dumps(elk_query), headers=headers, verify=False)
        if response.status_code == 200 and 'took' in response.text:
            elk_report = json.loads(response.text)
            aggs = next(iter(elk_report['aggregations']))
            for item in elk_report['aggregations'][aggs]['buckets']:
                for key, value in item.items():
                    if type(value) == dict:
                        # Checking if bucket values matches search criteria
                        if len(value.get('buckets')) >= hit_count and item.get('doc_count') >= hit_sum:
                            line = {}
                            line.update({'source.ip': item.get('key')})
                            line.update({'classification.type': classification})
                            report = self.new_report()
                            report.add('raw', json.dumps(line))
                            self.send_message(report)
        else:
            self.logger.error(response.text)


BOT = ELKCollectorBot

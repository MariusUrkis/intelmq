# Elasticsearch query collector bot
### Queries ElasticSearch to get events from stored data. Query 

###Parameters:
*elk_url: string. URL to the ElasticSearch interface
*query_file: string. Query to be sent to elastic to get aggregated data. 
                Query supposed to return 2-dimensional array (e.g. stacked bar chart data) 
                with IP address as a key
*period_to_query: int. For how many hours to query the elastic
*hit_count: int. How many buckets should hit the IP to be collected
*hit_sum: int. what is total amount of hits for IP in order to be collected
*classification: string

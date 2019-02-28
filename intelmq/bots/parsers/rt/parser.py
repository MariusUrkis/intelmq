# -*- coding: utf-8 -*-
"""
The source provides a JSON file with a dictionary of ticket field/customfiel name and value pairs
"""

import json

from datetime import datetime
from dateutil import tz

from intelmq.lib import utils
from intelmq.lib.bot import Bot

class RTParserBotPlain(Bot):

    field_mapping = {'CF.{Category}': 'extra.incident_category',
                    'CF.{Classification}': 'classification.taxonomy',
                    'CF.{Description}': 'event_description.text',
                    'CF.{Incident time}': 'time.source',
                    'CF.{Incident Type}': 'classification.type',
                    'CF.{IP}': 'extra.ip',
                    'Started':'extra.started',
                    'CF.{URLs}':'extra.urls',
                    'CF.{URL}':'extra.urls',
                    'Queue':'extra.queue',
                    'Created':'extra.created',
                    'Status':'status',
                    'Owner':'extra.owner',
                    'Requestors':'extra.requestors',
                    'Subject':'extra.subject',
                    'CF.{Description}':'event_description.text',
                    'Resolved':'extra.resolved',
                    'Priority':'extra.priority',
                    'CF.{IP}':'extra.ip',
                    'CF.{Customer}':'extra.organization.name'
                     }

    value_mapping = {'Spam': 'spam',
        'Harmful Speech': 'harmful-speech',
        'Child Porn/Sexual/Violent Content': 'violence',
        'Infected System': 'infected system',
        'C2 Server': 'c&c',
        'Malware Distribution': 'malware-distribution',
        'Malware Configuration': 'malware configuration',
        'Scanning': 'scanner',
        'Sniffing': 'sniffing',
        'Social Engineering': 'social-engineering',
        'Exploitation of known Vulnerabilities': 'ids alert',
        'Login attempts': 'brute-force',
        'New attack signature': 'exploit',
        'Privileged Account Compromise': 'privileged-account-compromise',
        'Unprivileged Account Compromise': 'unprivileged-account-compromise',
        'Application Compromise': 'application-compromise',
        'Burglary': 'burglary',
        'Denial of Service': 'dos',
        'Distributed Denial of Service': 'ddos',
        'Misconfiguration': 'outage',
        'Sabotage': 'sabotage',
        'Outage': 'outage',
        'Unauthorised access to information': 'Unauthorised-information-access',
        'Unauthorised modification of information': 'Unauthorised-information-modification',
        'Data Loss': 'data-loss',
        'Unauthorized use of resources': 'unauthorized-use-of-resources',
        'Copyright': 'copyright',
        'Masquerade': 'masquerade',
        'Phishing': 'phishing',
        'Weak crypto': 'weak-crypto',
        'DDoS amplifier': 'ddos-amplifier',
        'Potentially unwanted accessible services': 'potentially-unwanted-accessible',
        'Information disclosure': 'information-disclosure',
        'Vulnerable system': 'vulnerable-system',
        'Other': 'other',
        'Test': 'test',
        'Harassment': 'harmful-speech',
        'Child/sexual/violenc': 'violence',
        'Virus': 'malware',
        'Worm': 'malware',
        'Trojan': 'malware',
        'Spyware': 'malware',
        'Dialer': 'malware',
        'Rootkit': 'malware',
        'Social engineering': 'social-engineering',
        'Exploiting known vulnerabilities': 'ids alert',
        'Privileged account compromise': 'privileged-account-compromise',
        'Unprivileged account compromise': 'unprivileged-account-compromise',
        'Application compromise': 'application-compromise',
        'Bot': 'botnet drone',
        'DoS': 'dos',
        'DDoS': 'ddos',
        'Confidentiality loss': 'Unauthorised-information-access',
        'Integrity loss': 'Unauthorised-information-modification',
        'Availabilty loss': 'data-loss',
        'Detected vulnerability': 'vulnerable-system',
        'Security assessment': 'other',
        'Configuration/Maintenance': 'other',
        'Security consulting': 'other'

        }

    unique_field_mapping = {'id': 'extra.id'
                            }

    """
    Configuration parameters:
      fields_to_collect - list of field names to collect from ticket data
    """
    def init(self):
        self.fields_to_collect = []

        if self.parameters.fields_to_collect:
           self.fields_to_collect = [f.strip() for f in self.parameters.fields_to_collect.split(',')]

    def process(self):
        report = self.receive_message()
        event = self.new_event(report)

        ticket_json = utils.base64_decode(report.get("raw"))

        # try to parse a JSON object
        ticket = json.loads(ticket_json)

        event.add("raw", report.get("raw"), sanitize=False)
        event.add("rtir_id", int(ticket['id'].split('/')[1]))

        self.logger.debug('Process ticket %s.', int(ticket['id'].split('/')[1]))

        event = self.__extract_common_event(event, ticket)
        """
        Create distinct event for every field value in unique_field_mapping
        """
        for rt_field, intelmq_field in self.unique_field_mapping.items():
            # Check if value is not empty
            if rt_field in ticket and len(ticket[rt_field]) > 0:
                # There might be multiple values, extract them and create separate events for each
                values = ticket[rt_field].split(',')
                for value in values:
                    temp_event = event.copy()
                    temp_event.add(intelmq_field, value)
                    self.send_message(temp_event)

        self.acknowledge_message()

    """
    Extract common ticket fields that every event created from this ticket should have. 
    
    Iterate every ticket field and check if it is mapped in field_mapping property or
    required to be collected with fields_to_collect configuration. Both ticket fields and 
    CustomFields (CF.{<field_name>}) are checked.
    """
    def __extract_common_event(self, event, ticket):
        self.logger.info('Extracting common event from ticked data')

        for rt_field in ticket:
            if type(ticket[rt_field]) is not str or len(ticket[rt_field]) == 0:
               continue
            if rt_field in self.unique_field_mapping:
               continue

            if rt_field in self.field_mapping:
               field = self.field_mapping[rt_field]
               if (rt_field == 'Started' or rt_field == 'Created' or rt_field == 'Resolved') and ticket[rt_field] == "Not set":
                  continue
               if field == 'time.source':
                  value = str(self.__format_date(ticket[rt_field]))
               elif field == 'extra.started' or field == 'extra.created' or field == 'extra.resolved':
                  value = str(self.__format_rt_date(ticket[rt_field]))
               elif field == 'classification.type':
                  value = self.value_mapping[ticket[rt_field]]
                  event.add('extra.incident_type', ticket[rt_field])
               else:
                  value = ticket[rt_field].replace("'", "")

               event.add(field, value)
            else:
               for field in self.fields_to_collect:
                   if field.lower() == rt_field.lower() or self.__field_name_as_customfield(field) == rt_field.lower():
                      event.add('extra.' + field.lower().replace(" ", "_"), ticket[rt_field].replace("'", ""))

        return event
    
    def __field_name_as_customfield(self, field):
        return 'CF.{{0}}'.format(field).lower()

    def __format_date(self, date_string):
        date_obj = datetime.strptime(date_string, '%Y-%m-%d %H:%M:%S')
        
        return date_obj.replace(tzinfo=tz.tzutc())

    def __format_rt_date(self, date_string):
        # Tue May 08 16:19:50 2018
        date_obj = datetime.strptime(date_string, '%a %b %d %H:%M:%S %Y')

        return date_obj.replace(tzinfo=tz.tzutc())

BOT = RTParserBotPlain

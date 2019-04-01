# -*- coding: utf-8 -*-
"""
Request Tracker output bot

Creates a ticket in the specified queue
Parameters:
URI, user, password, queue
"""

from intelmq.lib.bot import Bot
try:
    import rt
except ImportError:
    rt = None
    
class RTOutputBot(Bot):
    # mapping taxonomy Custom Fields. 
    # L1 - for main classification, L2 - for subtype
    CF_taxonomyL1 = "Classification"
    CF_taxonomyL2 = "Incident Type"
    # Some event attributes are mapped to ticket custom fields 
    CF_mapping = {'Description': 'event_description.text',
        'source.ip': 'IP',
        'extra.incident.severity': 'Incident Severity',
        'extra.incident.importance': 'Importance',
        'extra.organization.name': 'Customer'
#        'source.url': 'URL',
    }
    # special mapping for Incident Type values
    # Incident ticket has CF Incident type 
    # (subtype of the main incident classification).
    # Values has to be properly mapped from classification.type to RT taxonomy CF values
    Taxonomy_mapping = {
        'backdoor': ['Abusive Content', 'Spam'],
        'blacklist': ['Other', 'Other'],
        'botnet drone': ['Malicious Code', 'Infected System'],
        'brute-force': ['Intrusion Attempts', 'Login attempts'],
        'burglary': ['Intrusions', 'Burglary'],
        'c&c': ['Malicious Code', 'C2 Server'],
        'compromised': ['Intrusions', 'Unprivileged Account Compromise'],
        'copyright': ['Fraud', 'Copyright'],
        'data-loss': ['Information Content Security', 'Data Loss'],
        'ddos': ['Availability', 'DDoS'],
        'ddos-amplifier': ['Vulnerable', 'DDoS amplifier'],
        'defacement': ['Intrusions', 'Privileged Account Compromise'],
        'dga domain': ['Malicious Code', 'Malware Configuration'],
        'dos': ['Availability', 'DoS'],
        'dropzone': ['Malicious Code', 'Malware Distribution'],
        'exploit': ['Intrusion Attempts', 'Exploitation of known Vulnerabilities'],
        'harmful-speech': ['Abusive Content', 'Harmful Speech'],
        'ids alert': ['Intrusion Attempts', 'Exploitation of known Vulnerabilities'],
        'infected system': ['Malicious Code', 'Infected System'],
        'information-disclosure': ['Vulnerable', 'Information disclosure'],
        'leak': ['Information Content Security', 'Unauthorised access to information'],
        'malware': ['Malicious Code', 'Infected System'],
        'malware configuration': ['Malicious Code', 'Malware Configuration'],
        'malware-distribution': ['Malicious Code', 'Malware Distribution'],
        'masquerade': ['Fraud', 'Masquerade'],
        'other': ['Other', 'Other'],
        'outage': ['Availability', 'Outage'],
        'phishing': ['Fraud', 'Phishing'],
        'potentially-unwanted-accessible': ['Vulnerable', 'Potentially unwanted accessible services'],
        'privileged-account-compromise': ['Intrusions', 'Privileged Account Compromise'],
        'proxy': ['Other', 'Other'],
        'ransomware': ['Malicious Code', 'Infected System'],
        'sabotage': ['Availability', 'Sabotage'],
        'scanner': ['Information Gathering', 'Scanning'],
        'sniffing': ['Information Gathering', 'Sniffing'],
        'social-engineering': ['Information Gathering', 'Social Engineering'],
        'spam': ['Abusive Content', 'Spam'],
        'test': ['Test', 'Test'],
        'tor': ['Other', 'Other'],
        'Unauthorised-information-access': ['Information Content Security', 'Unauthorised access to information'],
        'Unauthorised-information-modification': ['Information Content Security', 'Unauthorised modification of information'],
        'unauthorized-command': ['Intrusions', 'Application Compromise'],
        'unauthorized-login': ['Intrusions', 'Unprivileged Account Compromise'],
        'unauthorized-use-of-resources': ['Fraud', 'Unauthorized use of resources'],
        'unknown': ['Other', 'Other'],
        'unprivileged-account-compromise': ['Intrusions', 'Unprivileged Account Compromise'],
        'violence': ['Abusive Content', 'Child Porn/Sexual/Violent Content'],
        'vulnerable client': ['Vulnerable', 'Vulnerable system'],
        'vulnerable service': ['Vulnerable', 'Vulnerable system'],
        'vulnerable-system': ['Vulnerable', 'Vulnerable system'],
        'weak-crypto': ['Vulnerable', 'Weak crypto']
    }
    def init(self):
        if rt is None:
            self.logger.error('Could not import rt. Please install it.')
            self.stop()


        self.fieldnames = getattr(self.parameters, 'investigation_fields')
        if isinstance(self.fieldnames, str):
            self.fieldnames = self.fieldnames.split(',')
        # Investigations ticket can be created only when we work with Incidents ticket 
        # and there is a parameter provided
        if getattr(self.parameters, 'queue', 'None') == 'Incidents' and getattr(self.parameters, 'create_investigation', False):
            self.create_investigation = True
        else:
            self.create_investigation = False
        self.final_status = getattr(self.parameters, 'final_status', None)

        

            
    def process(self):
        event = self.receive_message()
        del event['raw']
        RT = rt.Rt(self.parameters.uri, verify_cert=self.parameters.verify_cert)
        if not RT.login(self.parameters.user,
                   self.parameters.password):
            raise ValueError('Login failed.')          
        kwargs = {}
        # we make subject in form of "Incident, Provider:feed name: IP"
        self.subject = 'Incident notification';
#        if event.get('feed.provider'):
#            self.subject += ", " + event['feed.provider']
#        if event.get('feed.name'):
#            self.subject += ":" + event['feed.name']
        if event.get('source.ip'):
            self.subject += ", " + event['source.ip']       
        if event.get('event_description.text'):
            self.content = event['event_description.text'] + "\n\n"
        
        classification = ""
        incident_type = ""
        if event.get('classification.type'):
            classification, incident_type = self.Taxonomy_mapping[event['classification.type']]
            self.logger.debug("Classification assigned: %s, %s", classification, incident_type)
            kwargs["CF_" + self.CF_taxonomyL1] = classification
            kwargs["CF_" + self.CF_taxonomyL2] = incident_type
        content = self.content    
        for key, value in event.items():
            # Add all event attributes to the body of the incident ticket
            content += key + ": " + str(value) + "\n"
            # Add some (mapped) event attributes to the Custom Fields of the ticket
            if self.CF_mapping.get(key):
                # In case we have event attribute which is mapped to the Incident Type CF,
                # we also do value mapping
                #if self.CF_mapping.get(key) == 'Incident Type' and self.Type_mapping.get(value):
                #    str_value = self.Type_mapping.get(value)
                #else:
                str_value = str(value)
                kwargs["CF_" + self.CF_mapping.get(key)] = str_value
                self.logger.debug("Added argument line CF_%s: %s", self.CF_mapping.get(key), kwargs["CF_" + self.CF_mapping.get(key)])
        self.logger.debug("RT ticket subject: %s", self.subject)
        ticket_id = RT.create_ticket(Queue=self.parameters.queue, Subject=self.subject, Text=content, **kwargs)
        if ticket_id > -1:
            self.logger.debug("RT ticket created: %i", ticket_id)
            if event.get('source.abuse_contact') and self.create_investigation:
                content = self.content
                requestor = event.get('source.abuse_contact')
                # only selected fields goes to the investigation
                for key in self.fieldnames:
                    if event.get(key):
                        content += key + ": " + str(event.get(key)) + "\n"
                investigation_id = RT.create_ticket(Queue="Investigations", Subject=self.subject, Text=content, Requestors=requestor)
                
                if investigation_id > -1:
                    self.logger.debug("Investigation ticket created: %i", investigation_id)
                    # make a link between Incident and Investigation tickets
                    if RT.edit_link(investigation_id, 'MemberOf', ticket_id):
                        self.logger.debug("Investigation ticket %i linked to parent: %i", investigation_id, ticket_id)
                    else:
                        self.logger.error("Failed to link tickets %i -> %i", ticket_id, investigation_id)
                else:
                    self.logger.error("Failed to create RT Investigation ticket")
            if self.final_status:
                if RT.edit_ticket(ticket_id, Status=self.final_status):
                    self.logger.debug("Status changed to %s for ticket %i", self.final_status, ticket_id)
                else:
                    self.logger.error("Failed to change status for RT ticket %i", ticket_id)            
        else:
            self.logger.error("Failed to create RT ticket")
        self.acknowledge_message()

BOT = RTOutputBot

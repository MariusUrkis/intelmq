# -*- coding: utf-8 -*-
import io
import re
import zipfile
from datetime import datetime, timedelta
import json

import requests
from dateutil import parser

from intelmq.lib.bot import CollectorBot
from intelmq.lib.utils import parse_relative

try:
    import rt
except ImportError:
    rt = None


class RTTicketCollectorBot(CollectorBot):
    parameter_mapping = {'search_owner': 'Owner',
                         'search_queue': 'Queue',
                         'search_requestor': 'Requestor',
                         'search_status': 'Status',
                         'search_subject_like': 'Subject__like',
                         }
    """
    Configuration parameters:
      set_status            - one or more statuses ticket should go trough. Should obey lifecycle rules of ticket queue
      set_customfield       - name of customfield to set value for. Used to mark tickets as processed by IntelMQ
      set_customfield_value - value for customfield
    """
    def init(self):
        if rt is None:
            self.logger.error('Could not import rt. Please install it.')
            self.stop()
 
        if getattr(self.parameters, 'search_not_older_than', None):
            try:
                self.not_older_than = parser.parse(self.parameters.search_not_older_than)
                self.not_older_than_type = 'absolute'
            except ValueError:
                try:
                    self.not_older_than_relative = timedelta(minutes=parse_relative(self.parameters.search_not_older_than))
                except ValueError:
                    self.logger.error("Parameter 'search_not_older_than' could not be parsed. "
                                      "Check your configuration.")
                    raise
                self.not_older_than_type = 'relative'
        else:
            self.not_older_than_type = False

        self.set_request_parameters()

    def process(self):
        RT = rt.Rt(self.parameters.uri, verify_cert=self.parameters.verify_cert)
    
        if not RT.login(self.parameters.user, self.parameters.password):
            raise ValueError('Login failed.')

        if self.not_older_than_type:
            if self.not_older_than_type == 'relative':
                self.not_older_than = datetime.now() - self.not_older_than_relative
            kwargs = {'Created__gt': self.not_older_than.isoformat()}
            self.logger.debug('Searching for tickets newer than %r.', kwargs['Created__gt'])
        else:
            kwargs = {}

        # Build RT search query
        for parameter_name, rt_name in self.parameter_mapping.items():
            parameter_value = getattr(self.parameters, parameter_name, None)
            if parameter_value:
                kwargs[rt_name] = parameter_value

        if self.parameters.set_customfield and self.parameters.set_customfield_value:
           field = 'CF_{0}__notexact'.format(self.parameters.set_customfield)
           kwargs[field] = self.parameters.set_customfield_value
        self.logger.debug("RT search query: %s", str(kwargs))
        query = RT.search(order='Created', **kwargs)
        self.logger.info('%s results on search query.', len(query))
          
        report_template = self.new_report()

        for ticket in query:
            ticket_id = int(ticket['id'].split('/')[1])
            self.logger.debug('Process ticket %s.', ticket_id)

            ticket = RT.get_ticket(ticket_id)

            report = report_template.copy()
            report.add('raw', json.dumps(ticket), overwrite=True)

            self.send_message(report)

            if self.parameters.set_customfield and self.parameters.set_customfield_value:
               kwargs = {'CF_{0}'.format(self.parameters.set_customfield): self.parameters.set_customfield_value}
               RT.edit_ticket(ticket_id, **kwargs)

            if self.parameters.set_status:
                statuses = self.parameters.set_status.split(',')
                for status in statuses:
                    RT.edit_ticket(ticket_id, status=status)

BOT = RTTicketCollectorBot


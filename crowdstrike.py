"""
Receives webhooks from Crowdstrike
Authenticated webhook authenticity
Sends alerts on Teams when required

Modules:
    3rd Party: termcolor, hmac, hashlib, base64
    Internal: core/teamschat, core/plugin

Classes:

    CrowdStrikeHandler
        Handle webhooks from the CrowdStrike platform

Functions

    None

Exceptions:

    None

Misc Variables:

    LOCATION : str
        The location of the config file

Author:
    Luke Robertson - April 2023
"""


import termcolor
import hmac
import hashlib
import base64

from core import teamschat
from core import plugin

# Location of the config file
LOCATION = 'plugins\\crowdstrike\\config.yaml'


class CrowdStrikeHandler(plugin.PluginTemplate):
    """Manage webhook alerts from the CrowdStrike platform

    Attributes
    ----------
    plugin.PluginTemplate
        Inherits the plugin template class

    Methods
    -------
    handle_event()
        Parses through a webhook
        Sends a formatted message to Teams
    authenticate()
        Authenticates that the webhook is genuine
    """

    def __init__(self):
        """Class constructor

        Reads config from the config file
        auth_header and auth_secret are values used to webhook authentication
        No SQL table yet

        Parameters
        ----------
        None

        Raises
        ------
        None

        Returns
        -------
        None
        """

        super().__init__(LOCATION)
        self.table = ""
        self.auth_header = self.config['config']['auth_header']
        self.auth_secret = self.config['config']['webhook_secret']

    def handle_event(self, raw_response, src):
        """Handles a webhook from CrowdStrike

        Parameters
        ----------
        raw_response : dict
            The webhook body
        src : str
            The IP that sent the webhook

        Raises
        ------
        Exception
            If certain fields don't exist in the webhook

        Returns
        -------
        None
        """

        # Log the event to the terminal
        print(termcolor.colored(
            f"CrowdStrike event: {raw_response}",
            "yellow"
        ))

        # Set up the fields we want to extract
        event = {
            'action': '',
            'hostname': '',
            'username': '',
            'url': '',
            'cli': '',
            'category': '',
            'name': '',
            'src_ip': src
        }

        # Populate the fields
        #   Raises an exception if the fields don't exist in the webhook
        try:
            cli = raw_response['data']['detections.command_line']
            cli = cli.replace("\\\\", "\\")
            event['action'] = raw_response['data']['detections.action_taken']
            event['hostname'] = raw_response['data']['detections.hostname']
            event['username'] = raw_response['data']['detections.user_name']
            event['url'] = raw_response['data']['detections.url']
            event['cli'] = cli
            event['category'] = raw_response['meta']['trigger_category']
            event['name'] = raw_response['meta']['trigger_name']

        # If the fields don't exist, just send the webhook as is
        except Exception as err:
            event['text'] = raw_response
            message = f"Event received: {event['text']}"
            print(termcolor.colored(f"Could not parse all fields: {err}"))

        # If all is according to plan, formulate an alert
        else:
            message = f"{event['name']} for \
                <span style=\"color:Yellow\"><b>{event['username']}</b></span>\
                on \
                <b><span style=\"color:Orange\">{event['hostname']}</span></b>\
                <br>{event['cli']} \
                <br><a href={event['url']}>See more detail here</a>"

        # Send the message to Teams
        teamschat.send_chat(
            message,
            self.config['config']['chat_id']
        )

    # Check webhook authentication
    def authenticate(self, request, plugin):
        """Authenticate a webhook from CrowdStrike

        Parameters
        ----------
        request : class (3rd party)
            The webhook, including headers
        plugin : dict
            Config information

        Raises
        ------
        Exception
            None

        Returns
        -------
        True : bool
            If the webhook has been authenticated
        False : bool
            If the webhook was not authenticated
        """

        # Check if there is an authentication header
        if plugin['handler'].auth_header != '':
            # Get the webhook body and the timestamp header
            body = request.get_data()
            timestamp = request.headers['X-Cs-Delivery-Timestamp']

            # Concatenate the body and the timestamp
            message = '{}{}'.format(body.decode('utf-8'), timestamp)

            # Get the authentication secret (in the config file)
            secret = self.auth_secret.encode()

            # Generate a signature
            signature = hmac.new(
                secret,
                bytes(message, 'utf-8'),
                hashlib.sha256
            ).digest()

            # Base64 encode the signature
            b64_sig = base64.b64encode(signature).decode()

            # Compare the generated signature with the one that was sent
            if b64_sig == request.headers[self.auth_header]:
                return True

            # If there is no match (webhook could not be authenticated)
            else:
                print(termcolor.colored(
                    "Bad CrowdStrike webhook received",
                    "red"))

                teamschat.send_chat(
                    "CrowdStrike sent a webhook that could not be verified",
                    self.config['config']['chat_id']
                )

                return False

        # If there is no authentication header
        else:
            print(termcolor.colored('Unauthenticated webhook', "yellow"))

            teamschat.send_chat(
                "CrowdStrike sent a webhook without authentication",
                self.config['config']['chat_id']
            )

            return False

# Copyright 2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.

import boto.sts
import os
import re
import sys
import logging
import fileinput
import datetime
import json
import requests
import getpass
import ConfigParser
import base64
import xml.etree.ElementTree as ET

# from os.path import expanduser
# from urlparse import urlparse, urlunparse

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.compat import urlsplit
from awscli.customizations.commands import BasicCommand
from awscli.compat import BinaryStdout

logger = logging.getLogger('botocore.credentials')


def initialize(cli):
    """
    The entry point for the credential helper
    """
    cli.register('building-command-table.codecommit', inject_commands)


def inject_commands(command_table, session, **kwargs):
    """
    Injects new commands into the codecommit subcommand.
    """
    command_table['credential-helper'] = CodeCommitCommand(session)


class CodeCommitNoOpStoreCommand(BasicCommand):
    NAME = 'store'
    DESCRIPTION = ('This operation does nothing, credentials'
                   ' are calculated each time')
    SYNOPSIS = ('aws codecommit credential-helper store')
    EXAMPLES = ''
    _UNDOCUMENTED = True

    def _run_main(self, args, parsed_globals):
        return 0


class CodeCommitNoOpEraseCommand(BasicCommand):
    NAME = 'erase'
    DESCRIPTION = ('This operation does nothing, no credentials'
                   ' are ever stored')
    SYNOPSIS = ('aws codecommit credential-helper erase')
    EXAMPLES = ''
    _UNDOCUMENTED = True

    def _run_main(self, args, parsed_globals):
        return 0


class CodeCommitGetCommand(BasicCommand):
    NAME = 'get'
    DESCRIPTION = ('get a username SigV4 credential pair'
                   ' based on protocol, host and path provided'
                   ' from standard in. This is primarily'
                   ' called by git to generate credentials to'
                   ' authenticate against AWS CodeCommit')
    SYNOPSIS = ('aws codecommit credential-helper get')
    EXAMPLES = (r'echo -e "protocol=https\\n'
                r'path=/v1/repos/myrepo\\n'
                'host=git-codecommit.us-east-1.amazonaws.com"'
                ' | aws codecommit credential-helper get')
    ARG_TABLE = [
        {
            'name': 'ignore-host-check',
            'action': 'store_true',
            'default': False,
            'group_name': 'ignore-host-check',
            'help_text': (
                'Optional. Generate credentials regardless of whether'
                ' the domain is an Amazon domain.'
                )
            }
        ]

    def __init__(self, session):
        super(CodeCommitGetCommand, self).__init__(session)

    def _run_main(self, args, parsed_globals):
        git_parameters = self.read_git_parameters()
        if ('amazon.com' in git_parameters['host'] or
                'amazonaws.com' in git_parameters['host'] or
                args.ignore_host_check):
            theUrl = self.extract_url(git_parameters)
            region = self.extract_region(git_parameters, parsed_globals)
            signature = self.sign_request(region, theUrl)
            self.write_git_parameters(signature)
        return 0

    def write_git_parameters(self, signature):
        ##########################################################################
        # Variables
        region = 'us-west-2'
        outputformat = 'json'
        awsconfigfile = '/.aws/credentials'
        sslverification = True
        saml_idp_entry_url =  'https://api.onelogin.com/api/v3/saml/assertion'
        saml_api_key = "ad5e09a6ff774d233e1d5f2709c6dc28d79b53b5"
        saml_app_id = "464336"
        ##########################################################################

        # Obtain username and password for SAML IdP auth
        save_stdout = sys.stdout
        sys.stdout = StringIO()        
        print "Username:",
        saml_user = raw_input()
        saml_pass = getpass.getpass()
        print ''
        
        # Programatically get the SAML assertion
        saml_payload = {"api_key": saml_api_key, "app_id": saml_app_id, "username": saml_user, "password": saml_pass}
        saml_response = requests.post(saml_idp_entry_url, params=saml_payload)
        #print (saml_response.text)
        
        saml_sso_response = json.loads(saml_response.text)
        saml_assertion = saml_sso_response["data"]
        #print (saml_assertion)
        
        # Overwrite and delete the credential variables, just for safety
        saml_user = '##############################################'
        saml_pass = '##############################################'
        del saml_user
        del saml_pass
        
        # Parse the returned assertion and extract the authorized roles
        awsroles = []
        root = ET.fromstring(base64.b64decode(saml_assertion))
        
        for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
            if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'):
                for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
                    print(saml2attributevalue.text)
                    awsroles.append(saml2attributevalue.text)
        
        # Note the format of the attribute value should be role_arn,principal_arn
        # but lots of blogs list it as principal_arn,role_arn so let's reverse
        # them if needed
        for awsrole in awsroles:
            chunks = awsrole.split(',')
            if'saml-provider' in chunks[0]:
                newawsrole = chunks[1] + ',' + chunks[0]
                index = awsroles.index(awsrole)
                awsroles.insert(index, newawsrole)
                awsroles.remove(awsrole)
        
        # If I have more than one role, ask the user which one they want,
        # otherwise just proceed
        print ""
        if len(awsroles) > 1:
            i = 0
            print "Please choose the role you would like to assume:"
            for awsrole in awsroles:
                print '[', i, ']: ', awsrole.split(',')[0]
                i += 1
        
            print "Selection: ",
            selectedroleindex = raw_input()
        
            # Basic sanity check of input
            if int(selectedroleindex) > (len(awsroles) - 1):
                print 'You selected an invalid role index, please try again'
                sys.exit(0)
        
            role_arn = awsroles[int(selectedroleindex)].split(',')[0]
            principal_arn = awsroles[int(selectedroleindex)].split(',')[1]
        
        else:
            role_arn = awsroles[0].split(',')[0]
            principal_arn = awsroles[0].split(',')[1]        

        # Use the assertion to get an AWS STS token using Assume Role with SAML
        sts_conn = boto.sts.connect_to_region(region)
        token = sts_conn.assume_role_with_saml(role_arn, principal_arn, assertion)
        
        # Write the AWS STS token into the AWS credential file
        home = expanduser("~")
        filename = home + awsconfigfile
        
        # Read in the existing config file
        config = ConfigParser.RawConfigParser()
        config.read(filename)
        
        # Put the credentials into a specific profile instead of clobbering
        # the default credentials
        if not config.has_section('saml'):
            config.add_section('saml')
        
        config.set('saml', 'output', outputformat)
        config.set('saml', 'region', region)
        config.set('saml', 'aws_access_key_id', token.credentials.access_key)
        config.set('saml', 'aws_secret_access_key', token.credentials.secret_key)
        config.set('saml', 'aws_session_token', token.credentials.session_token)
        
        # Write the updated config file
        with open(filename, 'w+') as configfile:
            config.write(configfile)
                
        # Give the user some basic info as to what has just happened
        print '\n\n----------------------------------------------------------------'
        print 'Your new access key pair has been stored in the AWS configuration file {0} under the saml profile.'.format(filename)
        print 'Note that it will expire at {0}.'.format(token.credentials.expiration)
        print 'After this time you may safely rerun this script to refresh your access key pair.'
        print 'To use this credential call the AWS CLI with the --profile option (e.g. aws --profile saml ec2 describe-instances).'
        print '----------------------------------------------------------------\n\n'

        # return to your regularly-scheduled program
        sys.stdout = save_stdout
        
        username = self._session.get_credentials().access_key
        if self._session.get_credentials().token is not None:
            username += "%" + self._session.get_credentials().token
        # Python will add a \r to the line ending for a text stdout in Windows.
        # Git does not like the \r, so switch to binary
        with BinaryStdout() as binary_stdout:
            binary_stdout.write('username={0}\n'.format(username))
            logger.debug('username\n%s', username)
            binary_stdout.write('password={0}\n'.format(signature))
            # need to explicitly flush the buffer here,
            # before we turn the stream back to text for windows
            binary_stdout.flush()
            logger.debug('signature\n%s', signature)

    def read_git_parameters(self):
        parsed = {}
        for line in sys.stdin:
            key, value = line.strip().split('=', 1)
            parsed[key] = value
        return parsed

    def extract_url(self, parameters):
        url = '{0}://{1}/{2}'.format(parameters['protocol'],
                                     parameters['host'],
                                     parameters['path'])
        return url

    def extract_region(self, parameters, parsed_globals):
        match = re.match(r'git-codecommit\.([^.]+)\.amazonaws\.com',
                         parameters['host'])
        if match is not None:
            return match.group(1)
        elif parsed_globals.region is not None:
            return parsed_globals.region
        else:
            return self._session.get_config_variable('region')

    def sign_request(self, region, url_to_sign):
        credentials = self._session.get_credentials()
        signer = SigV4Auth(credentials, 'codecommit', region)
        request = AWSRequest()
        request.url = url_to_sign
        request.method = 'GIT'
        now = datetime.datetime.utcnow()
        request.context['timestamp'] = now.strftime('%Y%m%dT%H%M%S')
        split = urlsplit(request.url)
        # we don't want to include the port number in the signature
        hostname = split.netloc.split(':')[0]
        canonical_request = '{0}\n{1}\n\nhost:{2}\n\nhost\n'.format(
            request.method,
            split.path,
            hostname)
        logger.debug("Calculating signature using v4 auth.")
        logger.debug('CanonicalRequest:\n%s', canonical_request)
        string_to_sign = signer.string_to_sign(request, canonical_request)
        logger.debug('StringToSign:\n%s', string_to_sign)
        signature = signer.signature(string_to_sign, request)
        logger.debug('Signature:\n%s', signature)
        return '{0}Z{1}'.format(request.context['timestamp'], signature)


class CodeCommitCommand(BasicCommand):
    NAME = 'credential-helper'
    SYNOPSIS = ('aws codecommit credential-helper')
    EXAMPLES = ''

    SUBCOMMANDS = [
        {'name': 'get', 'command_class': CodeCommitGetCommand},
        {'name': 'store', 'command_class': CodeCommitNoOpStoreCommand},
        {'name': 'erase', 'command_class': CodeCommitNoOpEraseCommand},
    ]
    DESCRIPTION = ('Provide a SigV4 compatible user name and'
                   ' password for git smart HTTP '
                   ' These commands are consumed by git and'
                   ' should not used directly. Erase and Store'
                   ' are no-ops. Get is operation to generate'
                   ' credentials to authenticate AWS CodeCommit.'
                   ' Run \"aws codecommit credential-helper help\"'
                   ' for details')

    def _run_main(self, args, parsed_globals):
        raise ValueError('usage: aws [options] codecommit'
                         ' credential-helper <subcommand> '
                         '[parameters]\naws: error: too few arguments')

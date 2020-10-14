# encoding: utf-8
'''
 License Scanning Script, based on Github data. 
 Uses a license YAML file that is pulled from a given repository or parametrized repository using a yaml format. 
 Checks out the YAML conditions file from a hosted repository to a given path, then uses that file to check effects of dependencies on projects. Project insights must be enabled in order for this license scanner to work properly. Also you have to have a github token available. --

@author:     mr.nobodi

@copyright:  2020 Metrosystems Romania. All rights reserved.

@license:    Apache License v2.0

@contact:    wouldn't you like to know...
@deffield    updated: Updated
'''

import datetime
import hashlib
import os
import re
import requests
import sys
import yaml

from difflib import SequenceMatcher

__all__ = []
__version__ = 1.0
__date__ = '2020-09-22'
__updated__ = '2020-09-22'

DEBUG = 1
TESTRUN = 0
PROFILE = 0


class CLIError(Exception):
    '''Generic exception to raise and log different fatal errors.'''
    def __init__(self, msg):
        super(CLIError).__init__(type(self))
        self.msg = "E: %s" % msg

    def __str__(self):
        return self.msg

    def __unicode__(self):
        return self.msg


class Utils(object):
    '''
    Some base objects to be used in the processing...
    '''
    license_type_strong = 'You are not allowed to use this dependency due to STRONG licensing conditions.'
    license_type_weak = 'There may be some licensing issues with this dependency. Please check usage conditions.'
    license_type_none = 'There are NO licensing effects for this dependency. You can use it freely.'
    github_api_link = 'https://api.github.com/'
    github_graphql_endpoint = 'https://api.github.com/graphql'
    pucker_factor = 0.85

    def __init__(self, git_workspace, yaml_conditions_file_name, yaml_conditions_file_path, license_rule_tag, secret_token, repository_name):
        self.git_workspace = git_workspace
        self.yaml_conditions_file_name = yaml_conditions_file_name
        self.yaml_conditions_file_path = yaml_conditions_file_path
        self.license_rule_tag = license_rule_tag
        self.secret_token = secret_token
        self.repository_name = repository_name

    def loadLicenseFile(self):
        print('\n Loading licensing rule file')
        try:
            fpath = ''.join([self.git_workspace, self.yaml_conditions_file_path, self.yaml_conditions_file_name])
            print ('Loading file from path: ' + fpath)
            with open(fpath, 'r') as stream:
                datap = yaml.load(stream)
                return datap
        except Exception as e:
            print ('\n Failed to load rules from yaml file. Check the following errors.\n')
            raise (e)

    def getLicensesForDependency(self, dependency_list):
        license_dictionary = []
        try:
            for i in dependency_list:
                license_req = ''.join([self.github_api_link, 'repos/', i, '/license'])
                dep_license = requests.get(license_req, headers={"Authorization": ''.join(['token ', self.secret_token])})
                m_val = dep_license.json()
                q_val = m_val.get('license', 'N/A')
                if isinstance(q_val, str):
                    license_dictionary.append([i, 'N/A'])
                else:
                    license_dictionary.append([i, q_val['name']])
            return license_dictionary
        except CLIError as e:
            print(' \n Failed to get the licenses for the required dependency. Please check the following errors. \n')
            raise (e)

    def getDependencyList(self):
        try:
            graphql_query = ''' {
                      repository(owner: \"%s\", name: \"%s\") {
                      dependencyGraphManifests(first: 100)
                        {
                            nodes
                                {
                                blobPath
                                dependencies
                                    {
                                    nodes
                                        {
                                        packageName
                                        requirements
                                        hasDependencies
                                        repository
                                        {
                                            nameWithOwner
                                        }
                                    }
                      } } } } }''' % (self.repository_name.split("/", 1)[0], self.repository_name.split("/", 1)[1])
            dependencyList = requests.post(Utils.github_graphql_endpoint, json={"query": graphql_query}, headers={"Authorization": ''.join(['token ', self.secret_token]), "Accept": "application/vnd.github.hawkgirl-preview+json"})
            dependencyList.raise_for_status()
            print (dependencyList.json())
            return dependencyList.json()
        except CLIError as e:
            print ('\n Failed to get a valid dependency list for the initialized project and owner! Check GraphQL results request!')
            raise (e)

    def buildDependencyListWithLicenses(self):
        raw_dep_list = self.getDependencyList()
        if not raw_dep_list:
            print ('\n')
            print ( 'No data is being retrieved for your project. Please check if insights is activated or your project technology stack is not yet supported!' )
            print ('\n')
            sys.exit()
        r_data = []
        try:
            for i in range(len(raw_dep_list['data']['repository']['dependencyGraphManifests']['nodes'][0]['dependencies']['nodes'])):
                nameWithOwner = raw_dep_list['data']['repository']['dependencyGraphManifests']['nodes'][0]['dependencies']['nodes'][i]['repository']
                if str(nameWithOwner) == 'None':
                    print ('No repository found for this dependency')
                else:
                    r_data.append(nameWithOwner['nameWithOwner'])
        except CLIError as e:
            print ('\nFailed to check licenses\n ')
            raise(e)
        except IndexError as ie:
            print ('\n Failed to build the dependency list, since the returned Github data is non existent!')
            print (ie)
            sys.exit()
        license_and_dependency_list = self.getLicensesForDependency(set(r_data))
        conditions = self.loadLicenseFile()
        # setup final results and return them
        dependency_with_licenses = []
        # build exact matches values or non-existent
        try:
            x = 0
            while x < len(license_and_dependency_list):
                for y in range(len(conditions)):
                    if license_and_dependency_list[x][1] == conditions[y]['Licensetype']:
                        dependency_with_licenses.append([license_and_dependency_list[x][0].split('/', 1)[1], license_and_dependency_list[x][1], conditions[y][self.license_rule_tag]])
                x += 1
        except CLIError as e:
            print (' Failed to build the dependency list with licenses for the given project. See next errors!')
            raise(e)
        # run the aproximative search option and add items whithout exact matches
        try:
            i = 0
            while i < len(license_and_dependency_list):
                for z in range(len(conditions)):
                    # Strip symbols and spaces in order to run the string analysis correctly
                    strip_license_and_dependency_list = ''.join(e for e in license_and_dependency_list[i][1] if e.isalnum())
                    strip_conditions = ''.join(g for g in conditions[z]['Licensetype'] if g.isalnum())
                    similarity_ratio = SequenceMatcher(None, strip_license_and_dependency_list, strip_conditions).ratio()
                    # Build the dependency list based on range for given similarity
                    if Utils.pucker_factor < similarity_ratio < 0.96:
                        dependency_with_licenses.append([license_and_dependency_list[i][0].split('/', 1)[1], license_and_dependency_list[i][1], conditions[z][self.license_rule_tag]])
                i += 1
        except CLIError as e:
            raise (e)
        return dependency_with_licenses

    # create a JSON File with all the dependencies with licenses per project then save it to the work location
    def makeJsonFile(self, depn_license_list):
        depn_license_obj = []
        json_rep = {}
        fpath = ''.join([os.path.dirname(os.path.abspath(__file__)), '/', 'license-scan-result-json.json'])
        try:
            for i in range(len(depn_license_list)):
                depn_license_obj.append({'Dependency': depn_license_list[i][0], 'License Name': depn_license_list[i][1], 'Copyleft-Effect': depn_license_list[i][2]})
            json_rep['License-List'] = depn_license_obj
            with open(fpath, "w+") as f:
                f.write(str(json_rep))
        except CLIError as e:
            raise (e)

    # create a HTML file report that is uploaded to the workpath of the pipeline per build
    def makeHTMLReport(self, dependency_with_license_list):
        q_path = ''.join([os.path.dirname(os.path.abspath(__file__)), '/html/license-scan-report-tpl.html'])
        html_report = ''.join([os.path.dirname(os.path.abspath(__file__)), '/license-scan-report.html'])
        slap_str = ''
        str_p = ''
        with open(q_path, "r") as g:
            str_p = g.read()
        try:
            for i in range(len(dependency_with_license_list)):
                if dependency_with_license_list[i][2] == 'strong':
                    slap_str += ''.join(['\n<tr><td>', dependency_with_license_list[i][0], '</td>', '\n<td>', dependency_with_license_list[i][1], '</td>', '\n<td>', Utils.license_type_strong, '</td></tr>'])
                elif dependency_with_license_list[i][2] == 'weak':
                    slap_str += ''.join(['\n<tr><td>', dependency_with_license_list[i][0], '</td>', '\n<td>', dependency_with_license_list[i][1], '</td>', '\n<td>', Utils.license_type_weak, '</td></tr>'])
                else:
                    slap_str += ''.join(['\n<tr><td>', dependency_with_license_list[i][0], '</td>', '\n<td>', dependency_with_license_list[i][1], '</td>', '\n<td>', Utils.license_type_none, '</td></tr>'])
            check_timestamp = datetime.date.today()
            check_project_id = self.repository_name
            z = str_p.replace("{{}}", slap_str)
            w = z.replace("{{check_timestamp}}", str(check_timestamp))
            u = w.replace("{{check_project_id}}", check_project_id)
            check_hash = hashlib.md5(z.encode('utf-8'))
            cm = u.replace("{{check_hash}}", check_hash.hexdigest())
            with open(html_report, "w+") as f_r:
                f_r.write(cm)
        except CLIError as e:
            raise (e)

    # create issues in the pipeline for the list of dependencies or whatever....
    def makeIssuesInThePipeline(self, depn_license_list):
        issue_api_uri = ''.join([self.github_api_link, 'repos/', self.repository_name, '/issues'])
        ### GET LIST OF ISSUES
        response_issues = requests.get(issue_api_uri, headers={"Authorization": ''.join(['token ', self.secret_token])})
        existing_issues_list = response_issues.json()
        if not existing_issues_list:
            print ( '\n No valid existing issues exists, the system will continue generating issues.')
            self.createSingleIssueNormal(depn_license_list)
        else:
            generated_issues_tags=[]
            #build pre-existing issues list, that have been opened for dependencies analyzed in the past.
            #List contains just the dependency names
            for pq in existing_issues_list:
                t_val = pq['body']
                print (t_val)
                if 'SEC-TAG' in t_val:
                    print ('SEC-TAG in body detected...')
                    ver_tag = re.findall('SEC-TAG:(.*). ', t_val )
                    ver_tag_no_space = ver_tag[0].strip()
                    if isinstance(ver_tag_no_space, str):
                        self.verifyOpenedIssueTag (ver_tag_no_space, depn_license_list, generated_issues_tags)
                    else:
                        print ('\n Some tag detected in issue, but could not determine type. Please check the issues you currently have opened or contact support!')
            #Start analyzing the pre-existing dependency with issues list...
            #...if there are no issues pre-opened
            if len (generated_issues_tags) ==0 :
                print (generated_issues_tags)
                print (' Running create single issue normal... ')
                self.createSingleIssueNormal(depn_license_list, issue_api_uri)
            #if there are any... open incidents only for the ones that haven't been analyzed
            else:
                 self.createSingleIssueForPreExisting(depn_license_list,generated_issues_tags, issue_api_uri)
    
    #make a single issue for non-pre-existing case
    def createSingleIssueNormal (self, depn_license_list, issue_api_uri):
        for i in range( len(depn_license_list) ):
            sp = depn_license_list[i][0]
            sq = sp.encode('utf-8')
            lblx = hashlib.md5(sq)
            if depn_license_list[i][2] == 'strong':
                issue = ''.join(['{', '"title"', ':', '"', ' Your dependency: ', depn_license_list[i][0], ' with the license: ', depn_license_list[i][1], ' may not be freely used. Please update your dependency list or check licensing conditions!','"', ',', '"body"', ':','"', ' You are not allowed to use the dependency: ', depn_license_list[i][0], ' with the license ', depn_license_list[i][1], ' BECAUSE it has restrictive licensing conditions. Please update or remove your dependency!', ' SEC-TAG: ', lblx.hexdigest(), ' ."', '}'])      
                print (issue)
                self.openNewIssueInThePipeline(issue, issue_api_uri)
            elif depn_license_list[i][2] == 'weak':
                issue = ''.join(['{', '"title"', ':', '"', ' Your dependency: ', depn_license_list[i][0], ' with the license: ', depn_license_list[i][1], ' may not be freely used. Please update your dependency list or check licensing conditions!','"', ',', '"body"', ':', '"', 'SEC-TAG: ', lblx.hexdigest(), ' You may not be allowed to use the dependency: ', depn_license_list[i][0], ' with the license ', depn_license_list[i][1], ' may have some usage restrictions. Please check the license and update your project accordingly!', ' SEC-TAG: ', lblx.hexdigest(), ' ."', '}'])
                self.openNewIssueInThePipeline(issue, issue_api_uri)
    
    #make a single issue for pre-existing case
    def createSingleIssueForPreExisting(self, depn_license_list,generated_issues_tags, issue_api_uri):
        for i in range( len(depn_license_list) ):
            if depn_license_list[i][0] not in generated_issues_tags:
                sp = depn_license_list[i][0]
                sq = sp.encode('utf-8')
                lblx = hashlib.md5(sq)
                if depn_license_list[i][2] == 'strong':
                    issue = ''.join(['{', '"title"', ':', '"', ' Your dependency: ', depn_license_list[i][0], ' with the license: ', depn_license_list[i][1], ' may not be freely used. Please update your dependency list or check licensing conditions!','"', ',', '"body"', ':', '"', ' You are not allowed to use the dependency: ', depn_license_list[i][0], ' with the license ', depn_license_list[i][1], ' BECAUSE it has restrictive licensing conditions. Please update or remove your dependency!', ' SEC-TAG: ', lblx.hexdigest(), ' ."', '}'])
                    self.openNewIssueInThePipeline(issue, issue_api_uri)
                elif depn_license_list[i][2] == 'weak':
                    issue = ''.join(['{', '"title"', ':', '"', ' Your dependency: ', depn_license_list[i][0], ' with the license: ', depn_license_list[i][1], ' may not be freely used. Please update your dependency list or check licensing conditions!','"', ',', '"body"', ':', '"', ' Dependency: ', depn_license_list[i][0], ' with the license ', depn_license_list[i][1], ' may have some usage restrictions. Please check the license and update your project accordingly!"', ' SEC-TAG: ', lblx.hexdigest(), ' ."',  '}'])
                    self.openNewIssueInThePipeline(issue, issue_api_uri)
                    
    #verify older issue tags
    def verifyOpenedIssueTag ( self, tag, depn_license_list, generated_issues_tags ):
        for i in range( len(depn_license_list) ):
            sp = depn_license_list[i][0]
            sq = sp.encode('utf-8')
            verif = hashlib.md5(sq)
            if verif.hexdigest() == tag:
                print ( verif.hexdigest() )
                print (  tag )
                generated_issues_tags.append( depn_license_list[i][0] )
            else:
                print (' New dependency detected, creating issue... ')
        print ('\n -------------------DEBUG:----------------\n')
        print (generated_issues_tags)
        print ( '-------------------')
           
    #open an issue in the pipeline
    def openNewIssueInThePipeline (self, issue, issue_api_uri):
        try:
            x = requests.post(issue_api_uri, data=issue, headers={"Authorization": ''.join(['token ', os.environ['SECRET_TOKEN']]), 'Accept': 'application/vnd.github.v3+json'})
            print (x.json() )
        except CLIError as e:
            print (' \n WARNIING: THE REQUESTED ISSUE COULD NOT BE CREATED. SEE NEXT ERRORS!')
            print (e)

    # runner function
    def _license_scanner_runner(self):
        _depn_license_list = self.buildDependencyListWithLicenses()
        self.makeHTMLReport(_depn_license_list)
        self.makeJsonFile(_depn_license_list)
        self.makeIssuesInThePipeline(_depn_license_list)


#########################################################################
def main(argv=None):  # IGNORE:C0111
    '''Command line options.'''

    program_name = os.path.basename(sys.argv[0])  # TODO: if we don't need this var we should remove it
    program_version = "v%s" % __version__
    program_build_date = str(__updated__)
    program_version_message = '%%(prog)s %s (%s)' % (program_version, program_build_date)  # TODO: if we don't need this var we should remove it
    program_shortdesc = __import__('__main__').__doc__.split("\n")[1]

    program_license = '''%s  # TODO: if we don't need this var we should remove it

  Created by mr.nobodi on %s.
  Copyright 2020 Metrosystems Romania. All rights reserved.

  Licensed under the Apache License 2.0
  http://www.apache.org/licenses/LICENSE-2.0

  Distributed on an "AS IS" basis without warranties
  or conditions of any kind, either express or implied.

USAGE
''' % (program_shortdesc, str(__date__))

    try:
        git_workspace = os.environ['GITHUB_WORKSPACE']
        yaml_conditions_file_name = '/oss_ampel.yml'
        yaml_conditions_file_path = '/devsecops-pipeline-license-conditions-file'
        license_rule_tag = 'Copyleft-effect-distribution'
        secret_token = os.environ['SECRET_TOKEN']
        repository_name = os.environ['GITHUB_REPOSITORY']

        if not secret_token:
            print ('Missing secret token setup so no API will be called from Github. Please setup an environment variable called SECRET_TOKEN with your Github PAT.')
            sys.exit(0)

        u = Utils(git_workspace, yaml_conditions_file_name, yaml_conditions_file_path, license_rule_tag, secret_token, repository_name)
        u._license_scanner_runner()

    except KeyboardInterrupt:
        # handle keyboard interrupt ###
        return 0
    except Exception as e:
        raise(e)


if __name__ == "__main__":
    if DEBUG:
        sys.argv.append("-h")
        sys.argv.append("-v")
        sys.argv.append("-r")
    if TESTRUN:
        import doctest
        doctest.testmod()
    if PROFILE:
        import cProfile
        import pstats
        profile_filename = '_profile.txt'
        cProfile.run('main()', profile_filename)
        statsfile = open("profile_stats.txt", "wb")
        p = pstats.Stats(profile_filename, stream=statsfile)
        stats = p.strip_dirs().sort_stats('cumulative')
        stats.print_stats()
        statsfile.close()
        sys.exit(0)
    sys.exit(main())

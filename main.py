import argparse
import json
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
import requests
from urllib import parse

api_base = 'https://api.veracode.com'
headers = {'User-Agent': 'Python HMAC'}
LINE_NUMBER_SLOP = 3 # adjust to allow for line number movement

def getApplicationGUID(appname, auth):
    params = {"name": parse.quote(appname)}

    try:
        response = requests.get(api_base + '/appsec/v1/applications', auth=auth, headers=headers, params=params)
    except requests.RequestException as e:
        print(e)

    data = response.json()

    if data:
        for i in data['_embedded']['applications']:
            return i['guid']

def getAllFindings(appguid, auth):
    page = 0
    allData = []

    try:
        needMorePages = True
        response = response = requests.get(api_base + f'/appsec/v2/applications/{appguid}/findings', auth=auth, headers=headers)
        data = response.json()
        totalPages = data['page']['total_pages']

        while(needMorePages):
            params = {'scan_type': 'STATIC', 'page':page}
            response = requests.get(api_base + f'/appsec/v2/applications/{appguid}/findings', auth=auth, headers=headers, params=params)
            data = response.json()
            allData += data['_embedded']['findings']
            
            page += 1
            needMorePages = page < totalPages

    except requests.RequestException as e:
        print(e)
    
    return allData

def getMitigationFindings(allFindings):
    return list(filter(lambda finding: finding['finding_status']['resolution_status'] == 'APPROVED', allFindings))

def getPipelineScanFindings(pipelineFile):
    pipelineFindings = []

    with open(pipelineFile) as file:
        data = json.load(file)

    pipelineFindings.extend(data['findings'])

    return pipelineFindings

def createMatchFormatPolicy(pipelineScanFindings):
    return [{'id': pf['issue_id'],
                'resolution': pf['finding_status']['resolution'],
                'cwe': pf['finding_details']['cwe']['id'],
                'source_file': pf['finding_details']['file_path'],
                'line': pf['finding_details']['file_line_number']} for pf in pipelineScanFindings]

def getMatchedFindings(appGuid, mitigationFindings, pipelineScanFindings):
    matchedFindings = []

    mitigatedIndex = createMatchFormatPolicy(mitigationFindings)

    for thisf in mitigatedIndex:
        # we allow for some movement of the line number in the pipeline scan findings relative to the mitigated finding as the code may
        # have changed. adjust LINE_NUMBER_SLOP for a more or less precise match, but don't broaden too far or you might match the wrong
        # finding.
        match = next((pf for pf in pipelineScanFindings if ((thisf['cwe'] == int(pf['cwe_id'])) & 
            (thisf['source_file'].find(pf['files']['source_file']['file']) > -1 ) & 
            ((pf['files']['source_file']['line'] - LINE_NUMBER_SLOP) <= thisf['line'] <= (pf['files']['source_file']['line'] + LINE_NUMBER_SLOP)))), None)
         
        if match != None:
            match['origin'] = { 'source_app': appGuid, 'source_id': thisf['id'], 'resolution': thisf['resolution'],'comment': 'Migrated from mitigated policy or sandbox finding'}
            matchedFindings.append(match)
        
            
    return matchedFindings

# removing matching issues here
def getNonMitigatedFindings(matchedFindings, pipelineScanFindings):
    nonMitigatedFindings = []

    issuesIDs = set(mf['issue_id'] for mf in matchedFindings)
    
    nonMitigatedFindings = [pf for pf in pipelineScanFindings if pf['issue_id'] not in issuesIDs]

    return nonMitigatedFindings

def processOutputFile(outputFilename, nonMitigatedFindings):
    content = {'findings': nonMitigatedFindings}

    with open(outputFilename, 'w', newline='') as f:
        f.write(json.dumps(content, indent=4))
        f.close()

def main():
    parser = argparse.ArgumentParser('This script create baseline from last policy scan of application.')
    parser.add_argument('-an', '--applicationname', help='Applications name in plataform', required=True)
    parser.add_argument('-rf', '--results', help='Location of a Pipeline Scan results file.', required=True)
    parser.add_argument('-of', '--outputfilename', help='Name for the file to generate', required=True)
    parser.add_argument('-vid', '--vid', help='Value of ID from API Credentials.', required=True)
    parser.add_argument('-vkey', '--vkey', help='Value of Secret Key from API Credentials.', required=True)
    args = parser.parse_args()

    appname = args.applicationname
    rf = args.results
    outputFilename = args.outputfilename
    vid = args.vid
    vkey = args.vkey

    auth = RequestsAuthPluginVeracodeHMAC(api_key_id=vid, api_key_secret=vkey)

    if appname:
        appguid = getApplicationGUID(appname, auth)

    allFindings = getAllFindings(appguid, auth)

    mitigatedFindings = getMitigationFindings(allFindings)

    pipelineScanFindings = getPipelineScanFindings(rf)

    matchedFindings = getMatchedFindings(appguid, mitigatedFindings, pipelineScanFindings)

    nonMitigatedFindings = getNonMitigatedFindings(matchedFindings, pipelineScanFindings)

    processOutputFile(outputFilename, nonMitigatedFindings)

if __name__ == '__main__':
    main()
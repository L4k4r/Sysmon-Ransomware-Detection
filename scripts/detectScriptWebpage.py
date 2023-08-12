'''
This code analyzes the Sysmon event logs from the Syslog server in order to identify suspicious activities that might indicate ransomware. 
'''

from datetime import datetime
from collections import defaultdict
import re
import requests
from secret import apiKey

# Number of commands from the Microsoft Hunt for Ransomware blog to flag process as suspicious
commandThreshold = 20
# Number of unique directories a processes accessed to get flagged as suspicious
directoryCountThreshold = 20
# Number of files a proccess creates before it gets flagged as suspicious
filesCreateThreshold = 20
# Number of seconds a process may take to create x files in
timeThreshold = 60
# Number of Sysmon logs to check
numOfLogs = '3000'

numoffiles = defaultdict(set)
suspiciousParentImages = defaultdict(int)
processIDModTime = defaultdict(list)
susSet = set()
numOfDirectories = defaultdict(set)

# Retrieve the webpage content
url = "http://134.221.49.98/eventlogs/?format=txt&n={}".format(numOfLogs)  # Replace with the actual URL of the webpage
response = requests.get(url)
data = response.text
events = data.split('\n\n')


def checkForHash(events, checkString):
    for event in events:
        sysmonId = re.findall(r"Sysmon: (\d+):", event)
        processID = re.findall(r"ProcessId: (\d+)", event)
        imageEvent = re.findall(r"Image: (.*)", event)
        hashList = re.findall(r"Hashes: (.*)", event)

        if sysmonId and sysmonId[0] == '1' and (checkString in imageEvent[0] or checkString in processID):
            if hashList:
                for md5 in hashList:
                    vtHash = (md5.split(',')[0].replace('MD5=',''))
                    url = f"https://www.virustotal.com/api/v3/files/{vtHash}"
                    headers = {
                        "x-apikey": apiKey
                    }
                    response = requests.get(url, headers=headers)
                    if response.status_code == 200:
                        jsonData = response.json()
                        if jsonData["data"]["attributes"]["last_analysis_stats"]["malicious"] > 0:
                            print(f"WARNING!!!! ---- THE MD5 HASH FROM {checkString} IS MALICIOUS!!!! (MD5={vtHash})")
                        else:
                            print(f"MD5 hash from {checkString} is not malicious or not in VT-database. (MD5={vtHash})")
                    else:
                        print(f"An error occurred while checking the MD5 hash for {checkString}")
                break
            else:
                print(f'\nNo hash availible for {checkString}\n')


def calcTimeDiff(prevTime, curTime):
    timeDiff = curTime - prevTime
    return timeDiff.total_seconds()


for event in events:
    eventDate = re.findall(r"EventDate: (.*)", event)
    if not eventDate:
        continue

    sysmonId = re.findall(r"Sysmon: (\d+):", event)
    processID = re.findall(r"ProcessId: (\d+)", event)
    imageEvent = re.findall(r"Image: (.*)", event)
    parentImage = re.findall(r"ParentImage: (.*)", event)

    # Check for suspicous activities in commandline
    if sysmonId and sysmonId[0] == "1":
        processHashes = re.findall(r"Hashes: (.*)", event)
        processCommand = re.findall(r"CommandLine: (.*)", event)
        for command in processCommand:
            if 'taskkill.exe' in imageEvent \
                or 'chiper' in command  \
                or 'net stop' in command \
                or 'wevutil' in command \
                or 'shadow copy' in command \
                or 'taskkill.exe' in command \
                or ('net.exe' in imageEvent and 'stop' in command) \
                or ('chiper.exe' in imageEvent and '/w' in command) \
                or ('WEVTUTIL' in command and 'CL' in command) \
                or ('sc' in command and 'config' in command and 'disabled' in command) \
                or ('vssadmin.exe' in imageEvent and ('list shadows' in command or 'Delete Shadows' in command)):
                
                suspiciousParentImages[parentImage[0]] += 1

    # Check how many different directories a process accessed 
    if sysmonId and sysmonId[0] == '11':
        targetFile = re.findall(r"TargetFilename: (.*)", event)
        if imageEvent:
            image = imageEvent[0]
            numoffiles[image].add(targetFile[0])

            directory = '\\'.join(targetFile[0].split('\\')[:-1])
            numOfDirectories[image].add(directory)

            # Check if the process has created files within the time threshold
            creationTime = datetime.strptime(eventDate[0], "%b %d %H:%M:%S")
            if image in processIDModTime and calcTimeDiff(processIDModTime[image], creationTime) <= 100:
                numoffiles[image].add(targetFile[0])
            processIDModTime[image] = creationTime


print('-------------------------------------------------------------------------------------------------\n')

#Check how many suspicious commands are exectuted
for pImage, count in suspiciousParentImages.items():
    if count > commandThreshold:
        print(f"Suspicious amount of commands by {pImage}, Count: {count}")
        susSet.add(pImage)
    if len(suspiciousParentImages) <= 0:
        print('No suspicious command activity')
print('-------------------------------------------------------------------------------------------------\n')

# Check how many files are being changed in x seconds
for image, files in numoffiles.items():
    if len(files) > filesCreateThreshold:
        print(f"Image {image} created {len(files)} files within 100 seconds.")
        susSet.add(image)
    if len(numoffiles) <= 0:
        print('No suspicious file activity')
print('-------------------------------------------------------------------------------------------------\n')

# # Check how many directies an image accessed
for image, directories in numOfDirectories.items():
    if len(directories) > directoryCountThreshold:
        print(f'Image {image} created files in {len(directories)} different directories')
    if len(numoffiles) <= 0:
        print('No suspicious directory activity')
print('-------------------------------------------------------------------------------------------------\n')

for i in susSet:
    checkForHash(events, i)
print('-------------------------------------------------------------------------------------------------\n')
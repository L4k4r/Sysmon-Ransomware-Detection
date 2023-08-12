import re
import requests
import matplotlib.pyplot as plt

eventNames = {
    '1': 'Process Create (1)',
    '2': 'Changed File Creation Time (2)',
    '3': 'Network Connection (3)',
    '5': 'Process Terminated (5)',
    '7': 'Image Loaded (6)',
    '8': 'Create Remote Thread (8)',
    '11': 'File Create (11)',
    '12': 'Registry create/delete (12)',
    '13': 'Registry set (13)',
    '22': 'DNS query (22)',
    '26': 'File Deleted (26)'
}

# Color of the plot
color = 'red'

# Retrieve the webpage content
numOfLogs = '10000'
url = "http://134.221.49.98/eventlogs/?format=txt&n={}".format(numOfLogs)  # Replace with the actual URL of the webpage
response = requests.get(url)
data = response.text

# target2 = '{9a7a01f9-8f8f-64c7-7e00-000000004b00}'
# target3 = '{9a7a01f9-8fe9-64c7-cd00-000000004b00}'
target = 'psRansomware.ps1'

events = data.split('EventDate')

# Extract Sysmon event IDs using regular expressions
sysmonEvents = r"Sysmon: (\d+):"
imageEvents = r"Image: (.*)"
parentImageEvents = r"ParentImage: (.*)"
parentCommandEvents = r"ParentCommandLine: (.*)"
guid = r"ProcessGuid: (.*)"

# Count the occurrences of each Sysmon event ID
eventCount = {}
for index, event in enumerate(events):
    if index == 0 or index == len(events) - 1:
        continue

    sysmonId = re.findall(sysmonEvents, event)
    image = re.findall(imageEvents, event)
    partentImage = re.findall(parentImageEvents, event)
    parentCommandLine = re.findall(parentCommandEvents, event)
    ProccessGUID = re.findall(guid, event)

    # for i in ProccessGUID:
    #     if target3 in i:
    #         if sysmonId:
    #             sysmonId = sysmonId[0]
    #             if sysmonId in eventCount:
    #                 eventCount[sysmonId] += 1
    #             else:
    #                 eventCount[sysmonId] = 1

    # for i in ProccessGUID:
    #     if target2 in i:
    #         if sysmonId:
    #             sysmonId = sysmonId[0]
    #             if sysmonId in eventCount:
    #                 eventCount[sysmonId] += 1
    #             else:
    #                 eventCount[sysmonId] = 1

    for i in image:
        if target in i:
            if sysmonId:
                sysmonId = sysmonId[0]
                if sysmonId in eventCount:
                    eventCount[sysmonId] += 1
                else:
                    eventCount[sysmonId] = 1

    for i in partentImage:
        if target in i:
            if sysmonId:
                sysmonId = sysmonId[0]
                if sysmonId in eventCount:
                    eventCount[sysmonId] += 1
                else:
                    eventCount[sysmonId] = 1

    for i in parentCommandLine:
        if target in i:
            if sysmonId:
                sysmonId = sysmonId[0]
                if sysmonId in eventCount:
                    eventCount[sysmonId] += 1
                else:
                    eventCount[sysmonId] = 1

# Create a list containing all the event names and set the counts for each event
allEventIds = sorted(list(eventNames.keys()), key=lambda x: int(x))
allEventCounts = [eventCount[event] if event in eventCount else 0 for event in allEventIds]

xNames = [eventNames[event] if event in eventNames else event for event in allEventIds]

# Plot the number of Event ID appearances
plt.figure(figsize=(12, 6))
# plt.yscale('symlog')
plt.bar(xNames, allEventCounts, color=color)
plt.xlabel('Sysmon Event ID')
plt.ylabel('Count')
plt.title('Occurrences of Sysmon Event IDs from {} in {} number of logs'.format(target, sum(allEventCounts)))
plt.xticks(rotation=90) 
plt.tight_layout()
plt.grid()
plt.show()

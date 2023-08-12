import re
from collections import defaultdict, Counter
import matplotlib.pyplot as plt
from datetime import datetime, timedelta

# Color of the line in plot
color = 'black' 

# Change this to the correct CSV-file
inputFile = r"C:\Users\Gebruiker\Desktop\project\csv\cont\contiLog1.csv" 

# Change this to the correct ProcessID --> see CSV-file
inputProcessId = '0x21b0' 
# Ryuk has 2 processes that encrypt, so track both PID
# inputPID2 = '0x14ec' 

# Initialize data structures to store information
directoriesPerSecond = defaultdict(set)
uniqueDirectoriesPerSecond = set()
processIdThreshold = []
direcoryAccessedThreshold = []
processIdCounter = Counter()
filesChangedCounter = Counter()

# Read the input file
with open(inputFile, 'r') as file:
    fileContent = file.read()

# Split the content into individual log entries
entries = fileContent.split('An attempt was made to access an object.')

# Create an empty list to store the dictionaries
eventDict = []

# Process each log entry
for entry in entries:
    # Extract the date and time using a flexible pattern
    dateTimeMatch = re.search(r'(\d{1,2}-\d{1,2}-\d{4}\s+\d{1,2}:\d{2}:\d{2})', entry)
    if dateTimeMatch:
        dateTime = dateTimeMatch.group(1)
    else:
        continue  # Skip the entry if the date and time are not found
    
    # Extract the desired fields using regular expressions
    objectNameMatch = re.search(r'Object Name:\s+(.+)', entry)
    processIdMatch = re.search(r'Process ID:\s+(.+)', entry)
    processNameMatch = re.search(r'Process Name:\s+(.+)', entry)

    # Check if all fields are present and extract the values
    if objectNameMatch and processIdMatch and processNameMatch:
        objectName = objectNameMatch.group(1).strip()
        processId = processIdMatch.group(1).strip()
        processName = processNameMatch.group(1).strip()

        # Check if processId is the same as inputProcesId
        if processId == inputProcessId: # or processId == inputPID2:
            # Add the extracted fields to the dictionaries and append to the list
            eventDict.append({
                'Date and Time': dateTime,
                'Process ID': processId,
                'Object Name': objectName, 
                'Process Name': processName
            })

            processIdCounter[(dateTime, processId)] += 1

            # Check how many different directories each Process ID accessed
            directory = re.search(r'(.+)\\[^\\]?', objectName)
            if directory:
                directory = directory.group(1)
                timeKey = datetime.strptime(dateTime, '%d-%m-%Y %H:%M:%S').strftime('%d-%m-%Y %H:%M:%S')

                # Only add directory if it wasn't modified before
                if directory not in uniqueDirectoriesPerSecond:
                    directoriesPerSecond[timeKey].add(directory)
                    uniqueDirectoriesPerSecond.add(directory)

            # Count how many times files were changed by the same process ID
            filesChangedCounter[(dateTime, processId)] += 1
        else:
            raise ValueError("Input process ID not in file")

# Extract x- and y-value for the plot
timeStamps = [dateTime for (dateTime, _) in filesChangedCounter.keys()]
fileCount = [count for (_, _), count in filesChangedCounter.items()]

# Sort the time with the corresponding counts 
timeStamps, fileCount = zip(*sorted(zip(timeStamps, fileCount), key=lambda x: datetime.strptime(x[0], '%d-%m-%Y %H:%M:%S')))

# Convert timestamps to datetime objects
timeStamps = [datetime.strptime(ts, '%d-%m-%Y %H:%M:%S') for ts in timeStamps]

# Find the minimum and maximum timestamps
minTime = min(timeStamps)
maxTime = max(timeStamps)

# Create a list of all timestamps with increments of 1 second
allTime = [minTime + timedelta(seconds=i) for i in range((maxTime - minTime).seconds + 1)]

# Create a dictionary to store the counts for directories and files
countDict = dict(zip(timeStamps, fileCount))

# Populate the counts with the actual data and set to 0 for timestamps with no data
allCount = [countDict.get(ts, 0) for ts in allTime]

# Plot data
plt.figure(figsize=(24, 6))

plt.plot(allTime, allCount, marker='o', linestyle='solid', color=color, linewidth=2)
plt.margins(x=0)
plt.yscale('symlog')

plt.xlabel("Time")
plt.ylabel("Number of files changed")
plt.title("Number of file change events per second - {}".format(eventDict[0]['Process Name'].split('\\')[-1]))

plt.gca().xaxis.set_major_formatter(plt.matplotlib.dates.DateFormatter('%H:%M:%S'))
plt.xticks(allTime[::10], rotation=90)
plt.tight_layout()
plt.grid()

plt.show()

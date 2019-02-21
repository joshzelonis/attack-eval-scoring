import json
import glob
import os
import re

# I didn't clean the data because I didn't want to modify anything,
# irregularities in data source lead to some duplication here.
scoring = { 'Specific Behavior':5,                                          \
            'Specific Behavior, Tainted':5,                                 \
            'Specific Behavior,Tainted':5,                                  \
            'General Behavior':5,                                           \
            'General Behavior, Tainted':5,                                  \
            'Specific Behavior, Delayed':3,                                 \
            'Specific Behavior,Delayed':3,                                  \
            'General Behavior, Delayed':3,                                  \
            'General Behavior,Delayed':3,                                   \
            'General Behavior,Delayed,Tainted':3,                           \
            'Enrichment':3,                                                 \
            'Enrichment, Tainted':3,                                        \
            'Enrichment,Tainted':3,                                         \
            'Enrichment, Delayed':1,                                        \
            'Enrichment, Delayed, Tainted':1,                               \
            'Enrichment,Delayed, Tainted':1,                                \
            'Enrichment,Delayed,Tainted':1,                                 \
            'Enrichment, Tainted, Delayed':1,                               \
            'Enrichment,Tainted, Delayed':1,                                \
            'Telemetry':1,                                                  \
            'Telemetry, Tainted':1,                                         \
            'Telemetry,Tainted':1,                                          \
            'Specific Behavior,Configuration Change':0,                     \
            'General Behavior,Configuration Change':0,                      \
            'General Behavior, Configuration Change, Delayed, Tainted':0,   \
            'General Behavior,Configuration Change, Delayed, Tainted':0,    \
            'Enrichment, Configuration Change':0,                           \
            'Enrichment,Configuration Change':0,                            \
            'Enrichment, Tainted,Configuration Change':0,                   \
            'Enrichment,Tainted,Configuration Change':0,                    \
            'Indicator of Compromise,Configuration Change':0,               \
            'Telemetry,Configuration Change':0,                             \
            'General Behavior, Configuration Change':0,                     \
            'Telemetry, Configuration Change':0,                            \
            'Indicator of Compromise':0,                                    \
            'Indicator of Compromise, Delayed':0,                           \
            'None':0 }

def generate_score(data):
    totalscore = {0:0, 1:0, 3:0, 5:0, 'tainted':0}
    for technique_id, technique in data.items():
        if technique_id == 'PublicRelease':
            continue
        for step in technique['Steps'].values():
            if not len(step["Procedure"]):
                continue
            stepscore = 0
            taint = 0
            for detection in step['DetectionCategories']:
                for k,v in detection.items():
                    if taint == 0 and scoring[k.strip()] > 0 and re.search('tainted', k.strip(), re.IGNORECASE):
                        taint = 1
                    if len(k.strip()) and stepscore < scoring[k.strip()]: 
                        stepscore = scoring[k.strip()]
            totalscore[stepscore] += 1
            totalscore['tainted'] += taint
    return totalscore


path = './data/'
for infile in glob.glob(os.path.join(path, '*json')):
    with open(infile) as json_data:
        data = json.load(json_data)
        score = generate_score(data)
        print(infile)
        print(f'  Coverage {int(((136-score[0])/136)*100)}%\n    Real-Time Alert: {score[5]}\n    Delayed/Enrichment: {score[3]}\n    Telemetry: {score[1]}\n    None: {score[0]}\n')
        print(f'  Correlation {int((score["tainted"]/(136-score[0]))*100)}%\n    Tainted: {score["tainted"]}\n    Untainted: {136-score[0]-score["tainted"]}\n\n')
    
    
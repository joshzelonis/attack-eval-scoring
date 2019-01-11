import json
import glob
import os

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
            'None':0 }

scenario = ['Initial Compromise',				\
			'Initial Discovery',				\
			'Privilege Escalation',				\
			'Discovery for Lateral Movement',	\
			'Credential Access',				\
			'Lateral Movement',					\
			'Persistence',						\
			'Collection',						\
			'Exfiltration',						\
			'Execution of Persistence' ]

def generate_score(data):
    totalscore = {}
    for i in range(20):
        totalscore[i] = 0

    for technique in data.values():
        for step_id, step in technique['Steps'].items():
            id = (int(step_id.split('.',1)[0]) - 1)
            for detection in step['DetectionCategories']:
                for k,v in detection.items():
                    if len(k.strip()) and totalscore[id] < scoring[k.strip()]: 
                        totalscore[id] = scoring[k.strip()]
    return totalscore


path = './data/'
for infile in glob.glob(os.path.join(path, '*json')):
    with open(infile) as json_data:
        data = json.load(json_data)
        score = generate_score(data)
        print(f'{infile}')
        print('  Cobalt Strike:')
        for i in range(10):
            print(f'    {scenario[i]}: {score[i]}')
        print('  Empire:')
        for i in range(10,20):
            print(f'    {scenario[i%10]}: {score[i]}')
    
    

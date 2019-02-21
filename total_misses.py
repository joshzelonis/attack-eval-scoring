import json
import glob
import os


def generate_score(data):
    totalmisses = 0
    for technique_id, technique in data.items():
        if technique_id == 'PublicRelease':
            continue
        for step in technique['Steps'].values():
            for detection in step['DetectionCategories']:
                for k,v in detection.items():
                    if k.strip() == 'None':
                        # This additional filter is required to recreate the numbers from the Endgame blog.
                        if v[:56] == 'No detection capability demonstrated for this procedure.': 
                            totalmisses += 1
    return totalmisses


path = './data/'
for infile in glob.glob(os.path.join(path, '*json')):
    with open(infile) as json_data:
        data = json.load(json_data)
        score = generate_score(data)
        print(f'{infile} - {score}')
    
    
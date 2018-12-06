# attack-eval-scoring
For my initial blog post on the subject, check out:
https://go.forrester.com/blogs/measuring-vendor-efficacy-using-the-mitre-attck-evaluation/

## simple_score.py
In parsing the results, I found 56 techniques were measured with 195 procedures for doing so. This is a quick script for applying the scale on a procedure (or per step) basis.

## detailed_score.py
There were 10 different stages of attack measured from initial compromise to execution of persistence. In approaching the method undertaken by simple_score.py, this breaks the scoring out by stage of attack.

## technique_score.py
One may argue that the most critical capability is being able to alert on any one of a sequence of events that constitutes an ATT&CK technique. This applies the scale at the technique level to get a better understanding how vendors are able to detect individual ATT&CK techniques.

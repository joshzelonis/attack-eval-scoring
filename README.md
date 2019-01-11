# attack-eval-scoring
For my initial blog post on the subject, check out:
https://go.forrester.com/blogs/measuring-vendor-efficacy-using-the-mitre-attck-evaluation/

## simple_score.py
In parsing the results, I found 56 ATT&CK techniques were measured with 195 procedures for doing so. This is a quick script for applying the scale on a procedure (or per step) basis.

## kill_chain_analysis.py
There were 10 different stages of attack measured from initial compromise to execution of persistence across two scenarios. One may argue that the most critical capability is being able to alert on an aversary at each stage of an intrusion. This script analyzes and breaks out how each vendor performed at each stage of these scenarios on the same 1-3-5 scale used by simple_score.py

## technique_score.py
One may argue that the most critical capability is being able to alert on any one of a sequence of events that constitutes an ATT&CK technique. This applies the scale at the technique level to get a better understanding how vendors were able to detect individual ATT&CK techniques.

## total_misses.py
Based on the Endgame Blog (https://www.endgame.com/blog/executive-blog/heres-why-we-cant-have-nice-things), we see that there's a number of situations where a product does have functionality that an investigator could use to surface some information about an event that the methodology did not recognize. It's not immediately obvious how to generate the numbers that correspond to the blog so I'm using the Endgame numbers here with a code comment so you can see how, with minor modification, you can obtain the scores that more strictly correspond to MITRE's evaluation.
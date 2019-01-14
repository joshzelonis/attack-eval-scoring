# attack-eval-scoring
For my initial blog post on the subject, check out:
https://go.forrester.com/blogs/measuring-vendor-efficacy-using-the-mitre-attck-evaluation/

## simple_score.py
In parsing the results, I found 56 ATT&CK techniques were measured with 195 procedures for doing so. This is a quick script for applying the scale on a procedure (or per step) basis.

## kill_chain_analysis.py
There were 10 different stages of attack measured from initial compromise to execution of persistence across two scenarios. One may argue that the most critical capability is being able to alert on an aversary at each stage of an intrusion. This script analyzes and breaks out how each vendor performed at each stage of these scenarios on the same 1-3-5 scale used by simple_score.py

## total_misses.py
Based on the Endgame Blog (https://www.endgame.com/blog/executive-blog/heres-why-we-cant-have-nice-things), we see that there's a number of situations where a product does have functionality that an investigator could use to surface some information about an event that the methodology did not recognize. It's not immediately obvious how to generate the numbers that correspond to the blog so I'm using the Endgame numbers here with a code comment so you can see how, with minor modification, you can obtain the scores that more strictly correspond to MITRE's evaluation.

## query_attack.py
In analyzing vender performance, I frequently wanted to do quick lookups against techniques or procedures to see how the vendors performed in a side by side basis such as `$ python query_attack.py -p 2.A.1` or `$ python query_attack.py -t T1016`. Also, I found myself wanting to do string searches against other fields in the evaluation reports, so I've enabled case insensitive string searching using regex against many of the fields in the reports. Want to know which procedures leveraged the ipconfig command? `$ python query_attack.py -s ipconfig` Want to know which delayed detections Microsoft had? `$ python query_attack.py -s delayed microsoft` Want to know which detections OverWatch sent an email for? `$ python query_attack.py -s "overwatch .* email"` If you really want to go nuts you can use all of these flags together to specifically see the tainted detection CounterTack had on technique T1055 in step 5.A.2 with `$ python query_attack.py -s tainted -p 5.A.2 -t T1055 countertack`. You get the idea.
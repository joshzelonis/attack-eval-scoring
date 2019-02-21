import json
import glob
import os
import argparse
import sys
import re

class QueryAttackEval:
	def __init__(self, args):
		self.args = args

		# this line is only to protect the object and should never trigger if running from this script
		assert(self.args.technique or self.args.procedure or self.args.search)


	def get_technique(self, technique_id):
		print(f'{self.filename}')
		technique = self.data[technique_id]
		name = technique['TechniqueName']
		print(f'  {technique_id}: {name}')
		for step_id, step in technique['Steps'].items():
			if not len(step["Procedure"]):
				continue
			print(f'    {step_id}) {step["Procedure"]}')
			for detection in step['DetectionCategories']:
				for k,v in detection.items():
					k = k.strip()
					if len(k): 
						print(f'      {k}')
		return

	def get_procedure(self, procedure_id):
		found_proc = False
		print(f'{self.filename}')
		for technique_id, technique in self.data.items():
			if technique_id == 'PublicRelease':
  				continue
			if procedure_id in technique['Steps']:
				step = technique['Steps'][procedure_id]
				if not len(step["Procedure"]):
					continue
				if not found_proc:
					print(f'  {procedure_id}) {step["Procedure"]}')
					found_proc = True
				print(f'    {technique_id}: {technique["TechniqueName"]}')
				for detection in step['DetectionCategories']:
					for k,v in detection.items():
						k = k.strip()
						if len(k): 
							print(f'      {k}')
		return

	def search_eval(self, substring):
		techniques = []
		procedures = []
		detections = []
		notes = []
		for technique_id, technique in self.data.items():
			if technique_id == 'PublicRelease':
  				continue
			if self.args.technique and not technique_id == self.args.technique:
				continue
			if re.search(substring, technique['TechniqueName'], re.IGNORECASE):
				techniques.append(f'{technique_id}:\t{technique["TechniqueName"]}')
			for step_id, step in technique['Steps'].items():
				if self.args.procedure and not step_id == self.args.procedure:
					continue
				if re.search(substring, step['Procedure'], re.IGNORECASE):
					procedures.append('{:20}{}'.format(f'{step_id}:{technique_id})',step["Procedure"]))
				for detection in step['DetectionCategories']:
					for k,v in detection.items():
						if re.search(substring, k, re.IGNORECASE): 
							detections.append('{:20}{}'.format(f'{step_id:}:{technique_id})', k))
						if re.search(substring, v, re.IGNORECASE):
							notes.append('{:20}{}\t{}'.format(f'{step_id}:{technique_id})', k, v))

		if len(techniques) or len(procedures) or len(detections) or len(notes):
			print(f'{self.filename}')
		if len(techniques):
			print('\n  Techniques\n  ----------')
			for technique in techniques:
				print(f'  {technique}')
		if len(procedures):
			print('\n  Procedures\n  ----------')
			for procedure in procedures:
				print(f'  {procedure}')
		if len(detections):
			print('\n  Detections\n  ----------')
			for detection in detections:
				print(f'  {detection}')
		if len(notes):
			print('\n  Detection Notes\n  ---------------')
			for note in notes:
				print(f'  {note}')
		return

	def run(self, infile):
		if not re.search(args.vendor, infile, re.IGNORECASE):
			return
		else:
			self.filename = infile

		with open(self.filename) as json_data:
			self.data = json.load(json_data)

		if self.args.search:
			self.search_eval(self.args.search)
		elif self.args.technique:
			self.get_technique(self.args.technique.upper())
		elif args.procedure:
			self.get_procedure(self.args.procedure.upper())


def parse_args():
	parser = argparse.ArgumentParser(
		description='Query utility for the MITRE ATT&CK Evaluations'
	)
	parser.add_argument(
		'-t', 
		'--technique',
		type=str,
		help='Query based on the supplied ATT&CK Technique (example: $ python query_attack.py -t T1043)',
		default=False
	)
	parser.add_argument(
		'-p', 
		'--procedure',
		type=str,
		help='Query based on the supplied Step/Procedure (example: $ python query_attack.py -p 1.A.1)',
		default=False
	)
	parser.add_argument(
		'-s', 
		'--search',
		type=str,
		help='Query all descriptions for the supplied substring (example: $ python query_attack.py -s ipconfig)',
		default=False
	)
	parser.add_argument(
		'vendor',
		type=str,
		nargs='?',
		help='Optional argument to allow you to filter down to a particular vendor (example: $ python query_attack.py -s tainted countertack)',
		default='.'
	)

	args = parser.parse_args()
	if not (args.technique or args.procedure or args.search):
		parser.print_help()
		return False

	return args


if __name__ == '__main__':
	args = parse_args()
	if args:
		attack = QueryAttackEval(args)

		for infile in glob.glob(os.path.join('./data/', '*json')):
			attack.run(infile)
	
	

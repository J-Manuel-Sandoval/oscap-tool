#!/usr/bin/python
#Author: Manuel Sandoval

import sys
import getopt
import os
import uuid

helpMsg = """
Usage: python3 oscaptool.py [OPTION] [ARGUMENT]
  -c, --compare       compare two scans reports vailable from the 
                      history, receive 2 arguments that are the scan
                      IDs.
  -g, --get-report    print scan report, receive 1 argument that is 
                      the scan ID.
  -l, --list          list history of executed scans, no argument needed.
  -s, --scan          execute scan and print scan, no argument needed.
"""
cmdFiles = 'ls ./files/*.xml | awk -F "/" \'{print $3}\' | awk -F "-" \'{print $1}\''
hexValue = uuid.uuid4().hex
commandScan = 'oscap xccdf eval --profile stig '\
    '--results ./files/'+hexValue+'-ssg-results.xml ' \
    '--report ./files/'+hexValue+'-ssg-results.html ' \
    '--cpe /usr/share/xml/scap/ssg/content/ssg-ol7-cpe-dictionary.xml' \
    '  /usr/share/xml/scap/ssg/content/ssg-ol7-xccdf.xml'

class OscapTool:
  
  def __init__(self, argv):
    self.argv = argv
  
  def checkExistDir(self):
    if not os.path.isdir('./files'):
      os.system('mkdir ./files')
  
  def existId(self,idScan):
    existFile = os.system(cmdFiles + ' | grep "' + idScan + '" &> /dev/null')
    if existFile == 0:
      return True
    else:
      return False
  
  def compareReports(self,id1, id2):
    if self.existId(id1) and self.existId(id2):
      print('SCAN ID #1: ', id1)
      print('Total rules: ')
      os.system('cat files/' + id1 +'-ssg-results.html | grep -o \'[0-9]* rules taken\' | grep -o \'[0-9]*\'')
      print('Passed: ')
      os.system('cat files/' + id1 +'-ssg-results.html | grep -o \'[0-9]* passed\' | grep -o \'[0-9]*\'')
      print('Failed: ')
      os.system('cat files/' + id1 +'-ssg-results.html | grep -o \'[0-9]* failed\' | grep -o \'[0-9]*\'')
      print('Other: ')
      os.system('cat files/' + id1 +'-ssg-results.html | grep \'progress-bar-warning\' | grep -o \'[0-9]* other\' | grep -o \'[0-9]*\'')
      print()
      print('SCAN ID #2: ', id2)
      print('Total rules: ')
      os.system('cat files/' + id2 +'-ssg-results.html | grep -o \'[0-9]* rules taken\' | grep -o \'[0-9]*\'')
      print('Passed: ')
      os.system('cat files/' + id2 +'-ssg-results.html | grep -o \'[0-9]* passed\' | grep -o \'[0-9]*\'')
      print('Failed: ')
      os.system('cat files/' + id2 +'-ssg-results.html | grep -o \'[0-9]* failed\' | grep -o \'[0-9]*\'')
      print('Other: ')
      os.system('cat files/' + id2 +'-ssg-results.html | grep \'progress-bar-warning\' | grep -o \'[0-9]* other\' | grep -o \'[0-9]*\'')
    else:
      print('Invalid ID')

  def runTool(self):
    self.checkExistDir()
    if len(self.argv)==1:
      if self.argv[0] in ['-s', '--scan']:
        os.system(commandScan)
      elif self.argv[0] in ['-l', '--list']:
        existXml = os.system('ls ./files/*.xml &> /dev/null')
        if existXml != 0 :
          print('No history of executed scans')
          sys.exit()
        else:
          print('SCAN ID:')
          os.system(cmdFiles)
      elif self.argv[0] in ['-h', '--help']:
        print (helpMsg)
        sys.exit()
      else:
        print('Invalid option '+ self.argv[0])
        print (helpMsg)
        sys.exit(2)
    else:
      try:
        if(len(self.argv) == 0):
          print(helpMsg)
          sys.exit(2)
        opts, args = getopt.getopt(self.argv,"hc:g:",["compare=","get-report="])

      except getopt.GetoptError:
        print('Invalid option '+ self.argv[0])
        print (helpMsg)
        sys.exit(2)

      for opt, arg in opts:
        if opt == '-h':
          print (helpMsg)
          sys.exit()
        elif opt in ("-c", "--compare"):
          if len(self.argv) > 3 and len(self.argv) < 3:
            print('Compare requires 2 IDs')
            sys.exit(2)
          self.compareReports(self.argv[1],self.argv[2])
        elif opt in ("-g", "--get-report"):
          if self.existId(arg):
            os.system('oscap info "./files/' + arg + '-ssg-results.xml"')
          else:
            print('ID doesn\'t match')
            sys.exit(2)
        else:
          print (helpMsg)
          sys.exit(2)

def main(argv):
  tool = OscapTool(argv)

  tool.runTool()

if __name__ == "__main__":
    main(sys.argv[1:])
   

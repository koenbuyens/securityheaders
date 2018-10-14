
""" This script checks whether a URI returns secure security headers. The script implements various security checks, including the 
ones implemented by https://github.com/google/csp-evaluator and securityheaders.io as well as checks based on my own research. 
 

Run the script with python securityheaders.py -h for more information
"""
import argparse, argcomplete
import sys
import errno

try:
    from urlparse import urlparse
except ModuleNotFoundError:
    from urllib.parse import urlparse #python3
from securityheaders import SecurityHeaders, FindingSeverity


from os import listdir, makedirs
from os.path import isfile, join, exists
from threading import Lock                                    
                                                                                
def write( outputs, result):
    for output in outputs:
        try:
            output.write(result +"\n")
        except IOError as e:
            sys.stderr.write("\t" + '\033[91m' + str(e) + '\033[0m' + "\n")

def close_output_streams(streams):
    for stream in streams:
        if stream != sys.stdout and stream != sys.stderr:
            stream.close()

def create_output_streams(temppath, fid, screen):
    outputstreams = []

    if(temppath):
        make_output_dirs(temppath)
        outputstreams.append(open(join(temppath, str(fid) + ".csv"), "a+"))
    if(screen):
        outputstreams.append(sys.stdout)

    return outputstreams

def make_output_dirs(temp):
    if temp:
        try:
            makedirs(temp)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise

def create_urls(args):
    urlcolumn = args.urlcolumn
    result = list()
    data = []
    for f in args.url:
         
        if(exists(f)):
            data.extend(open(f))
        else:
            data.extend(f.split(','))

    i = 1
    for line in data:
        if i > args.startrow:
            line = line.strip()
            k = line.split(',')
            fid = k[0]
            if(len(k) == 1):
                fid = str(i)
                urlcolumn = 0
            result.append((fid,k[urlcolumn])) 
        i = i + 1   
    return result

class ResultProcesser():
    def __init__(self, args, api):
        self.args = args
        self.api = api

    def callback(self,value):
        self.process(value)

    def process(self, result):
        if(len(result) > 0):
            formatted_findings = self.api.format_findings(self.args.formatter, result)
            outputstreams = create_output_streams(self.args.temp, result[0].urlid,self.args.screen)
            write(outputstreams, formatted_findings)
            close_output_streams(outputstreams)

def main(args=sys.argv[1:],output=sys):
    api = SecurityHeaders()
    parser = argparse.ArgumentParser(description='Check HTTP security headers', \
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    
    group=parser.add_mutually_exclusive_group()
    group.add_argument('url', nargs='*',metavar='URL', default='', type=str, help='Target URL, path to file with a list of target URLs.')
    group.add_argument('--listcheckers', action='store_true', dest='listcheckers', help='Show a list of built-in checkers.')
    group.add_argument('--listformatters', action='store_true', dest='listformatters', help='Show a list of built-in finding formatters.')
    group.add_argument('--listheaders', action='store_true', dest='listheaders', help='Show the headers that are analyzed.')
    group.add_argument('--headers', metavar='HEADERS',dest='headers', type=str, default='',help='List of headers to analyze.')
    group.add_argument('--response', dest='response', type=argparse.FileType('r'), help='Analyze headers saved in this response file.')

    parser.add_argument('--defaultscheme', metavar='https', dest='defaultscheme', default='https', type=str, choices=['http','https'],help='Default scheme if not part of url')
    parser.add_argument('--max-redirects', metavar='2', dest='redirects', default=2, type=int, help='Max redirects, set 0 to disable')

    parser.add_argument('--config', dest='config', metavar='./conf/app.conf', default=None, type=str, help='Path to directory with optional configuration files the parser uses.')
    parser.add_argument('--urlcolumn', metavar='0', dest='urlcolumn', default=0, type=int, help='If a CSV file with URLs is provided as input, then this is the column containing the urls/domains')
    parser.add_argument('--startrow', metavar='0', dest='startrow', default=0, type=int, help='If a CSV file with URLs is provided as input, then this is the line to start fetching urls at.')

    parser.add_argument('--screen', action='store_true', dest='screen', help='Print result to the screen')
    parser.add_argument('--file', dest='temp', metavar="./tmp", default=None, type=str, help='If the results are saved to a file, then they are put in this directory.')
    parser.add_argument('--formatter', metavar='Tabulate',dest='formatter', default='console',choices=api.get_all_formatter_names(),help='How do you want to format the findings.')
    parser.add_argument('--flatten', action='store_true', dest='flatten', help='Merge multiple results into one table.') 

    checkernames = api.get_all_checker_names()
    parser.add_argument('--skipcheckers',dest='unwanted', nargs='*',metavar='checkername',default=[],type=str,help='A list of checkers to skip.', choices=checkernames)
    parser.add_argument('--checkers',dest='checks', nargs='*',metavar='Checker',default=['Checker'],type=str,help='A list of checkers to run.', choices=checkernames+['Checker'])
    
    argcomplete.autocomplete(parser)
    args = parser.parse_args(args)

    if(args.listcheckers):
        sys.stdout.write(api.get_all_checker_names_as_tree_string() + "\n")
        sys.exit(0)
    elif(args.listformatters):
        sys.stdout.write(', '.join(api.get_all_formatter_names()) + "\n")
        sys.exit(0)
    elif(args.listheaders):
        sys.stdout.write(', '.join(api.get_all_header_names()) + "\n")
        sys.exit(0)
    else:
        if not args.url and not (args.headers or args.response):
            parser.print_help()
            sys.exit(0) 
    if not args.temp:
        args.screen = True    

    try:
        api.load_options_from_file(args.config)
    except Exception as error:
        sys.stderr.write('\033[91m' + str(error) + '\033[0m' + "\n")

    for key, value in vars(args).items():
        api.set_option(key, value)

    processer = ResultProcesser(args, api)
    if not args.flatten:
        callback = processer.callback
    else:
        callback = None

    if args.response:
        results = api.check_headers_from_file(args.response)
        callback(results)
    elif args.url:
        results = api.check_headers_parallel(create_urls(args), callback = callback)
    elif args.headers:
        results = api.check_headers_from_string(args.headers)
        callback(results)

    if args.flatten:
        results = [r.get() for r in results]
        results = [[item for sublist in results for item in sublist]]
    for result in results:
        if args.flatten:
            processer.process(result)
            
    sys.exit(0) 

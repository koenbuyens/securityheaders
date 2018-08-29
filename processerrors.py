import argparse
import pandas as pd
import os
from os import listdir
from os.path import isfile, join
from urlparse import urlparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Check HTTP security headers for a list of sites', \
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--temp', dest='temp', metavar='N', default="./tmp", type=str, help='working directory')
    args = parser.parse_args()
    temp = args.temp

    onlyfiles = [f.split('.')[0] for f in listdir(temp) if isfile(join(temp, f))]
    incsv = join(temp ,'errors.txt')
    df = pd.read_csv(incsv,header=None, names=['ID', 'URL', 'ERROR'])
    tryhttp = df[df['ERROR'].str.contains("SSL")==True]
    
    #http
    for x in tryhttp.itertuples():
        eid = x[1]
        error = x[3]
        url = x[2]
        host = urlparse(url).netloc
        if eid not in onlyfiles:
            print eid + ",http://" + host + "," + error
#    print df.groupby('ERROR').agg({'ERROR':'count'})

    

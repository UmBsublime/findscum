#!/usr/bin/env python

import json
import operator
import urllib2
import socket
from BeautifulSoup import BeautifulSoup

# Sample Entry
"""
[{"phish_id":"2720989",
 "url":"http:\/\/www.ibex.ir\/spouse\/contact\/css\/call-us\/91e895c6ea20a661d76d4cc5f9ef6f35\/neko.php",
 "phish_detail_url":"http:\/\/www.phishtank.com\/phish_detail.php?phish_id=2720989",
"submission_time":"2014-10-23T14:00:59+00:00",
"verified":"yes",
"verification_time":"2014-10-23T15:27:36+00:00",
"online":"yes",
"details":[{"ip_address":"199.26.84.237",
            "cidr_block":"199.26.84.0\/22",
            "announcing_network":"30496",
            "rir":"arin","country":"US",
            "detail_time":"2014-10-23T14:02:07+00:00"}],
"target":"Other"}]
"""

def from_fishtank():
    # Get file from http://data.phishtank.com/data/online-valid.json
    file_path = '/home/charles.vaillancourt/Downloads/verified_online.json'

    with open(file_path) as f:
        content = f.readline()

    t = json.loads(content)

    ips_to_check = {}
    for e in t:
        if e['details'][0]['announcing_network'] == '16276':
            print '*'*60
            print 'Phishing url: {}'.format(e['url'])
            print 'Verfication Time: {}'.format(e['verification_time'])
            print 'Scum IP: {}'.format(e['details'][0]['ip_address'])
            print 'Scum cidr: {}'.format(e['details'][0]['cidr_block'])
            print 'Site cloned: {}'.format(e['target'])

            try:
                ips_to_check[e['details'][0]['ip_address']] += 1
            except KeyError:
                ips_to_check[e['details'][0]['ip_address']] = 1
    print '*'*60

    sorted_ips_to_check = sorted(ips_to_check.items(), key=operator.itemgetter(1) ,reverse=True)
    for k,v in sorted_ips_to_check:
        print 'IP: {:<15} appeared {} times'.format(k, v)

def from_malwaredomains():
    url = 'http://mirror1.malwaredomains.com/updates/'
    content = urllib2.urlopen(url)
    #print content.read()
    #exit()

    soup = BeautifulSoup(content.read())
    print dir(soup)


    malware_list = soup.findAll('a',href=True)
    source_files = []
    for ls in malware_list :
        if (ls['href'] != '../') and (ls['href'].endswith('.txt')):
            source_files.append(ls['href'])
            print 'Fetching {}'.format(ls['href'])

    formated_content = []
    for file in source_files:
        content = urllib2.urlopen(url+file)
        content =  content.read().split('\n')

        formated_content.append(sort_malware_csv(content))

    for source in formated_content:
        print 'New Source:'
        for item in source:
            try:
                item.append(socket.gethostbyname('www.'+item[0]))
            except socket.gaierror:
                item.append('UNKNOWN')
            except IndexError:
                print 'Figure out why this happens: {}'.format(item)
            print item

    for items in formated_content:
        print items[0]


def sort_malware_csv(content):
    final_rows =[]
    for column in content:
        column = column.split('\t')
        final_column = []
        for item in column:
            if item is not '':
                final_column.append(item)
        if final_column is not []:
            final_rows.append(final_column)
    return final_rows

from_malwaredomains()

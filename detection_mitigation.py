import os, re, threading

class ip_check(threading.Thread):
    """the class ip_check is for checking the availability of requesting users to reply them back

    Args:
        threading (Thread): contains run method to start thread automatcally to recieve ping response of users
    
    Methods:
        status (int): returns 0 if no ping response and other returning values for successful ping
    """
    def __init__ (self,ip):
		threading.Thread.__init__(self)
		self.ip = ip
		self.__successful_pings = -1
    def run(self):
		ping_out = os.popen("ping -q -c2 "+self.ip,"r")
		while True:
			line = ping_out.readline()
			if not line: break
			n_received = re.findall(received_packages,line)
			if n_received:
				self.__successful_pings = int(n_received[0])
    def status(self):
		if self.__successful_pings == 0:
			return 0
		elif self.__successful_pings == 1:
			return 1
		elif self.__successful_pings == 2:
			return 1
		else:
			return 0
received_packages = re.compile(r"(\d) received")

import pandas as pd

df = pd.read_csv('train.csv')
# print(df.head())

import sklearn
from sklearn import svm as sa
from sklearn.metrics import confusion_matrix
from sklearn.metrics import accuracy_score
from sklearn.metrics import classification_report

features = ['No_Src_IP', 'Entropy', 'Total_length', 'No_Packet', 'No_TCP_conn', 'No_UDP_conn']
Y = df['Attack']
X = df[features]

C = 0.001
clf = sa.SVC(kernel='linear',C=C)

model = clf.fit(X,Y)
print("Model Trained successfully!")

#import pickle
#loaded_model = pickle.load(open('trained_model1.pkl','rb'))
#preds = loaded_model.predict(xTest)
# print(preds)
# print(accuracy_score(yTest, preds))
# print(confusion_matrix(yTest, preds))

import os
import time
import pandas as pd
import csv
import numpy as np
import collections

import re

regex = '''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
			25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
			25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
			25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)'''

def check(Ip):
    """checks for valid IP

    Args:
        Ip (string): passed any string values to check if it is valid IP or not

    Returns:
        boolean: 'True' for valid IP and 'False' for invalid IP
    """
	# pass the regular expression 
	# and the string in search() method 
    if(re.search(regex, Ip)):  
		return True
    else:  
		return False

flagX = 0
flagY = 0
countX = 0
i = 0
while 1:
    """
        an infinite loop for always checking if server is under attack or not
    """
    x = "tshark -T fields -E separator=, -E quote=d -e _ws.col.No. -e _ws.col.Source -e _ws.col.Destination -e _ws.col.Protocol -e _ws.col.Length -a duration:5 > t.csv"
    T= "form"

    os.system(x)
	
    dict2 = ['No_Src_IP', 'Entropy', 'Total_length', 'No_Packet', 'No_HTTP_conn', 'No_TCP_conn', 'No_UDP_conn', 'Attack']
	
    with open('tD1.csv', 'w') as fd1:
		writer = csv.writer(fd1)
		writer.writerow(dict2)
    fd1.close()

    datafile = 't.csv'
    col_Names=["Sequence", "SrcIP", "DstIP", "Protocol", "Length"]
    df = pd.read_csv(datafile, names=col_Names)
	
    No_Rows = len(df)
    No_Dist = df['SrcIP'].nunique()
    Total = df['Length'].sum()
    No_tcp = len(df[df['Protocol'] == 'TCP'])
    No_udp = len(df[df['Protocol'] == 'UDP'])
    No_http = len(df[df['Protocol'] == 'HTTP'])
    C = collections.Counter(df['SrcIP'])
    counts = np.array(list(C.values()),dtype=float)
    prob = counts/counts.sum()
    shannon_entropy = (-prob*np.log2(prob)).sum()
	
    dIP = df['SrcIP'].unique()

    dict1 = [No_Dist, shannon_entropy, Total, No_Rows, No_http, No_tcp, No_udp]
    i=i+1
    with open('tD1.csv', 'a') as fd:
		writer = csv.writer(fd)
		writer.writerow(dict1)
    fd.close()
    df2 = pd.read_csv('tD1.csv')
    xt = df2[features]
    yt = df2['Attack']
    preds = clf.predict(xt)
    print(preds)
	#print(accuracy_score(yTest, preds))
	#print(confusion_matrix(yTest, preds))

    if preds==1:
        """
            run if attack detected
        """
        nIP = []
        bIP = []
        for x in dIP:
			if check(x.__str__())==False:
				nIP.append(x)

        check_results = []
        for ip in nIP:
			current = ip_check(ip)
			check_results.append(current)
			current.start()

        for el in check_results:
			el.join()
			if el.status() == 0:
				os.system('iptables -A INPUT -s '+el.ip+' -j DROP')
				print('IP address : ',el.ip,' blocked.')
				bIP.append(el.ip)
			else:
				print('IP address: ',el.ip,'ping successful!')

        output = 'blocked'+flagX.__str__()
        import pickle
        with open(output, 'wb') as bFile:
			pickle.dump(bIP, bFile)
        flagX=(flagX+1)%10

        if flagX == flagY:
			output = 'blocked'+flagY.__str__()
			nbIP = []
			with open(output, 'rb') as bFile:
				nbIP = pickle.load(bFile)
			for x in nbIP:
				os.system('iptables -D INPUT -s '+el.ip+' -j DROP')
				print('IP address : ',x,' unblocked.')
			os.system('rm '+output)
			flagY = (flagY + 1)%10
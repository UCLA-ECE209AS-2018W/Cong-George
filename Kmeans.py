import numpy as np
import re
import sys
from sklearn.cluster import KMeans
#For metric.calinski_harabaz_score
from sklearn import metrics
from sklearn.metrics import pairwise_distances

num_cluster = 2

#convert plain text to feature matrix to be further classified
def text2mat(filename):
	output_file = filename

	file = open(output_file, 'r')
	contend = file.readlines()

	num_slice = len(re.findall(r'device', str(contend)))


	all_nums =re.findall(r'[\d\.\d]+', str(contend))

	data_array = np.asarray(all_nums, dtype=np.float32)

	print '802.11 Frame Data in each time interval:'
	print data_array.reshape(num_slice,4)
	return data_array.reshape(num_slice,4)


#Kmeans clustering
def kmeans_clster(feature_mat):
	kmeans = KMeans(n_clusters=num_cluster, random_state=0).fit(feature_mat)
	print kmeans.labels_
	#print kmeans.cluster_centers_
	print 'Clustering scores:'
	#The higher the score, the better the clustering result
	print metrics.calinski_harabaz_score(feature_mat, kmeans.labels_)





if __name__ == '__main__':
	if len(sys.argv) < 2:
		print 'Missing command line arguments: Kmeans.py + raw data .txt file'
		exit()
	feature_mat = text2mat(sys.argv[1])
	print 'Performing clustering:'
	kmeans_clster(feature_mat)




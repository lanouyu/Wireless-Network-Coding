import sys, random
import string

def main(argv):
	log_file = open("log_2.txt", 'w')
	for i in range(9999):
		log_file.write(str(int(random.random() * 1000)) + '\n')
	log_file.close()

if __name__ == '__main__':
    main(sys.argv)

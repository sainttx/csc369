import random

afile = open("Random.txt", "w" )


for i in range(int(input('How many random numbers?: '))):
    line = str(random.randint(1, 5000000)) + ' ' + str(random.randint(0, 3)) + ' ' + str(random.randint(0, 3)) + '\n'
    afile.write(line)
 

afile.close()

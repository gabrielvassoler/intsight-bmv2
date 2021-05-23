import sys
import json

if __name__ == '__main__':
    choice = str(sys.argv[1])
    f = open('choice.txt', 'w')
    f.write(choice)
    f.close()

    f = open('choice.txt', 'r')
    c = str(f.read())
    f.close()
    if c != '-1':
        f = open('cases.json', 'r')
        a = json.load(f)
        wp = a[c]
        start = int(wp[0][1])
        end = int(wp[1][1])
        points = wp[3].split(",")
        f.close()
        path_id_decoder = 0

        f = open('path_ID_decoder.txt', 'r')
        g = f.read()
        remov = ["'"]
        for character in remov:
            g = g.replace(character, "\"")
        f.close()
        f = open('path_ID_decoder.txt', 'w')
        f.write(g)
        f.close()
        f = open('path_ID_decoder.txt', 'r')
        path_id_decoder = json.load(f)

        path = path_id_decoder[str(wp[0])+','+str(wp[1])+','+str(wp[2])+',0']
        f.close()

        if c != '-1':
            if start == int(pkt[IntSight_Report].path_src) and end == (pkt[IntSight_Report].path_dst):
                path = path_id_decoder[str(wp[0])+','+str(wp[1])+','+str(wp[2])+',0']
                #if(stop == 0 and not set(points).issubset(path)): #not necessary right now
                stop = 1
                fil = open('time.txt', 'a')
                fil.write(current_mili())
                fil.close()
        print(path)

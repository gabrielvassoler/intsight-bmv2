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
    f = open('cases.json', 'r')
    a = json.load(f)
    wp = a[c]
    start = int(wp[0][1])
    end = int(wp[1][1])
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
    print(start, end)
    print(path)

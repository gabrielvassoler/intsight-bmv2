import json

configs = ''
PROPERTIES = {}
multiPathProperties = []
MPid = 0

class FlowDescription:
    def __init__(self, startLocation, endLocation, flowID):
        self.endLocation = endLocation
        self.flowID = flowID
        self.startLocation = startLocation

#Each property to be verified will have its own class
class Reachability:
    def __init__(self, endLocation, flowID, startLocation):
        self.endLocation = endLocation
        self.flowID = flowID
        self.startLocation = startLocation
        self.lastSeen = 0
        self.largestGap = 0
        self.gapF = 0
        self.gapS = 0

class Waypoint:
    def __init__(self, startLocation, endLocation, flowID, expectedWaypoints, unexpectedWaypoints):
        self.endLocation = endLocation
        self.flowID = flowID
        self.startLocation = startLocation
        self.expectedWaypoints = expectedWaypoints
        self.unexpectedWaypoints = unexpectedWaypoints
        self.errorFound = 0

class EqualPathLength:
    def __init__(self, startLocation, endLocation, flowID, expectedLength):
        self.endLocation = endLocation
        self.flowID = flowID
        self.startLocation = startLocation
        self.expectedLength = expectedLength
        self.errorFound = 0

class DisjointPathAux:
    def __init__(self, startLocation, endLocation, flowID, id):
        self.flow = FlowDescription(startLocation, endLocation, flowID)
        self.id = id

class DisjointPath:
    def __init__(self):
        self.sets = {}
        self.errorFound = 0

    def check(self, flow, decoder):
        path = decoder['s'+str(flow.startLocation)+',s'+str(flow.endLocation)+','+str(abs(flow.endLocation - flow.startLocation)+1)+',0']
        self.sets[str(flow.startLocation)+','+str(flow.endLocation)+','+str(flow.flowID)].update(path)
        aux = dict(self.sets)
        aux.pop(str(flow.startLocation)+','+str(flow.endLocation)+','+str(flow.flowID))
        indexes = list(aux)
        for a in indexes:
            if(self.sets[str(flow.startLocation)+','+str(flow.endLocation)+','+str(flow.flowID)].intersection(self.sets[a]) != set()):
                self.errorFound = 1
                return a
        return ""
        


def main():
    with open('path_ID_decoder.txt', 'r') as f:
        path_id_decoder = json.load(f)
    #here we will be receiving the packets, but for this implementation, we will be reading from the logs we received from INTSIGHT
    a = open('experiments/e2edelay/paper_results/logs/s5-reports.csv') #THE SWITCH WE ARE CHECKING RIGHT NOW
    n = a.readlines()
    n = n[1:]
    for x in n:
        b = x.split(',')
        pathLength = int(b[6])
        pathdst = int(b[4])
        pathsrc = int(b[3])
        flow = int(b[2])
        epoch = int(b[0])

        if(pathdst in PROPERTIES):
            for prop in PROPERTIES[pathdst]:
                #CHECKING FOR REACHABILITY
                if isinstance(prop, Reachability):
                    if pathdst == prop.endLocation and pathsrc == prop.startLocation and flow == prop.flowID: 
                        lgap = epoch - prop.lastSeen
                        if lgap > prop.largestGap:
                            prop.largestGap = lgap
                            prop.gapS = prop.lastSeen
                            prop.gapF = epoch

                        prop.lastSeen = epoch

                #CHECKING FOR WAYPOINTS
                if isinstance(prop, Waypoint):
                    if pathdst == prop.endLocation and pathsrc == prop.startLocation and flow == prop.flowID: 
                        path = path_id_decoder['s'+str(pathsrc)+',s'+str(pathdst)+','+str(abs(pathdst - pathsrc)+1)+',0']
                        if(prop.expectedWaypoints != [] and not set(prop.expectedWaypoints).issubset(path)):
                            prop.errorFound = 1
                            print('\nFOR PROPERTY: WAYPOINT.')
                            print('flowID = '+str(prop.flowID)+' startL = '+str(prop.startLocation)+' endL = '+str(prop.endLocation))
                            print('EXPECTED WAYPOINTS: ' + ','.join(str(e) for e in prop.expectedWaypoints))
                            print('GIVEN PATH: '+ ','.join(str(e) for e in path))

                        if(prop.unexpectedWaypoints != [] and set(prop.unexpectedWaypoints).issubset(path)):
                            prop.errorFound = 1
                            print('\nFOR PROPERTY: WAYPOINT.')
                            print('flowID = '+str(prop.flowID)+' startL = '+str(prop.startLocation)+' endL = '+str(prop.endLocation))
                            print('UNEXPECTED WAYPOINTS: ' + ','.join(str(e) for e in prop.unexpectedWaypoints))
                            print('GIVEN PATH: '+ ','.join(str(e) for e in path))

                #CHECKING FOR EQUAL PATH LENGTH
                if isinstance(prop, EqualPathLength):
                    if pathdst == prop.endLocation and pathsrc == prop.startLocation and flow == prop.flowID:
                        if prop.expectedLength < pathLength:
                            prop.errorFound = 1
                            print('\nFOR PROPERTY: EQUAL PATH LENGTH.')
                            print('flowID = '+str(prop.flowID)+' startL = '+str(prop.startLocation)+' endL = '+str(prop.endLocation))
                            print('EXPECTED MAX LENGTH: ' + str(prop.expectedLength))
                            print('GIVEN LENGTH: '+ str(pathLength))

                #CHECKING FOR DISJOINT PATHS
                if isinstance(prop, DisjointPathAux):
                    if pathdst == prop.flow.endLocation and pathsrc == prop.flow.startLocation and flow == prop.flow.flowID:
                        f = multiPathProperties[prop.id].check(prop.flow, path_id_decoder)
                        if f != "":
                            print('\nFOR PROPERTY: DISJOINT PATH.')
                            print('flowID = '+str(prop.flow.flowID)+' startL = '+str(prop.flow.startLocation)+' endL = '+str(prop.flow.endLocation))
                            path = path_id_decoder['s'+str(pathsrc)+',s'+str(pathdst)+','+str(abs(pathdst - pathsrc)+1)+',0']
                            print('PATH: '+ ','.join(str(e) for e in path))
                            print('FOUND INTERSECTION WITH FLOW: ' + f)
                            print('PATH: '+ ','.join(str(e) for e in sorted(multiPathProperties[prop.id].sets[f])))
    
    for a in PROPERTIES:
        for prop in PROPERTIES[a]:
            #FINAL RESULT FOR REACHABILITY
            if isinstance(prop, Reachability):
                print('\nFOR PROPERTY: REACHABILITY.')
                print('flowID = '+str(prop.flowID)+' startL = '+str(prop.startLocation)+' endL = '+str(prop.endLocation)+'\n')
                if prop.lastSeen != 0 :
                    print('PROPERTY HOLD IN THIS TEST')
                    print('LAST PACKET SEEN ON EPOCH '+str(prop.lastSeen))
                    print('LARGEST TIME BETWEEN PACKETS ON THIS RUN: '+str(prop.largestGap))
                    print('GAP HAPPENED BETWEEN EPOCHS: '+str(prop.gapS)+' - '+str(prop.gapF))
                else:
                    print('PROPERTY DID NOT HOLD IN THIS TEST')
            
            if isinstance(prop, Waypoint):
                print('\nFOR PROPERTY: WAYPOINT.')
                print('flowID = '+str(prop.flowID)+' startL = '+str(prop.startLocation)+' endL = '+str(prop.endLocation))
                print('EXPECTED WAYPOINTS: ' + ','.join(str(e) for e in prop.expectedWaypoints))
                if prop.errorFound == 0 :
                    print('PROPERTY HOLD IN THIS TEST')
                else:
                    print('PROPERTY DID NOT HOLD IN THIS TEST')

            if isinstance(prop, EqualPathLength):
                print('\nFOR PROPERTY: EQUAL PATH LENGTH.')
                print('flowID = '+str(prop.flowID)+' startL = '+str(prop.startLocation)+' endL = '+str(prop.endLocation))
                print('EXPECTED MAX LENGTH: ' + str(prop.expectedLength))
                if prop.errorFound == 0 :
                    print('PROPERTY HOLD IN THIS TEST')
                else:
                    print('PROPERTY DID NOT HOLD IN THIS TEST')


with open('network-e2edelay.json', 'r') as f:
    configs = json.load(f)

if 'reachability' in configs:
    r = configs['reachability']
    for a in r:
        if(a["endLocation"] in PROPERTIES):
            PROPERTIES[a["endLocation"]].append(Reachability(a["endLocation"], a["flowID"], a["startLocation"]))
        else:
            PROPERTIES[a["endLocation"]] = []
            PROPERTIES[a["endLocation"]].append(Reachability(a["endLocation"], a["flowID"], a["startLocation"]))

if 'waypoint' in configs:
    r = configs['waypoint']
    for a in r:
        if(a["endLocation"] in PROPERTIES):
            PROPERTIES[a["endLocation"]].append(Waypoint(a["startLocation"], a["endLocation"], a["flowID"], a["expectedWaypoints"], a["unexpectedWaypoints"]))
        else:
            PROPERTIES[a["endLocation"]] = []
            PROPERTIES[a["endLocation"]].append(Waypoint(a["startLocation"], a["endLocation"], a["flowID"], a["expectedWaypoints"], a["unexpectedWaypoints"]))

if 'equalPathLength' in configs:
    r = configs['equalPathLength']
    for a in r:
        if(a["endLocation"] in PROPERTIES):
            PROPERTIES[a["endLocation"]].append(EqualPathLength(a["startLocation"], a["endLocation"], a["flowID"], a["pathLength"]))
        else:
            PROPERTIES[a["endLocation"]] = []
            PROPERTIES[a["endLocation"]].append(EqualPathLength(a["startLocation"], a["endLocation"], a["flowID"], a["pathLength"]))

if 'disjointPath' in configs:
    r = configs['disjointPath']
    for a in r:
        multiPathProperties.append(DisjointPath())
        for b in a:
            multiPathProperties[MPid].sets[str(b["startLocation"])+','+str(b["endLocation"])+','+str(b["flowID"])] = set()
            if(b["endLocation"] in PROPERTIES):
                PROPERTIES[b["endLocation"]].append(DisjointPathAux(b["startLocation"], b["endLocation"], b["flowID"], MPid))
            else:
                PROPERTIES[b["endLocation"]] = []
                PROPERTIES[b["endLocation"]].append(DisjointPathAux(b["startLocation"], b["endLocation"], b["flowID"], MPid))
        MPid += 1


main()
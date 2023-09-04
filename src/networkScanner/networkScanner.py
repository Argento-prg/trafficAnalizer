import nmap
import os
import pandas
from networkScanner.customTypes import *
from networkScanner.bduFSTECcheck import findVulnFSTEC

#сканирует порты отдельного хоста или нескольких хостов
def ScanNetwork(targetHosts: str) -> List[PortInfo]:
    #формируем строку пути к файлу БДУ ФСТЕК   
    pathToBDU = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 
        'data/vullist.xlsx'
    )
    excelFile = pandas.DataFrame(pandas.read_excel(pathToBDU))

    portScanner = nmap.PortScanner()
    resultScanDict = portScanner.scan(hosts=targetHosts, arguments='-v -n -A')
    resultScanDict = resultScanDict['scan']
    result: List[PortInfo] = []
    for host, hostInfo in resultScanDict.items():
        protocols = ['tcp', 'udp']
        for proto in protocols:
            protoHostInfo = hostInfo.get(proto)
            if protoHostInfo:
                for port, protoPortInfo in dict(protoHostInfo).items():
                    protoPortInfo = dict(protoPortInfo)
                    portInfo = PortInfo(
                        host=str(host),
                        proto=str(proto),
                        port=str(port),
                        state=str(protoPortInfo.get('state')),
                        reason=str(protoPortInfo.get('reason')),
                        extrainfo=str(protoPortInfo.get('extrainfo')),
                        name=protoPortInfo.get('name'),
                        version=protoPortInfo.get('version'),
                        product=str(protoPortInfo.get('cpe')),
                        script=str(protoPortInfo.get('script')),
                        vulnFSTEC=findVulnFSTEC(
                            protoPortInfo.get('name'), 
                            protoPortInfo.get('version'),
                            excelFile
                        )
                    )
                    result.append(portInfo)
    return result
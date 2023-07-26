import nmap
from typing import List, Dict, Any
import os
import pandas
from networkScanner.bduFSTECcheck import VulnInfo, findVulnFSTEC
from networkScanner.customTypes import FieldInfo

class FieldInfoList():
    name: str
    value: List[VulnInfo]

    def __init__(self, name: str):
        self.name = name
        self.value = []

class PortInfo():
    host: FieldInfo
    proto: FieldInfo
    port: FieldInfo
    state: FieldInfo
    reason: FieldInfo
    extrainfo: FieldInfo
    name: FieldInfo
    version: FieldInfo
    product: FieldInfo
    script: FieldInfo
    vulnFSTEC: FieldInfoList

    def __init__(self):
        self.host = FieldInfo('host')
        self.proto = FieldInfo('protocol')
        self.port = FieldInfo('port')
        self.state = FieldInfo('state')
        self.reason = FieldInfo('reason')
        self.extrainfo = FieldInfo('extrainfo')
        self.name = FieldInfo('name')
        self.version = FieldInfo('version')
        self.product = FieldInfo('cpe')
        self.script = FieldInfo('script')
        self.vulnFSTEC = FieldInfoList('vulnerabilities')

    def getDictMapping(self) -> Dict[str, Any]:
        result = dict()

        result.update({self.host.name: self.host.value})
        result.update({self.proto.name: self.proto.value})
        result.update({self.port.name: self.port.value})
        result.update({self.state.name: self.state.value})
        result.update({self.reason.name: self.reason.value})
        result.update({self.extrainfo.name: self.extrainfo.value})
        result.update({self.name.name: self.name.value})
        result.update({self.version.name: self.version.value})
        result.update({self.product.name: self.product.value})
        result.update({self.script.name: self.script.value})

        vulnList = []
        for item in self.vulnFSTEC.value:
            vulnList.append(item.getDictMapping())
        result.update({self.vulnFSTEC.name: vulnList})

        return result



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
    result = []
    for host, hostInfo in resultScanDict.items():
        protocols = ['tcp', 'udp']
        for proto in protocols:
            protoHostInfo = hostInfo.get(proto)
            if protoHostInfo:
                for port, protoPortInfo in dict(protoHostInfo).items():
                    portInfo = PortInfo()
                    portInfo.host.value = host
                    portInfo.proto.value = proto
                    portInfo.port.value = port
                    portInfo.state.value = dict(protoPortInfo).get(portInfo.state.name)
                    portInfo.reason.value = dict(protoPortInfo).get(portInfo.reason.name)
                    portInfo.extrainfo.value = dict(protoPortInfo).get(portInfo.extrainfo.name)
                    portInfo.name.value = dict(protoPortInfo).get(portInfo.name.name)
                    portInfo.version.value = dict(protoPortInfo).get(portInfo.version.name)
                    portInfo.product.value = dict(protoPortInfo).get(portInfo.product.name)
                    portInfo.script.value = dict(protoPortInfo).get(portInfo.script.name)
                    portInfo.vulnFSTEC.value = findVulnFSTEC(
                        portInfo.name.value, 
                        portInfo.version.value,
                        excelFile
                    )
                    result.append(portInfo)
    return result
import re
import pandas
from packaging import version
from typing import List, Dict
from networkScanner.customTypes import FieldInfo

class VulnInfo():
    id: FieldInfo
    cve: FieldInfo
    name: FieldInfo
    versions: FieldInfo
    describtion: FieldInfo

    def __init__(self):
        self.id = FieldInfo('id')
        self.cve = FieldInfo('cve')
        self.name = FieldInfo('name')
        self.versions = FieldInfo('versions')
        self.describtion = FieldInfo('describtion')
    
    def getDictMapping(self) -> Dict[str, str]:
        result = dict()

        result.update({self.id.name: self.id.value})
        result.update({self.cve.name: self.cve.value})
        result.update({self.name.name: self.name.value})
        result.update({self.versions.name: self.versions.value})
        result.update({self.describtion.name: self.describtion.value})

        return result


def searchPatternVersion(versions: str, cur_ver: str) -> bool:
    for current_service_version in versions.split(','):
        # нижняя граница версии
        begin_version = ''
        end_version = ''
        if 'от' in current_service_version:
            begin_version = re.search('[^\d.]?[\d.]+[^\d.]?', str(current_service_version)+' ')[0]
            while re.search('[\d]', begin_version[0]) is None:
                begin_version = begin_version[1:]
            while re.search("[\d]", begin_version[-1]) is None:
                begin_version = begin_version[:-1]
        if 'до' in current_service_version:
            end_version = re.search('[^\d.]?[\d.]+[^\d.]?', str(current_service_version)+ ' ')
            end_version = end_version[0]
            while re.search('[^\d]', end_version[0]):
                end_version = end_version[1:]
            while re.search('[^\d]', end_version[-1]):
                end_version = end_version[:-1]
            cur_ver = re.search('[^\d.]?[\d.]+[^\d.]?', str(cur_ver)+ ' ')
            cur_ver = cur_ver[0]
            while re.search('[^\d]', cur_ver[0]):
                 end_version = end_version[1:]
            while re.search('[^\d]', cur_ver[-1]):
                 cur_ver = cur_ver[:-1]
        flag_begin_vesion = (begin_version and (not end_version) and (version.parse(begin_version) <= version.parse(cur_ver)))
        flag_end_vesion = ((not begin_version) and (end_version) and (version.parse(cur_ver) <= version.parse(end_version)))
        flag_both_vesion = (begin_version and (end_version) and (version.parse(begin_version) <= version.parse(cur_ver)) and (version.parse(cur_ver) <= version.parse(end_version)))
        
        if flag_begin_vesion or flag_end_vesion or flag_both_vesion:
            return True

    return False

#поиск возможных уязвимостей для 
def findVulnFSTEC(serviceName: str, serviceVersion: str, bduFSTEC: pandas.DataFrame) -> List[VulnInfo]:
    #читаем построчно датафрейм, чтобы найти возможные уязвимости для данного ПО

    result = []

    for _, row in bduFSTEC.iterrows():
        softName = str(row.get('Название ПО'))
        versions = str(row.get('Версия ПО'))
        if serviceName.lower() in softName.lower():
            try:
                if searchPatternVersion(versions, serviceVersion):
                    newVuln = VulnInfo()

                    newVuln.id.value = str(row.get('Идентификатор'))
                    newVuln.cve.value = str(row.get('Идентификаторы других систем описаний уязвимости'))
                    newVuln.name.value = str(row.get('Название ПО'))
                    newVuln.versions.value = str(row.get('Версия ПО'))
                    newVuln.describtion.value = str(row.get('Описание уязвимости'))
            
                    result.append(newVuln)
            except Exception:
                continue
    
    return result
    
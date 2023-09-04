import re
import pandas
from packaging import version
from networkScanner.customTypes import *

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

    result: List[VulnInfo] = []

    for _, row in bduFSTEC.iterrows():
        softName = str(row.get('Название ПО'))
        versions = str(row.get('Версия ПО'))
        if serviceName.lower() in softName.lower():
            try:
                if searchPatternVersion(versions, serviceVersion):
                    newVuln = VulnInfo(
                        id=str(row.get('Идентификатор')),
                        cve=str(row.get('Идентификаторы других систем описаний уязвимости')),
                        name=str(row.get('Название ПО')),
                        versions=str(row.get('Версия ПО')),
                        describtion=str(row.get('Описание уязвимости'))
                    )
                    result.append(newVuln)
            except Exception:
                continue
    
    return result
    
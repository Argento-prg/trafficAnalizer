from networkScanner.networkScanner import ScanNetwork

def main():

    #result = networkScanner.ScanNetwork('localhost')
    result = ScanNetwork('127.0.0.1')
    for item in result:
        print(item.getDictMapping())
        print("+++++++++++++++++++++++++++++++++++++")

if __name__ == '__main__':
    main()
from scapy.all import sniff
from matplotlib import pyplot as plt
from collections import deque
import matplotlib.animation as animation
import sys
import pywt



def packetSniffGenerator():
    counter = 0.0
    limit = 1000
    while limit > counter:
        counter += float(sys.argv[1])
        packets = sniff(timeout=float(sys.argv[1]))
        yield len(packets)

#x = [0]
y = [0]
#fig, ax = plt.subplots()
#[line] = ax.step(x, y)

def update(dy):
    x.append(x[-1] + 1)  # update data
    y.append(dy)

    line.set_xdata(x)  # update plot data
    line.set_ydata(y)

    ax.relim()  # update axes limits
    ax.autoscale_view(True, True, True)
    return line, ax

def main():
	#ani = animation.FuncAnimation(fig, update, packetSniffGenerator)
    for length in packetSniffGenerator():
        #x.append(x[-1] + 1)
        y.append(length)

    (cA, cD) = pywt.dwt(y, 'sym5')
    plt.subplot(3, 1, 1)
    plt.plot(y)
    plt.grid()
    plt.subplot(3, 1, 2)
    plt.plot(cA)
    plt.grid()
    plt.subplot(3, 1, 3)
    plt.plot(cD)
    plt.grid()
    plt.show()


if __name__ == "__main__":
	main()





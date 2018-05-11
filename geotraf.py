'''
Display location of incoming and outgoing network traffic on world map

Run as python geotraf.py

Author: Max Mahlke
'''

from datetime import datetime
import socket
import struct
import sys
import urllib
from urllib.request  import urlopen

import dpkt
import geoip2.database
from matplotlib.figure import Figure
import matplotlib.animation as animation
import matplotlib.pyplot as plt
plt.rcParams['keymap.pan'] = ''  # disable default keyboard shortcuts for 'l', 'q', and 'p'
plt.rcParams['keymap.yscale'] = ''
plt.rcParams['keymap.quit'] = ''
from mpl_toolkits.basemap import Basemap
import numpy as np
import pcap



class TrafficDisplay:
    '''
        The display of world map and animation of incoming and outgoing traffic
    '''

    def __init__(self, reader, my_lat, my_lon, my_city, my_country):
        '''
        Create and display plot of world map

        params
        ------
        reader - geoip2 Reader instance
        my_lat - string, latitude in degrees
        my_lon - string, longitude in degrees
        my_city - string, city of client based on public ip
        my_country - string, country of client based on public ip
        '''

        self.reader = reader
        self.my_lat = my_lat
        self.my_lon = my_lon
        self.my_city = my_city
        self.my_country = my_country

        self.connections = dict()  # dict to hold recent connections

        # Turn on interactive mode
        plt.ion()

        # Create figure
        self.fig = plt.figure(figsize=(9, 6))
        self.ax = self.fig.add_axes([0, 0, 1, 1])

        print('\n\nControls\n--------\nq - exit\np - save screenshot\nl - print recent conncetions to console')

        # ------
        # Use Mercator projection, see https://matplotlib.org/basemap/users/examples.html
        self.traffic_map = Basemap(llcrnrlat=-61.9, urcrnrlat=84, projection='merc',
                                   llcrnrlon=-180, urcrnrlon=180, lat_ts=20,
                                   resolution='l')
        self.traffic_map.drawcoastlines()
        self.traffic_map.fillcontinents(color='lightgray')
        self.fig.canvas.mpl_connect('key_press_event', self.pressed_key)

        self.fig.show()


    def pressed_key(self, event):
        if event.key == 'l':
            print('\n{0: <21}{1: <17}{2: <17}{3: <17}{4: <17}{5: <17}{6: <17}'.format('Time', 'Source IP', 'Dest IP', 'Source City', \
                                                                                    'Source Country', 'Dest City', 'Dest Country'))
            for timestamp, props in self.connections.items():
                time = datetime.utcfromtimestamp(int(timestamp)).strftime('%Y-%m-%d %H:%M:%S')
                try:
                    print('{0: <21}{1: <17}{2: <17}{3: <17}{4: <17}{5: <17}{6: <17}'.format(time, *props))
                except TypeError:
                    pass
            print('\n')
        elif event.key == 'q':
            plt.close(event.canvas.figure)
            sys.exit()
        elif event.key == 'p':
            plt.savefig('traffic_display_%s.png' % datetime.now().strftime('%d%m%Y-%H%M%S'))
            print('Saved screenshot to CWD')


    def sniff_and_animate(self):
        # ------
        # Initiate packet sniffer
        self.sniffer = pcap.pcap(name=None, immediate=True)

        # ------
        # Iterate over traffic in buffer. Display IP packets on world map
        for timestamp, raw_buffer in self.sniffer:

            packet = {}

            # Unpack ethernet frame into
            # mac src, mac dst, ether type
            eth = dpkt.ethernet.Ethernet(raw_buffer)
            packet['eth'] = {'src': eth.src, 'dst': eth.dst, 'type':eth.type}

            # Ensure the packet is IP
            if not isinstance(eth.data, dpkt.ip.IP):
                continue

            # Extract ip packet
            ip_packet = eth.data

            # Extract parts of interest from packet
            # source IP, destination IP, protocol
            packet['ip'] = {'src':ip_packet.src ,
                            'dst':ip_packet.dst, 'p': ip_packet.p}

            # Convert IP addresses from byte to raw decimal strings
            source = byte_to_str(ip_packet.src)
            dest = byte_to_str(ip_packet.dst)

            # ------
            # Filter out broadcast messages and private traffic
            if source != '255.255.255.255' and dest != '255.255.255.255':
                if source.startswith(('192.168.','10.','172.16.','172.31.')):
                    if dest.startswith(('192.168.','10.','172.16.','172.31.')):
                        continue  # local connections
                    else:
                        # Source is local but destination is external -> outgoing traffic
                        try:
                            # Look up destination coordinates
                            response = self.reader.city(dest)
                            dst_lat = response.location.latitude
                            dst_lon = response.location.longitude
                            # Plot connection
                            line, = self.traffic_map.drawgreatcircle(dst_lon, dst_lat, self.my_lon, self.my_lat,
                            linewidth=2, color='r', alpha=0.5)

                            # Add connection to log
                            self.connections[timestamp] = [source, dest, self.my_city, self.my_country, \
                                                           response.city.name, response.country.name]
                        except geoip2.errors.AddressNotFoundError:
                            # If the IP address was not found in the database go to next connection
                            continue
                else:
                    # Source is not local IP, so it is incoming traffic
                    try:
                        # Look up source coordinates
                        response = self.reader.city(source)
                        src_lat = response.location.latitude
                        src_lon = response.location.longitude
                        # Plot connection
                        line, = self.traffic_map.drawgreatcircle(src_lon, src_lat, self.my_lon, self.my_lat,
                                                         linewidth=2, color='g', alpha=0.5)
                        # Add connection to log
                        self.connections[timestamp] = [source, dest, response.city.name, response.country.name, \
                                                       self.my_city, self.my_country]

                    except geoip2.errors.AddressNotFoundError:
                        continue

            # ------
            # Reduce opacity older connections to get vanishing animation
            for connection in self.ax.get_children():
                # Check that line is  visible
                # Basemap lines have alpha=None
                if connection.get_alpha():
                    if connection.get_alpha() > 0.1:
                        reduced_alpha = connection.get_alpha() - 0.1
                        connection.set_alpha(reduced_alpha)
                    else:
                        # If the line's opacity is close to zero, remove it from plot to
                        # release memory
                        connection.remove()

            # Make sure that size of connections dict does not exceed limit of 100
            if len(self.connections.keys()) > 100:
                # Find oldest logged connection
                del self.connections[min(self.connections.keys())]

            # Update plot
            self.fig.canvas.flush_events()


def byte_to_str(adr):
    '''
     Helper function to convert byte addresses to decimal format

     params
     ------
     adr - byte string

     returns
     ------
     return_ip - string, IP address in decimal format
    '''

    return_ip = '.'.join([str(int.from_bytes([i], 'big')) for i in adr])
    return return_ip


def retrieve_ip_and_location(reader):
    '''
        Retrieves public IP address and looks up location

        params
        ------
        reader - geoip2 Reader instance

        returns
        ------
        my_ip - string, public IP address in decimal format
        my_lat - string, latitude of client in degrees
        my_lon - string, longitude of client in degrees
        my_city - string, city of client based on public ip
        my_country - string, country of client based on public ip
    '''

    sys.stdout.write('\n!IP geolocation is inherently imprecise. Interpret with caution!\n')
    sys.stdout.write('\nRetrieving IP address..'.ljust(29))
    # Retrieve public IP
    try:
        my_ip = urlopen('http://ip.42.pl/raw', timeout=3).read().decode('utf-8')
        sys.stdout.write(my_ip)
    except urllib.error.URLError:
        sys.stdout.write('error\nCould not retrieve IP. Is the computer connected to the Internet?\n\n')
        sys.exit()

    # Look-up of coordinates and city based on public IP
    response = reader.city(my_ip)
    my_lat = response.location.latitude
    my_lon = response.location.longitude
    my_city = response.city.name
    my_country = response.country.name

    # Print out retrieved information
    print('\n%s%s, %s' % ('Location:'.ljust(28), my_city, my_country))
    print('%s%.2fdeg, %.2fdeg' % ('Coordinates:'.ljust(28), my_lat, my_lon))
    return my_ip, my_lat, my_lon, my_city, my_country


def main():
    # ------
    # Start by retrieving public IP and looking up own coordinates
    # Requires database GeoLite2-City.mmdb to be present in CWD
    try:
        reader = geoip2.database.Reader('GeoLite2-City.mmdb')
    except FileNotFoundError:
        print('\nCould not find "GeoLite2-City.mmdb" in current working directory. Exiting.\n')
        sys.exit()

    my_ip, my_lat, my_lon, my_city, my_country = retrieve_ip_and_location(reader)

    # ------
    # Initiate world map and packet sniffer
    my_traffic = TrafficDisplay(reader, my_lat, my_lon, my_city, my_country)


    # ------
    # Animate the incoming and outgoing internet traffic
    my_traffic.sniff_and_animate()


if __name__ == '__main__':
    main()

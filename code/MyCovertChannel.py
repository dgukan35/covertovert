from CovertChannelBase import CovertChannelBase
from scapy.all import sniff
from scapy.all import ARP
from scapy.all import Ether
import random

class MyCovertChannel(CovertChannelBase):
    def __init__(self):
        pass

    def generate_random_hex(self, minval, maxval):
        rnd_int = random.randint(minval, maxval)
        return format(rnd_int, "02x")

    def send(self, psrc, pdst, hwdst, hwsrc_prefix, cmpbit, op,
             min_range1, max_range1, min_range2, max_range2, log_file_name):
        """
        - First generate a random binary message.
        - Then for each bit in the message generate a random int between min_range1 and max_range1
          if the bit is equal to cmpbit else between min_range2 and max_range2 and convert this int
          to hex value with length 2.
        - Append this hex value as the last byte of source mac address.
        - Using ARP, send the encoded bit in the hwsrc field.
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)

        for bit in binary_message:

            if bit == cmpbit:
                src_mac = hwsrc_prefix + self.generate_random_hex(min_range1, max_range1)
            else:
                src_mac = hwsrc_prefix + self.generate_random_hex(min_range2, max_range2)

            packet = Ether(dst=hwdst) / ARP(
                op=op,
                hwsrc=src_mac,
                hwdst=hwdst,
                psrc=psrc,
                pdst=pdst
            )
            print(f"Sending bit: {bit}, Packet: {packet.summary()}")
            super().send(packet)

    def receive(self, psrc, cmpval, splt_char, stp_char, filter_arp, iface, store, log_file_name):
        """
        - Initialize an empty list to store the received bits.
        - Then, for each received message decode the source mac address by checking in which interval
          the last byte is laying in.
        - Append this bit to the list.
        - For every new char received, check whether it is '.'. If it is, stop sniffing.
        - After the message is received, convert the binary representation to chars and construct the full message.
        """
        received_message = []
        stop_sniffing = False

        def process_packet(packet):
            nonlocal stop_sniffing
            if packet[ARP].psrc == psrc:
                src_mac = packet[ARP].hwsrc

                last_byte = int(src_mac.split(splt_char)[-1], 16)

                if last_byte < cmpval:
                    bit = "0"
                else:
                    bit = "1"

                received_message.append(bit)

                print(f"Received src_mac: {src_mac}, Decoded bit: {bit}")
                if len(received_message) % 8 == 0:
                    last_8_bits = ''.join(received_message[-8:])
                    char = self.convert_eight_bits_to_character(last_8_bits)
                    if char == stp_char:
                        stop_sniffing = True

        sniff(filter=filter_arp, iface=iface, prn=process_packet, store=store, stop_filter=lambda x: stop_sniffing)
        decoded_message = "".join(
            self.convert_eight_bits_to_character(''.join(received_message[i:i + 8]))
            for i in range(0, len(received_message), 8)
        )

        self.log_message(decoded_message, log_file_name)
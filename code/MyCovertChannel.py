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

    def convert_hex_to_int(self, hex_val):
        return int(hex_val, 16)

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
            super().send(packet)

    def receive(self, psrc, cmpval, splt_char, stp_char, filter_arp,
                iface, store, byte_len, bit_0, bit_1, empty_char,
                last_index, zero, true, false, empty_list, log_file_name):
        """
        - Initialize an empty list to store the received bits.
        - Then, for each received message decode the source mac address by checking in which interval
          the last byte is laying in.
        - Append this bit to the list.
        - For every new char received, check whether it is '.'. If it is, stop sniffing.
        - After the message is received, convert the binary representation to chars and construct the full message.
        """
        received_message = empty_list
        stop_sniffing = false

        def process_packet(packet):
            nonlocal stop_sniffing
            if packet[ARP].psrc == psrc:
                src_mac = packet[ARP].hwsrc

                last_byte = self.convert_hex_to_int(src_mac.split(splt_char)[last_index])

                if last_byte < cmpval:
                    bit = bit_0
                else:
                    bit = bit_1

                received_message.append(bit)

                if not (len(received_message) % byte_len):
                    last_8_bits = empty_char.join(received_message[-byte_len:])
                    char = self.convert_eight_bits_to_character(last_8_bits)
                    if char == stp_char:
                        stop_sniffing = true

        sniff(filter=filter_arp, iface=iface, prn=process_packet, store=store, stop_filter=lambda x: stop_sniffing)
        decoded_message = empty_char.join(
            self.convert_eight_bits_to_character(empty_char.join(received_message[i:i + byte_len]))
            for i in range(zero, len(received_message), byte_len)
        )

        self.log_message(decoded_message, log_file_name)
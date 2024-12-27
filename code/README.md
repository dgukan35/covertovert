## Covert Storage Channel that Exploits Protocol Field Manipulation Using the Source MAC Address Field in ARP

In this project, we are introducing a method that exploits the source MAC address field in ARP to send and receive information over the network layer in an encrypted manner.

## What is a Covert Channel & Covert Storage Channel?

A covert channel is a way of using communication channels in unintended ways. The main motivation behind covert channels is to bypass security controls.
A Covert Storage Channel is one method of implementing a covert channel. In this method, we exploit a field or fields of a communication protocol to embed a message by designing a consensus between the sender and receiver. This way, the embedded messages will be harder, if not impossible, to detect by someone analyzing the message.

## How Does Our Approach Work?

First, we convert each character in our message to its binary representation to get the full binary representation of the entire message, which consists of 8*len(message) bits. Then, we encode each bit by generating a random value within two different intervals. For instance, when the bit is 0, we generate a random integer between 1 and 127. Then, we convert this integer to its hexadecimal representation (with a fixed length of 2).

Next, we add this hex value as the last byte of the source MAC address field in ARP. On the receiver side, we check whether the last byte of the source MAC address is smaller than 128. If it is, we decode it as 0. For encoding 1, we generate a random integer between 128 and 255.

Our receiver appends every decoded bit into a list, and for every new 8 bits received, we convert it back to its character representation to check whether we have received the last character of the message: ".". After receiving the last character, we convert the entire list of bits back into characters and write the message to the log file.

## Covert Channel Capacity

According to our measurements, our covert channel sends around 45 bits per second.
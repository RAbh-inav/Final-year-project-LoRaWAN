# Final-year-project-LoRaWAN
## Performance Measurement of various security mechanisms and simulation of ChaCha encryption and BLAKE2s integrity algorithm for the LoRaWAN network

Basic LoRaWAN network (No security features implemented) with 2 end devices , 1 gateway and 1 network server is implemented in Network Simulator 3 simulation tool (NS-3) using C++ and network analysis is done as part of the first phase of the project. LoRaWAN Network implemented in NS-3 is created based on NS-3 module for LoRaWAN (https://github.com/signetlabdei/lorawan).

For the second phase of the project, Various confidentiality and integrity algorithms are analyzed for performance metrics like speed, latency etc using CryptoPP library  and study of security features of algorithms are done to finalize an efficient and secure algorithm for confidentiality (ChaCha) and integrity(BLAKE2s).

ChaCha and BLAKE2s algorithm are implemented into the LoRaWAN Network by integrating CryptoPP library into NS-3 and by modifying existing header files and creating new header files to incorporate security aspects of LoRaWAN Network.

Metrics like Packet Delivery Rate and Throughput are measured to evaluate performance of the network created
 

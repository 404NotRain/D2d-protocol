# Overview
This repository is a proof of concept for our paper:"An Anonymous and Secure Data Transmission Mechanism with Trajectory Tracking for D2D Relay Communication in 3GPP 5G Networks". The implementation includes session configuration, secure data transmission, and session confirmation process and the experiment is executed under the WLAN. The experiment consists of two parts：Time consuming test corresponding to watchmen(benchmark) and Robustness test corresponding to watchmen.

# Testbed
AMF: DELL laptop with Intel Core i5-7200U processor and 8GB RAM  
Device: HUAWEI P10 with Kirin 960 eight-core processor and 4GB RAM

# Time consuming test
Considering that D2D relay communication will be in 5G frequency band in practice, but the WLAN lacks reliability and works at low broadband, therefore we ignore the propagation delay and the performance of entire procedures. In this part, we mainly test the efficiency of the proposed protocol in terms of computational overhead by executing the embedding procedures in different devices for 1000 times. During the total authentication process, for the time consuming on different devices, the UES, UEi, UET ’s time efficiency are 25.45 ms, 21.07 ms, 0.99 ms, respectively.

# Robustness
In this part, we choose the tampering attack and replaying attack as the representative
## Tampering attack
The tampering attack can be executed by malicious relay device or outside attacker. Here, we assume the relay device as attacker, the relay node acts as follows in the attack experiment. At first the source device initiates the transmission session. After the relay node receives the message, we command that the relay node tampers with the first byte in the field ”data”, then executes the original remaining procedures and outputs the result to the target device. According to the LOG info ”error => sigma m is invalid” on the target device shown in Fig.1, it is obvious that our protocol can detect the modifying attack in time.   
<p align="center">
<img width="200" height="400" src="https://user-images.githubusercontent.com/75431986/155907028-73f784ae-5cb2-42c4-bd1c-3173b22f7041.png" />   
</p>
<p align = "center">
Fig.1 - Tampering attack result
</p>

## Replaying attack
Replaying attack is simulated through two sessions among the source device, the relay device and the target device through the APP. In this attack experiment during the first session procedures, we make the relay node store temporarily the received message from the source device as shown in Fig.2 ”Replay => capture and save the data”.
<p align="center">
<img width="200" height="400" src="https://user-images.githubusercontent.com/75431986/155907162-78d2e2bb-edf2-423b-96dd-0d871e9e9674.png"/>
</p>
<p align = "center">
Fig.2 - Replaying attack process 1
</p>

In the second session, we set the relay node impersonates the original source device and replays the previously captured packet as shown in Fig.3 ”Replay => msg is replaced with the previously captured packet”.
<p align="center">
<img width="200" height="400" src="https://user-images.githubusercontent.com/75431986/155907168-4a8bdf61-fa72-445c-9a7c-db34ac28f289.png"/>
</p>
<p align = "center">
Fig.3 - Replaying attack process 2
</p>

In the end, we set another device as new relay device, then execute the original remaining procedures. According to the LOG info ”error => sid is invalid” shown in Fig.4, it is obvious that our protocol can detect the replay attack in time by the use of sid.
<p align="center">
<img width="200" height="400" src="https://user-images.githubusercontent.com/75431986/155907174-75a280c9-b915-47f5-9069-5db32dd14077.png"/> 
</p>
<p align = "center">
Fig.4 - Replaying attack result
</p>

For more details, please refer to our paper.

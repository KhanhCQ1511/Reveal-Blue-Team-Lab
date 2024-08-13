# Reveal-Blue-Team-Lab

Link Lab: https://cyberdefenders.org/blueteam-ctf-challenges/reveal

Join this lab and download the resource called 192-Reveal.dmp

Use Volability3 tool to analyze dump file

### Q1: Identifying the name of the malicious process helps in understanding the nature of the attack. What is the name of the malicious process?
#### ANS: powershell.exe

![image](https://github.com/user-attachments/assets/19950a0d-f1b4-4c26-87d2-1e3026ded572)

python3 vol.py -f /home/k0i3n/Desktop/192-Reveal.dmp windows.pstree > /home/k0i3n/Desktop/192.txt

Note: "windows.pstree" to see all the process

Looking at the output file you can see there is an anomaly run from powershell pointing to a different IP address.

![image](https://github.com/user-attachments/assets/1127dc4d-60a5-4c7b-9668-f67a599afe4b)

By definition it can be seen that <em><b>net use</b></em> is a command to connect to another computer.

From the IP address found in the dump file <em>45.9.74.32</em>. Using VirusTotal to check this address gives bad results

![image](https://github.com/user-attachments/assets/5028657f-2768-4061-bd54-fa9b1580a784)

From here we determine that this is a malicious process

### Q2: Knowing the parent process ID (PID) of the malicious process aids in tracing the process hierarchy and understanding the attack flow. What is the parent PID of the malicious process?
#### ANS: 4120

You can find ANS in here:
![image](https://github.com/user-attachments/assets/ec6453a6-d8bc-4d6a-99a8-c81e854e558a)

### Q3: Determining the file name used by the malware for executing the second-stage payload is crucial for identifying subsequent malicious activities. What is the file name that the malware uses to execute the second-stage payload?
#### ANS: 3435.dll

![image](https://github.com/user-attachments/assets/7c169b12-402a-41b9-a363-fd46d0f8cf91)

Through this, we determine that after using net use to connect to another computer, this malicious process continues to use <em><b>rundll32</b></em> to run the <em><b>3435.dll</b></em> file on this malicious IP address. Determine that this is the second step to perform

### Q4: Identifying the shared directory on the remote server helps trace the resources targeted by the attacker. What is the name of the shared directory being accessed on the remote server?
#### ANS: davwwwroot

![image](https://github.com/user-attachments/assets/7c169b12-402a-41b9-a363-fd46d0f8cf91)

From the path of running the rundll32 command, we can determine the directory on the malicious server.

### Q5: What is the MITRE sub-technique ID used by the malware to execute the second-stage payload?
#### ANS: T1218.011

![image](https://github.com/user-attachments/assets/821519fb-2331-46b5-b100-5c7291da5278)

Using search in MITRE ATT&CK Framework to find information about the rundll32 command, we will see the MITRE ID

### Q6: Identifying the username under which the malicious process runs helps in assessing the compromised account and its potential impact. What is the username that the malicious process runs under?
#### ANS: Elon

In this question we will probably have to decode the dump file we have in a different way to get the user.

![image](https://github.com/user-attachments/assets/c35a9843-6584-4713-9377-96256bf37f25)

python3 vol.py -f /home/alim/Desktop/192-Reveal.dmp windows.registry.userassist.UserAssist

Using “UserAssist” Windows keeps track of programs you run using a feature in the registry called UserAssist keys. These keys record how many times each program is executed and when it was last run also it will have the name of the user.

![image](https://github.com/user-attachments/assets/9b7053ed-e08f-4242-a628-db92fb4571c0)

There is only 1 user used throughout this file so we can predict this is the user that answers the question.

### Q7: Knowing the name of the malware family is essential for correlating the attack with known threats and developing appropriate defenses. What is the name of the malware family?
#### ANS: 

![image](https://github.com/user-attachments/assets/b69867bc-77d8-4084-9a90-7d8d2f0b6b08)

Through VirusTotal we can know the name of the malware.

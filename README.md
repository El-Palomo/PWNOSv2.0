# PWNOSv2.0
Desarrollo del CTF PWNOSv2.0
> Download: https://www.vulnhub.com/entry/pwnos-20-pre-release,34/

## 1. Configuración.
- La máquina virtual viene configurada con la dirección IP 10.10.10.100.
- Debes configurar tu interfaz de red en este segmento para realizar el ejercicio.

## 2. Escano de Puertos

```
root@kali:~/PWNOS# nmap -n -P0 -p- -sC -sV -O -T5 -oA full 10.10.10.100
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-04 21:36 EST
Nmap scan report for 10.10.10.100
Host is up (0.00033s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.8p1 Debian 1ubuntu3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 85:d3:2b:01:09:42:7b:20:4e:30:03:6d:d1:8f:95:ff (DSA)
|   2048 30:7a:31:9a:1b:b8:17:e7:15:df:89:92:0e:cd:58:28 (RSA)
|_  256 10:12:64:4b:7d:ff:6a:87:37:26:38:b1:44:9f:cf:5e (ECDSA)
80/tcp open  http    Apache httpd 2.2.17 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.2.17 (Ubuntu)
|_http-title: Welcome to this Site!
MAC Address: 00:0C:29:B5:1E:1F (VMware)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.32 - 2.6.39
Network Distance: 1 hop


```














<img src="https://github.com/El-Palomo/-DEV-RANDOM-SCREAM/blob/main/scream1.jpg" width=80% />

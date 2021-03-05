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

<img src="https://github.com/El-Palomo/PWNOSv2.0/blob/main/pwnos1.jpg" width=80% />


## 3. Enumeración de Servicios
- Dado que tenemos un servidor web vamos a buscar carpetas "interesantes" con GOBUSTER.

```
root@kali:~/PWNOS# gobuster dir -u http://10.10.10.100:80/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -e -k -l -s "200,204,301,302,307,401,403" -x "txt,html,php,asp,aspx,jsp"
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.100:80/
[+] Threads:        10
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Show length:    true
[+] Extensions:     html,php,asp,aspx,jsp,txt
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2021/03/05 13:58:49 Starting gobuster
===============================================================
http://10.10.10.100:80/.htpasswd (Status: 403) [Size: 289]
http://10.10.10.100:80/.htpasswd.html (Status: 403) [Size: 294]
http://10.10.10.100:80/.htpasswd.php (Status: 403) [Size: 293]
http://10.10.10.100:80/.htpasswd.asp (Status: 403) [Size: 293]
http://10.10.10.100:80/.htpasswd.aspx (Status: 403) [Size: 294]
http://10.10.10.100:80/.htpasswd.jsp (Status: 403) [Size: 293]
http://10.10.10.100:80/.htpasswd.txt (Status: 403) [Size: 293]
http://10.10.10.100:80/.htaccess (Status: 403) [Size: 289]
http://10.10.10.100:80/.htaccess.aspx (Status: 403) [Size: 294]
http://10.10.10.100:80/.htaccess.jsp (Status: 403) [Size: 293]
http://10.10.10.100:80/.htaccess.txt (Status: 403) [Size: 293]
http://10.10.10.100:80/.htaccess.html (Status: 403) [Size: 294]
http://10.10.10.100:80/.htaccess.php (Status: 403) [Size: 293]
http://10.10.10.100:80/.htaccess.asp (Status: 403) [Size: 293]
http://10.10.10.100:80/.hta (Status: 403) [Size: 284]
http://10.10.10.100:80/.hta.jsp (Status: 403) [Size: 288]
http://10.10.10.100:80/.hta.txt (Status: 403) [Size: 288]
http://10.10.10.100:80/.hta.html (Status: 403) [Size: 289]
http://10.10.10.100:80/.hta.php (Status: 403) [Size: 288]
http://10.10.10.100:80/.hta.asp (Status: 403) [Size: 288]
http://10.10.10.100:80/.hta.aspx (Status: 403) [Size: 289]
http://10.10.10.100:80/activate (Status: 302) [Size: 0]
http://10.10.10.100:80/activate.php (Status: 302) [Size: 0]
http://10.10.10.100:80/blog (Status: 301) [Size: 311]
http://10.10.10.100:80/cgi-bin/ (Status: 403) [Size: 288]
http://10.10.10.100:80/cgi-bin/.html (Status: 403) [Size: 293]
http://10.10.10.100:80/includes (Status: 301) [Size: 315]
http://10.10.10.100:80/index (Status: 200) [Size: 854]
http://10.10.10.100:80/index.php (Status: 200) [Size: 854]
http://10.10.10.100:80/index.php (Status: 200) [Size: 854]
http://10.10.10.100:80/info.php (Status: 200) [Size: 49900]
http://10.10.10.100:80/info (Status: 200) [Size: 49888]
http://10.10.10.100:80/info.php (Status: 200) [Size: 49900]
http://10.10.10.100:80/login (Status: 200) [Size: 1174]
http://10.10.10.100:80/login.php (Status: 200) [Size: 1174]
http://10.10.10.100:80/register (Status: 200) [Size: 1562]
http://10.10.10.100:80/register.php (Status: 200) [Size: 1562]
http://10.10.10.100:80/server-status (Status: 403) [Size: 293]
===============================================================
2021/03/05 13:58:55 Finished
===============================================================
```
- Resaltan algunos archivos: info.php, server-status y la carpeta BLOG.

<img src="https://github.com/El-Palomo/PWNOSv2.0/blob/main/pwnos2.jpg" width=80% />

<img src="https://github.com/El-Palomo/PWNOSv2.0/blob/main/pwnos3.jpg" width=80% />


> Dado que encontramos la carpeta /BLOG/ vamos a seguir enumerando dentro.
```
root@kali:~/PWNOS# gobuster dir -u http://10.10.10.100:80/blog/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -e -k -l -s "200,204,301,302,307,401,403" -x "txt,html,php,asp,aspx,jsp"
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.100:80/blog/
[+] Threads:        10
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Show length:    true
[+] Extensions:     asp,aspx,jsp,txt,html,php
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2021/03/05 14:04:21 Starting gobuster
===============================================================
http://10.10.10.100:80/blog/.htaccess (Status: 403) [Size: 294]
http://10.10.10.100:80/blog/.htaccess.aspx (Status: 403) [Size: 299]
http://10.10.10.100:80/blog/.htaccess.jsp (Status: 403) [Size: 298]
http://10.10.10.100:80/blog/.htaccess.txt (Status: 403) [Size: 298]
http://10.10.10.100:80/blog/.htaccess.html (Status: 403) [Size: 299]
http://10.10.10.100:80/blog/.htaccess.php (Status: 403) [Size: 298]
http://10.10.10.100:80/blog/.htaccess.asp (Status: 403) [Size: 298]
http://10.10.10.100:80/blog/.htpasswd (Status: 403) [Size: 294]
http://10.10.10.100:80/blog/.htpasswd.aspx (Status: 403) [Size: 299]
http://10.10.10.100:80/blog/.htpasswd.jsp (Status: 403) [Size: 298]
http://10.10.10.100:80/blog/.htpasswd.txt (Status: 403) [Size: 298]
http://10.10.10.100:80/blog/.htpasswd.html (Status: 403) [Size: 299]
http://10.10.10.100:80/blog/.htpasswd.php (Status: 403) [Size: 298]
http://10.10.10.100:80/blog/.htpasswd.asp (Status: 403) [Size: 298]
http://10.10.10.100:80/blog/.hta (Status: 403) [Size: 289]
http://10.10.10.100:80/blog/.hta.txt (Status: 403) [Size: 293]
http://10.10.10.100:80/blog/.hta.html (Status: 403) [Size: 294]
http://10.10.10.100:80/blog/.hta.php (Status: 403) [Size: 293]
http://10.10.10.100:80/blog/.hta.asp (Status: 403) [Size: 293]
http://10.10.10.100:80/blog/.hta.aspx (Status: 403) [Size: 294]
http://10.10.10.100:80/blog/.hta.jsp (Status: 403) [Size: 293]
http://10.10.10.100:80/blog/add (Status: 302) [Size: 0]
http://10.10.10.100:80/blog/add.php (Status: 302) [Size: 0]
http://10.10.10.100:80/blog/atom (Status: 200) [Size: 1071]
http://10.10.10.100:80/blog/atom.php (Status: 200) [Size: 1071]
http://10.10.10.100:80/blog/categories (Status: 302) [Size: 0]
http://10.10.10.100:80/blog/categories.php (Status: 302) [Size: 0]
http://10.10.10.100:80/blog/config (Status: 301) [Size: 318]
http://10.10.10.100:80/blog/content (Status: 301) [Size: 319]
http://10.10.10.100:80/blog/comments (Status: 302) [Size: 0]
http://10.10.10.100:80/blog/comments.php (Status: 302) [Size: 0]
http://10.10.10.100:80/blog/contact (Status: 200) [Size: 6233]
http://10.10.10.100:80/blog/contact.php (Status: 200) [Size: 6233]
http://10.10.10.100:80/blog/delete (Status: 302) [Size: 0]
http://10.10.10.100:80/blog/delete.php (Status: 302) [Size: 0]
http://10.10.10.100:80/blog/docs (Status: 301) [Size: 316]
http://10.10.10.100:80/blog/flash (Status: 301) [Size: 317]
http://10.10.10.100:80/blog/images (Status: 301) [Size: 318]
http://10.10.10.100:80/blog/index.php (Status: 200) [Size: 8342]
http://10.10.10.100:80/blog/interface (Status: 301) [Size: 321]
http://10.10.10.100:80/blog/info.php (Status: 302) [Size: 0]
http://10.10.10.100:80/blog/index (Status: 200) [Size: 8342]
http://10.10.10.100:80/blog/index.php (Status: 200) [Size: 8342]
http://10.10.10.100:80/blog/languages (Status: 301) [Size: 321]
http://10.10.10.100:80/blog/languages.php (Status: 302) [Size: 0]
http://10.10.10.100:80/blog/info (Status: 302) [Size: 0]
http://10.10.10.100:80/blog/info.php (Status: 302) [Size: 0]
http://10.10.10.100:80/blog/logout (Status: 302) [Size: 0]
http://10.10.10.100:80/blog/logout.php (Status: 302) [Size: 0]
http://10.10.10.100:80/blog/login (Status: 200) [Size: 5982]
http://10.10.10.100:80/blog/login.php (Status: 200) [Size: 5981]
http://10.10.10.100:80/blog/options (Status: 302) [Size: 0]
http://10.10.10.100:80/blog/options.php (Status: 302) [Size: 0]
http://10.10.10.100:80/blog/rdf (Status: 200) [Size: 1432]
http://10.10.10.100:80/blog/rdf.php (Status: 200) [Size: 1432]
http://10.10.10.100:80/blog/scripts (Status: 301) [Size: 319]
http://10.10.10.100:80/blog/rss (Status: 200) [Size: 1255]
http://10.10.10.100:80/blog/rss.php (Status: 200) [Size: 1255]
http://10.10.10.100:80/blog/setup (Status: 302) [Size: 0]
http://10.10.10.100:80/blog/setup.php (Status: 302) [Size: 0]
http://10.10.10.100:80/blog/static (Status: 302) [Size: 0]
http://10.10.10.100:80/blog/static.php (Status: 302) [Size: 0]
http://10.10.10.100:80/blog/themes (Status: 301) [Size: 318]
http://10.10.10.100:80/blog/themes.php (Status: 302) [Size: 0]
http://10.10.10.100:80/blog/trackback (Status: 302) [Size: 0]
http://10.10.10.100:80/blog/trackback.php (Status: 302) [Size: 0]
http://10.10.10.100:80/blog/upgrade (Status: 302) [Size: 0]
http://10.10.10.100:80/blog/upgrade.php (Status: 302) [Size: 0]
http://10.10.10.100:80/blog/search (Status: 200) [Size: 5266]
http://10.10.10.100:80/blog/search.php (Status: 200) [Size: 5266]
http://10.10.10.100:80/blog/stats (Status: 200) [Size: 5694]
http://10.10.10.100:80/blog/stats.php (Status: 200) [Size: 5694]
```

- Tenemos más carpetas y archivos importantes.  Dado que es bastante información, voy a colocar un resumen a:


| Archivo identificado | Información obtenida |
| ------------- | ------------- |
| / | Aplicación en la carpeta raiz |
| /blog/ | Aplicación web identificada, parece un blog |
| /info.php  | PHPINFO, carpeta raiz /var/www/   |
| /blog/config/  | carpeta que contiene un archivo password.txt con hash  |
| /blog/content/  | Contenido de la aplicación  |
| /blog/images/  | imagenes de la aplicación  |


<img src="https://github.com/El-Palomo/PWNOSv2.0/blob/main/pwnos4.jpg" width=80% />

- Llama la atención el password identificado en formato HASH. Vamos a identificar que algoritmo utilizaron para crearlo.

<img src="https://github.com/El-Palomo/PWNOSv2.0/blob/main/pwnos5.jpg" width=80% />

- Le ejecuté un HASHCAT. Sin suerte!
```
hashcat -m 500 -a 0 -o cracked.txt md5.txt /usr/share/wordlists/fasttrack.txt -O
```


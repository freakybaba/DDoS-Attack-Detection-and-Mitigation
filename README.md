# DDoS-attack-Detection-and-mitigation
DDoS attack mitigation for hping3 tool attack restriction/mitigation.

> <b>Note: </b>every thing is defined for debian/ubuntu based linux environment.
# <center>Steps to follow</center>
    1. Installing required packages
    2. Running server
    3. Distributing codes to its required places
    4. Attacking the server

## <center>Step - 1</center>
> First thing is first make sure you are in `superUser` mode.
> </br>For installation just run `install.sh` and you are good to go.
> </br>It will handle every thing inside it.

## <center>Step - 2</center>
> install apache server.
> </br>And make sure you have enabled it and put your any http website to its `/var/www/html` location.
> </br>Now you can access it via running `localhost` to the web browser.

## <center>Step - 3</center>

### For attacker
>http_flood.sh file contains code for attacking to server `<server_IP>` to `your serverIP` like example: `192.168.1.106`.
>
> Put this  to other `linux machine` or `Virtual linux machine`.

### For Server
> make sure you run everything in `superuser` mode.
> </br>now run `python3 detection_mitigation.py`

> ### If running via virtual box
> <b>Note: </b>Make sure that you have enabled `bridged network` to both VMs.
![image of bridged settings](https://www.howtogeek.com/wp-content/uploads/2012/08/ximage319.png.pagespeed.gp+jp+jw+pj+ws+js+rj+rp+rw+ri+cp+md.ic.wub4WwKyDv.png)

## <center>Step - 4</center>
> make sure you run everything in `superuser` mode.
> </br>run ```chmod +x http_flood.sh```
> </br>run ```./http_flood.sh```

> <b><i>Now you are good to go.</i></b>

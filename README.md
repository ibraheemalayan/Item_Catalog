# Item Catalog - Udacity
### Full Stack Web Development ND
_______________________
## Prerequisites
* Python 3 > [https://realpython.com/installing-python/]  
* Vagrant [https://www.vagrantup.com/docs/installation/]  
* VirtualBox 3 [https://www.virtualbox.org/wiki/Downloads]  
* Python Libraries :  
    - flask  
    - sqlalchemy  
    - google_auth_oauthlib  
    - googleapiclient  
    - hashlib  
    - requests  

## Owner
Ibraheem Alyan

## Overview:
* For short, this project is Website project made with python over the flask framework
* This website is a catalog that contains items sorted within categories
* The catalog is dynamic, meaning that it supports CRUD operations through users interactions
* CRUD operations privileges are controlled by the built-in Authorization & Authentication system
* The Authentication system supports logins and sign-ups with multiple third-party platforms (including Google and Facebook)
* Also an internal signing system is available

## Project Main Components

* project.py : contains the main python code that runs the whole servers  
* database_setup.py : a python script that configures the SQLite Database  
* Fill_DB.py : a python script that fills the database with a sample data  
* Item_Catalog.db : a SQLite Database file  
* templates (Directory) : contains HTML templates and CSS stylesheets  

## Setup Instructions

### Install VirtualBox
VirtualBox is the software that actually runs the virtual machine. You can download it from virtualbox.org. Install the platform package for your operating system. You do not need the extension pack or the SDK. You do not need to launch VirtualBox after installing it; Vagrant will do that.

Ubuntu users: If you are running Ubuntu 14.04, install VirtualBox using the Ubuntu Software Center instead. Due to a reported bug, installing VirtualBox from the site may uninstall other software you need.

### Install Vagrant
Vagrant is the software that configures the VM and lets you share files between your host computer and the VM's filesystem. Download it from vagrantup.com. Install the version for your operating system.

Windows users: The Installer may ask you to grant network permissions to Vagrant or make a firewall exception. Be sure to allow this.

### Download the VM configuration
There are a couple of different ways you can download the VM configuration.

You can download and unzip this file: FSND-Virtual-Machine.zip
> (https://s3.amazonaws.com/video.udacity-data.com/topher/2018/April/5acfbfa3_fsnd-virtual-machine/fsnd-virtual-machine.zip)  
This will give you a directory called FSND-Virtual-Machine. It may be located inside your Downloads folder.

Note: If you are using Windows OS you will find a Time Out error, to fix it use the new Vagrant file configuration
> (https://s3.amazonaws.com/video.udacity-data.com/topher/2019/March/5c7ebe7a_vagrant-configuration-windows/vagrant-configuration-windows.zip)  
to replace you current Vagrant file.

Alternately, you can use Github to fork and clone the repository
> (https://github.com/udacity/fullstack-nanodegree-vm)  

Either way, you will end up with a new directory containing the VM files. Change to this directory in your terminal with cd. Inside, you will find another directory called vagrant. Change directory to the vagrant directory

### Start the virtual machine
From your terminal, inside the vagrant subdirectory, run the command vagrant up. This will cause Vagrant to download the Linux operating system and install it. This may take quite a while (many minutes) depending on how fast your Internet connection is.
When vagrant up is finished running, you will get your shell prompt back. At this point, you can run vagrant ssh to log in to your newly installed Linux VM!

### Logged in!
If you are now looking at a shell prompt that starts with the word vagrant (as in the above screenshot), congratulations — you've gotten logged into your Linux VM.

### The files for this project
Inside the VM, change directory to /vagrant and look around with ls.

The files you see here are the same as the ones in the vagrant subdirectory on your computer (where you started Vagrant from). Any file you create in one will be automatically shared to the other. This means that you can edit code in your favorite text editor, and run it inside the VM.

Files in the VM's /vagrant directory are shared with the vagrant folder on your computer. But other data inside the VM is not. For instance, the PostgreSQL database itself lives only inside the VM.

### Logging out and in
If you type exit (or Ctrl-D) at the shell prompt inside the VM, you will be logged out, and put back into your host computer's shell. To log back in, make sure you're in the same directory and type vagrant SSH again.

If you reboot your computer, you will need to run vagrant up to restart the VM

_______________________
## Project Setup

### Installing required libraries
To automatically install all required dependencies run the following commands in a bash shell in the project main directory
>     sudo apt-get install python3-pip   
>     sudo apt install git  

### Installing the project
run the following command in the directory you want to setup the project in
>     git clone https://github.com/ibraheemalayan/Item_Catalog.git  
>     cd Item_Catalog
>     pip3 install -r requirements.txt
you may get errors installing hashlib using pip, if you got errors please remove hashlib from the requirments.txt file and rerun the above command then intall hashlib using another installer like easy_install 

### setting up the database
Run the following commands to setup the database and fill it with a sample data
>     python3 database_setup.py  
>     python3 Fill_DB.py  

 * now you have a SQLite database file named " Item_Catalog.db "

### Running the Project
to start the main python script to run the server just enter the following command
>     python3 project.py  
to visit the website from your host device just setup a port forwarding from port 5000 on the host to port 5000 on the guest os (for more https://www.howtogeek.com/122641/how-to-forward-ports-to-a-virtual-machine-and-use-it-as-a-server/)
_______________________
## Testing
to visit the website just open up your browser and go to the following link
### https://localhost:5000/  
you may get a warning because the website uses SSL without a valid certification to skip this (in most browsers) click advanced then proceed to localhost

### Facebook Test User
email : udacity_sighkxm_grader@tfbnw.net
password : Grader@098

### Notes
* the project is shipped debug mode on , but you can still turn off the debugging mode by replacing line 1733 with the following  
>     app.debug = True  

* the project uses https because Facebook login doesn't support plain http

* for easier testing ,if you use the sample data you can use one of those 3 accounts to login to the site :
  > email="m.h123@sis.com"                   password="12PassCode34@Dunno"  
  > email="ibraheemalayan@gmail.com"         password="Mary@ItemCata321"  
  > email="sami.Rn@twio.edu"                 password="SsAaMmIi40.50"  

## HOPE it works with you ...

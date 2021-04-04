# server setup
apt update
apt install apache2
cp index.html /var/www/html/
service apache2 reload

# python package installation
pip install pandas
pip install -U scikit-learn
pip install pickle
pip install numpy
pip install csv
